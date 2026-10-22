import ipaddress
import re
import httpx
from urllib.parse import urlencode
from fastapi import Request as HttpRequest
from fastapi.responses import RedirectResponse, JSONResponse
from . import security
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from .diagnostics import execute
from . import inventory

@asynccontextmanager
async def lifespan(app):
    inventory.initialize()
    security.init()
    yield

app = FastAPI(title="Linux AI Diagnostic", docs_url=None, redoc_url=None, lifespan=lifespan)

def require_auth(request: HttpRequest):
    return security.admin(request)

class Request(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    action: str
    service: str | None = None

class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)

class ProxyCreate(GroupCreate):
    pass

class HostCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str
    ssh_port: int = Field(default=22, ge=1, le=65535)
    group_id: int | None = None
    proxy_id: int | None = None

@app.get("/")
def home(request: HttpRequest):
    if not security.configured():
        return FileResponse("web/setup.html")
    try: security.admin(request)
    except HTTPException: return RedirectResponse("/login",status_code=303)
    return FileResponse("web/index.html")

@app.get("/settings")
def settings_page(request: HttpRequest):
    security.admin(request)
    return FileResponse("web/settings.html")

@app.get("/inventory")
def inventory_page(request: HttpRequest):
    security.admin(request)
    return FileResponse("web/inventory.html")

@app.get("/login")
def login():
    return FileResponse("web/login.html")

class BootstrapRequest(BaseModel):
    bootstrap_token: str
    app_id: str = Field(pattern=r"^cli_[A-Za-z0-9]{8,80}$")
    app_secret: str = Field(min_length=10,max_length=300)
    admin_open_id: str = Field(pattern=r"^ou_[A-Za-z0-9_-]{8,150}$")
    public_url: str

@app.post("/setup")
def bootstrap(body: BootstrapRequest, request: HttpRequest):
    from urllib.parse import urlsplit
    u=urlsplit(body.public_url)
    if u.scheme!="https" or not u.hostname or u.username or u.password or u.path not in ("","/") or u.query or u.fragment:
        raise HTTPException(400,"Public URL must be an HTTPS origin")
    security.setup(body.bootstrap_token,body.app_id,body.app_secret,body.admin_open_id,body.public_url.rstrip("/"))
    return {"ok":True,"redirect_uri":body.public_url.rstrip("/")+"/auth/feishu/callback"}

@app.get("/auth/feishu")
def feishu_start():
    if not security.configured(): raise HTTPException(503,"Setup required")
    state=security.issue_state()
    params={"client_id":security.get("feishu_app_id"),"response_type":"code",
            "redirect_uri":security.get("public_url")+"/auth/feishu/callback","state":state}
    return RedirectResponse("https://accounts.feishu.cn/open-apis/authen/v1/authorize?"+urlencode(params),status_code=303)

@app.get("/auth/feishu/callback")
async def feishu_callback(code: str, state: str):
    if not security.consume_state(state): raise HTTPException(403,"Invalid OAuth state")
    async with httpx.AsyncClient(timeout=8.0) as client:
        response=await client.post("https://open.feishu.cn/open-apis/authen/v2/oauth/token",
            json={"grant_type":"authorization_code","client_id":security.get("feishu_app_id"),
                  "client_secret":security.get("feishu_app_secret"),"code":code,
                  "redirect_uri":security.get("public_url")+"/auth/feishu/callback"})
        response.raise_for_status()
        data=response.json()
        access=data.get("access_token") or data.get("data",{}).get("access_token")
        if not access: raise HTTPException(401,"Feishu token exchange failed")
        profile=await client.get("https://open.feishu.cn/open-apis/authen/v1/user_info",
                                 headers={"Authorization":"Bearer "+access})
        profile.raise_for_status()
        payload=profile.json()
        open_id=(payload.get("data") or payload).get("open_id")
    if not open_id or not secrets.compare_digest(open_id,security.get("admin_open_id")):
        raise HTTPException(403,"Not an authorized administrator")
    token=security.issue_session(open_id)
    security.audit(open_id,"login")
    result=RedirectResponse("/",status_code=303)
    result.set_cookie("diag_session",token,httponly=True,secure=True,samesite="lax",max_age=28800,path="/")
    return result

@app.get("/api/me", dependencies=[Depends(require_auth)])
def me(request: HttpRequest):
    return {"open_id":security.admin(request),"role":"admin"}

@app.post("/api/logout", dependencies=[Depends(require_auth)])
def logout(request: HttpRequest):
    security.csrf_guard(request)
    security.revoke(request)
    response=JSONResponse({"ok":True})
    response.delete_cookie("diag_session",path="/")
    return response

@app.get("/api/settings", dependencies=[Depends(require_auth)])
def settings():
    return {"app_id":security.get("feishu_app_id"),
            "admin_open_id":security.get("admin_open_id"),
            "public_url":security.get("public_url"),
            "app_secret_configured":bool(security.get("feishu_app_secret"))}

class SettingsUpdate(BaseModel):
    app_secret: str | None = Field(default=None,min_length=10,max_length=300)

@app.put("/api/settings", dependencies=[Depends(require_auth)])
def update_settings(body: SettingsUpdate, request: HttpRequest):
    security.csrf_guard(request)
    if body.app_secret:
        security.put("feishu_app_secret",body.app_secret)
        security.audit(security.admin(request),"rotate_feishu_secret")
    return {"ok":True}

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.post("/api/diagnose", dependencies=[Depends(require_auth)])
def diagnose(req: Request, request: HttpRequest):
    security.csrf_guard(request)
    security.audit(security.admin(request),"diagnose:"+req.action)
    # The inventory proxy field is metadata only: never silently route via a proxy.
    try:
        return execute(req.host, req.action, req.service)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "Diagnostic execution failed")

@app.get("/api/groups", dependencies=[Depends(require_auth)])
def groups():
    return inventory.list_rows("host_groups")

@app.post("/api/groups", dependencies=[Depends(require_auth)])
def create_group(req: GroupCreate, request: HttpRequest):
    security.csrf_guard(request)
    # Cross-site mutations must originate from the configured HTTPS origin.\n    try:
        return {"id": inventory.insert_group(req.name, req.description)}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Group already exists")

@app.delete("/api/groups/{row_id}", dependencies=[Depends(require_auth)])
def delete_group(row_id: int, request: HttpRequest):
    security.csrf_guard(request)
    # Cross-site mutations must originate from the configured HTTPS origin.\n    if not inventory.remove("host_groups", row_id):
        raise HTTPException(404, "Group not found")
    return {"ok": True}

@app.get("/api/proxies", dependencies=[Depends(require_auth)])
def proxies():
    return inventory.list_rows("proxies")

@app.post("/api/proxies", dependencies=[Depends(require_auth)])
def create_proxy(req: ProxyCreate, request: HttpRequest):
    security.csrf_guard(request)
    # Cross-site mutations must originate from the configured HTTPS origin.\n    try:
        return {"id": inventory.insert_proxy(req.name, req.description), "status": "unconfigured"}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Proxy already exists")

@app.delete("/api/proxies/{row_id}", dependencies=[Depends(require_auth)])
def delete_proxy(row_id: int, request: HttpRequest):
    security.csrf_guard(request)
    # Cross-site mutations must originate from the configured HTTPS origin.\n    if not inventory.remove("proxies", row_id):
        raise HTTPException(404, "Proxy not found")
    return {"ok": True}

@app.get("/api/hosts", dependencies=[Depends(require_auth)])
def hosts():
    return inventory.list_rows("hosts")

@app.post("/api/hosts", dependencies=[Depends(require_auth)])
def create_host(req: HostCreate, request: HttpRequest):
    security.csrf_guard(request)
    # Cross-site mutations must originate from the configured HTTPS origin.\n    try:
        ipaddress.ip_address(req.address)
    except ValueError:
        raise HTTPException(400, "Only literal IPv4/IPv6 addresses are allowed")
    try:
        return {"id": inventory.insert_host(req.name, req.address, req.ssh_port, req.group_id, req.proxy_id)}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Duplicate host")
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@app.delete("/api/hosts/{row_id}", dependencies=[Depends(require_auth)])
def delete_host(row_id: int, request: HttpRequest):
    security.csrf_guard(request)
    # Cross-site mutations must originate from the configured HTTPS origin.\n    if not inventory.remove("hosts", row_id):
        raise HTTPException(404, "Host not found")
    return {"ok": True}
