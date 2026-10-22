import ipaddress
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
    yield

app = FastAPI(title="Linux AI Diagnostic", docs_url=None, redoc_url=None, lifespan=lifespan)

def require_auth(authorization: str | None = Header(default=None)):
    token = os.environ.get("DIAG_API_TOKEN", "")
    if not token or not secrets.compare_digest(authorization or "", "Bearer " + token):
        raise HTTPException(401, "Unauthorized")

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
def home():
    return FileResponse("web/index.html")

@app.get("/inventory")
def inventory_page():
    return FileResponse("web/inventory.html")

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.post("/api/diagnose", dependencies=[Depends(require_auth)])
def diagnose(req: Request):
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
def create_group(req: GroupCreate):
    try:
        return {"id": inventory.insert_group(req.name, req.description)}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Group already exists")

@app.delete("/api/groups/{row_id}", dependencies=[Depends(require_auth)])
def delete_group(row_id: int):
    if not inventory.remove("host_groups", row_id):
        raise HTTPException(404, "Group not found")
    return {"ok": True}

@app.get("/api/proxies", dependencies=[Depends(require_auth)])
def proxies():
    return inventory.list_rows("proxies")

@app.post("/api/proxies", dependencies=[Depends(require_auth)])
def create_proxy(req: ProxyCreate):
    try:
        return {"id": inventory.insert_proxy(req.name, req.description), "status": "unconfigured"}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Proxy already exists")

@app.delete("/api/proxies/{row_id}", dependencies=[Depends(require_auth)])
def delete_proxy(row_id: int):
    if not inventory.remove("proxies", row_id):
        raise HTTPException(404, "Proxy not found")
    return {"ok": True}

@app.get("/api/hosts", dependencies=[Depends(require_auth)])
def hosts():
    return inventory.list_rows("hosts")

@app.post("/api/hosts", dependencies=[Depends(require_auth)])
def create_host(req: HostCreate):
    try:
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
def delete_host(row_id: int):
    if not inventory.remove("hosts", row_id):
        raise HTTPException(404, "Host not found")
    return {"ok": True}
