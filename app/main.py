"""Web control plane; public routes are explicitly limited."""

import ipaddress
import logging
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import diagnostics, inventory, security

VERSION = "0.1.0"
LOG = logging.getLogger(__name__)
WEB = Path(__file__).resolve().parent.parent / "web"


@asynccontextmanager
async def lifespan(_: FastAPI):
    security.init()
    inventory.initialize()
    diagnostics.initialize()
    yield


app = FastAPI(
    title="Linux AI Diagnostic",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # HTTPS reverse proxy must preserve Host and reject unknown hosts at the edge.
    if (
        request.url.path != "/healthz"
        and security.storage.DB.exists()
        and security.configured()
    ):
        expected = urlsplit(security.get("public_url") or "").netloc.lower()
        actual = (request.headers.get("host") or "").lower()
        if not secrets.compare_digest(actual, expected):
            return JSONResponse({"detail": "Unrecognized Host"}, status_code=400)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["Cache-Control"] = "no-store"
    return response


def admin(request: Request) -> str:
    return security.admin(request)


def mutation(request: Request) -> str:
    security.csrf_guard(request)
    return security.admin(request)


def check_url(raw: str) -> str:
    try:
        u = urlsplit(raw)
        if (
            u.scheme != "https"
            or not u.hostname
            or u.username
            or u.password
            or u.path not in ("", "/")
            or u.query
            or u.fragment
            or any(c.isspace() for c in raw)
        ):
            raise ValueError()
        host = u.hostname.encode("idna").decode("ascii").lower()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if host == "localhost" or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in host.split(".")
            ):
                raise ValueError()
        else:
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                raise ValueError()
            host = f"[{ip}]" if ip.version == 6 else str(ip)
        port = u.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        return "https://" + host + (f":{port}" if port and port != 443 else "")
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Public URL must be a valid HTTPS origin")


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Omit submitted input, which can contain a private key or app secret.
    return JSONResponse(
        {"detail": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]},
        status_code=422,
    )


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BootstrapRequest(InputModel):
    bootstrap_token: str = Field(min_length=20, max_length=200)
    app_id: str = Field(pattern=r"^cli_[A-Za-z0-9]{8,80}$")
    app_secret: str = Field(min_length=10, max_length=300)
    admin_open_id: str = Field(pattern=r"^ou_[A-Za-z0-9_-]{8,150}$")
    public_url: str = Field(max_length=300)


class HostCreate(InputModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    group_id: int | None = Field(default=None, ge=1)
    proxy_id: int | None = Field(default=None, ge=1)
    host_key: str = Field(min_length=20, max_length=2500)


class NameCreate(InputModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Name cannot be blank")
        return value.strip()


class ProxySave(NameCreate):
    address: str = Field(default="", max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(
        default="diag-proxy", pattern=r"^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$"
    )
    host_key: str = Field(default="", max_length=2500)
    private_key: str | None = Field(default=None, min_length=80, max_length=20000)
    passphrase: str | None = Field(default=None, max_length=1000)


class DiagnoseRequest(InputModel):
    host_id: int = Field(ge=1)
    action: str = Field(min_length=1, max_length=30)
    service: str | None = Field(default=None, max_length=64)


class SettingsUpdate(InputModel):
    app_id: str | None = Field(default=None, pattern=r"^cli_[A-Za-z0-9]{8,80}$")
    app_secret: str | None = Field(default=None, min_length=10, max_length=300)
    admin_open_id: str | None = Field(
        default=None, pattern=r"^ou_[A-Za-z0-9_-]{8,150}$"
    )
    public_url: str | None = Field(default=None, max_length=300)


class SSHSettingsUpdate(InputModel):
    private_key: str = Field(min_length=80, max_length=20000)
    passphrase: str | None = Field(default=None, max_length=1000)


@app.get("/")
def home(request: Request):
    if not security.configured():
        return FileResponse(WEB / "setup.html")
    try:
        admin(request)
    except HTTPException:
        return RedirectResponse("/login", status_code=303)
    return FileResponse(WEB / "index.html")


@app.get("/login")
def login():
    if not security.configured():
        return RedirectResponse("/", status_code=303)
    return FileResponse(WEB / "login.html")


@app.get("/inventory")
def inventory_page(request: Request):
    try:
        admin(request)
    except HTTPException:
        return RedirectResponse("/login", status_code=303)
    return FileResponse(WEB / "inventory.html")


@app.get("/settings")
def settings_page(request: Request):
    try:
        admin(request)
    except HTTPException:
        return RedirectResponse("/login", status_code=303)
    return FileResponse(WEB / "settings.html")


@app.get("/healthz")
def health():
    return {"status": "ok", "version": VERSION}


@app.post("/setup")
def bootstrap(body: BootstrapRequest, request: Request):
    security.rate_limit("bootstrap:" + request.client.host, 8, 600)
    public_url = check_url(body.public_url)
    security.setup(
        body.bootstrap_token,
        body.app_id,
        body.app_secret,
        body.admin_open_id,
        public_url,
    )
    return {"ok": True, "redirect_uri": public_url + "/auth/feishu/callback"}


@app.get("/auth/feishu")
def feishu_start(request: Request):
    if not security.configured():
        raise HTTPException(503, "Setup required")
    security.rate_limit("login:" + request.client.host, 30, 60)
    state, nonce = security.issue_state()
    params = {
        "client_id": security.get("feishu_app_id"),
        "response_type": "code",
        "redirect_uri": security.get("public_url") + "/auth/feishu/callback",
        "state": state,
    }
    response = RedirectResponse(
        "https://accounts.feishu.cn/open-apis/authen/v1/authorize?" + urlencode(params),
        status_code=303,
    )
    response.set_cookie(
        "diag_oauth",
        nonce,
        max_age=300,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/auth/feishu/callback",
    )
    return response


def login_failure(reason: str):
    response = RedirectResponse("/login?error=" + reason, status_code=303)
    response.delete_cookie("diag_oauth", path="/auth/feishu/callback")
    return response


@app.get("/auth/feishu/callback")
async def feishu_callback(
    request: Request, code: str = "", state: str = "", error: str = ""
):
    security.rate_limit("callback:" + request.client.host, 30, 60)
    if not security.consume_state(state, request.cookies.get("diag_oauth", "")):
        return login_failure("state")
    if error or not code:
        return login_failure("cancelled")
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            r = await client.post(
                "https://open.feishu.cn/open-apis/authen/v2/oauth/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": security.get("feishu_app_id"),
                    "client_secret": security.get("feishu_app_secret"),
                    "code": code,
                    "redirect_uri": security.get("public_url")
                    + "/auth/feishu/callback",
                },
            )
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict) or str(data.get("code", 0)) != "0":
                raise ValueError("Token exchange rejected")
            nested = data.get("data") or {}
            if not isinstance(nested, dict):
                raise ValueError("Invalid token data")
            access = data.get("access_token") or nested.get("access_token")
            if not access or not isinstance(access, str):
                raise ValueError("Missing access token")
            r = await client.get(
                "https://open.feishu.cn/open-apis/authen/v1/user_info",
                headers={"Authorization": "Bearer " + access},
            )
            r.raise_for_status()
            payload = r.json()
            if not isinstance(payload, dict) or str(payload.get("code", 0)) != "0":
                raise ValueError("User lookup rejected")
            user = payload.get("data") or payload
            if not isinstance(user, dict):
                raise ValueError("Invalid user data")
            open_id = user.get("open_id")
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        LOG.warning("Feishu OAuth verification failed")
        return login_failure("unavailable")
    if (
        not open_id
        or not isinstance(open_id, str)
        or not re.fullmatch(r"ou_[A-Za-z0-9_-]{8,150}", open_id)
        or not secrets.compare_digest(open_id, security.get("admin_open_id") or "")
    ):
        security.audit("feishu-oauth", "login:unauthorized")
        return login_failure("unauthorized")
    token = security.issue_session(open_id)
    security.audit(open_id, "login")
    result = RedirectResponse("/", status_code=303)
    result.set_cookie(
        "diag_session",
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=security.SESSION_TTL,
        path="/",
    )
    result.delete_cookie("diag_oauth", path="/auth/feishu/callback")
    return result


@app.get("/api/me", dependencies=[Depends(admin)])
def me(request: Request):
    return {
        "open_id": security.admin(request),
        "role": "admin",
        "csrf_token": security.csrf_token(request),
        "version": VERSION,
    }


@app.post("/api/logout", dependencies=[Depends(mutation)])
def logout(request: Request):
    security.revoke(request)
    response = JSONResponse({"ok": True})
    response.delete_cookie("diag_session", path="/")
    return response


@app.get("/api/settings", dependencies=[Depends(admin)])
def settings():
    return {
        "app_id": security.get("feishu_app_id"),
        "admin_open_id": security.get("admin_open_id"),
        "public_url": security.get("public_url"),
        "app_secret_configured": bool(security.get("feishu_app_secret")),
        "ssh_private_key_configured": bool(security.get("ssh_private_key")),
    }


@app.put("/api/settings", dependencies=[Depends(mutation)])
def update_settings(body: SettingsUpdate, request: Request):
    values = body.model_dump(exclude_none=True)
    if "public_url" in values:
        values["public_url"] = check_url(values["public_url"])
    mapping = {
        "app_id": "feishu_app_id",
        "app_secret": "feishu_app_secret",
        "admin_open_id": "admin_open_id",
        "public_url": "public_url",
    }
    who = security.admin(request)
    changed = {
        mapping[key]: value
        for key, value in values.items()
        if security.get(mapping[key]) != value
    }
    reauth = bool(changed)
    security.put_many(changed, revoke_sessions=reauth)
    security.audit(who, "update_settings")
    return {
        "ok": True,
        "reauth_required": reauth,
        "redirect_url": (values.get("public_url") or security.get("public_url"))
        + "/login",
    }


@app.put("/api/settings/ssh", dependencies=[Depends(mutation)])
def update_ssh(body: SSHSettingsUpdate, request: Request):
    try:
        diagnostics.validate_private_key(body.private_key, body.passphrase)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    security.put_many(
        {
            "ssh_private_key": body.private_key,
            "ssh_key_passphrase": body.passphrase or "",
        }
    )
    security.audit(security.admin(request), "rotate_ssh_credential")
    return {"ok": True}


@app.get("/api/audit", dependencies=[Depends(admin)])
def audit():
    return security.recent_audit()


@app.get("/api/groups", dependencies=[Depends(admin)])
def groups():
    return inventory.list_rows("host_groups")


@app.post("/api/groups", dependencies=[Depends(mutation)])
def create_group(req: NameCreate, request: Request):
    try:
        group_id = inventory.add_group(req.name, req.description)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Duplicate group")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    security.audit(security.admin(request), "create_group")
    return {"id": group_id}


@app.delete("/api/groups/{row_id}", dependencies=[Depends(mutation)])
def delete_group(row_id: int, request: Request):
    if not inventory.remove("host_groups", row_id):
        raise HTTPException(404, "Group not found")
    security.audit(security.admin(request), "delete_group")
    return {"ok": True}


@app.get("/api/proxies", dependencies=[Depends(admin)])
def proxies():
    return inventory.list_rows("proxies")


def save_proxy(req: ProxySave, row_id: int | None = None):
    try:
        if req.private_key:
            diagnostics.validate_private_key(req.private_key, req.passphrase)
        saved = inventory.save_proxy(**req.model_dump(), row_id=row_id)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Duplicate proxy") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if saved is None:
        raise HTTPException(404, "Proxy not found")
    return {"id": saved}


@app.post("/api/proxies", dependencies=[Depends(mutation)])
def create_proxy(req: ProxySave, request: Request):
    result = save_proxy(req)
    security.audit(security.admin(request), "create_proxy:" + str(result["id"]))
    return result


@app.put("/api/proxies/{row_id}", dependencies=[Depends(mutation)])
def update_proxy(row_id: int, req: ProxySave, request: Request):
    result = save_proxy(req, row_id)
    security.audit(security.admin(request), "update_proxy:" + str(row_id))
    return result


@app.delete("/api/proxies/{row_id}", dependencies=[Depends(mutation)])
def delete_proxy(row_id: int, request: Request):
    try:
        deleted = inventory.remove("proxies", row_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if not deleted:
        raise HTTPException(404, "Proxy not found")
    security.audit(security.admin(request), "delete_proxy")
    return {"ok": True}


@app.get("/api/hosts", dependencies=[Depends(admin)])
def hosts():
    return inventory.list_rows("hosts")


@app.post("/api/hosts", dependencies=[Depends(mutation)])
def create_host(req: HostCreate, request: Request):
    try:
        host_id = inventory.add_host(
            req.name,
            req.address,
            req.ssh_port,
            req.group_id,
            req.proxy_id,
            req.host_key,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Duplicate host")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    security.audit(security.admin(request), "create_host")
    return {"id": host_id}


@app.delete("/api/hosts/{row_id}", dependencies=[Depends(mutation)])
def delete_host(row_id: int, request: Request):
    if not inventory.remove("hosts", row_id):
        raise HTTPException(404, "Host not found")
    security.audit(security.admin(request), "delete_host")
    return {"ok": True}


@app.put("/api/groups/{row_id}", dependencies=[Depends(mutation)])
def update_group(row_id: int, req: NameCreate, request: Request):
    try:
        saved = inventory.save_group(req.name, req.description, row_id)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Duplicate group") from exc
    if saved is None:
        raise HTTPException(404, "Group not found")
    security.audit(security.admin(request), "update_group:" + str(row_id))
    return {"id": saved}


@app.put("/api/hosts/{row_id}", dependencies=[Depends(mutation)])
def update_host(row_id: int, req: HostCreate, request: Request):
    try:
        saved = inventory.save_host(
            req.name,
            req.address,
            req.ssh_port,
            req.group_id,
            req.proxy_id,
            req.host_key,
            row_id,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Duplicate host name or address") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if saved is None:
        raise HTTPException(404, "Host not found")
    security.audit(security.admin(request), "update_host:" + str(row_id))
    return {"id": saved}


@app.get("/api/runs", dependencies=[Depends(admin)])
def runs():
    return diagnostics.recent_runs()


@app.get("/api/runs/{row_id}", dependencies=[Depends(admin)])
def run_detail(row_id: int):
    record = diagnostics.get_run(row_id)
    if record is None:
        raise HTTPException(404, "Diagnostic run not found")
    return record


@app.post("/api/diagnose", dependencies=[Depends(mutation)])
def diagnose(req: DiagnoseRequest, request: Request):
    who = security.admin(request)
    security.rate_limit("diagnose:" + who, 30, 60)
    try:
        return diagnostics.run(req.host_id, req.action, req.service, who)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except diagnostics.DiagnosticError as exc:
        raise HTTPException(exc.status, str(exc)) from exc
    except Exception as exc:
        LOG.warning("Diagnostic error: %s", type(exc).__name__)
        raise HTTPException(502, "Diagnostic execution failed") from exc
