import os
import secrets
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from .diagnostics import execute

app = FastAPI(title="Linux AI Diagnostic", docs_url=None, redoc_url=None)
class Request(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    action: str
    service: str | None = None

@app.get("/")
def home():
    return FileResponse("web/index.html")

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.post("/api/diagnose")
def diagnose(req: Request, authorization: str | None = Header(default=None)):
    token = os.environ.get("DIAG_API_TOKEN", "")
    if not token or not secrets.compare_digest(authorization or "", "Bearer " + token):
        raise HTTPException(401, "Unauthorized")
    try:
        return execute(req.host, req.action, req.service)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "Diagnostic execution failed")
