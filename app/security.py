import os, secrets, sqlite3, time, hashlib, hmac
from pathlib import Path
from contextlib import contextmanager
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request

DATA = Path("/app/data")
DATA.mkdir(parents=True, exist_ok=True)
KEYFILE = DATA / "master.key"
BOOTFILE = DATA / "bootstrap.token"
DB = DATA / "inventory.db"
if not KEYFILE.exists():
    fd = os.open(KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f: f.write(Fernet.generate_key())
if not BOOTFILE.exists() and not DB.exists():
    fd = os.open(BOOTFILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f: f.write(secrets.token_urlsafe(36))
cipher = Fernet(KEYFILE.read_bytes())

@contextmanager
def db():
    c=sqlite3.connect(DB, timeout=10)
    c.row_factory=sqlite3.Row
    try:
        yield c
        c.commit()
    finally: c.close()

def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, open_id TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS oauth_states(state_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time INTEGER, actor TEXT, action TEXT);
        """)
    # A first-start bootstrap token must remain available until setup completes.
    if not configured() and not BOOTFILE.exists():
        fd=os.open(BOOTFILE, os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f: f.write(secrets.token_urlsafe(36))

def configured():
    with db() as c:
        return bool(c.execute("SELECT 1 FROM app_settings WHERE key='feishu_app_id'").fetchone())

def put(key, value):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO app_settings VALUES (?,?)",(key,cipher.encrypt(value.encode())))

def get(key):
    with db() as c:
        row=c.execute("SELECT value FROM app_settings WHERE key=?",(key,)).fetchone()
    return cipher.decrypt(row["value"]).decode() if row else None

def setup(token, app_id, app_secret, admin_open_id, public_url):
    if configured(): raise HTTPException(409,"Already initialized")
    if not BOOTFILE.exists() or not secrets.compare_digest(token,BOOTFILE.read_text()):
        raise HTTPException(403,"Invalid bootstrap token")
    with db() as c:
        if c.execute("SELECT 1 FROM app_settings WHERE key='feishu_app_id'").fetchone():
            raise HTTPException(409,"Already initialized")
        for k,v in {"feishu_app_id":app_id,"feishu_app_secret":app_secret,
                    "admin_open_id":admin_open_id,"public_url":public_url}.items():
            c.execute("INSERT INTO app_settings VALUES (?,?)",(k,cipher.encrypt(v.encode())))
    BOOTFILE.unlink(missing_ok=True)

def issue_state():
    state=secrets.token_urlsafe(32)
    with db() as c:
        c.execute("DELETE FROM oauth_states WHERE expires<?",(int(time.time()),))
        c.execute("INSERT INTO oauth_states VALUES (?,?)",(hashlib.sha256(state.encode()).hexdigest(),int(time.time())+300))
    return state

def consume_state(state):
    digest=hashlib.sha256(state.encode()).hexdigest()
    with db() as c:
        row=c.execute("SELECT expires FROM oauth_states WHERE state_hash=?",(digest,)).fetchone()
        c.execute("DELETE FROM oauth_states WHERE state_hash=?",(digest,))
    return bool(row and row["expires"]>=time.time())

def issue_session(open_id):
    token=secrets.token_urlsafe(40)
    with db() as c:
        c.execute("INSERT INTO sessions VALUES (?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),open_id,int(time.time())+28800))
    return token

def actor(request: Request):
    token=request.cookies.get("diag_session","")
    if not token: raise HTTPException(401,"Feishu login required")
    with db() as c:
        row=c.execute("SELECT open_id FROM sessions WHERE token_hash=? AND expires>?",(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
    if not row: raise HTTPException(401,"Session expired")
    return row["open_id"]

def admin(request: Request):
    who=actor(request)
    if not hmac.compare_digest(who,get("admin_open_id") or ""):
        raise HTTPException(403,"Administrator required")
    return who

def revoke(request: Request):
    token=request.cookies.get("diag_session","")
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(token.encode()).hexdigest(),))

def audit(who, action):
    with db() as c:
        c.execute("INSERT INTO audit(time,actor,action) VALUES (?,?,?)",(int(time.time()),who,action))

def csrf_guard(request: Request):
    # Public URL is an explicit trusted origin; reject cross-site mutations.
    origin=request.headers.get("origin","")
    expected=get("public_url")
    if not expected or origin!=expected:
        raise HTTPException(403,"Origin mismatch")
