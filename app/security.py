"""Feishu identity, encrypted settings, browser-bound OAuth and CSRF."""

import hashlib
import hmac
import secrets
import time
from urllib.parse import urlsplit
from fastapi import HTTPException, Request
from . import storage

ALLOWED_SETTINGS = {
    "feishu_app_id",
    "feishu_app_secret",
    "admin_open_id",
    "public_url",
    "ssh_private_key",
    "ssh_key_passphrase",
}
SESSION_TTL = 8 * 3600
OAUTH_TTL = 300


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def init() -> None:
    storage.initialize()
    with storage.connect() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, open_id TEXT NOT NULL, expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_states (
                state_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL, nonce_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, time INTEGER NOT NULL,
                actor TEXT NOT NULL, action TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_limits (
                identifier TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL
            );
        """)
        fields = {row["name"] for row in c.execute("PRAGMA table_info(oauth_states)")}
        if "nonce_hash" not in fields:
            c.execute("ALTER TABLE oauth_states ADD COLUMN nonce_hash TEXT")
    if not configured():
        storage._exclusive(storage.BOOTSTRAP, secrets.token_urlsafe(48).encode())
    elif storage.BOOTSTRAP.exists():
        storage.BOOTSTRAP.unlink()


def configured() -> bool:
    with storage.connect() as c:
        return (
            c.execute("SELECT 1 FROM app_settings WHERE key='feishu_app_id'").fetchone()
            is not None
        )


def get(key: str) -> str | None:
    if key not in ALLOWED_SETTINGS:
        raise ValueError("Invalid settings key")
    with storage.connect() as c:
        row = c.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    return storage.decrypt(row["value"]) if row else None


def put_many(values: dict[str, str], revoke_sessions: bool = False) -> None:
    if not values.keys() <= ALLOWED_SETTINGS:
        raise ValueError("Invalid settings key")
    encrypted = {key: storage.encrypt(value) for key, value in values.items()}
    with storage.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        c.executemany(
            "INSERT OR REPLACE INTO app_settings(key,value) VALUES (?,?)",
            encrypted.items(),
        )
        if revoke_sessions:
            c.execute("DELETE FROM sessions")
            c.execute("DELETE FROM oauth_states")


def setup(
    token: str, app_id: str, app_secret: str, admin_open_id: str, public_url: str
) -> None:
    with storage.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        if c.execute("SELECT 1 FROM app_settings WHERE key='feishu_app_id'").fetchone():
            raise HTTPException(409, "Already initialized")
        if (
            not token.isascii()
            or not storage.BOOTSTRAP.exists()
            or not secrets.compare_digest(token, storage.BOOTSTRAP.read_text())
        ):
            raise HTTPException(403, "Invalid bootstrap token")
        for key, value in {
            "feishu_app_id": app_id,
            "feishu_app_secret": app_secret,
            "admin_open_id": admin_open_id,
            "public_url": public_url,
        }.items():
            c.execute(
                "INSERT INTO app_settings(key,value) VALUES (?,?)",
                (key, storage.encrypt(value)),
            )
    storage.BOOTSTRAP.unlink(missing_ok=True)


def issue_state() -> tuple[str, str]:
    state, nonce = secrets.token_urlsafe(36), secrets.token_urlsafe(36)
    with storage.connect() as c:
        c.execute("DELETE FROM oauth_states WHERE expires<?", (int(time.time()),))
        c.execute(
            "INSERT INTO oauth_states(state_hash,expires,nonce_hash) VALUES (?,?,?)",
            (_hash(state), int(time.time()) + OAUTH_TTL, _hash(nonce)),
        )
    return state, nonce


def consume_state(state: str, nonce: str) -> bool:
    if not state or not nonce or len(state) > 200 or len(nonce) > 200:
        return False
    with storage.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            "SELECT expires,nonce_hash FROM oauth_states WHERE state_hash=?",
            (_hash(state),),
        ).fetchone()
        c.execute("DELETE FROM oauth_states WHERE state_hash=?", (_hash(state),))
        return bool(
            row
            and row["nonce_hash"]
            and row["expires"] >= int(time.time())
            and secrets.compare_digest(row["nonce_hash"], _hash(nonce))
        )


def issue_session(open_id: str) -> str:
    token = secrets.token_urlsafe(48)
    with storage.connect() as c:
        c.execute("DELETE FROM sessions WHERE expires<?", (int(time.time()),))
        c.execute(
            "INSERT INTO sessions VALUES (?,?,?)",
            (_hash(token), open_id, int(time.time()) + SESSION_TTL),
        )
    return token


def actor(request: Request) -> str:
    token = request.cookies.get("diag_session", "")
    if not token or len(token) > 160:
        raise HTTPException(401, "Feishu login required")
    with storage.connect() as c:
        row = c.execute(
            "SELECT open_id FROM sessions WHERE token_hash=? AND expires>?",
            (_hash(token), int(time.time())),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "Session expired")
    return row["open_id"]


def admin(request: Request) -> str:
    who = actor(request)
    expected = get("admin_open_id") or ""
    if not expected or not hmac.compare_digest(who, expected):
        raise HTTPException(403, "Administrator required")
    return who


def csrf_token(request: Request) -> str:
    """Derive the token after the caller has authenticated the request."""
    cookie = request.cookies["diag_session"]
    return hmac.new(
        storage.key(), ("csrf:" + cookie).encode(), hashlib.sha256
    ).hexdigest()


def secure_cookie() -> bool:
    """Use the persisted scheme, never untrusted forwarding headers."""
    return urlsplit(get("public_url") or "").scheme == "https"


def csrf_guard(request: Request) -> str:
    who = admin(request)
    origin = request.headers.get("origin", "")
    if origin != get("public_url"):
        raise HTTPException(403, "Origin mismatch")
    submitted = request.headers.get("x-csrf-token", "")
    if (
        not submitted.isascii()
        or not submitted
        or not secrets.compare_digest(submitted, csrf_token(request))
    ):
        raise HTTPException(403, "Invalid CSRF token")
    return who


def revoke(request: Request) -> None:
    token = request.cookies.get("diag_session", "")
    with storage.connect() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (_hash(token),))


def audit(who: str, action: str) -> None:
    with storage.connect() as c:
        c.execute(
            "INSERT INTO audit(time,actor,action) VALUES (?,?,?)",
            (int(time.time()), who[:160], action[:255]),
        )


def recent_audit() -> list[dict]:
    with storage.connect() as c:
        return [
            dict(row)
            for row in c.execute(
                "SELECT time, actor, action FROM audit ORDER BY id DESC LIMIT 100"
            )
        ]


def rate_limit(key: str, limit: int, seconds: int) -> None:
    now = int(time.time())
    with storage.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            "SELECT window,count FROM rate_limits WHERE identifier=?", (key,)
        ).fetchone()
        if row is None or now - row["window"] >= seconds:
            c.execute(
                "INSERT OR REPLACE INTO rate_limits VALUES (?,?,?)", (key, now, 1)
            )
        elif row["count"] >= limit:
            raise HTTPException(429, "Rate limit exceeded")
        else:
            c.execute("UPDATE rate_limits SET count=count+1 WHERE identifier=?", (key,))
