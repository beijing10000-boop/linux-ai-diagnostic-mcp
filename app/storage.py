"""One persistent SQLite database and a local encryption trust root."""
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from cryptography.fernet import Fernet

DATA = Path(os.getenv("DIAG_DATA_DIR", "/app/data"))
DB = DATA / "inventory.db"
MASTER = DATA / "master.key"
BOOTSTRAP = DATA / "bootstrap.token"

def _exclusive(path: Path, value: bytes) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, "wb") as f:
        f.write(value)

def initialize() -> None:
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    _exclusive(MASTER, Fernet.generate_key())
    if stat.S_IMODE(MASTER.stat().st_mode) & 0o077:
        raise RuntimeError("Unsafe master.key permissions (required: 0600)")
    with connect() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value BLOB NOT NULL)")

def key() -> bytes:
    if not MASTER.is_file():
        raise RuntimeError("Master key missing; refusing to generate a replacement")
    return MASTER.read_bytes()

def encrypt(value: str) -> bytes:
    return Fernet(key()).encrypt(value.encode("utf-8"))

def decrypt(value: bytes) -> str:
    return Fernet(key()).decrypt(value).decode("utf-8")

@contextmanager
def connect():
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
