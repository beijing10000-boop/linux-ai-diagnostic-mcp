"""Persistent inventory with explicit SSH host-key pinning and private-IP restrictions."""
import base64
import ipaddress
import re
import sqlite3
import paramiko
from . import storage

PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
PRIVATE_V6 = ipaddress.ip_network("fc00::/7")

def validate_address(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if not ((ip.version == 4 and any(ip in n for n in PRIVATE_V4)) or
            (ip.version == 6 and ip in PRIVATE_V6)):
        raise ValueError("Only RFC1918 or ULA addresses are allowed")
    return str(ip)

def validate_host_key(raw: str) -> str:
    fields = raw.strip().split()
    if len(fields) != 2 or fields[0] != "ssh-ed25519" or len(fields[1]) > 2000:
        raise ValueError("Use a verified SSH public host key: ssh-ed25519 AAAA...")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
        key = paramiko.PKey.from_type_string("ssh-ed25519", decoded)
        if key.get_name() != "ssh-ed25519":
            raise ValueError()
    except Exception as exc:
        raise ValueError("Invalid SSH host key") from exc
    return " ".join(fields)

def initialize() -> None:
    with storage.connect() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS host_groups (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS proxies (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'unconfigured'
            );
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                address TEXT NOT NULL UNIQUE, ssh_port INTEGER NOT NULL DEFAULT 22,
                group_id INTEGER REFERENCES host_groups(id) ON DELETE SET NULL,
                proxy_id INTEGER REFERENCES proxies(id) ON DELETE SET NULL,
                host_key TEXT NOT NULL DEFAULT ''
            );
        """)
        cols = {row["name"] for row in c.execute("PRAGMA table_info(hosts)")}
        if "host_key" not in cols:
            c.execute("ALTER TABLE hosts ADD COLUMN host_key TEXT NOT NULL DEFAULT ''")

def list_rows(table: str) -> list[dict]:
    if table not in ("host_groups", "hosts", "proxies"):
        raise ValueError("Unknown table")
    with storage.connect() as c:
        return [dict(row) for row in c.execute(f"SELECT * FROM {table} ORDER BY id DESC")]

def get_host(host_id: int) -> dict | None:
    with storage.connect() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        return dict(row) if row else None

def add_group(name: str, description: str) -> int:
    with storage.connect() as c:
        return c.execute("INSERT INTO host_groups(name,description) VALUES (?,?)",
                         (name.strip(), description)).lastrowid

def add_proxy(name: str, description: str) -> int:
    with storage.connect() as c:
        return c.execute("INSERT INTO proxies(name,description) VALUES (?,?)",
                         (name.strip(), description)).lastrowid

def add_host(name: str, address: str, port: int, group_id: int | None,
             proxy_id: int | None, host_key: str) -> int:
    address = validate_address(address)
    host_key = validate_host_key(host_key)
    with storage.connect() as c:
        if group_id is not None and not c.execute("SELECT 1 FROM host_groups WHERE id=?", (group_id,)).fetchone():
            raise ValueError("Unknown group")
        if proxy_id is not None and not c.execute("SELECT 1 FROM proxies WHERE id=?", (proxy_id,)).fetchone():
            raise ValueError("Unknown proxy")
        return c.execute("""INSERT INTO hosts(name,address,ssh_port,group_id,proxy_id,host_key)
                            VALUES (?,?,?,?,?,?)""",
                         (name.strip(), address, port, group_id, proxy_id, host_key)).lastrowid

def remove(table: str, row_id: int) -> bool:
    if table not in ("host_groups", "hosts", "proxies"):
        raise ValueError("Unknown table")
    with storage.connect() as c:
        return c.execute(f"DELETE FROM {table} WHERE id=?", (row_id,)).rowcount > 0
