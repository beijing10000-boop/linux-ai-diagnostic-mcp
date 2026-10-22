"""Persistent host inventory and SSH jump proxies with pinned identities."""

import base64
import hashlib
import ipaddress
import re

import paramiko

from . import storage

PRIVATE_V4 = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
PRIVATE_V6 = ipaddress.ip_network("fc00::/7")
TABLES = ("host_groups", "hosts", "proxies")


def validate_address(address: str) -> str:
    ip = ipaddress.ip_address(address.strip())
    if getattr(ip, "scope_id", None) or not (
        (ip.version == 4 and any(ip in n for n in PRIVATE_V4))
        or (ip.version == 6 and ip in PRIVATE_V6)
    ):
        raise ValueError("Only RFC1918 or ULA addresses are allowed")
    return str(ip)


def validate_host_key(raw: str) -> str:
    fields = raw.strip().split()
    # Accept the optional comment from /etc/ssh/ssh_host_ed25519_key.pub.
    if (
        len(fields) < 2
        or fields[0] != "ssh-ed25519"
        or len(fields[1]) > 2000
        or "\n" in raw.strip()
    ):
        raise ValueError("Use a verified SSH public host key: ssh-ed25519 AAAA...")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
        key = paramiko.PKey.from_type_string("ssh-ed25519", decoded)
        if key.get_name() != "ssh-ed25519" or key.asbytes() != decoded:
            raise ValueError()
    except Exception as exc:
        raise ValueError("Invalid SSH host key") from exc
    return " ".join(fields[:2])


def fingerprint(raw: str) -> str:
    if not raw:
        return ""
    encoded = validate_host_key(raw).split()[1]
    digest = hashlib.sha256(base64.b64decode(encoded)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


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
        additions = {
            "hosts": {"host_key": "TEXT NOT NULL DEFAULT ''"},
            "proxies": {
                "address": "TEXT NOT NULL DEFAULT ''",
                "ssh_port": "INTEGER NOT NULL DEFAULT 22",
                "username": "TEXT NOT NULL DEFAULT 'diag-proxy'",
                "host_key": "TEXT NOT NULL DEFAULT ''",
                "private_key": "BLOB",
                "passphrase": "BLOB",
            },
        }
        for table, columns in additions.items():
            existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _public(row: dict) -> dict:
    if "private_key" in row:
        row["key_configured"] = bool(row.pop("private_key"))
        row.pop("passphrase", None)
        row["status"] = (
            "configured"
            if all((row["address"], row["host_key"], row["key_configured"]))
            else "unconfigured"
        )
    if "host_key" in row:
        row["fingerprint"] = fingerprint(row["host_key"])
    return row


def list_rows(table: str) -> list[dict]:
    if table not in TABLES:
        raise ValueError("Unknown table")
    with storage.connect() as c:
        return [
            _public(dict(row))
            for row in c.execute(f"SELECT * FROM {table} ORDER BY id DESC")
        ]


def get_host(host_id: int) -> dict | None:
    with storage.connect() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        return dict(row) if row else None


def get_proxy(proxy_id: int) -> dict | None:
    """Internal use only: includes encrypted credentials; never return from an API."""
    with storage.connect() as c:
        row = c.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
        return dict(row) if row else None


def _name(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 80:
        raise ValueError("Name must contain 1 to 80 characters")
    return value


def save_group(name: str, description: str, row_id: int | None = None) -> int | None:
    with storage.connect() as c:
        if row_id is not None:
            updated = c.execute(
                "UPDATE host_groups SET name=?,description=? WHERE id=?",
                (_name(name), description, row_id),
            ).rowcount
            return row_id if updated else None
        return c.execute(
            "INSERT INTO host_groups(name,description) VALUES (?,?)",
            (_name(name), description),
        ).lastrowid


def add_group(name: str, description: str) -> int:
    return save_group(name, description)


def save_proxy(
    name: str,
    description: str = "",
    address: str = "",
    ssh_port: int = 22,
    username: str = "diag-proxy",
    host_key: str = "",
    private_key: str | None = None,
    passphrase: str | None = None,
    row_id: int | None = None,
) -> int | None:
    if address or host_key:
        address, host_key = validate_address(address), validate_host_key(host_key)
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,31}", username):
        raise ValueError("Invalid proxy SSH username")
    if not 1 <= ssh_port <= 65535:
        raise ValueError("Invalid SSH port")
    encrypted_key = storage.encrypt(private_key) if private_key else None
    encrypted_pass = storage.encrypt(passphrase or "") if private_key else None
    with storage.connect() as c:
        if row_id is not None:
            updated = c.execute(
                """UPDATE proxies SET name=?,description=?,address=?,ssh_port=?,username=?,host_key=?,
                private_key=COALESCE(?,private_key),passphrase=COALESCE(?,passphrase) WHERE id=?""",
                (
                    _name(name),
                    description,
                    address,
                    ssh_port,
                    username,
                    host_key,
                    encrypted_key,
                    encrypted_pass,
                    row_id,
                ),
            ).rowcount
            return row_id if updated else None
        return c.execute(
            """INSERT INTO proxies(name,description,address,ssh_port,username,host_key,private_key,passphrase)
            VALUES (?,?,?,?,?,?,?,?)""",
            (
                _name(name),
                description,
                address,
                ssh_port,
                username,
                host_key,
                encrypted_key,
                encrypted_pass,
            ),
        ).lastrowid


def save_host(
    name: str,
    address: str,
    port: int,
    group_id: int | None,
    proxy_id: int | None,
    host_key: str,
    row_id: int | None = None,
) -> int | None:
    address, host_key = validate_address(address), validate_host_key(host_key)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid SSH port")
    with storage.connect() as c:
        for table, foreign_id, label in (
            ("host_groups", group_id, "group"),
            ("proxies", proxy_id, "proxy"),
        ):
            if (
                foreign_id is not None
                and not c.execute(
                    f"SELECT 1 FROM {table} WHERE id=?", (foreign_id,)
                ).fetchone()
            ):
                raise ValueError("Unknown " + label)
        values = (_name(name), address, port, group_id, proxy_id, host_key)
        if row_id is not None:
            updated = c.execute(
                """UPDATE hosts SET name=?,address=?,ssh_port=?,group_id=?,proxy_id=?,host_key=?
                WHERE id=?""",
                (*values, row_id),
            ).rowcount
            return row_id if updated else None
        return c.execute(
            """INSERT INTO hosts(name,address,ssh_port,group_id,proxy_id,host_key)
            VALUES (?,?,?,?,?,?)""",
            values,
        ).lastrowid


def add_host(
    name: str,
    address: str,
    port: int,
    group_id: int | None,
    proxy_id: int | None,
    host_key: str,
) -> int:
    return save_host(name, address, port, group_id, proxy_id, host_key)


def remove(table: str, row_id: int) -> bool:
    if table not in TABLES:
        raise ValueError("Unknown table")
    with storage.connect() as c:
        c.execute("BEGIN IMMEDIATE")
        if (
            table == "proxies"
            and c.execute("SELECT 1 FROM hosts WHERE proxy_id=?", (row_id,)).fetchone()
        ):
            raise ValueError(
                "Proxy is assigned to hosts; reassign them before deleting"
            )
        return c.execute(f"DELETE FROM {table} WHERE id=?", (row_id,)).rowcount > 0
