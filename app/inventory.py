"""SQLite registry for host groups, hosts and proxy inventory.
Proxy routing is intentionally not enabled until authenticated agent transport exists.
"""
import os
import sqlite3
from contextlib import contextmanager

DB = os.getenv("DIAG_DB_PATH", "/tmp/diagnostic-inventory.db")

@contextmanager
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def initialize():
    with db() as c:
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
            proxy_id INTEGER REFERENCES proxies(id) ON DELETE SET NULL
        );
        """)

def list_rows(table):
    if table not in ("host_groups", "hosts", "proxies"):
        raise ValueError("Unknown inventory table")
    with db() as c:
        return [dict(r) for r in c.execute(f"SELECT * FROM {table} ORDER BY id DESC")]

def insert_group(name, description):
    with db() as c:
        return c.execute("INSERT INTO host_groups(name,description) VALUES (?,?)",
                         (name,description)).lastrowid

def insert_proxy(name, description):
    with db() as c:
        return c.execute("INSERT INTO proxies(name,description) VALUES (?,?)",
                         (name,description)).lastrowid

def insert_host(name, address, ssh_port, group_id, proxy_id):
    with db() as c:
        if group_id is not None and not c.execute("SELECT 1 FROM host_groups WHERE id=?", (group_id,)).fetchone():
            raise ValueError("Unknown group")
        if proxy_id is not None and not c.execute("SELECT 1 FROM proxies WHERE id=?", (proxy_id,)).fetchone():
            raise ValueError("Unknown proxy")
        return c.execute("""INSERT INTO hosts(name,address,ssh_port,group_id,proxy_id)
                            VALUES (?,?,?,?,?)""",
                         (name,address,ssh_port,group_id,proxy_id)).lastrowid

def remove(table, row_id):
    if table not in ("host_groups", "hosts", "proxies"):
        raise ValueError("Unknown inventory table")
    with db() as c:
        count=c.execute(f"DELETE FROM {table} WHERE id=?", (row_id,)).rowcount
        return bool(count)
