"""Bounded, pinned SSH diagnostics over direct or SSH jump connections."""

import base64
import io
import json
import re
import socket
import threading
import time

import paramiko

from . import inventory, security, storage

ACTIONS = frozenset(("cpu", "memory", "disk", "network", "sockets", "processes"))
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$", re.ASCII)
SLOTS = threading.BoundedSemaphore(4)
MAX_STDOUT, MAX_STDERR = 32768, 2048


class DiagnosticError(RuntimeError):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def initialize() -> None:
    with storage.connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS diagnostic_runs (
            id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, host_name TEXT NOT NULL,
            action TEXT NOT NULL, service TEXT, time INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL, status TEXT NOT NULL, result BLOB NOT NULL
        )""")


def validate(action: str, service: str | None = None) -> str:
    if action in ACTIONS and service is None:
        return action
    if (
        action == "service"
        and service
        and SERVICE_RE.fullmatch(service)
        and not service.startswith("-")
    ):
        return "service " + service
    raise ValueError("Unsupported diagnostic request")


def validate_private_key(raw: str, passphrase: str | None = None):
    if len(raw) > 20000:
        raise ValueError("SSH key too large")
    try:
        return paramiko.Ed25519Key.from_private_key(
            io.StringIO(raw.strip() + "\n"), password=passphrase or None
        )
    except Exception as exc:
        raise ValueError("Invalid Ed25519 SSH private key or passphrase") from exc


def _connect(client, address, port, username, host_key, key, sock=None):
    key_type, key_b64 = inventory.validate_host_key(host_key).split()
    hostkey = paramiko.PKey.from_type_string(
        key_type, base64.b64decode(key_b64, validate=True)
    )
    known_host = address if port == 22 else f"[{address}]:{port}"
    client.get_host_keys().add(known_host, key_type, hostkey)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        hostname=address,
        port=port,
        username=username,
        pkey=key,
        allow_agent=False,
        look_for_keys=False,
        timeout=5,
        banner_timeout=5,
        auth_timeout=5,
        channel_timeout=5,
        sock=sock,
    )


def _read_channel(chan, host_id, action):
    deadline = time.monotonic() + 15
    out, err = bytearray(), bytearray()
    while time.monotonic() < deadline:
        for ready, recv, buf, limit in (
            (chan.recv_ready, chan.recv, out, MAX_STDOUT),
            (chan.recv_stderr_ready, chan.recv_stderr, err, MAX_STDERR),
        ):
            if ready():
                buf.extend(recv(min(4096, limit + 1 - len(buf))))
                if len(buf) > limit:
                    return {
                        "host_id": host_id,
                        "action": action,
                        "output": bytes(out[:MAX_STDOUT]).decode("utf-8", "replace"),
                        "stderr": bytes(err[:MAX_STDERR]).decode("utf-8", "replace"),
                        "exit_code": None,
                        "truncated": True,
                    }
        if (
            chan.exit_status_ready()
            and not chan.recv_ready()
            and not chan.recv_stderr_ready()
        ):
            code = chan.recv_exit_status()
            if code == -1:
                raise DiagnosticError(
                    "SSH connection closed before returning an exit status"
                )
            return {
                "host_id": host_id,
                "action": action,
                "output": out.decode("utf-8", "replace"),
                "stderr": err.decode("utf-8", "replace"),
                "exit_code": code,
                "truncated": code == 125 and b"DIAG_OUTPUT_TRUNCATED" in err,
            }
        time.sleep(0.025)
    raise DiagnosticError(
        "SSH diagnostic timed out; check the target gateway and network", 504
    )


def execute(host_id: int, action: str, service: str | None = None) -> dict:
    command = validate(action, service)
    host = inventory.get_host(host_id)
    if host is None:
        raise ValueError("Unknown host")
    address = inventory.validate_address(host["address"])
    inventory.validate_host_key(host["host_key"])
    proxy = (
        inventory.get_proxy(host["proxy_id"]) if host["proxy_id"] is not None else None
    )
    if host["proxy_id"] is not None and (
        not proxy
        or not all((proxy["address"], proxy["host_key"], proxy["private_key"]))
    ):
        raise ValueError(
            "Proxy routing is not configured; edit the proxy address, host key and SSH credential"
        )
    raw_key = security.get("ssh_private_key")
    if not raw_key:
        raise ValueError("SSH private key has not been configured")
    key = validate_private_key(raw_key, security.get("ssh_key_passphrase"))
    if not SLOTS.acquire(blocking=False):
        raise DiagnosticError("Diagnostic workers are busy; retry shortly", 503)
    client, jump = paramiko.SSHClient(), None
    chan, tunnel = None, None
    try:
        if proxy:
            jump = paramiko.SSHClient()
            proxy_key = validate_private_key(
                storage.decrypt(proxy["private_key"]),
                storage.decrypt(proxy["passphrase"]) if proxy["passphrase"] else None,
            )
            _connect(
                jump,
                inventory.validate_address(proxy["address"]),
                proxy["ssh_port"],
                proxy["username"],
                proxy["host_key"],
                proxy_key,
            )
            transport = jump.get_transport()
            if transport is None:
                raise DiagnosticError("SSH proxy transport unavailable")
            tunnel = transport.open_channel(
                "direct-tcpip", (address, host["ssh_port"]), ("127.0.0.1", 0), timeout=5
            )
        _connect(
            client, address, host["ssh_port"], "root", host["host_key"], key, tunnel
        )
        transport = client.get_transport()
        if transport is None:
            raise DiagnosticError("SSH transport unavailable")
        chan = transport.open_session(timeout=5)
        chan.settimeout(5)
        chan.exec_command(command)
        return _read_channel(chan, host_id, action)
    except paramiko.BadHostKeyException as exc:
        raise DiagnosticError(
            "SSH host key mismatch; verify the target and proxy public keys"
        ) from exc
    except paramiko.AuthenticationException as exc:
        raise DiagnosticError(
            "SSH authentication failed; check the dedicated key and authorized_keys"
        ) from exc
    except paramiko.ChannelException as exc:
        raise DiagnosticError(
            "SSH channel denied; check proxy forwarding and permitopen restrictions"
        ) from exc
    except (TimeoutError, socket.timeout) as exc:
        raise DiagnosticError(
            "SSH connection timed out; check address, port and routing", 504
        ) from exc
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise DiagnosticError(
            "SSH connection failed; check sshd, network and pinned host keys"
        ) from exc
    finally:
        if chan is not None:
            chan.close()
        client.close()
        if tunnel is not None:
            tunnel.close()
        if jump is not None:
            jump.close()
        SLOTS.release()


def run(host_id: int, action: str, service: str | None, actor: str) -> dict:
    """Share audit and encrypted history between Web and MCP callers."""
    start = time.monotonic()
    host = inventory.get_host(host_id)
    try:
        result = execute(host_id, action, service)
        status = (
            "success"
            if result.get("exit_code") == 0 and not result.get("truncated")
            else "warning"
        )
    except Exception as exc:
        status = "failed"
        result = {
            "error": str(exc)
            if isinstance(exc, (ValueError, DiagnosticError))
            else "Diagnostic execution failed"
        }
        raise
    finally:
        if "result" in locals():
            duration = int((time.monotonic() - start) * 1000)
            security.audit(actor, f"diagnose:{host_id}:{action}:{status}")
            with storage.connect() as c:
                c.execute(
                    "INSERT INTO diagnostic_runs(host_id,host_name,action,service,time,duration_ms,status,result) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        host_id,
                        host["name"] if host else "Unknown host",
                        action,
                        service,
                        int(time.time()),
                        duration,
                        status,
                        storage.encrypt(json.dumps(result, ensure_ascii=False)),
                    ),
                )
                c.execute(
                    "DELETE FROM diagnostic_runs WHERE id NOT IN (SELECT id FROM diagnostic_runs ORDER BY id DESC LIMIT 500)"
                )
    result["duration_ms"] = duration
    return result


def recent_runs() -> list[dict]:
    with storage.connect() as c:
        return [
            dict(row)
            for row in c.execute("""SELECT id,host_id,host_name,action,service,time,duration_ms,status
            FROM diagnostic_runs ORDER BY id DESC LIMIT 50""")
        ]


def get_run(row_id: int) -> dict | None:
    with storage.connect() as c:
        row = c.execute(
            "SELECT * FROM diagnostic_runs WHERE id=?", (row_id,)
        ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["result"] = json.loads(storage.decrypt(record["result"]))
    return record


def run_page(
    page: int = 1, page_size: int = 20, status: str = "all", query: str = ""
) -> dict:
    """Return encrypted-result metadata only; decrypt a result on explicit detail access."""
    clauses, values = [], []
    if status != "all":
        clauses.append("status=?")
        values.append(status)
    if query:
        clauses.append("instr(lower(host_name),lower(?))>0")
        values.append(query.strip())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with storage.connect() as c:
        total = c.execute(
            "SELECT COUNT(*) FROM diagnostic_runs" + where, values
        ).fetchone()[0]
        rows = c.execute(
            """SELECT id,host_id,host_name,action,service,time,duration_ms,status
            FROM diagnostic_runs"""
            + where
            + " ORDER BY id DESC LIMIT ? OFFSET ?",
            (*values, page_size, (page - 1) * page_size),
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def overview() -> dict:
    with storage.connect() as c:
        counts = {
            row["status"]: row["amount"]
            for row in c.execute(
                "SELECT status,COUNT(*) AS amount FROM diagnostic_runs GROUP BY status"
            )
        }
        last_run = c.execute("SELECT MAX(time) FROM diagnostic_runs").fetchone()[0]
        groups = c.execute("SELECT COUNT(*) FROM host_groups").fetchone()[0]
    hosts, proxies = inventory.list_rows("hosts"), inventory.list_rows("proxies")
    ready_proxies = {p["id"] for p in proxies if p["status"] == "configured"}
    configured_hosts = sum(
        bool(h["host_key"])
        and (h["proxy_id"] is None or h["proxy_id"] in ready_proxies)
        for h in hosts
    )
    return {
        "database": "ok",
        "ssh_configured": bool(security.get("ssh_private_key")),
        "inventory": {
            "hosts": len(hosts),
            "groups": groups,
            "proxies": len(proxies),
            "configured_proxies": len(ready_proxies),
            "configured_hosts": configured_hosts,
        },
        "runs": {
            "total": sum(counts.values()),
            "success": counts.get("success", 0),
            "warning": counts.get("warning", 0),
            "failed": counts.get("failed", 0),
            "last_run": last_run,
        },
    }


def public_key_info() -> dict:
    raw = security.get("ssh_private_key")
    if not raw:
        return {"ssh_public_key": "", "ssh_fingerprint": ""}
    key = validate_private_key(raw, security.get("ssh_key_passphrase"))
    public = key.get_name() + " " + key.get_base64()
    return {"ssh_public_key": public, "ssh_fingerprint": inventory.fingerprint(public)}
