"""Restricted SSH diagnostics; no arbitrary shell or SFTP tools."""
import base64
import io
import re
import threading
import time
import paramiko
from . import inventory, security

ACTIONS = frozenset(("cpu", "memory", "disk", "network", "sockets", "processes"))
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$", re.ASCII)
SLOTS = threading.BoundedSemaphore(4)
MAX_STDOUT, MAX_STDERR = 32768, 2048

def validate(action: str, service: str | None = None) -> str:
    if action in ACTIONS and service is None:
        return action
    if action == "service" and service and SERVICE_RE.fullmatch(service) and not service.startswith("-"):
        return "service " + service
    raise ValueError("Unsupported diagnostic request")

def validate_private_key(raw: str, passphrase: str | None = None):
    if len(raw) > 20000:
        raise ValueError("SSH key too large")
    try:
        return paramiko.Ed25519Key.from_private_key(io.StringIO(raw), password=passphrase or None)
    except Exception as exc:
        raise ValueError("Invalid Ed25519 SSH private key or passphrase") from exc

def execute(host_id: int, action: str, service: str | None = None) -> dict:
    command = validate(action, service)
    host = inventory.get_host(host_id)
    if host is None:
        raise ValueError("Unknown host")
    if host["proxy_id"] is not None:
        raise ValueError("Proxy routing is not enabled in v0.1.0")
    address = inventory.validate_address(host["address"])
    pinned = inventory.validate_host_key(host["host_key"])
    raw_key = security.get("ssh_private_key")
    if not raw_key:
        raise ValueError("SSH private key has not been configured")
    key = validate_private_key(raw_key, security.get("ssh_key_passphrase"))
    if not SLOTS.acquire(blocking=False):
        raise RuntimeError("Diagnostic worker busy")
    client = paramiko.SSHClient()
    try:
        key_type, key_b64 = pinned.split()
        hostkey = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_b64, validate=True))
        known_host = address if host["ssh_port"] == 22 else f"[{address}]:{host['ssh_port']}"
        client.get_host_keys().add(known_host, key_type, hostkey)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(hostname=address, port=host["ssh_port"], username="root", pkey=key,
                       allow_agent=False, look_for_keys=False, timeout=5,
                       banner_timeout=5, auth_timeout=5)
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport unavailable")
        chan = transport.open_session(timeout=5)
        chan.exec_command(command)
        deadline = time.monotonic() + 15
        out, err = bytearray(), bytearray()
        truncated = False
        while time.monotonic() < deadline:
            if chan.recv_ready():
                chunk = chan.recv(min(4096, MAX_STDOUT + 1 - len(out)))
                out.extend(chunk)
                if len(out) > MAX_STDOUT:
                    truncated = True
                    break
            if chan.recv_stderr_ready():
                chunk = chan.recv_stderr(min(2048, MAX_STDERR + 1 - len(err)))
                err.extend(chunk)
                if len(err) > MAX_STDERR:
                    truncated = True
                    break
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                return {"host_id": host_id, "action": action,
                        "output": out.decode("utf-8", "replace"),
                        "stderr": err.decode("utf-8", "replace"),
                        "exit_code": chan.recv_exit_status(), "truncated": False}
            time.sleep(0.025)
        if truncated:
            raise RuntimeError("Diagnostic output exceeded configured limit")
        raise TimeoutError("Diagnostic timed out")
    finally:
        client.close()
        SLOTS.release()
