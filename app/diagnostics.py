import os
import re
import shlex
import paramiko

ACTIONS = {"cpu", "memory", "disk", "network", "sockets", "processes"}
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")

def validate(action: str, service: str | None = None) -> str:
    if action in ACTIONS and not service:
        return action
    if action == "service" and service and SERVICE_RE.fullmatch(service) and not service.startswith("-"):
        return f"service {service}"
    raise ValueError("Unsupported diagnostic request")

def execute(host: str, action: str, service: str | None = None) -> dict:
    allowed = {s.strip() for s in os.environ.get("DIAG_ALLOWED_HOSTS", "").split(",") if s.strip()}
    if host not in allowed:
        raise ValueError("Host not authorized")
    command = validate(action, service)
    client = paramiko.SSHClient()
    client.load_host_keys(os.environ["DIAG_KNOWN_HOSTS"])
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(hostname=host, username=os.environ.get("DIAG_SSH_USER", "root"),
                       key_filename=os.environ["DIAG_SSH_KEY"], look_for_keys=False,
                       allow_agent=False, timeout=5, auth_timeout=5, banner_timeout=5)
        _, stdout, stderr = client.exec_command(command, timeout=12)
        channel = stdout.channel
        channel.settimeout(12)
        out = stdout.read(32768).decode("utf-8", "replace")
        err = stderr.read(2048).decode("utf-8", "replace")
        return {"host": host, "action": action, "output": out, "stderr": err, "exit_code": channel.recv_exit_status()}
    finally:
        client.close()
