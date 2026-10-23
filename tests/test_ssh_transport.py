"""Real Paramiko handshakes and forwarding with ephemeral test identities."""

import io
import socket
import threading
import time
from contextlib import ExitStack, contextmanager

import paramiko
import pytest

from app import diagnostics, inventory, security
from .test_management import private_key


def keypair():
    raw = private_key()
    key = paramiko.Ed25519Key.from_private_key(io.StringIO(raw))
    return raw, key, "ssh-ed25519 " + key.get_base64()


class SSHServer(paramiko.ServerInterface):
    def __init__(self, authorized_key, target=None, stall_exec=False):
        self.authorized_key = authorized_key
        self.target = target
        self.command = None
        self.destination = None
        self.command_event = threading.Event()
        self.stall_exec = stall_exec
        self.release_ack = threading.Event()

    def check_auth_publickey(self, username, key):
        expected = "diag-proxy" if self.target else "root"
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == expected and key == self.authorized_key
            else paramiko.AUTH_FAILED
        )

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session" and not self.target
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        self.command = command
        self.command_event.set()
        if self.stall_exec:
            self.release_ack.wait(5)
        return command == b"cpu"

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.destination = destination
        return (
            paramiko.OPEN_SUCCEEDED
            if self.target and destination == ("172.20.1.10", 22)
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )


@contextmanager
def serve_ssh(host_key, client_key, target=None, stall_exec=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    server = SSHServer(client_key, target, stall_exec)
    resources = []
    stop = threading.Event()

    def pump(source, dest):
        try:
            while not stop.is_set():
                data = source.recv(8192)
                if not data:
                    break
                dest.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            try:
                dest.shutdown_write() if isinstance(
                    dest, paramiko.Channel
                ) else dest.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def worker():
        try:
            conn, _ = listener.accept()
            transport = paramiko.Transport(conn)
            resources.append(transport)
            transport.add_server_key(host_key)
            transport.start_server(server=server)
            chan = transport.accept(timeout=8)
            if chan is None:
                return
            if target:
                forward = socket.create_connection(target, timeout=5)
                resources.append(forward)
                threading.Thread(target=pump, args=(forward, chan), daemon=True).start()
                pump(chan, forward)
            elif stall_exec:
                stop.wait(5)
            elif server.command_event.wait(5):
                chan.sendall(b"load average: 0.15, 0.12, 0.08\n")
                chan.send_exit_status(0)
                chan.shutdown_write()
                stop.wait(3)
        except (paramiko.SSHException, OSError, EOFError):
            pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        yield listener.getsockname(), server
    finally:
        stop.set()
        server.release_ack.set()
        for resource in resources:
            resource.close()
        listener.close()
        thread.join(timeout=2)


def test_real_direct_ssh_and_pinned_identity(authorized, monkeypatch):
    raw, client_key, _ = keypair()
    _, host_key, pub = keypair()
    security.put_many({"ssh_private_key": raw})
    host_id = inventory.save_host("target", "172.20.1.10", 22, None, None, pub)
    original = diagnostics._connect
    with serve_ssh(host_key, client_key) as (address, server):

        def connect(client, ip, port, user, pinned, key, sock=None):
            return original(
                client,
                ip,
                port,
                user,
                pinned,
                key,
                socket.create_connection(address, timeout=5),
            )

        monkeypatch.setattr(diagnostics, "_connect", connect)
        result = diagnostics.execute(host_id, "cpu")
        assert result["exit_code"] == 0 and "load average" in result["output"]
        assert server.command == b"cpu"


def test_real_ssh_jump_pins_both_ends(authorized, monkeypatch):
    raw, target_client, _ = keypair()
    proxy_raw, proxy_client, _ = keypair()
    _, target_host, target_pub = keypair()
    _, proxy_host, proxy_pub = keypair()
    security.put_many({"ssh_private_key": raw})
    proxy_id = inventory.save_proxy(
        "jump", address="172.20.200.20", host_key=proxy_pub, private_key=proxy_raw
    )
    host_id = inventory.save_host(
        "target", "172.20.1.10", 22, None, proxy_id, target_pub
    )
    original = diagnostics._connect
    with serve_ssh(target_host, target_client) as (target_address, target_server):
        with serve_ssh(proxy_host, proxy_client, target=target_address) as (
            jump_address,
            jump_server,
        ):

            def connect(client, ip, port, user, pinned, key, sock=None):
                if sock is None:
                    assert ip == "172.20.200.20" and user == "diag-proxy"
                    sock = socket.create_connection(jump_address, timeout=5)
                return original(client, ip, port, user, pinned, key, sock)

            monkeypatch.setattr(diagnostics, "_connect", connect)
            result = diagnostics.execute(host_id, "cpu")
            assert result["exit_code"] == 0
            assert jump_server.destination == ("172.20.1.10", 22)
            assert target_server.command == b"cpu"


def test_real_wrong_host_key_is_rejected(authorized, monkeypatch):
    raw, client_key, _ = keypair()
    _, server_key, _ = keypair()
    _, _, wrong_key = keypair()
    security.put_many({"ssh_private_key": raw})
    host_id = inventory.save_host("target", "172.20.1.10", 22, None, None, wrong_key)
    original = diagnostics._connect
    with serve_ssh(server_key, client_key) as (address, server):

        def connect(client, ip, port, user, pinned, key, sock=None):
            return original(
                client,
                ip,
                port,
                user,
                pinned,
                key,
                socket.create_connection(address, timeout=5),
            )

        monkeypatch.setattr(diagnostics, "_connect", connect)
        with pytest.raises(diagnostics.DiagnosticError, match="host key mismatch"):
            diagnostics.execute(host_id, "cpu")
        assert server.command is None


@pytest.mark.parametrize("use_jump", [False, True])
def test_exec_ack_timeout_releases_worker(authorized, monkeypatch, use_jump):
    raw, client_key, _ = keypair()
    _, host_key, pub = keypair()
    security.put_many({"ssh_private_key": raw})
    original = diagnostics._connect
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(diagnostics, "SLOTS", slots)
    monkeypatch.setattr(diagnostics, "COMMAND_TIMEOUT", 0.2)
    with serve_ssh(host_key, client_key, stall_exec=True) as (target_address, server):
        # Exercise the same deadline through both direct and jump transports.
        with ExitStack() as stack:
            proxy_id = None
            address = target_address
            if use_jump:
                proxy_raw, proxy_client, _ = keypair()
                _, proxy_host, proxy_pub = keypair()
                address, _ = stack.enter_context(
                    serve_ssh(proxy_host, proxy_client, target=target_address)
                )
                proxy_id = inventory.save_proxy(
                    "jump",
                    address="172.20.200.20",
                    host_key=proxy_pub,
                    private_key=proxy_raw,
                )
            host_id = inventory.save_host(
                "target", "172.20.1.10", 22, None, proxy_id, pub
            )

            def connect(client, ip, port, user, pinned, key, sock=None):
                if sock is None:
                    sock = socket.create_connection(address, timeout=5)
                return original(client, ip, port, user, pinned, key, sock)

            monkeypatch.setattr(diagnostics, "_connect", connect)
            start = time.monotonic()
            with pytest.raises(diagnostics.DiagnosticError, match="timed out") as error:
                diagnostics.execute(host_id, "cpu")
            assert error.value.status == 504
            assert server.command == b"cpu"
            assert time.monotonic() - start < 3
            assert slots.acquire(blocking=False), (
                "timed out execution must release its slot"
            )
            slots.release()


class FloodChannel:
    def recv_ready(self):
        return True

    def recv(self, size):
        return b"x" * size

    def recv_stderr_ready(self):
        return False

    def recv_stderr(self, size):
        return b""

    def exit_status_ready(self):
        return False


def test_output_limit_returns_useful_partial_result():
    result = diagnostics._read_channel(FloodChannel(), 1, "processes")
    assert result["truncated"] and result["exit_code"] is None
    assert len(result["output"]) == diagnostics.MAX_STDOUT


def test_deadline_rejects_stalled_channel(monkeypatch):
    ticks = iter([0, 16])
    monkeypatch.setattr(diagnostics.time, "monotonic", lambda: next(ticks))
    with pytest.raises(diagnostics.DiagnosticError, match="timed out") as error:
        diagnostics._read_channel(FloodChannel(), 1, "cpu")
    assert error.value.status == 504
