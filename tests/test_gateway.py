"""Exercise the actual forced-command program without shell interpretation."""

import runpy
import subprocess
import sys
from pathlib import Path

import pytest

GATEWAY = Path(__file__).resolve().parents[1] / "gateway" / "ai-diagnostic-gateway"


@pytest.mark.parametrize(
    "command",
    [
        "id",
        "reboot",
        "cpu; id",
        "service --help",
        "service nginx;reboot",
        "service nginx\nreboot",
        "sftp",
        "",
    ],
)
def test_gateway_rejects_arbitrary_commands(command):
    result = subprocess.run(
        [sys.executable, "-I", str(GATEWAY)],
        env={"SSH_ORIGINAL_COMMAND": command},
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 2
    assert result.stdout == b""


def test_gateway_executes_only_fixed_cpu_program():
    result = subprocess.run(
        [sys.executable, "-I", str(GATEWAY)],
        env={"SSH_ORIGINAL_COMMAND": "cpu", "PATH": "/nonexistent"},
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0
    assert b"load average" in result.stdout


def test_gateway_caps_child_output(monkeypatch, capfd):
    namespace = runpy.run_path(str(GATEWAY))
    monkeypatch.setattr(
        namespace["shutil"], "which", lambda *args, **kwargs: sys.executable
    )
    code = namespace["run"](
        ["test-utility", "-c", "import os;os.write(1,b'x'*1000000)"]
    )
    out, err = capfd.readouterr()
    assert code == 125 and len(out) == 32768
    assert "DIAG_OUTPUT_TRUNCATED" in err


def test_gateway_reports_missing_utility(monkeypatch, capsys):
    namespace = runpy.run_path(str(GATEWAY))
    monkeypatch.setattr(namespace["shutil"], "which", lambda *args, **kwargs: None)
    assert namespace["run"](["missing"]) == 127
    assert "unavailable" in capsys.readouterr().err
