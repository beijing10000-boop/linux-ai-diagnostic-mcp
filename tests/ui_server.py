"""Isolated UI test server. Never imported by the production application."""

import datetime
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID


def main():
    with tempfile.TemporaryDirectory(prefix="diag-ui-") as directory:
        data = Path(directory)
        os.environ["DIAG_DATA_DIR"] = directory
        from app import diagnostics, inventory, security, storage
        from app.main import app
        from app import main as web_main

        strict_check_url = web_main.check_url
        # Allow only this loopback origin in this isolated HTTPS UI fixture.
        web_main.check_url = lambda value: (
            value if value == "https://127.0.0.1:9443" else strict_check_url(value)
        )

        security.init()
        inventory.initialize()
        diagnostics.initialize()
        key = ed25519.Ed25519PrivateKey.generate()
        ssh_private = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ).decode()
        ssh_public = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
            )
            .decode()
        )

        def fixture_execute(host_id, action, service=None):
            # UI-only fixture; transport behavior is tested against real SSH separately.
            time.sleep(0.15)
            if action == "disk":
                raise diagnostics.DiagnosticError(
                    "SSH diagnostic timed out; check the target gateway and network",
                    504,
                )
            inactive = action == "service" and service != "nginx"
            output = (
                "inactive\n"
                if inactive
                else "load average: 0.15, 0.12, 0.08\nCPU load is below the available core count.\n"
            )
            return {
                "host_id": host_id,
                "action": action,
                "output": output,
                "stderr": "",
                "exit_code": 3 if inactive else 0,
                "truncated": False,
            }

        diagnostics.execute = fixture_execute
        cert_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "diag.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(cert_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=2))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("diag.test")]), critical=False
            )
            .sign(cert_key, hashes.SHA256())
        )
        cert_path, key_path = data / "tls.crt", data / "tls.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            cert_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        Path(sys.argv[1]).write_text(
            json.dumps(
                {
                    "bootstrap_token": storage.BOOTSTRAP.read_text(),
                    "session": security.issue_session("ou_browser_test_admin123"),
                    "private_key": ssh_private,
                    "host_key": ssh_public,
                }
            )
        )
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=9443,
            ssl_keyfile=str(key_path),
            ssl_certfile=str(cert_path),
            proxy_headers=False,
            log_level="warning",
        )


if __name__ == "__main__":
    main()
