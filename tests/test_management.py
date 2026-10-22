"""Regression coverage for editable inventory, credentials and diagnostic history."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import diagnostics, inventory, security, storage
from .conftest import APP_ID, OPEN_ID, PUBLIC_URL
from .test_inventory_diagnostics import valid_host_key


def private_key():
    return (
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )


def host_payload(**overrides):
    return {
        "name": "web-01",
        "address": "172.20.1.10",
        "host_key": valid_host_key(),
        **overrides,
    }


def test_edit_inventory_and_keep_relations(authorized):
    client, headers = authorized
    group = client.post("/api/groups", headers=headers, json={"name": "dev"}).json()[
        "id"
    ]
    host = client.post(
        "/api/hosts", headers=headers, json=host_payload(group_id=group)
    ).json()["id"]
    changed = host_payload(name="web-02", ssh_port=2222, group_id=group)
    assert (
        client.put(f"/api/hosts/{host}", headers=headers, json=changed).status_code
        == 200
    )
    assert (
        client.put(
            f"/api/groups/{group}", headers=headers, json={"name": "test"}
        ).status_code
        == 200
    )
    row = client.get("/api/hosts").json()[0]
    assert (row["name"], row["ssh_port"], row["group_id"]) == ("web-02", 2222, group)
    assert row["fingerprint"].startswith("SHA256:")
    assert client.delete(f"/api/groups/{group}", headers=headers).status_code == 200
    assert client.get("/api/hosts").json()[0]["group_id"] is None


def test_proxy_secrets_encrypted_and_not_returned(authorized):
    client, headers = authorized
    key = private_key()
    payload = {
        "name": "D3",
        "address": "172.20.200.20",
        "username": "diag-proxy",
        "host_key": valid_host_key(),
        "private_key": key,
        "passphrase": "",
    }
    proxy = client.post("/api/proxies", headers=headers, json=payload)
    assert proxy.status_code == 200, proxy.text
    row_id = proxy.json()["id"]
    row = client.get("/api/proxies").json()[0]
    assert row["key_configured"] and row["status"] == "configured"
    assert "private_key" not in row and "passphrase" not in row
    assert key.encode() not in storage.DB.read_bytes()
    payload.pop("private_key")
    payload.pop("passphrase")
    payload["name"] = "D3-new"
    assert (
        client.put(f"/api/proxies/{row_id}", headers=headers, json=payload).status_code
        == 200
    )
    assert storage.decrypt(inventory.get_proxy(row_id)["private_key"]) == key
    host_id = client.post(
        "/api/hosts", headers=headers, json=host_payload(proxy_id=row_id)
    ).json()["id"]
    assert client.delete(f"/api/proxies/{row_id}", headers=headers).status_code == 409
    assert inventory.get_host(host_id)["proxy_id"] == row_id


def test_invalid_credentials_are_400_and_not_echoed(authorized):
    client, headers = authorized
    invalid_key = "invalid_PRIVATE_KEY_sensitive_value" * 6
    result = client.put(
        "/api/settings/ssh", headers=headers, json={"private_key": invalid_key}
    )
    assert result.status_code == 400
    assert invalid_key not in result.text
    assert security.get("ssh_private_key") is None
    result = client.put(
        "/api/settings/ssh", headers=headers, json={"private_key": "secret"}
    )
    assert result.status_code == 422
    assert "secret" not in result.text


def test_settings_unchanged_do_not_logout(authorized):
    client, headers = authorized
    result = client.put(
        "/api/settings",
        headers=headers,
        json={"app_id": APP_ID, "admin_open_id": OPEN_ID, "public_url": PUBLIC_URL},
    )
    assert result.json()["reauth_required"] is False
    assert client.get("/api/me").status_code == 200


def test_domain_change_revokes_sessions_and_oauth(authorized):
    client, headers = authorized
    state, nonce = security.issue_state()
    result = client.put(
        "/api/settings", headers=headers, json={"public_url": "https://new.example.com"}
    )
    assert result.json()["reauth_required"] is True
    assert result.json()["redirect_url"] == "https://new.example.com/login"
    assert not security.consume_state(state, nonce)
    assert client.get("/api/me", headers={"Host": "new.example.com"}).status_code == 401


def test_key_with_comment_is_accepted():
    key = valid_host_key()
    assert inventory.validate_host_key(key + " root@trusted-host") == key
    with pytest.raises(ValueError):
        inventory.validate_host_key(key + "\n" + valid_host_key())


def test_whitespace_names_and_missing_records(authorized):
    client, headers = authorized
    for path in ["groups", "proxies", "hosts"]:
        payload = host_payload(name="  ") if path == "hosts" else {"name": "  "}
        assert client.post(
            "/api/" + path, headers=headers, json=payload
        ).status_code in (400, 422)
    assert (
        client.put("/api/hosts/999", headers=headers, json=host_payload()).status_code
        == 404
    )
    assert (
        client.put(
            "/api/groups/999", headers=headers, json={"name": "missing"}
        ).status_code
        == 404
    )


def test_history_includes_success_and_failure_and_encrypts_outputs(
    authorized, monkeypatch
):
    client, headers = authorized
    host_id = client.post("/api/hosts", headers=headers, json=host_payload()).json()[
        "id"
    ]

    def execute(*_):
        return {
            "host_id": host_id,
            "action": "cpu",
            "exit_code": 0,
            "output": "sensitive test output 123",
            "stderr": "",
            "truncated": False,
        }

    monkeypatch.setattr(diagnostics, "execute", execute)
    result = client.post(
        "/api/diagnose", headers=headers, json={"host_id": host_id, "action": "cpu"}
    )
    assert result.status_code == 200 and result.json()["duration_ms"] >= 0
    runs = client.get("/api/runs").json()
    assert runs[0]["status"] == "success" and "result" not in runs[0]
    assert (
        client.get("/api/runs/" + str(runs[0]["id"])).json()["result"]["output"]
        == "sensitive test output 123"
    )
    assert b"sensitive test output 123" not in storage.DB.read_bytes()

    def fail(*_):
        raise diagnostics.DiagnosticError("SSH test timeout", 504)

    monkeypatch.setattr(diagnostics, "execute", fail)
    assert (
        client.post(
            "/api/diagnose", headers=headers, json={"host_id": host_id, "action": "cpu"}
        ).status_code
        == 504
    )
    assert client.get("/api/runs").json()[0]["status"] == "failed"
    assert "failed" in client.get("/api/audit").json()[0]["action"]


def test_missing_master_does_not_replace_key(configured):
    storage.MASTER.unlink()
    before = storage.DB.read_bytes()
    with pytest.raises(RuntimeError, match="Master key missing"):
        storage.initialize()
    assert not storage.MASTER.exists() and storage.DB.read_bytes() == before


def test_migrates_legacy_proxy_records(client):
    with storage.connect() as c:
        c.execute("DROP TABLE hosts")
        c.execute("DROP TABLE proxies")
        c.execute(
            "CREATE TABLE proxies(id INTEGER PRIMARY KEY,name TEXT UNIQUE,description TEXT DEFAULT '',status TEXT DEFAULT 'unconfigured')"
        )
        c.execute("INSERT INTO proxies(name) VALUES ('legacy-dc')")
    inventory.initialize()
    row = inventory.list_rows("proxies")[0]
    assert (
        row["name"] == "legacy-dc"
        and row["status"] == "unconfigured"
        and not row["key_configured"]
    )
    assert row["username"] == "diag-proxy"


def test_run_history_bounded(authorized, monkeypatch):
    def execute(*_):
        return {"exit_code": 0, "output": "ok", "truncated": False}

    monkeypatch.setattr(diagnostics, "execute", execute)
    with storage.connect() as c:
        c.executemany(
            "INSERT INTO diagnostic_runs(host_id,host_name,action,time,duration_ms,status,result) VALUES (?,?,?,?,?,?,?)",
            [
                (
                    1,
                    "h",
                    "cpu",
                    1,
                    0,
                    "success",
                    storage.encrypt(json.dumps({"output": "old"})),
                )
                for _ in range(501)
            ],
        )
    diagnostics.run(1, "cpu", None, "mcp-stdio")
    with storage.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM diagnostic_runs").fetchone()[0] == 500


def test_repository_pages_have_no_inline_event_handlers():
    for page in (Path(__file__).resolve().parents[1] / "web").glob("*.html"):
        content = page.read_text()
        assert (
            "onclick=" not in content
            and "<script>" not in content
            and "<style>" not in content
        )


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://DIAG.Example.com:443/", "https://diag.example.com"),
        ("https://diag.example.com:9443", "https://diag.example.com:9443"),
        ("https://[fd00::1]:9443", "https://[fd00::1]:9443"),
    ],
)
def test_public_origin_canonicalization(raw, expected):
    from app.main import check_url

    assert check_url(raw) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost",
        "https://127.0.0.2",
        "https://bad\\host.example",
        "https://diag.example.com:0",
        "https://diag.example.com/subpath",
    ],
)
def test_invalid_public_origins(url):
    from fastapi import HTTPException
    from app.main import check_url

    with pytest.raises(HTTPException):
        check_url(url)
