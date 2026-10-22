import pytest
from fastapi.testclient import TestClient
from app import storage, security
from app.main import app

APP_ID = "cli_1234567890abc"
OPEN_ID = "ou_1234567890abcdefgh"
PUBLIC_URL = "https://diag.example.com"

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA", tmp_path)
    monkeypatch.setattr(storage, "DB", tmp_path / "inventory.db")
    monkeypatch.setattr(storage, "MASTER", tmp_path / "master.key")
    monkeypatch.setattr(storage, "BOOTSTRAP", tmp_path / "bootstrap.token")
    with TestClient(app, base_url=PUBLIC_URL) as c:
        yield c

@pytest.fixture
def configured(client):
    token = storage.BOOTSTRAP.read_text()
    resp = client.post("/setup", json={"bootstrap_token": token, "app_id": APP_ID,
        "app_secret": "a_fake_secret_for_unit_tests_only",
        "admin_open_id": OPEN_ID, "public_url": PUBLIC_URL})
    assert resp.status_code == 200, resp.text
    return client

@pytest.fixture
def authorized(configured):
    token = security.issue_session(OPEN_ID)
    configured.cookies.set("diag_session", token)
    csrf = configured.get("/api/me").json()["csrf_token"]
    return configured, {"Origin": PUBLIC_URL, "X-CSRF-Token": csrf}
