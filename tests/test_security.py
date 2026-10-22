from urllib.parse import parse_qs, urlsplit
import pytest
from app import security, storage
from .conftest import APP_ID, OPEN_ID, PUBLIC_URL

def test_bootstrap_once(client):
    token = storage.BOOTSTRAP.read_text()
    payload={"bootstrap_token":token,"app_id":APP_ID,
             "app_secret":"secret_for_test_12345","admin_open_id":OPEN_ID,
             "public_url":PUBLIC_URL}
    response=client.post("/setup",json=payload)
    assert response.status_code==200
    assert not storage.BOOTSTRAP.exists()
    assert client.post("/setup",json=payload).status_code==409
    assert b"secret_for_test_12345" not in storage.DB.read_bytes()

def test_no_anonymous_access(configured):
    for path in ("/api/me","/api/settings","/api/hosts","/inventory","/settings"):
        assert configured.get(path).status_code==401
    assert configured.post("/api/diagnose",json={"host_id":1,"action":"cpu"}).status_code==401

def test_csrf_enforced(authorized):
    client,headers=authorized
    assert client.post("/api/groups",json={"name":"dev"}).status_code==403
    assert client.post("/api/groups",headers={"Origin":PUBLIC_URL},json={"name":"dev"}).status_code==403
    assert client.post("/api/groups",headers={"Origin":"https://evil.example",
                            "X-CSRF-Token":headers["X-CSRF-Token"]},json={"name":"dev"}).status_code==403
    assert client.post("/api/groups",headers=headers,json={"name":"dev"}).status_code==200
    assert any(x["name"]=="dev" for x in client.get("/api/groups").json())

def test_oauth_state_bound_to_browser(configured):
    r=configured.get("/auth/feishu",follow_redirects=False)
    assert r.status_code==303
    state=parse_qs(urlsplit(r.headers["location"]).query)["state"][0]
    assert not security.consume_state(state,"nonce_from_other_browser")
    assert not security.consume_state(state,configured.cookies.get("diag_oauth",""))

def test_settings_revoke_session(authorized):
    client,headers=authorized
    result=client.put("/api/settings",headers=headers,json={"app_secret":"another_secret_12345"})
    assert result.status_code==200
    assert result.json()["reauth_required"] is True
    assert client.get("/api/me").status_code==401

def test_security_headers(configured):
    r=configured.get("/login")
    assert r.headers["x-frame-options"]=="DENY"
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"]=="nosniff"

def test_host_header_denied(configured):
    r=configured.get("/login",headers={"Host":"evil.example"})
    assert r.status_code==400

def test_invalid_setup_public_url(client):
    token=storage.BOOTSTRAP.read_text()
    data={"bootstrap_token":token,"app_id":APP_ID,"app_secret":"secret_123456789",
          "admin_open_id":OPEN_ID,"public_url":"http://diag.example.com"}
    assert client.post("/setup",json=data).status_code==400
    assert storage.BOOTSTRAP.exists()
