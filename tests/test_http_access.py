"""LAN HTTP retains OAuth state, administrator checks and CSRF protection."""

from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app import main, security, storage
from .conftest import APP_ID, OPEN_ID
from .test_feishu_oauth import FakeClient

HTTP_ORIGIN = "http://172.20.200.100:9099"


@pytest.fixture
def http_client(client):
    with TestClient(main.app, base_url=HTTP_ORIGIN) as c:
        result = c.post(
            "/setup",
            json={
                "bootstrap_token": storage.BOOTSTRAP.read_text(),
                "app_id": APP_ID,
                "app_secret": "lan_test_secret_only",
                "admin_open_id": OPEN_ID,
                "public_url": HTTP_ORIGIN,
            },
        )
        assert result.status_code == 200, result.text
        yield c


def test_http_oauth_login_and_session_cookie(http_client, monkeypatch):
    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)
    start = http_client.get("/auth/feishu", follow_redirects=False)
    assert "Secure" not in start.headers["set-cookie"]
    assert (
        "HttpOnly" in start.headers["set-cookie"]
        and "SameSite=lax" in start.headers["set-cookie"]
    )
    params = parse_qs(urlsplit(start.headers["location"]).query)
    assert params["redirect_uri"] == [HTTP_ORIGIN + "/auth/feishu/callback"]
    callback = http_client.get(
        "/auth/feishu/callback",
        params={"code": "lan-code", "state": params["state"][0]},
        follow_redirects=False,
    )
    assert callback.headers["location"] == "/"
    session = [
        cookie
        for cookie in callback.headers.get_list("set-cookie")
        if cookie.startswith("diag_session=")
    ][0]
    assert "Secure" not in session and "HttpOnly" in session
    assert http_client.get("/api/me").status_code == 200
    assert "strict-transport-security" not in http_client.get("/").headers
    assert (
        http_client.post("/api/groups", json={"name": "unauthorized-write"}).status_code
        == 403
    )
    token = http_client.get("/api/me").json()["csrf_token"]
    headers = {"Origin": HTTP_ORIGIN, "X-CSRF-Token": token}
    assert (
        http_client.post(
            "/api/groups", json={"name": "lan"}, headers=headers
        ).status_code
        == 200
    )
    assert (
        http_client.post(
            "/api/groups",
            json={"name": "evil"},
            headers={**headers, "Origin": "http://evil.example"},
        ).status_code
        == 403
    )
    assert (
        http_client.get("/api/hosts", headers={"Host": "evil.example"}).status_code
        == 400
    )
    assert http_client.post("/api/logout", headers=headers).status_code == 200
    assert http_client.get("/api/me").status_code == 401


def test_http_anonymous_diagnostic_remains_forbidden(http_client):
    assert (
        http_client.post(
            "/api/diagnose", json={"host_id": 1, "action": "cpu"}
        ).status_code
        == 401
    )
    assert http_client.get("/api/hosts").status_code == 401


def test_https_cookie_stays_secure(configured):
    response = configured.get("/auth/feishu", follow_redirects=False)
    assert "Secure" in response.headers["set-cookie"]
    assert "strict-transport-security" in response.headers


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://172.20.200.100:9099/", HTTP_ORIGIN),
        ("http://10.1.2.3:80", "http://10.1.2.3"),
        ("http://192.168.1.1:9099", "http://192.168.1.1:9099"),
        ("http://[fd00::1]:9099", "http://[fd00::1]:9099"),
        ("http://127.0.0.1:9099", "http://127.0.0.1:9099"),
        ("http://localhost:9099", "http://localhost:9099"),
    ],
)
def test_private_http_origin_validation(url, expected):
    assert main.check_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8:9099",
        "http://diag.example.com",
        "http://169.254.1.1:9099",
        "http://0.0.0.0:9099",
    ],
)
def test_public_http_or_invalid_listener_address_is_rejected(url):
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        main.check_url(url)


def test_http_to_https_migration_revokes_old_sessions(http_client):
    token = security.issue_session(OPEN_ID)
    http_client.cookies.set("diag_session", token)
    csrf = http_client.get("/api/me").json()["csrf_token"]
    response = http_client.put(
        "/api/settings",
        json={"public_url": "https://diag.example.com"},
        headers={"Origin": HTTP_ORIGIN, "X-CSRF-Token": csrf},
    )
    assert response.json()["reauth_required"] and security.secure_cookie()
    assert response.json()["redirect_url"] == "https://diag.example.com/login"
    assert (
        http_client.get("/api/me", headers={"Host": "diag.example.com"}).status_code
        == 401
    )
