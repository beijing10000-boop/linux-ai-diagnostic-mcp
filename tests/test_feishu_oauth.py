from urllib.parse import parse_qs, urlsplit
from app import main
from .conftest import OPEN_ID


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class FakeClient:
    def __init__(self, **_):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def post(self, *_, **__):
        return Response({"code": 0, "access_token": "test-user-token"})

    async def get(self, *_, **__):
        return Response({"code": 0, "data": {"open_id": OPEN_ID}})


def test_callback_requires_same_browser_and_authorized_user(configured, monkeypatch):
    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)
    login = configured.get("/auth/feishu", follow_redirects=False)
    state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
    callback = configured.get(
        "/auth/feishu/callback",
        params={"code": "one-time-code", "state": state},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert "diag_session" in callback.headers["set-cookie"]
    assert "HttpOnly" in callback.headers["set-cookie"]
    assert configured.get("/api/me").status_code == 200
    replay = configured.get(
        "/auth/feishu/callback",
        params={"code": "replay", "state": state},
        follow_redirects=False,
    )
    assert replay.status_code == 303
    assert replay.headers["location"] == "/login?error=state"


def callback_state(client):
    response = client.get("/auth/feishu", follow_redirects=False)
    return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]


def test_authorization_cancel_is_readable(configured):
    state = callback_state(configured)
    response = configured.get(
        "/auth/feishu/callback",
        params={"error": "access_denied", "state": state},
        follow_redirects=False,
    )
    assert (
        response.status_code == 303
        and response.headers["location"] == "/login?error=cancelled"
    )
    assert configured.get("/api/me").status_code == 401


def test_unapproved_user_never_receives_session(configured, monkeypatch):
    class Stranger(FakeClient):
        async def get(self, *_, **__):
            return Response({"code": 0, "data": {"open_id": "ou_unapproved12345"}})

    monkeypatch.setattr(main.httpx, "AsyncClient", Stranger)
    state = callback_state(configured)
    response = configured.get(
        "/auth/feishu/callback",
        params={"code": "code", "state": state},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/login?error=unauthorized"
    assert configured.get("/api/me").status_code == 401


def test_malformed_provider_response_returns_login_page(configured, monkeypatch):
    class Malformed(FakeClient):
        async def post(self, *_, **__):
            return Response([])

    monkeypatch.setattr(main.httpx, "AsyncClient", Malformed)
    state = callback_state(configured)
    response = configured.get(
        "/auth/feishu/callback",
        params={"code": "code", "state": state},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/login?error=unavailable"
    assert configured.get("/api/me").status_code == 401
