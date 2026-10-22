from urllib.parse import parse_qs, urlsplit
from app import security
from app import main
from .conftest import OPEN_ID

class Response:
    def __init__(self,payload):self.payload=payload
    def raise_for_status(self):pass
    def json(self):return self.payload

class FakeClient:
    def __init__(self,**_): pass
    async def __aenter__(self):return self
    async def __aexit__(self,*_):pass
    async def post(self,*_,**__):return Response({"code":0,"access_token":"test-user-token"})
    async def get(self,*_,**__):return Response({"code":0,"data":{"open_id":OPEN_ID}})

def test_callback_requires_same_browser_and_authorized_user(configured,monkeypatch):
    monkeypatch.setattr(main.httpx,"AsyncClient",FakeClient)
    login=configured.get("/auth/feishu",follow_redirects=False)
    state=parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
    callback=configured.get("/auth/feishu/callback",params={"code":"one-time-code","state":state},
                            follow_redirects=False)
    assert callback.status_code==303
    assert "diag_session" in callback.headers["set-cookie"]
    assert "HttpOnly" in callback.headers["set-cookie"]
    assert configured.get("/api/me").status_code==200
    assert configured.get("/auth/feishu/callback",params={"code":"replay","state":state}).status_code==403
