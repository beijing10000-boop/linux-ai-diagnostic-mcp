"""Protected overview, public credential metadata and paginated diagnostic records."""

import json

import pytest

from app import storage
from .test_management import host_payload, private_key


def seed_runs():
    with storage.connect() as c:
        c.executemany(
            "INSERT INTO diagnostic_runs(host_id,host_name,action,time,duration_ms,status,result) VALUES (?,?,?,?,?,?,?)",
            [
                (
                    1,
                    "D3-web-" + str(n),
                    "cpu",
                    n + 1,
                    10,
                    ["success", "warning", "failed"][n % 3],
                    storage.encrypt(
                        json.dumps(
                            {"output": "private result " + str(n), "exit_code": 0}
                        )
                    ),
                )
                for n in range(45)
            ],
        )


def test_new_pages_and_apis_require_login(configured):
    for page in ["/connections", "/diagnostics", "/activity"]:
        result = configured.get(page, follow_redirects=False)
        assert result.status_code == 303 and result.headers["location"] == "/login"
    for api in ["/api/status", "/api/activity"]:
        assert configured.get(api).status_code == 401


def test_overview_uses_real_inventory_and_task_counts(authorized):
    client, headers = authorized
    client.post("/api/hosts", headers=headers, json=host_payload())
    seed_runs()
    data = client.get("/api/status").json()
    assert data["database"] == "ok" and data["ssh_configured"] is False
    assert (
        data["inventory"]["hosts"] == 1 and data["inventory"]["configured_hosts"] == 1
    )
    assert data["runs"] == {
        "total": 45,
        "success": 15,
        "warning": 15,
        "failed": 15,
        "last_run": 45,
    }
    assert data["mcp_transport"] == "stdio" and data["protocol"] == "https"
    assert "private_key" not in json.dumps(data)


def test_activity_pagination_returns_all_kept_metadata(authorized):
    client, _ = authorized
    seed_runs()
    first = client.get("/api/activity?page=1&page_size=20").json()
    second = client.get("/api/activity?page=2&page_size=20").json()
    third = client.get("/api/activity?page=3&page_size=20").json()
    assert (
        first["total"],
        len(first["items"]),
        len(second["items"]),
        len(third["items"]),
    ) == (45, 20, 20, 5)
    assert first["items"][0]["time"] == 45 and third["items"][-1]["time"] == 1
    assert not {r["id"] for r in first["items"]} & {r["id"] for r in second["items"]}
    assert all("result" not in row for row in first["items"])
    assert "private result" not in json.dumps(first)


def test_activity_filters_status_and_literal_host_name(authorized):
    client, _ = authorized
    seed_runs()
    data = client.get(
        "/api/activity",
        params={"status": "failed", "query": "D3-web-4", "page_size": 100},
    ).json()
    assert data["total"] == 2 and all(
        r["status"] == "failed" and "D3-web-4" in r["host_name"] for r in data["items"]
    )
    assert (
        client.get("/api/activity", params={"query": "' OR 1=1 --"}).json()["total"]
        == 0
    )
    assert client.get("/api/activity", params={"query": "%"}).json()["total"] == 0


@pytest.mark.parametrize(
    "query", ["page=0", "page_size=0", "page_size=101", "status=unknown"]
)
def test_activity_invalid_filters_rejected(authorized, query):
    client, _ = authorized
    assert client.get("/api/activity?" + query).status_code == 422


def test_only_ssh_public_key_is_returned_to_administrator(authorized):
    client, headers = authorized
    raw = private_key()
    assert (
        client.put(
            "/api/settings/ssh", headers=headers, json={"private_key": raw}
        ).status_code
        == 200
    )
    data = client.get("/api/settings").json()
    assert data["ssh_public_key"].startswith("ssh-ed25519 ")
    assert data["ssh_fingerprint"].startswith("SHA256:")
    assert raw not in json.dumps(
        data
    ) and "BEGIN OPENSSH PRIVATE KEY" not in json.dumps(data)
    assert data["ssh_private_key_configured"] is True


def test_old_host_link_opens_dedicated_diagnostic_page(authorized):
    client, _ = authorized
    result = client.get("/?host=7", follow_redirects=False)
    assert (
        result.status_code == 303
        and result.headers["location"] == "/diagnostics?host=7"
    )
