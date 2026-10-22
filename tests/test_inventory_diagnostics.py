import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from app import diagnostics, inventory

def valid_host_key():
    key=Ed25519PrivateKey.generate().public_key()
    return key.public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()

def test_injection_rejected():
    for action,service in [("cpu; reboot",None),("service","nginx;reboot"),("service","--help"),
                           ("service","x\\ny"),("disk","extra"),("cat /etc/shadow",None)]:
        with pytest.raises(ValueError): diagnostics.validate(action,service)
    assert diagnostics.validate("service","nginx.service")=="service nginx.service"

def test_private_ip_only():
    for host in ("127.0.0.1","8.8.8.8","169.254.10.20","0.0.0.0","224.1.2.3"):
        with pytest.raises(ValueError):inventory.validate_address(host)
    assert inventory.validate_address("172.20.1.10")=="172.20.1.10"

def test_host_restrictions(authorized):
    client,headers=authorized
    host_key=valid_host_key()
    bad={"name":"public","address":"8.8.8.8","host_key":host_key}
    assert client.post("/api/hosts",headers=headers,json=bad).status_code==400
    good={"name":"internal-01","address":"172.20.1.10","host_key":host_key}
    r=client.post("/api/hosts",headers=headers,json=good)
    assert r.status_code==200,r.text
    host_id=r.json()["id"]
    assert client.post("/api/diagnose",headers=headers,
       json={"host_id":host_id,"action":"cpu"}).status_code==400
    assert client.post("/api/diagnose",headers=headers,
       json={"host_id":host_id,"action":"cpu;id"}).status_code==400

def test_key_pinning_validation():
    with pytest.raises(ValueError): inventory.validate_host_key("ssh-rsa AAAA")
    with pytest.raises(ValueError): inventory.validate_host_key("ssh-ed25519 AAAA")
    assert inventory.validate_host_key(valid_host_key()).startswith("ssh-ed25519 ")

def test_proxy_not_executed(authorized):
    client,headers=authorized
    proxy_id=client.post("/api/proxies",headers=headers,json={"name":"dc-proxy"}).json()["id"]
    host_id=client.post("/api/hosts",headers=headers,json={
        "name":"proxy-host","address":"172.20.1.11","host_key":valid_host_key(),
        "proxy_id":proxy_id}).json()["id"]
    result=client.post("/api/diagnose",headers=headers,
        json={"host_id":host_id,"action":"cpu"})
    assert result.status_code==400
    assert "Proxy routing" in result.json()["detail"]
