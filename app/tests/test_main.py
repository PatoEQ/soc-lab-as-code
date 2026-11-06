from fastapi.testclient import TestClient

from app.main import app, classify_ioc
from app.intel import abuseipdb

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_health_includes_service_and_timestamp():
    body = client.get("/health").json()
    assert body["service"] == "ioc-enricher"
    assert body["timestamp"].endswith("+00:00")


def test_public_ipv4():
    result = classify_ioc("8.8.8.8")
    assert result.type == "ipv4"
    assert result.detail["private"] is False


def test_private_ipv4():
    assert classify_ioc("192.168.1.10").detail["private"] is True


def test_defanged_ip():
    assert classify_ioc("8[.]8[.]8[.]8").type == "ipv4"


def test_ipv6():
    assert classify_ioc("2001:4860:4860::8888").type == "ipv6"


def test_domain():
    result = classify_ioc("Example.COM")
    assert result.type == "domain"
    assert result.value == "example.com"


def test_hashes():
    assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e").detail["algorithm"] == "md5"
    assert classify_ioc("a" * 40).detail["algorithm"] == "sha1"
    assert classify_ioc("b" * 64).detail["algorithm"] == "sha256"


def test_unknown():
    assert classify_ioc("this is not an ioc").type == "unknown"


def test_classify_endpoint():
    response = client.post("/ioc/classify", json={"value": "example.com"})
    assert response.status_code == 200
    assert response.json()["type"] == "domain"


def test_classify_endpoint_rejects_empty_value():
    response = client.post("/ioc/classify", json={"value": ""})
    assert response.status_code == 422

def test_enrich_skips_private_ip():
    body = client.post("/ioc/enrich", json={"value": "10.0.0.5"}).json()
    assert body["enrichment"] is None
    assert "internal" in body["note"]


def test_enrich_unsupported_type():
    body = client.post("/ioc/enrich", json={"value": "example.com"}).json()
    assert "not supported" in body["note"]


def test_enrich_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    response = client.post("/ioc/enrich", json={"value": "185.220.101.1"})
    assert response.status_code == 503


def test_enrich_public_ip(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    fake = {"source": "abuseipdb", "verdict": "malicious", "abuse_confidence_score": 100}
    monkeypatch.setattr(abuseipdb, "check_ip", lambda ip, key, client: fake)
    body = client.post("/ioc/enrich", json={"value": "185.220.101.1"}).json()
    assert body["enrichment"]["verdict"] == "malicious"
