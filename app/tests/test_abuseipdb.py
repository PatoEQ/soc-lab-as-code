import httpx
import pytest

from app.intel import abuseipdb

IP = "185.220.101.1"
SAMPLE = {
    "data": {
        "ipAddress": IP,
        "abuseConfidenceScore": 100,
        "totalReports": 42,
        "lastReportedAt": "2026-11-01T10:00:00+00:00",
        "countryCode": "DE",
        "isp": "Example Hosting",
        "usageType": "Data Center/Web Hosting/Transit",
        "isTor": True,
    }
}


def make_client(status: int = 200, payload: dict | None = None) -> httpx.Client:
    """Fake HTTP client: answers like AbuseIPDB without touching the network."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Key"] == "test-key"
        assert request.url.params["ipAddress"] == IP
        assert "test-key" not in str(request.url)
        return httpx.Response(status, json=payload or {})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_malicious_ip():
    result = abuseipdb.check_ip(IP, "test-key", make_client(payload=SAMPLE))
    assert result["verdict"] == "malicious"
    assert result["total_reports"] == 42
    assert result["is_tor"] is True


@pytest.mark.parametrize(
    "score, verdict",
    [(0, "no_known_abuse"), (24, "no_known_abuse"), (25, "suspicious"), (74, "suspicious"), (75, "malicious")],
)
def test_score_to_verdict(score, verdict):
    assert abuseipdb.score_to_verdict(score) == verdict


def test_invalid_api_key():
    with pytest.raises(abuseipdb.AbuseIPDBError, match="invalid"):
        abuseipdb.check_ip(IP, "test-key", make_client(status=401))


def test_rate_limit():
    with pytest.raises(abuseipdb.AbuseIPDBError, match="rate limit"):
        abuseipdb.check_ip(IP, "test-key", make_client(status=429))
