"""AbuseIPDB client: looks up the reputation of an IP address.

API docs: https://docs.abuseipdb.com/#check-endpoint
"""

import httpx

API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90


class AbuseIPDBError(Exception):
    """Raised when AbuseIPDB cannot be queried."""


def score_to_verdict(score: int) -> str:
    """Map the AbuseIPDB confidence score (0-100) to a simple verdict."""
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "no_known_abuse"


def check_ip(ip: str, api_key: str, client: httpx.Client) -> dict:
    """Query AbuseIPDB for a single IP and return a normalized result."""
    try:
        response = client.get(
            API_URL,
            params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS},
            # The key travels in a header, never in the URL, so it does not end up in logs.
            headers={"Key": api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status in (401, 403):
            raise AbuseIPDBError("invalid or missing AbuseIPDB API key") from exc
        if status == 429:
            raise AbuseIPDBError("AbuseIPDB rate limit reached") from exc
        raise AbuseIPDBError(f"AbuseIPDB returned HTTP {status}") from exc
    except httpx.RequestError as exc:
        raise AbuseIPDBError("could not reach AbuseIPDB") from exc

    data = response.json()["data"]
    score = data.get("abuseConfidenceScore", 0)
    return {
        "source": "abuseipdb",
        "verdict": score_to_verdict(score),
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "is_tor": data.get("isTor", False),
    }
