"""IOC Enricher API — v0.1

Classifies an indicator of compromise (IOC) and enriches public IP addresses
with AbuseIPDB reputation data. VirusTotal and AlienVault OTX come next.
"""
import ipaddress
import os
import re
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.intel import abuseipdb

app = FastAPI(
    title="IOC Enricher",
    version="0.1.0",
    description="IOC classification and enrichment API for the SOC Lab.",
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE
)
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)


class IOCRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=253, examples=["8.8.8.8"])


class IOCResponse(BaseModel):
    value: str
    type: str
    detail: dict

class EnrichResponse(BaseModel):
    ioc: IOCResponse
    enrichment: dict | None
    note: str | None = None

def classify_ioc(raw: str) -> IOCResponse:
    """Detect the IOC type without calling any external service."""
    value = raw.strip()

    # Refang values commonly defanged in reports: 8[.]8[.]8[.]8 or example[.]com
    value = value.replace("[.]", ".").replace("(.)", ".")

    try:
        ip = ipaddress.ip_address(value)
        return IOCResponse(
            value=value,
            type=f"ipv{ip.version}",
            detail={
                "private": ip.is_private,
                "loopback": ip.is_loopback,
                "reserved": ip.is_reserved,
            },
        )
    except ValueError:
        pass

    if HEX_RE.match(value) and len(value) in HASH_TYPES:
        return IOCResponse(
            value=value.lower(),
            type="hash",
            detail={"algorithm": HASH_TYPES[len(value)]},
        )

    if DOMAIN_RE.match(value):
        return IOCResponse(
            value=value.lower(),
            type="domain",
            detail={"tld": value.rsplit(".", 1)[-1].lower()},
        )

    return IOCResponse(value=value, type="unknown", detail={})


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "ioc-enricher",
        "version": app.version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/ioc/classify", response_model=IOCResponse)
def classify(request: IOCRequest) -> IOCResponse:
    return classify_ioc(request.value)

@app.post("/ioc/enrich", response_model=EnrichResponse)
def enrich(request: IOCRequest) -> EnrichResponse:
    ioc = classify_ioc(request.value)

    if ioc.type not in ("ipv4", "ipv6"):
        return EnrichResponse(
            ioc=ioc,
            enrichment=None,
            note=f"enrichment for type '{ioc.type}' is not supported yet",
        )

    # Internal addresses are never sent to a third party.
    if ioc.detail["private"] or ioc.detail["loopback"]:
        return EnrichResponse(ioc=ioc, enrichment=None, note="internal address, not looked up")

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="ABUSEIPDB_API_KEY is not configured")

    try:
        with httpx.Client(timeout=10) as client:
            result = abuseipdb.check_ip(ioc.value, api_key, client)
    except abuseipdb.AbuseIPDBError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return EnrichResponse(ioc=ioc, enrichment=result)
