"""IOC Enricher API — v0.2

Classifies an indicator of compromise (IOC), enriches public IP addresses
with AbuseIPDB reputation data and keeps a history of every lookup.
"""

import ipaddress
import logging
import os
import re
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.intel import abuseipdb

logger = logging.getLogger("ioc_enricher")

app = FastAPI(
    title="IOC Enricher",
    version="0.2.0",
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


class LookupRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    value: str
    ioc_type: str
    verdict: str | None
    score: int | None
    source: str | None
    created_at: datetime


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


def lookup_reputation(ioc: IOCResponse) -> EnrichResponse:
    """Ask threat intelligence sources about an IOC."""
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


def save_lookup(ioc: IOCResponse, enrichment: dict | None) -> None:
    """Store the lookup. A database outage must not break enrichment."""
    try:
        db.record_lookup(
            value=ioc.value,
            ioc_type=ioc.type,
            verdict=enrichment.get("verdict") if enrichment else None,
            score=enrichment.get("abuse_confidence_score") if enrichment else None,
            source=enrichment.get("source") if enrichment else None,
        )
    except SQLAlchemyError:
        logger.exception("could not record lookup for %s", ioc.value)


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
    response = lookup_reputation(ioc)
    save_lookup(ioc, response.enrichment)
    return response


@app.get("/ioc/history", response_model=list[LookupRecord])
def history(
    limit: int = Query(20, ge=1, le=100),
    value: str | None = Query(None, min_length=1, max_length=253),
) -> list[LookupRecord]:
    """Most recent lookups, newest first. Optionally filtered by IOC value."""
    normalized = classify_ioc(value).value if value else None
    try:
        rows = db.list_lookups(limit=limit, value=normalized)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="history database is unavailable") from exc
    return [LookupRecord.model_validate(row) for row in rows]
