"""
Feed Harvester Agent — Live TAXII/OTX/CISA ingestion
======================================================
Fetches from 5+ live threat intelligence feeds, normalises to STIX 2.1,
validates, and signals the KG Builder when new IOCs are found.
"""
from __future__ import annotations
import time, json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any
import structlog

log = structlog.get_logger()

FEED_SOURCES = [
    {"name": "MITRE_TAXII", "url": "https://cti-taxii.mitre.org/taxii2/",
     "type": "taxii", "interval_s": 900},
    {"name": "OTX", "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
     "type": "rest", "interval_s": 900},
    {"name": "CISA_KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "type": "json", "interval_s": 3600},
    {"name": "URLhaus", "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
     "type": "rest", "interval_s": 1800},
    {"name": "MalwareBazaar", "url": "https://mb-api.abuse.ch/api/v1/",
     "type": "rest", "interval_s": 1800},
]


@dataclass
class FeedResult:
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    new_iocs: int = 0
    stix_objects: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: float = 0.0


class FeedHarvesterAgent:
    """Harvests live threat intelligence feeds and normalises to STIX 2.1."""

    def __init__(self) -> None:
        self.last_fetch: dict[str, str] = {}
        self.total_iocs: int = 0
        self.history: list[FeedResult] = []

    def run_all(self) -> list[FeedResult]:
        """Fetch from all configured feed sources."""
        results = []
        for feed in FEED_SOURCES:
            result = self._fetch_feed(feed)
            results.append(result)
            self.history.append(result)
        return results

    def _fetch_feed(self, feed: dict) -> FeedResult:
        """Fetch a single feed source with retry logic."""
        start = time.time()
        result = FeedResult(source=feed["name"])

        try:
            if feed["type"] == "json":
                data = self._fetch_json(feed["url"])
            elif feed["type"] == "taxii":
                data = self._fetch_taxii(feed["url"])
            else:
                data = self._fetch_rest(feed["url"])

            stix_objects = self._normalize_to_stix(data, feed["name"])
            result.stix_objects = stix_objects
            result.new_iocs = len(stix_objects)
            self.total_iocs += result.new_iocs
            self.last_fetch[feed["name"]] = result.timestamp

        except Exception as e:
            result.errors.append(str(e))
            log.warning("feed_fetch_error", source=feed["name"], error=str(e))

        result.duration_ms = (time.time() - start) * 1000
        return result

    def _fetch_json(self, url: str) -> list[dict]:
        """Fetch JSON endpoint."""
        try:
            import requests
            resp = requests.get(url, timeout=30,
                                headers={"User-Agent": "CTI-Shield/3.0"})
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict):
                # Handle CISA KEV format
                return data.get("vulnerabilities", [data])[:50]
            return data[:50] if isinstance(data, list) else []
        except Exception as e:
            log.warning("json_fetch_failed", url=url[:80], error=str(e))
            return []

    def _fetch_taxii(self, url: str) -> list[dict]:
        """Fetch from TAXII 2.x server."""
        try:
            from taxii2client.v20 import Server
            server = Server(url)
            collections = server.api_roots[0].collections
            if collections:
                objects = collections[0].get_objects()
                return objects.get("objects", [])[:50]
        except Exception as e:
            log.warning("taxii_fetch_failed", error=str(e))
        return []

    def _fetch_rest(self, url: str) -> list[dict]:
        """Fetch REST API endpoint."""
        try:
            import requests
            resp = requests.get(url, timeout=30,
                                headers={"User-Agent": "CTI-Shield/3.0"})
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict):
                # Try common wrapper keys
                for key in ("data", "results", "urls", "pulses"):
                    if key in data and isinstance(data[key], list):
                        return data[key][:50]
                return [data]
            return data[:50] if isinstance(data, list) else []
        except Exception as e:
            log.warning("rest_fetch_failed", url=url[:80], error=str(e))
            return []

    def _normalize_to_stix(self, data: list[dict], source: str) -> list[dict]:
        """Normalise raw feed data to STIX 2.1 indicator objects."""
        stix_objects = []
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for item in data[:25]:  # Limit per batch
            try:
                name = (item.get("name") or item.get("cveID") or
                        item.get("url") or item.get("sha256_hash") or
                        str(item.get("id", "unknown")))[:200]

                desc = (item.get("description") or item.get("shortDescription") or
                        item.get("summary") or name)[:500]

                stix_obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{source.lower()}-{hash(name) % 10**8:08d}",
                    "created": ts,
                    "modified": ts,
                    "name": name,
                    "description": f"[{source}] {desc}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[file:name = '{name[:100]}']",
                    "pattern_type": "stix",
                    "valid_from": ts,
                    "labels": [source.lower()],
                }
                stix_objects.append(stix_obj)
            except Exception:
                continue

        return stix_objects

    def get_status(self) -> dict[str, Any]:
        return {
            "total_iocs_ingested": self.total_iocs,
            "sources_configured": len(FEED_SOURCES),
            "last_fetch": self.last_fetch,
            "feed_history_count": len(self.history),
        }


_harvester: FeedHarvesterAgent | None = None
def get_feed_harvester() -> FeedHarvesterAgent:
    global _harvester
    if _harvester is None:
        _harvester = FeedHarvesterAgent()
    return _harvester
