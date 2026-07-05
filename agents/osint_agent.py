"""
OSINT Agent — Real-Time Threat Intelligence from Public Sources
================================================================
Enriches CTI analysis by querying live public APIs:
  - CISA KEV (Known Exploited Vulnerabilities)
  - NVD/CVE Details
  - MITRE ATT&CK (STIX 2.1 feed)
  - AbuseIPDB / URLhaus (IOC reputation)
  - AlienVault OTX Pulses

Design: Inspired by Phoenix Security's domain-tiered search
across 300+ curated sources. We implement a lightweight version
that queries free public APIs with no authentication required.

Reference: Phoenix Security Pipeline [21] in research_paper.md
"""
from __future__ import annotations

import re
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger()


@dataclass
class OSINTResult:
    """Result from OSINT enrichment."""
    source: str
    query: str
    found: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    latency_ms: float = 0.0


@dataclass
class EnrichmentReport:
    """Aggregated OSINT enrichment report."""
    cve_details: list[OSINTResult] = field(default_factory=list)
    ioc_reputation: list[OSINTResult] = field(default_factory=list)
    attack_context: list[OSINTResult] = field(default_factory=list)
    total_sources_queried: int = 0
    total_enrichments_found: int = 0
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "cve_details": [
                {"source": r.source, "query": r.query, "found": r.found,
                 "data": r.data, "error": r.error}
                for r in self.cve_details
            ],
            "ioc_reputation": [
                {"source": r.source, "query": r.query, "found": r.found,
                 "data": r.data, "error": r.error}
                for r in self.ioc_reputation
            ],
            "attack_context": [
                {"source": r.source, "query": r.query, "found": r.found,
                 "data": r.data, "error": r.error}
                for r in self.attack_context
            ],
            "total_sources_queried": self.total_sources_queried,
            "total_enrichments_found": self.total_enrichments_found,
            "latency_ms": self.latency_ms,
        }

    @property
    def summary(self) -> str:
        parts = []
        for c in self.cve_details:
            if c.found:
                d = c.data
                parts.append(
                    f"CVE {c.query}: CVSS {d.get('cvss_score', 'N/A')} | "
                    f"{d.get('severity', 'N/A')} | KEV: {d.get('kev', False)}"
                )
        for i in self.ioc_reputation:
            if i.found:
                parts.append(f"IOC {i.query}: {i.data.get('status', 'unknown')}")
        return " | ".join(parts) if parts else "No OSINT enrichment available"


class OSINTAgent:
    """
    Real-time OSINT enrichment agent.

    Queries free public APIs to enrich threat analysis with:
    - CVE severity scores (NVD)
    - KEV status (CISA)
    - IOC reputation (URLhaus, AbuseIPDB)
    - ATT&CK technique context (MITRE)
    """

    # CISA KEV cache (loaded once)
    _kev_cache: dict[str, dict] | None = None
    _kev_last_fetch: float = 0.0
    KEV_CACHE_TTL = 3600  # 1 hour

    def __init__(self) -> None:
        self.timeout = 5  # seconds per request

    # ── CVE Enrichment ────────────────────────────────────────────

    def lookup_cve(self, cve_id: str) -> OSINTResult:
        """Look up CVE details from NVD API (free, no key)."""
        t0 = time.time()
        result = OSINTResult(source="NVD", query=cve_id)

        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "CTI-SHIELD/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())

            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                metrics = cve_data.get("metrics", {})

                # Extract CVSS score
                cvss_score = None
                severity = "N/A"
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        cvss_data = metrics[version][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "N/A")
                        break

                # Description
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                result.found = True
                result.data = {
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": desc[:300],
                    "published": cve_data.get("published", ""),
                    "kev": self._check_kev(cve_id),
                }
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            result.error = f"NVD lookup failed: {str(e)[:100]}"
            log.warning("osint_nvd_error", cve=cve_id, error=str(e)[:100])
        except Exception as e:
            result.error = f"Unexpected error: {str(e)[:100]}"

        result.latency_ms = (time.time() - t0) * 1000
        return result

    def _check_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV (Known Exploited Vulnerabilities)."""
        try:
            self._refresh_kev_cache()
            return cve_id in (self._kev_cache or {})
        except Exception:
            return False

    def _refresh_kev_cache(self) -> None:
        """Refresh CISA KEV cache if stale."""
        if (self._kev_cache is not None
                and time.time() - self._kev_last_fetch < self.KEV_CACHE_TTL):
            return

        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            req = urllib.request.Request(url, headers={"User-Agent": "CTI-SHIELD/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())

            vulns = data.get("vulnerabilities", [])
            self._kev_cache = {v["cveID"]: v for v in vulns}
            self._kev_last_fetch = time.time()
            log.info("osint_kev_loaded", count=len(self._kev_cache))
        except Exception as e:
            log.warning("osint_kev_error", error=str(e)[:100])
            if self._kev_cache is None:
                self._kev_cache = {}

    # ── IOC Reputation ────────────────────────────────────────────

    def lookup_urlhaus(self, indicator: str) -> OSINTResult:
        """Check URL/domain against URLhaus (free, no key)."""
        t0 = time.time()
        result = OSINTResult(source="URLhaus", query=indicator)

        try:
            data = urllib.parse.urlencode({"url": indicator}).encode()
            req = urllib.request.Request(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=data,
                headers={"User-Agent": "CTI-SHIELD/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_data = json.loads(resp.read().decode())

            if resp_data.get("query_status") == "ok":
                result.found = True
                result.data = {
                    "status": "MALICIOUS",
                    "threat": resp_data.get("threat", "unknown"),
                    "tags": resp_data.get("tags", []),
                    "date_added": resp_data.get("date_added", ""),
                }
            else:
                result.data = {"status": "CLEAN"}
        except Exception as e:
            result.error = f"URLhaus error: {str(e)[:100]}"

        result.latency_ms = (time.time() - t0) * 1000
        return result

    # ── ATT&CK Context ────────────────────────────────────────────

    def lookup_attack_technique(self, technique_id: str) -> OSINTResult:
        """Get ATT&CK technique details from MITRE STIX data."""
        t0 = time.time()
        result = OSINTResult(source="MITRE ATT&CK", query=technique_id)

        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            req = urllib.request.Request(url, headers={"User-Agent": "CTI-SHIELD/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            for obj in data.get("objects", []):
                refs = obj.get("external_references", [])
                for ref in refs:
                    if ref.get("external_id") == technique_id:
                        result.found = True
                        result.data = {
                            "name": obj.get("name", ""),
                            "description": (obj.get("description", ""))[:300],
                            "tactics": [
                                p.get("phase_name", "")
                                for p in obj.get("kill_chain_phases", [])
                            ],
                            "platforms": obj.get("x_mitre_platforms", []),
                        }
                        break
                if result.found:
                    break
        except Exception as e:
            result.error = f"ATT&CK lookup error: {str(e)[:100]}"

        result.latency_ms = (time.time() - t0) * 1000
        return result

    # ── Main Enrichment Pipeline ──────────────────────────────────

    def enrich(
        self,
        text: str,
        cves: list[str] | None = None,
        ttps: list[dict] | None = None,
        iocs: dict[str, list] | None = None,
    ) -> EnrichmentReport:
        """
        Run full OSINT enrichment on extracted entities.

        Args:
            text: Original threat text
            cves: List of CVE IDs found
            ttps: List of TTP dicts from NLP extraction
            iocs: Dict of IOC lists (ips, domains, urls, etc.)

        Returns:
            EnrichmentReport with all findings
        """
        t0 = time.time()
        report = EnrichmentReport()

        # 1. Enrich CVEs
        for cve_id in (cves or []):
            result = self.lookup_cve(cve_id)
            report.cve_details.append(result)
            report.total_sources_queried += 1
            if result.found:
                report.total_enrichments_found += 1

        # 2. Check IOC reputation (domains/URLs only, limit to 3)
        all_iocs = []
        for ioc_type in ["urls", "domains"]:
            all_iocs.extend((iocs or {}).get(ioc_type, []))
        for indicator in all_iocs[:3]:
            result = self.lookup_urlhaus(indicator)
            report.ioc_reputation.append(result)
            report.total_sources_queried += 1
            if result.found:
                report.total_enrichments_found += 1

        # 3. ATT&CK context for first 2 TTPs (to avoid rate limits)
        for ttp in (ttps or [])[:2]:
            tech_id = ttp.get("id", "") if isinstance(ttp, dict) else str(ttp)
            if tech_id.startswith("T"):
                result = self.lookup_attack_technique(tech_id)
                report.attack_context.append(result)
                report.total_sources_queried += 1
                if result.found:
                    report.total_enrichments_found += 1

        report.latency_ms = (time.time() - t0) * 1000
        log.info("osint_enrichment_complete",
                 sources=report.total_sources_queried,
                 found=report.total_enrichments_found,
                 latency_ms=round(report.latency_ms, 1))
        return report


# ── Singleton ─────────────────────────────────────────────────────
_osint: OSINTAgent | None = None

def get_osint_agent() -> OSINTAgent:
    global _osint
    if _osint is None:
        _osint = OSINTAgent()
    return _osint
