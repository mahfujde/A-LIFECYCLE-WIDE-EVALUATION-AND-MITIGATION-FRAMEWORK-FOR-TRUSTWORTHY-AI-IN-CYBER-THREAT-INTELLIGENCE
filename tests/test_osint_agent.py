"""Tests for OSINT Agent."""
import pytest
from agents.osint_agent import OSINTAgent, get_osint_agent, OSINTResult, EnrichmentReport


def test_osint_agent_singleton():
    a = get_osint_agent()
    b = get_osint_agent()
    assert a is b


def test_osint_result_defaults():
    r = OSINTResult(source="test", query="CVE-2021-44228")
    assert r.found is False
    assert r.error is None
    assert r.data == {}


def test_enrichment_report_to_dict():
    report = EnrichmentReport()
    d = report.to_dict()
    assert d["total_sources_queried"] == 0
    assert d["total_enrichments_found"] == 0
    assert isinstance(d["cve_details"], list)


def test_enrichment_report_summary_empty():
    report = EnrichmentReport()
    assert report.summary == "No OSINT enrichment available"


def test_enrichment_report_summary_with_data():
    r = OSINTResult(source="NVD", query="CVE-2021-44228", found=True,
                    data={"cvss_score": 10.0, "severity": "CRITICAL", "kev": True})
    report = EnrichmentReport(cve_details=[r])
    s = report.summary
    assert "CVE-2021-44228" in s
    assert "10.0" in s
    assert "CRITICAL" in s


def test_osint_enrich_no_entities():
    agent = OSINTAgent()
    report = agent.enrich("no entities here")
    assert report.total_sources_queried == 0
    assert report.total_enrichments_found == 0


def test_osint_agent_init():
    agent = OSINTAgent()
    assert agent.timeout == 5
