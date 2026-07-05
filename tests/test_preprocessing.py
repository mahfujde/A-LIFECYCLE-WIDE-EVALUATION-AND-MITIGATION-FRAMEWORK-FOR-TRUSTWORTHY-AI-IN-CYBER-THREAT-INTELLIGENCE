"""Tests for preprocessing module."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cti_shield.preprocessing import clean_text, extract_iocs, chunk_text, deduplicate_chunks

class TestCleanText:
    def test_removes_html(self):
        assert "<b>" not in clean_text("Hello <b>world</b>")

    def test_normalises_whitespace(self):
        result = clean_text("too   many    spaces")
        assert "   " not in result

    def test_empty_input(self):
        assert clean_text("") == ""
        assert clean_text("   ") == ""

    def test_preserves_iocs(self):
        text = "IP: 192.168.1.1 hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        result = clean_text(text)
        assert "192.168.1.1" in result

class TestExtractIOCs:
    def test_extracts_ipv4(self):
        iocs = extract_iocs("Server at 192.168.1.1 and 10.0.0.1")
        assert "192.168.1.1" in iocs["ipv4"]

    def test_extracts_urls(self):
        iocs = extract_iocs("Visit https://evil.com/malware for details")
        assert any("evil.com" in u for u in iocs["urls"])

    def test_extracts_cves(self):
        iocs = extract_iocs("Exploiting CVE-2024-1234 vulnerability")
        assert "CVE-2024-1234" in iocs["cves"]

    def test_extracts_hashes(self):
        md5 = "a" * 32
        iocs = extract_iocs(f"Hash: {md5}")
        assert md5 in iocs["md5"]

    def test_extracts_emails(self):
        iocs = extract_iocs("Contact attacker@evil.com")
        assert "attacker@evil.com" in iocs["emails"]

class TestChunking:
    def test_basic_chunking(self):
        text = "A" * 1000
        chunks = chunk_text(text, chunk_size=200, chunk_overlap=20)
        assert len(chunks) > 1
        assert all(len(c) <= 210 for c in chunks)  # Slightly over due to boundary

    def test_empty_text(self):
        assert chunk_text("") == []

    def test_small_text(self):
        chunks = chunk_text("Small text", chunk_size=100)
        assert len(chunks) == 1

class TestDedup:
    def test_removes_duplicates(self):
        chunks = ["hello", "hello", "world"]
        result = deduplicate_chunks(chunks)
        assert len(result) == 2

    def test_preserves_unique(self):
        chunks = ["a", "b", "c"]
        assert len(deduplicate_chunks(chunks)) == 3
