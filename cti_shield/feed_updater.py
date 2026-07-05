"""
Feed Updater — Live OSINT Feed Ingestion
==========================================
Ingests threat intelligence from TAXII, RSS, and API feeds.
"""
from __future__ import annotations
import json, time, hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import structlog
from config import settings, OSINT_DIR

logger = structlog.get_logger(__name__)

class FeedUpdater:
    """Manages live OSINT feed ingestion."""
    
    def __init__(self) -> None:
        self.config = settings.feed
        self.last_update: Optional[datetime] = None
        self.stats: dict[str, int] = {"fetched": 0, "new": 0, "errors": 0}
    
    def update_all(self) -> dict[str, Any]:
        """Run all feed updates."""
        self.stats = {"fetched": 0, "new": 0, "errors": 0}
        results: dict[str, Any] = {}
        results["rss"] = self._fetch_rss_feeds()
        results["cisa_kev"] = self._fetch_cisa_kev()
        self.last_update = datetime.now(timezone.utc)
        results["stats"] = self.stats.copy()
        results["timestamp"] = self.last_update.isoformat()
        return results
    
    def _fetch_rss_feeds(self) -> list[dict[str, Any]]:
        articles = []
        try:
            import feedparser
        except ImportError:
            logger.warning("feedparser not installed")
            return articles
        
        for url in self.config.rss_feeds:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:10]:
                    article = {
                        "title": getattr(entry, "title", ""),
                        "link": getattr(entry, "link", ""),
                        "summary": getattr(entry, "summary", "")[:500],
                        "published": getattr(entry, "published", ""),
                        "source": url,
                    }
                    articles.append(article)
                    self.stats["fetched"] += 1
                    # Save to disk
                    self._save_report(article["title"], article["summary"], url)
            except Exception as e:
                logger.error("RSS fetch error", url=url, error=str(e))
                self.stats["errors"] += 1
        return articles
    
    def _fetch_cisa_kev(self) -> list[dict[str, Any]]:
        vulns = []
        try:
            import requests
            resp = requests.get(self.config.cisa_kev_url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for v in data.get("vulnerabilities", [])[:20]:
                    vulns.append({
                        "cve": v.get("cveID", ""),
                        "vendor": v.get("vendorProject", ""),
                        "product": v.get("product", ""),
                        "description": v.get("shortDescription", ""),
                        "date_added": v.get("dateAdded", ""),
                    })
                    self.stats["fetched"] += 1
        except Exception as e:
            logger.error("CISA KEV fetch error", error=str(e))
            self.stats["errors"] += 1
        return vulns
    
    def _save_report(self, title: str, content: str, source: str) -> None:
        if not title or not content:
            return
        slug = hashlib.md5(title.encode()).hexdigest()[:12]
        filepath = OSINT_DIR / f"feed_{slug}.txt"
        if not filepath.exists():
            filepath.write_text(f"Source: {source}\nTitle: {title}\n\n{content}", encoding="utf-8")
            self.stats["new"] += 1

# Singleton
_updater: FeedUpdater | None = None

def get_feed_updater() -> FeedUpdater:
    global _updater
    if _updater is None:
        _updater = FeedUpdater()
    return _updater
