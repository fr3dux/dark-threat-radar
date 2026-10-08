import logging
import json
import hashlib
import os
import re
import html
from datetime import datetime, timezone
import httpx
import feedparser
from app.database import get_db, update_feed_status
from app.config import LOCAL_NEWS_FILE
from app.news_dates import normalize_news_date

logger = logging.getLogger("ingestion.news_feed")

FEEDS = {
    "The Hacker News": "https://thehackernews.com/feeds/posts/default?alt=rss",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "CISO Advisor": "https://www.cisoadvisor.com.br/feed/",
    "CERT.br": "https://www.cert.br/rss/certbr-rss.xml"
}

def clean_html(raw_html: str) -> str:
    if not raw_html:
        return ""
    clean_text = re.sub(r"<[^>]+>", " ", raw_html)
    clean_text = html.unescape(clean_text)
    return " ".join(clean_text.split())[:350]

async def ingest_news_feed() -> int:
    logger.info("Starting CTI News ingestion (local + feeds)...")
    await update_feed_status("news_feed", "running", 0, "Ingesting local CTI history and feeds...")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    count = 0

    async with get_db() as conn:
        # 1. Ingest local news history if available
        if LOCAL_NEWS_FILE.exists():
            try:
                with open(LOCAL_NEWS_FILE, "r", encoding="utf-8") as f:
                    local_data = json.load(f)

                for link, item in local_data.items():
                    title = item.get("title", "").strip()
                    if not title or not link:
                        continue
                    pub_date = item.get("date", "")
                    published_at = normalize_news_date(pub_date)
                    # Deduce source from link
                    source = "Local CTI"
                    if "bleepingcomputer" in link:
                        source = "BleepingComputer"
                    elif "thehackernews" in link:
                        source = "The Hacker News"
                    elif "tecnoblog" in link:
                        source = "Tecnoblog"
                    elif "securityweek" in link:
                        source = "SecurityWeek"
                    elif "cisoadvisor" in link:
                        source = "CISO Advisor"

                    news_id = hashlib.sha256(link.encode("utf-8")).hexdigest()[:16]

                    await conn.execute("""
                        INSERT INTO cti_news (
                            id, title, link, source, published_date, published_at, snippet, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            title = excluded.title,
                            source = excluded.source,
                            published_date = excluded.published_date,
                            published_at = COALESCE(excluded.published_at, cti_news.published_at),
                            updated_at = excluded.updated_at;
                    """, (news_id, title, link, source, pub_date, published_at, "", now_str))
                    count += 1
            except Exception as e:
                logger.warning(f"Failed parsing local news history: {e}")

        # 2. Ingest online feeds
        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "ThreatRadar-CTI/1.0"}) as client:
            for source_name, feed_url in FEEDS.items():
                try:
                    resp = await client.get(feed_url)
                    if resp.status_code == 200:
                        parsed = feedparser.parse(resp.text)
                        for entry in parsed.entries[:25]:
                            title = entry.get("title", "").strip()
                            link = entry.get("link", "").strip()
                            if not title or not link:
                                continue

                            published = entry.get("published", "") or entry.get("updated", "")
                            published_at = normalize_news_date(published)
                            summary = clean_html(entry.get("summary", "") or entry.get("description", ""))
                            news_id = hashlib.sha256(link.encode("utf-8")).hexdigest()[:16]

                            await conn.execute("""
                                INSERT INTO cti_news (
                                    id, title, link, source, published_date, published_at, snippet, updated_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(id) DO UPDATE SET
                                    title = excluded.title,
                                    source = excluded.source,
                                    published_date = excluded.published_date,
                                    published_at = COALESCE(excluded.published_at, cti_news.published_at),
                                    snippet = excluded.snippet,
                                    updated_at = excluded.updated_at;
                            """, (
                                news_id, title, link, source_name, published,
                                published_at, summary, now_str,
                            ))
                            count += 1
                except Exception as e:
                    logger.warning(f"Error fetching feed {source_name}: {e}")

        await conn.commit()

    msg = f"Synced {count} CTI news items."
    logger.info(msg)
    await update_feed_status("news_feed", "success", count, msg)
    return count
