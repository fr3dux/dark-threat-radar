import asyncio

from app import database
from app.watchlist_monitor import (
    domain_matches,
    refresh_watchlist_alerts,
    text_matches,
)


def test_boundary_and_domain_matching():
    assert text_matches("ACME", "ACME suffered a public data exposure")
    assert not text_matches("ACME", "ACMECorp suffered a public data exposure")
    assert domain_matches("example.com", "https://portal.example.com/path")
    assert not domain_matches("example.com", "notexample.com")
    assert not domain_matches("example..com", "example..com")


def test_exposure_watchlist_persists_cross_source_alerts(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "watchlist.db")

    async def scenario():
        await database.init_db()
        async with database.get_db() as conn:
            await conn.execute(
                "INSERT INTO watchlist (id, item_type, value, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                ("wl-company01", "company", "Example Corp", "Customer", "2026-10-08T10:00:00+00:00"),
            )
            await conn.execute(
                "INSERT INTO watchlist (id, item_type, value, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                ("wl-domain001", "domain", "example.com", "Primary domain", "2026-10-08T10:00:00+00:00"),
            )
            await conn.execute(
                """INSERT INTO ransomware_victims
                   (id, victim_name, group_name, domain, description, discovered, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                ("victim-1", "Example Corp", "actor", "example.com", "Data allegedly exfiltrated", "2026-10-08", "2026-10-08"),
            )
            await conn.execute(
                """INSERT INTO cti_news
                   (id, title, link, source, published_date, published_at, snippet, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                ("news-1", "Example Corp investigates exposure", "https://news.invalid/item", "Test News", "2026-10-08", "2026-10-08T11:00:00Z", "Incident response is under way", "2026-10-08"),
            )
            await conn.execute(
                """INSERT INTO normalized_iocs
                   (id, indicator_type, indicator_value, normalized_value, confidence,
                    severity, source_name, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                ("ioc-1", "domain", "malware.example.com", "malware.example.com", 90, "HIGH", "test_feed", "2026-10-08"),
            )
            await conn.commit()

        assert await refresh_watchlist_alerts() == 4
        assert await refresh_watchlist_alerts() == 0

        async with database.get_db() as conn:
            rows = await (await conn.execute(
                "SELECT source_type, matched_value FROM watchlist_alerts ORDER BY source_type, matched_value"
            )).fetchall()
            assert len(rows) == 4
            assert {row["source_type"] for row in rows} == {"ioc", "news", "ransomware"}

            await conn.execute("DELETE FROM watchlist WHERE id='wl-domain001'")
            await conn.commit()
            remaining = await (await conn.execute(
                "SELECT COUNT(*) AS total FROM watchlist_alerts WHERE watchlist_id='wl-domain001'"
            )).fetchone()
            assert remaining["total"] == 0

    asyncio.run(scenario())
