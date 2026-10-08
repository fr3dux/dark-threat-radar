"""Normalize heterogeneous RSS and local-news timestamps for stable ordering."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def normalize_news_date(value: object) -> str | None:
    """Return a lexicographically sortable UTC timestamp without changing display text."""
    if not isinstance(value, str) or not value.strip():
        return None

    raw = value.strip()
    parsed: datetime | None = None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        pass

    if parsed is None:
        candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
