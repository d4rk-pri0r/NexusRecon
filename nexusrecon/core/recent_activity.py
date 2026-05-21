"""RecentActivity records — Phase E8 producer / E9 consumer shared shape.

A :class:`RecentActivity` is a time-stamped public observation about
a target (a domain, an identity, an org). They power the **timing**
axis of E9 pretext scoring ── "what's plausibly topical right now":
a news article from yesterday makes a "did you see the Acme breach?"
pretext credible; the same article from two years ago is just trivia.

Producers (Phase E8 + future tools):

  - ``news_tool`` (extended in E8) emits news / press / blog records.
  - ``recent_activity_tool`` (if added later) wraps additional
    sources ── changelogs, status-page incidents, SEC EDGAR filings.

Consumer (Phase E9):

  - ``pretext_scoring`` reads :class:`RecentActivity` records by
    target and combines their recency-decayed weight with the
    sender-plausibility signal from
    :class:`RelationshipEdge` to produce
    ``PretextCandidate`` rankings.

Design choices:

  - **Time-window filtering is best-effort.** ``published_at`` is
    free-text from upstream sources (RSS pubDate, NewsAPI
    publishedAt, scraped blog header), so the filter tolerates
    unparseable values. Records with unknown timestamps are
    excluded from windowed views but preserved in the full set ──
    losing them entirely would silently drop signal.
  - **Pure Python, no network.** The dataclass + helpers do not
    fetch anything; producer tools call out, then construct
    records.
  - **JSON-safe out of the box.** Every dataclass has a
    ``to_dict()`` returning a serialisable representation so audit
    log + state checkpoint reuse the same shape.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ──────────────────────────────────────────────────────────────────────
# Dataclass
# ──────────────────────────────────────────────────────────────────────


# Default time-window for "recent" activity used by E9. 90 days
# matches the half-life of pretext relevance ── older items feel
# stale to most targets, newer items still feel current.
DEFAULT_WINDOW_DAYS = 90


@dataclass
class RecentActivity:
    """A single dated public observation about a target.

    Attributes:
        target: The handle / domain / identity_id the activity was
            found for. Free-text because producers may not always
            map to a canonical identity (e.g. a news article about
            an org rather than an individual). E9 normalises at
            scoring time.
        kind: Coarse classification ── one of:
            ``"news_article"``, ``"press_release"``, ``"blog_post"``,
            ``"changelog"``, ``"social_post"``, ``"filing"``,
            ``"earnings"``, ``"other"``. Used by the scoring engine
            to weight different activity types.
        source: Producer tool name (e.g. ``"news_intel"``,
            ``"google_news_rss"``, ``"newsapi"``). Lets the
            operator trace back to a primary source.
        title: Short headline / subject line. May be empty when the
            upstream feed had only a URL.
        url: Permalink to the source artifact. ``None`` when no
            durable URL is available.
        summary: Short text snippet (≤500 chars). Trimmed from the
            source description / first-paragraph extract.
        published_at: ISO-8601 timestamp, best-effort. ``None``
            when the source didn't surface a date.
        raw: The original upstream record, preserved unmodified so
            future tooling (audit, reprocessing) doesn't need a
            re-fetch.
    """

    target: str
    kind: str
    source: str
    title: str = ""
    url: str | None = None
    summary: str = ""
    published_at: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "source": self.source,
            "title": self.title,
            "url": self.url,
            "summary": self.summary,
            "published_at": self.published_at,
            # ``raw`` may contain large blobs; consumers that want
            # them include them explicitly. By default the dict view
            # keeps just the structured fields ── matches the
            # IdentityGraph.to_dict pattern of "tidy for state, raw
            # for audit".
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecentActivity:
        return cls(
            target=data["target"],
            kind=data.get("kind", "other"),
            source=data.get("source", ""),
            title=data.get("title", ""),
            url=data.get("url"),
            summary=data.get("summary", ""),
            published_at=data.get("published_at"),
            raw=dict(data.get("raw", {})),
        )


# ──────────────────────────────────────────────────────────────────────
# Time parsing
# ──────────────────────────────────────────────────────────────────────


def _to_timestamp(value: str | float | int | None) -> float | None:
    """Best-effort parse of a published-at value into a UTC unix
    timestamp.

    Accepts ISO-8601 strings (with or without ``Z`` / explicit
    offset), epoch numbers, and RFC-2822 RSS-style dates
    (``Wed, 01 May 2024 12:00:00 GMT``). Returns ``None`` for
    unparseable input ── callers treat that as "no recency signal".
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Try ISO-8601 first
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except ValueError:
        pass
    # Try RFC-2822 (common in RSS feeds)
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


# ──────────────────────────────────────────────────────────────────────
# Filters / aggregators
# ──────────────────────────────────────────────────────────────────────


def filter_by_window(
    records: list[RecentActivity],
    *,
    window_days: float = DEFAULT_WINDOW_DAYS,
    now: float | None = None,
) -> list[RecentActivity]:
    """Keep only records within the last ``window_days`` days.

    Records with unparseable / missing ``published_at`` are DROPPED
    from the filtered view ── inclusion would inflate the "recent"
    bucket with undated noise. Use the full unfiltered list when
    you want everything.

    Pre-condition: ``window_days >= 0``. ``window_days == 0``
    returns an empty list (no records are "within zero days").
    """
    if window_days <= 0:
        return []
    now_ts = now if now is not None else time.time()
    threshold = now_ts - (window_days * 86400.0)
    out: list[RecentActivity] = []
    for r in records:
        ts = _to_timestamp(r.published_at)
        if ts is None:
            continue
        if ts >= threshold:
            out.append(r)
    return out


def group_by_target(
    records: list[RecentActivity],
) -> dict[str, list[RecentActivity]]:
    """Bucket records by their ``target`` field. Targets are
    case-preserving but matched as the literal string ── upstream
    normalisation is the caller's responsibility."""
    buckets: dict[str, list[RecentActivity]] = defaultdict(list)
    for r in records:
        buckets[r.target].append(r)
    return dict(buckets)


def latest_for_target(
    records: list[RecentActivity],
    target: str,
    *,
    n: int = 10,
) -> list[RecentActivity]:
    """Top-N most-recent records for ``target``, sorted descending
    by ``published_at``. Records with unparseable timestamps sort
    last (treated as oldest)."""
    relevant = [r for r in records if r.target == target]

    def _sort_key(r: RecentActivity) -> float:
        ts = _to_timestamp(r.published_at)
        # Unparseable → very-old sentinel so they sort last.
        return ts if ts is not None else -1.0

    relevant.sort(key=_sort_key, reverse=True)
    return relevant[:n]
