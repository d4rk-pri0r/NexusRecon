"""Tests for nexusrecon.core.recent_activity (PR-4 prep).

Covers:
  - RecentActivity dataclass serialisation round-trip.
  - _to_timestamp parses ISO-8601 (Z + offset + naive), epoch, RFC-2822
    (RSS-style), and returns None for unparseable input.
  - filter_by_window:
      * keeps records inside the window
      * drops records outside the window
      * drops records with unparseable / missing timestamps
      * window_days <= 0 returns empty list
      * deterministic with ``now=`` override
  - group_by_target buckets correctly.
  - latest_for_target sorts descending, applies n limit, undated items
    sort last.
"""
from __future__ import annotations

from datetime import UTC, datetime

from nexusrecon.core.recent_activity import (
    DEFAULT_WINDOW_DAYS,
    RecentActivity,
    _to_timestamp,
    filter_by_window,
    group_by_target,
    latest_for_target,
)

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _iso(year: int, month: int = 1, day: int = 1) -> str:
    return datetime(year, month, day, tzinfo=UTC).isoformat()


def _activity(
    target: str = "example.com",
    kind: str = "news_article",
    title: str = "Story",
    published_at: str | None = "2024-06-01T00:00:00+00:00",
) -> RecentActivity:
    return RecentActivity(
        target=target,
        kind=kind,
        source="test",
        title=title,
        published_at=published_at,
        summary="snippet",
        url="https://example.com/x",
        raw={},
    )


# ──────────────────────────────────────────────────────────────────────
# Dataclass round-trip
# ──────────────────────────────────────────────────────────────────────


class TestRecentActivityShape:
    def test_to_dict_then_from_dict(self):
        a = _activity()
        rebuilt = RecentActivity.from_dict(a.to_dict())
        # to_dict omits raw by design; from_dict treats missing raw as {}
        assert rebuilt.target == a.target
        assert rebuilt.kind == a.kind
        assert rebuilt.source == a.source
        assert rebuilt.title == a.title
        assert rebuilt.url == a.url
        assert rebuilt.summary == a.summary
        assert rebuilt.published_at == a.published_at

    def test_default_kind_other(self):
        rebuilt = RecentActivity.from_dict({"target": "x"})
        assert rebuilt.kind == "other"

    def test_to_dict_keys_present(self):
        d = _activity().to_dict()
        assert set(d.keys()) >= {
            "target", "kind", "source", "title", "url",
            "summary", "published_at",
        }


# ──────────────────────────────────────────────────────────────────────
# _to_timestamp
# ──────────────────────────────────────────────────────────────────────


class TestToTimestamp:
    def test_iso_z_suffix(self):
        ts = _to_timestamp("2024-01-01T00:00:00Z")
        assert ts == datetime(2024, 1, 1, tzinfo=UTC).timestamp()

    def test_iso_with_offset(self):
        ts = _to_timestamp("2024-01-01T00:00:00+00:00")
        assert ts == datetime(2024, 1, 1, tzinfo=UTC).timestamp()

    def test_naive_iso_assumed_utc(self):
        ts = _to_timestamp("2024-01-01T00:00:00")
        assert ts == datetime(2024, 1, 1, tzinfo=UTC).timestamp()

    def test_epoch_int(self):
        assert _to_timestamp(1_700_000_000) == 1_700_000_000.0

    def test_epoch_float(self):
        assert _to_timestamp(1_700_000_000.5) == 1_700_000_000.5

    def test_rfc_2822_rss_style(self):
        # Common RSS feed style (Google News RSS uses this).
        ts = _to_timestamp("Mon, 01 Jan 2024 00:00:00 GMT")
        # Compare to ISO equivalent; tolerate small offset.
        expected = datetime(2024, 1, 1, tzinfo=UTC).timestamp()
        assert abs(ts - expected) < 1.0

    def test_none(self):
        assert _to_timestamp(None) is None

    def test_empty_string(self):
        assert _to_timestamp("") is None

    def test_garbage_string(self):
        assert _to_timestamp("not-a-date") is None


# ──────────────────────────────────────────────────────────────────────
# filter_by_window
# ──────────────────────────────────────────────────────────────────────


class TestFilterByWindow:
    def test_keeps_inside_window(self):
        now = datetime(2024, 6, 1, tzinfo=UTC).timestamp()
        recs = [
            _activity(published_at=_iso(2024, 5, 1)),  # 31 days old
            _activity(published_at=_iso(2024, 5, 25)),  # 7 days old
        ]
        out = filter_by_window(recs, window_days=60, now=now)
        assert len(out) == 2

    def test_drops_outside_window(self):
        now = datetime(2024, 6, 1, tzinfo=UTC).timestamp()
        recs = [
            _activity(published_at=_iso(2024, 5, 25)),  # 7 days old
            _activity(published_at=_iso(2023, 5, 1)),   # > 365 days
        ]
        out = filter_by_window(recs, window_days=30, now=now)
        assert len(out) == 1
        assert out[0].published_at == _iso(2024, 5, 25)

    def test_drops_unparseable(self):
        now = datetime(2024, 6, 1, tzinfo=UTC).timestamp()
        recs = [
            _activity(published_at="garbage"),
            _activity(published_at=None),
            _activity(published_at=_iso(2024, 5, 30)),
        ]
        out = filter_by_window(recs, window_days=30, now=now)
        assert len(out) == 1

    def test_zero_window(self):
        # window_days == 0 → nothing is "within" zero days
        recs = [_activity(published_at=_iso(2024, 5, 30))]
        assert filter_by_window(recs, window_days=0) == []

    def test_negative_window(self):
        recs = [_activity(published_at=_iso(2024, 5, 30))]
        assert filter_by_window(recs, window_days=-5) == []

    def test_default_uses_time_time(self):
        # Without ``now``, defaults to time.time() — sanity-check it
        # doesn't crash and treats far-past records as outside the
        # default 90-day window.
        recs = [_activity(published_at=_iso(2000, 1, 1))]
        # Time-dependent but the assertion is direction-only.
        assert filter_by_window(recs) == []


# ──────────────────────────────────────────────────────────────────────
# group_by_target
# ──────────────────────────────────────────────────────────────────────


class TestGroupByTarget:
    def test_buckets_by_target(self):
        recs = [
            _activity(target="a.com", title="A1"),
            _activity(target="a.com", title="A2"),
            _activity(target="b.com", title="B1"),
        ]
        out = group_by_target(recs)
        assert set(out.keys()) == {"a.com", "b.com"}
        assert len(out["a.com"]) == 2
        assert len(out["b.com"]) == 1

    def test_case_preserved(self):
        # Targets are matched as literals; no normalisation.
        recs = [
            _activity(target="Example.com"),
            _activity(target="example.com"),
        ]
        out = group_by_target(recs)
        assert set(out.keys()) == {"Example.com", "example.com"}

    def test_empty_input(self):
        assert group_by_target([]) == {}


# ──────────────────────────────────────────────────────────────────────
# latest_for_target
# ──────────────────────────────────────────────────────────────────────


class TestLatestForTarget:
    def test_descending_order(self):
        recs = [
            _activity(target="a", title="old", published_at=_iso(2024, 1, 1)),
            _activity(target="a", title="recent", published_at=_iso(2024, 6, 1)),
            _activity(target="a", title="middle", published_at=_iso(2024, 3, 1)),
        ]
        out = latest_for_target(recs, "a")
        assert [r.title for r in out] == ["recent", "middle", "old"]

    def test_n_limit(self):
        recs = [
            _activity(target="a", title=f"item{i}", published_at=_iso(2024, 1, i))
            for i in range(1, 11)
        ]
        out = latest_for_target(recs, "a", n=3)
        assert len(out) == 3

    def test_undated_sort_last(self):
        recs = [
            _activity(target="a", title="undated", published_at=None),
            _activity(target="a", title="dated", published_at=_iso(2024, 6, 1)),
        ]
        out = latest_for_target(recs, "a")
        assert [r.title for r in out] == ["dated", "undated"]

    def test_filters_other_targets(self):
        recs = [
            _activity(target="a", title="for-a"),
            _activity(target="b", title="for-b"),
        ]
        assert [r.title for r in latest_for_target(recs, "a")] == ["for-a"]

    def test_target_with_no_records(self):
        recs = [_activity(target="a")]
        assert latest_for_target(recs, "z") == []


# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────


class TestConstants:
    def test_default_window_positive(self):
        assert DEFAULT_WINDOW_DAYS > 0
