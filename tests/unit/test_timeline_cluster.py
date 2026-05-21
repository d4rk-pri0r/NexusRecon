"""Tests for nexusrecon.core.timeline_cluster."""
from __future__ import annotations

from datetime import UTC, datetime

from nexusrecon.core.timeline_cluster import (
    AccountTimestamp,
    annotate_hits_with_cluster_ids,
    extract_timestamps_from_hits,
    find_timeline_clusters,
    parse_timestamp,
)

# ──────────────────────────────────────────────────────────────────────
# Timestamp parsing
# ──────────────────────────────────────────────────────────────────────


class TestParseTimestamp:
    def test_iso_with_z_suffix(self):
        dt = parse_timestamp("2014-03-04T12:00:00Z")
        assert dt is not None
        assert dt.year == 2014
        assert dt.month == 3
        assert dt.tzinfo is not None

    def test_iso_with_offset(self):
        dt = parse_timestamp("2014-03-04T12:00:00+00:00")
        assert dt is not None
        assert dt.year == 2014

    def test_unix_seconds(self):
        # 1395849600 = 2014-03-26 12:00:00 UTC.
        dt = parse_timestamp("1395849600")
        assert dt is not None
        assert dt.year == 2014

    def test_unix_seconds_with_fraction(self):
        dt = parse_timestamp("1395849600.5")
        assert dt is not None

    def test_unix_milliseconds(self):
        # 1395849600000 ms = same Unix-seconds time.
        dt = parse_timestamp("1395849600000")
        assert dt is not None
        assert dt.year == 2014

    def test_bare_date(self):
        dt = parse_timestamp("2014-03-04")
        assert dt is not None
        assert dt.month == 3

    def test_none_returns_none(self):
        assert parse_timestamp(None) is None
        assert parse_timestamp("") is None
        assert parse_timestamp("   ") is None

    def test_malformed_returns_none(self):
        assert parse_timestamp("not a date") is None
        assert parse_timestamp("2014-99-99T99:99:99") is None

    def test_naive_iso_assumed_utc(self):
        """An ISO timestamp without a timezone gets UTC ── prevents
        downstream code from comparing naive vs aware datetimes."""
        dt = parse_timestamp("2014-03-04T12:00:00")
        assert dt is not None
        assert dt.tzinfo is not None


# ──────────────────────────────────────────────────────────────────────
# Clustering
# ──────────────────────────────────────────────────────────────────────


def _ts(service: str, username: str, year: int, month: int, day: int) -> AccountTimestamp:
    return AccountTimestamp(
        service=service, username=username,
        created_at=datetime(year, month, day, tzinfo=UTC),
    )


class TestClustering:
    def test_no_accounts_returns_empty(self):
        assert find_timeline_clusters([]) == []

    def test_single_account_returns_empty(self):
        accounts = [_ts("GitHub", "jane", 2014, 3, 4)]
        assert find_timeline_clusters(accounts) == []

    def test_close_accounts_cluster(self):
        """Two accounts within the default 30-day window should
        cluster together."""
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 3, 15),
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        assert len(clusters) == 1
        assert clusters[0].size == 2

    def test_far_apart_accounts_dont_cluster(self):
        """Accounts created years apart shouldn't cluster ── the
        signal is "same time window," not "any pair of dates"."""
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2020, 3, 15),
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        assert clusters == []

    def test_three_accounts_within_window(self):
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 3, 8),
            _ts("Mastodon", "jane", 2014, 3, 20),
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        assert len(clusters) == 1
        assert clusters[0].size == 3

    def test_two_separate_clusters(self):
        """Two clusters separated by a large gap."""
        accounts = [
            # First cluster: early 2014
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 3, 8),
            # Second cluster: late 2020
            _ts("Reddit", "jane", 2020, 9, 1),
            _ts("Mastodon", "jane", 2020, 9, 15),
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        assert len(clusters) == 2

    def test_window_threshold_respected(self):
        """An account 35 days after the prior one shouldn't extend
        a 30-day window."""
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 4, 5),  # 35 days later
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        assert clusters == []

    def test_wider_window_clusters_more(self):
        accounts = [
            _ts("GitHub", "jane", 2014, 1, 1),
            _ts("Twitter", "jane", 2014, 6, 1),
        ]
        # 30-day default → no cluster.
        assert find_timeline_clusters(accounts, window_days=30) == []
        # 180-day window → cluster.
        clusters = find_timeline_clusters(accounts, window_days=180)
        assert len(clusters) == 1

    def test_min_cluster_size_respected(self):
        """``min_cluster_size=3`` should reject 2-element clusters."""
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 3, 8),
        ]
        clusters = find_timeline_clusters(
            accounts, window_days=30, min_cluster_size=3,
        )
        assert clusters == []


class TestClusterProperties:
    def test_span_days(self):
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 3, 15),
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        cluster = clusters[0]
        assert cluster.span_days == 14

    def test_earliest_and_latest(self):
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 15),
            _ts("Twitter", "jane", 2014, 3, 1),
            _ts("Mastodon", "jane", 2014, 3, 20),
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        cluster = clusters[0]
        assert cluster.earliest.day == 1
        assert cluster.latest.day == 20

    def test_to_dict_is_json_safe(self):
        import json
        accounts = [
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 3, 15),
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        d = clusters[0].to_dict()
        json.dumps(d)  # would raise if not


# ──────────────────────────────────────────────────────────────────────
# Hit integration
# ──────────────────────────────────────────────────────────────────────


class TestHitIntegration:
    def test_extract_from_fetched_profile(self):
        hits = [
            {
                "service": "GitHub",
                "username": "jane",
                "fetched_profile": {"created_at": "2014-03-04T12:00:00Z"},
            },
        ]
        accounts = extract_timestamps_from_hits(hits)
        assert len(accounts) == 1
        assert accounts[0].service == "GitHub"

    def test_extract_handles_missing_profile(self):
        hits = [
            {"service": "GitHub", "username": "jane"},  # no fetched_profile
        ]
        accounts = extract_timestamps_from_hits(hits)
        assert accounts == []

    def test_extract_handles_malformed_timestamp(self):
        hits = [
            {
                "service": "GitHub",
                "username": "jane",
                "fetched_profile": {"created_at": "garbage"},
            },
        ]
        accounts = extract_timestamps_from_hits(hits)
        assert accounts == []  # silently dropped

    def test_annotate_hits_with_cluster_ids(self):
        hits = [
            {"service": "GitHub", "username": "jane"},
            {"service": "Twitter", "username": "jane"},
            {"service": "Reddit", "username": "alice"},
        ]
        # Build a single cluster of two accounts.
        from nexusrecon.core.timeline_cluster import TimelineCluster
        cluster = TimelineCluster(accounts=[
            _ts("GitHub", "jane", 2014, 3, 1),
            _ts("Twitter", "jane", 2014, 3, 15),
        ])
        annotate_hits_with_cluster_ids(hits, [cluster])

        gh_hit = next(h for h in hits if h["service"] == "GitHub")
        tw_hit = next(h for h in hits if h["service"] == "Twitter")
        rd_hit = next(h for h in hits if h["service"] == "Reddit")
        assert gh_hit["timeline_cluster_size"] == 2
        assert tw_hit["timeline_cluster_size"] == 2
        # Reddit not in any cluster ── no annotation.
        assert "timeline_cluster_size" not in rd_hit


# ──────────────────────────────────────────────────────────────────────
# End-to-end realistic scenario
# ──────────────────────────────────────────────────────────────────────


class TestRealisticScenario:
    def test_employee_setting_up_presence_at_new_job(self):
        """Jane started at GitLab in March 2014 and set up her
        professional online presence in the first few weeks. Three
        accounts cluster; a separate hobby account from years earlier
        doesn't."""
        accounts = [
            _ts("GitHub", "jane.doe", 2014, 3, 5),    # day 1 at GitLab
            _ts("Twitter", "jane.doe", 2014, 3, 8),
            _ts("Mastodon", "jane.doe", 2014, 3, 20),
            _ts("Reddit", "jane.doe", 2009, 11, 4),   # old hobby account
        ]
        clusters = find_timeline_clusters(accounts, window_days=30)
        assert len(clusters) == 1
        assert clusters[0].size == 3
        # The hobby account didn't join.
        cluster_services = {a.service for a in clusters[0].accounts}
        assert cluster_services == {"GitHub", "Twitter", "Mastodon"}
