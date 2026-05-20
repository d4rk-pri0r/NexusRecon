"""Tests for nexusrecon.core.handle_ubiquity."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from nexusrecon.core.handle_ubiquity import (
    HandleUbiquityTracker,
    _commonness_for_count,
    get_current_tracker,
    ubiquity_context,
)


@pytest.fixture
def tmp_tracker(tmp_path):
    """Fresh per-test tracker with a temporary DB. Ensures tests don't
    contaminate each other or the developer's real DB at
    ~/.nexusrecon/."""
    db_path = tmp_path / "ubiquity_test.db"
    tracker = HandleUbiquityTracker(db_path=db_path)
    yield tracker
    tracker.close()


# ──────────────────────────────────────────────────────────────────────
# Basic recording and counting
# ──────────────────────────────────────────────────────────────────────


class TestBasicRecordAndCount:
    def test_unseen_handle_returns_zero(self, tmp_tracker):
        assert tmp_tracker.campaign_count("jane.doe") == 0

    def test_single_observation_returns_one(self, tmp_tracker):
        tmp_tracker.record_observation(
            handle="jane.doe", service="GitHub", campaign_id="camp-001",
        )
        assert tmp_tracker.campaign_count("jane.doe") == 1

    def test_dedup_within_same_campaign(self, tmp_tracker):
        """Two recordings of the same (handle, service, campaign)
        triple must collapse to one ── otherwise a single campaign's
        re-runs would pollute the cross-campaign signal."""
        for _ in range(3):
            tmp_tracker.record_observation(
                handle="jane.doe", service="GitHub", campaign_id="camp-001",
            )
        assert tmp_tracker.campaign_count("jane.doe") == 1
        assert tmp_tracker.total_observations() == 1

    def test_distinct_campaigns_increment_count(self, tmp_tracker):
        tmp_tracker.record_observation("jdoe", "GitHub", "camp-001")
        tmp_tracker.record_observation("jdoe", "GitHub", "camp-002")
        tmp_tracker.record_observation("jdoe", "GitHub", "camp-003")
        assert tmp_tracker.campaign_count("jdoe") == 3

    def test_same_handle_multiple_services_in_one_campaign_counts_once(self, tmp_tracker):
        """``jdoe`` on GitHub + Twitter in the same campaign should
        contribute one campaign to the count, not two ── ubiquity is
        about cross-CAMPAIGN frequency, not cross-service per
        campaign."""
        tmp_tracker.record_observation("jdoe", "GitHub", "camp-001")
        tmp_tracker.record_observation("jdoe", "Twitter", "camp-001")
        tmp_tracker.record_observation("jdoe", "Reddit", "camp-001")
        # Three observations but one distinct campaign.
        assert tmp_tracker.total_observations() == 3
        assert tmp_tracker.campaign_count("jdoe") == 1


# ──────────────────────────────────────────────────────────────────────
# Hash normalisation
# ──────────────────────────────────────────────────────────────────────


class TestHandleHashing:
    def test_case_variations_collapse(self, tmp_tracker):
        """``Jane.Doe`` and ``jane.doe`` and ``JANE.DOE`` must all hash
        the same so ubiquity counts work across the case variation
        that real handle data has."""
        tmp_tracker.record_observation("Jane.Doe", "GitHub", "camp-001")
        tmp_tracker.record_observation("jane.doe", "GitHub", "camp-002")
        tmp_tracker.record_observation("JANE.DOE", "GitHub", "camp-003")
        assert tmp_tracker.campaign_count("jane.doe") == 3
        assert tmp_tracker.campaign_count("JANE.DOE") == 3

    def test_whitespace_stripped(self, tmp_tracker):
        tmp_tracker.record_observation("  jane.doe  ", "GitHub", "camp-001")
        assert tmp_tracker.campaign_count("jane.doe") == 1

    def test_different_handles_have_different_hashes(self, tmp_tracker):
        tmp_tracker.record_observation("jane.doe", "GitHub", "camp-001")
        tmp_tracker.record_observation("john.smith", "GitHub", "camp-001")
        # Counts must be independent.
        assert tmp_tracker.campaign_count("jane.doe") == 1
        assert tmp_tracker.campaign_count("john.smith") == 1


# ──────────────────────────────────────────────────────────────────────
# Salt and privacy
# ──────────────────────────────────────────────────────────────────────


class TestSaltAndPrivacy:
    def test_salt_generated_on_first_init(self, tmp_path):
        db_path = tmp_path / "first_init.db"
        tracker = HandleUbiquityTracker(db_path=db_path)
        tracker.close()

        # The DB should now exist with the install_metadata table
        # populated.
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cur = conn.execute(
            "SELECT value FROM install_metadata WHERE key = 'handle_salt'"
        )
        row = cur.fetchone()
        conn.close()
        assert row is not None
        # 16 bytes = 32 hex chars.
        assert len(row[0]) == 32

    def test_salt_persists_across_reopen(self, tmp_path):
        """The salt is generated once and reused on subsequent opens
        of the same DB ── otherwise a re-init would invalidate all
        prior observations."""
        db_path = tmp_path / "persist.db"
        t1 = HandleUbiquityTracker(db_path=db_path)
        t1.record_observation("jane.doe", "GitHub", "camp-001")
        t1.close()

        t2 = HandleUbiquityTracker(db_path=db_path)
        # Same hash → still finds the prior observation.
        assert t2.campaign_count("jane.doe") == 1
        t2.close()

    def test_plaintext_handle_never_stored(self, tmp_path):
        """A leaked DB should not contain plaintext handles. Verify by
        inspecting the raw rows."""
        db_path = tmp_path / "no_plaintext.db"
        tracker = HandleUbiquityTracker(db_path=db_path)
        tracker.record_observation(
            "very-specific-handle-vukovic-2018", "GitHub", "camp-001",
        )
        tracker.close()

        # Dump all stored data.
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cur = conn.execute("SELECT handle_hash FROM handle_observations")
        rows = [row[0] for row in cur.fetchall()]
        conn.close()

        for row in rows:
            assert "vukovic" not in row.lower()
            assert "specific" not in row.lower()
            # Hash should look like a 64-char hex digest.
            assert len(row) == 64
            int(row, 16)  # confirms it parses as hex

    def test_different_installs_have_different_salts(self, tmp_path):
        """Two fresh DBs (different install paths) get different
        salts, so the same handle hashes differently ── prevents
        collusion attacks across leaked operator DBs."""
        db_a = tmp_path / "install_a.db"
        db_b = tmp_path / "install_b.db"
        ta = HandleUbiquityTracker(db_path=db_a)
        tb = HandleUbiquityTracker(db_path=db_b)
        ta.record_observation("jane.doe", "GitHub", "camp-001")
        tb.record_observation("jane.doe", "GitHub", "camp-001")
        ta.close()
        tb.close()

        # Read both hash values.
        import sqlite3
        for db in (db_a, db_b):
            conn = sqlite3.connect(str(db))
            cur = conn.execute("SELECT handle_hash FROM handle_observations")
            row = cur.fetchone()
            conn.close()
            globals().setdefault("_hashes", []).append(row[0])

        hashes = globals()["_hashes"]
        assert hashes[0] != hashes[1], (
            "salts didn't change the hash ── per-install isolation broken"
        )
        del globals()["_hashes"]


# ──────────────────────────────────────────────────────────────────────
# Commonness scoring curve
# ──────────────────────────────────────────────────────────────────────


class TestCommonnessScore:
    def test_unseen_returns_zero(self, tmp_tracker):
        assert tmp_tracker.commonness_score("never-recorded") == 0.0

    def test_one_campaign_returns_zero(self, tmp_tracker):
        tmp_tracker.record_observation("jane.doe", "GitHub", "camp-001")
        # Single-campaign observations don't carry ubiquity signal ──
        # could be this is the first time we see what turns out to be
        # a popular handle.
        assert tmp_tracker.commonness_score("jane.doe") == 0.0

    def test_three_campaigns_returns_modest_commonness(self, tmp_tracker):
        for cid in ("c1", "c2", "c3"):
            tmp_tracker.record_observation("jdoe", "GitHub", cid)
        # Per the curve, count<=3 → 0.30.
        assert tmp_tracker.commonness_score("jdoe") == 0.30

    def test_many_campaigns_returns_high_commonness(self, tmp_tracker):
        for cid in [f"c{i}" for i in range(20)]:
            tmp_tracker.record_observation("admin", "GitHub", cid)
        # Per the curve, count>10 → 0.85.
        assert tmp_tracker.commonness_score("admin") == 0.85

    def test_commonness_curve_directly(self):
        assert _commonness_for_count(0) == 0.0
        assert _commonness_for_count(1) == 0.0
        assert _commonness_for_count(2) == 0.30
        assert _commonness_for_count(3) == 0.30
        assert _commonness_for_count(4) == 0.60
        assert _commonness_for_count(10) == 0.60
        assert _commonness_for_count(11) == 0.85
        assert _commonness_for_count(1000) == 0.85


# ──────────────────────────────────────────────────────────────────────
# DB path resolution
# ──────────────────────────────────────────────────────────────────────


class TestDbPathResolution:
    def test_explicit_path_used(self, tmp_path):
        db = tmp_path / "explicit.db"
        tracker = HandleUbiquityTracker(db_path=db)
        assert tracker.db_path == db
        tracker.close()

    def test_env_var_override(self, tmp_path, monkeypatch):
        db = tmp_path / "via_env.db"
        monkeypatch.setenv("NEXUS_UBIQUITY_DB_PATH", str(db))
        tracker = HandleUbiquityTracker()
        assert tracker.db_path == db
        tracker.close()


# ──────────────────────────────────────────────────────────────────────
# Context var binding
# ──────────────────────────────────────────────────────────────────────


class TestContextVarBinding:
    def test_no_tracker_by_default(self):
        # Outside any context, get_current_tracker returns None.
        assert get_current_tracker() is None

    def test_context_binds_and_unbinds(self, tmp_tracker):
        assert get_current_tracker() is None
        with ubiquity_context(tmp_tracker):
            assert get_current_tracker() is tmp_tracker
        assert get_current_tracker() is None

    def test_explicit_none_in_nested_context(self, tmp_tracker):
        """Setting ``None`` inside a nested context unbinds the outer
        tracker for that scope ── useful for tests that want to bypass
        ubiquity within an otherwise-tracker-bound run."""
        with ubiquity_context(tmp_tracker):
            with ubiquity_context(None):
                assert get_current_tracker() is None
            # Outer tracker restored.
            assert get_current_tracker() is tmp_tracker


# ──────────────────────────────────────────────────────────────────────
# Robustness
# ──────────────────────────────────────────────────────────────────────


class TestRobustness:
    def test_empty_handle_ignored(self, tmp_tracker):
        """Empty handle silently no-ops ── caller shouldn't have to
        guard, recording garbage shouldn't poison the store."""
        tmp_tracker.record_observation("", "GitHub", "camp-001")
        assert tmp_tracker.total_observations() == 0

    def test_empty_service_ignored(self, tmp_tracker):
        tmp_tracker.record_observation("jdoe", "", "camp-001")
        assert tmp_tracker.total_observations() == 0

    def test_empty_campaign_id_ignored(self, tmp_tracker):
        tmp_tracker.record_observation("jdoe", "GitHub", "")
        assert tmp_tracker.total_observations() == 0

    def test_double_close_safe(self, tmp_tracker):
        tmp_tracker.close()
        tmp_tracker.close()  # must not raise

    def test_context_manager_closes_on_exit(self, tmp_path):
        db = tmp_path / "ctx.db"
        with HandleUbiquityTracker(db_path=db) as t:
            t.record_observation("jdoe", "GitHub", "camp-001")
            assert t.campaign_count("jdoe") == 1
        # After the with-block, connection is closed; opening a new
        # tracker should still find the observation.
        with HandleUbiquityTracker(db_path=db) as t2:
            assert t2.campaign_count("jdoe") == 1
