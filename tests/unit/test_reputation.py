"""Tests for nexusrecon.core.reputation: per-service reputation boosts."""
from __future__ import annotations

import pytest

from nexusrecon.core.reputation import (
    boost_for_profile,
    reputation_boost,
)


# ──────────────────────────────────────────────────────────────────────
# Per-service threshold tables
# ──────────────────────────────────────────────────────────────────────


class TestPerServiceThresholds:
    def test_github_thresholds(self):
        # GitHub uses follower_count as reputation proxy.
        assert reputation_boost("GitHub", 5) == 0.0    # below low
        assert reputation_boost("GitHub", 10) == 0.10  # at low
        assert reputation_boost("GitHub", 99) == 0.10  # just below mid
        assert reputation_boost("GitHub", 100) == 0.20 # at mid
        assert reputation_boost("GitHub", 1000) == 0.30 # at high

    def test_stackoverflow_thresholds(self):
        assert reputation_boost("StackOverflow", 50) == 0.0
        assert reputation_boost("StackOverflow", 100) == 0.10
        assert reputation_boost("StackOverflow", 1000) == 0.20
        assert reputation_boost("StackOverflow", 10000) == 0.30
        # Both naming variants work.
        assert reputation_boost("Stack Overflow", 1000) == 0.20

    def test_reddit_thresholds(self):
        assert reputation_boost("Reddit", 50) == 0.0
        assert reputation_boost("Reddit", 100) == 0.10
        assert reputation_boost("Reddit", 1000) == 0.20
        assert reputation_boost("Reddit", 10000) == 0.30

    def test_gitlab_thresholds(self):
        assert reputation_boost("GitLab", 1) == 0.0
        assert reputation_boost("GitLab", 3) == 0.10
        assert reputation_boost("GitLab", 10) == 0.20
        assert reputation_boost("GitLab", 50) == 0.30

    def test_unmapped_service_returns_zero(self):
        """Services we haven't categorised get 0.0 ── no signal, not
        a guess."""
        assert reputation_boost("SomeRandomForum", 999999) == 0.0
        assert reputation_boost("", 100) == 0.0
        assert reputation_boost(None, 100) == 0.0

    def test_case_insensitive_lookup(self):
        assert reputation_boost("github", 100) == 0.20
        assert reputation_boost("GITHUB", 100) == 0.20
        assert reputation_boost("GitHub", 100) == 0.20


# ──────────────────────────────────────────────────────────────────────
# Input handling
# ──────────────────────────────────────────────────────────────────────


class TestInputHandling:
    def test_none_value_returns_zero(self):
        assert reputation_boost("GitHub", None) == 0.0

    def test_zero_value_returns_zero(self):
        assert reputation_boost("GitHub", 0) == 0.0

    def test_negative_value_returns_zero(self):
        """Defensive ── reputation can't be negative on any real
        service. Treat as a data anomaly, not a penalty."""
        assert reputation_boost("GitHub", -1) == 0.0

    def test_string_numeric_value_works(self):
        """ProfileData may carry stringified numbers from some APIs.
        Treat numeric strings the same as numbers."""
        assert reputation_boost("GitHub", "100") == 0.20

    def test_non_numeric_string_returns_zero(self):
        assert reputation_boost("GitHub", "many followers") == 0.0


# ──────────────────────────────────────────────────────────────────────
# Boost cap
# ──────────────────────────────────────────────────────────────────────


class TestBoostCap:
    def test_max_boost_is_0_30(self):
        """A super-active account can never exceed +0.30 contribution
        to profile_coherence. Prevents reputation from saturating the
        score."""
        # Massive Stack Overflow rep should still cap at 0.30.
        assert reputation_boost("StackOverflow", 1_000_000) == 0.30
        # Same for GitHub mega-followers.
        assert reputation_boost("GitHub", 100_000) == 0.30


# ──────────────────────────────────────────────────────────────────────
# Profile data adapter
# ──────────────────────────────────────────────────────────────────────


class TestBoostForProfile:
    def test_dict_profile_with_reputation(self):
        profile = {"service": "StackOverflow", "reputation": 5000}
        assert boost_for_profile(profile) == 0.20

    def test_dict_profile_with_follower_count_only(self):
        """GitHub case ── reputation comes via follower_count when
        ``reputation`` isn't set."""
        profile = {"service": "GitHub", "follower_count": 150}
        assert boost_for_profile(profile) == 0.20

    def test_reputation_field_preferred_over_follower_count(self):
        """If both fields are present, ``reputation`` wins."""
        profile = {
            "service": "GitHub",
            "reputation": 50,        # low boost
            "follower_count": 100000, # would be high boost
        }
        # Should use reputation (50) → 0.10 boost, not follower_count.
        assert boost_for_profile(profile) == 0.10

    def test_none_profile_returns_zero(self):
        assert boost_for_profile(None) == 0.0

    def test_empty_dict_returns_zero(self):
        assert boost_for_profile({}) == 0.0

    def test_profile_without_relevant_fields_returns_zero(self):
        profile = {"service": "GitHub", "bio": "Hello"}
        assert boost_for_profile(profile) == 0.0

    def test_attribute_access_profile(self):
        """ProfileData (or any object with attribute access) works
        the same as a dict."""

        class _MockProfile:
            service = "GitHub"
            reputation = None
            follower_count = 200

        assert boost_for_profile(_MockProfile()) == 0.20


# ──────────────────────────────────────────────────────────────────────
# End-to-end attribution integration
# ──────────────────────────────────────────────────────────────────────


class TestAttributionIntegration:
    """Verify that the reputation boost actually flows through the
    attribution scorer's profile_coherence signal."""

    def test_high_reputation_lifts_profile_signal(self):
        from nexusrecon.core.attribution import score_handle_attribution

        low_rep = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="StackOverflow",
            profile_data={"service": "StackOverflow", "reputation": 50},
        )
        high_rep = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="StackOverflow",
            profile_data={"service": "StackOverflow", "reputation": 12450},
        )
        # High-rep account should produce a strictly higher profile
        # signal than low-rep at the same email + handle + service.
        assert high_rep.signals["profile"] > low_rep.signals["profile"]
        # And consequently a higher final score.
        assert high_rep.score > low_rep.score

    def test_unmapped_service_no_rep_boost(self):
        """Reputation on an unmapped service contributes nothing ──
        attribution should match a profile with no reputation at all."""
        from nexusrecon.core.attribution import score_handle_attribution
        no_rep = score_handle_attribution(
            email="jane@example.com", handle="jane",
            service="SomeRandomForum",
            profile_data={"service": "SomeRandomForum"},
        )
        with_rep = score_handle_attribution(
            email="jane@example.com", handle="jane",
            service="SomeRandomForum",
            profile_data={"service": "SomeRandomForum", "reputation": 999999},
        )
        # Unmapped service → 0.0 boost → identical profile signals.
        assert no_rep.signals["profile"] == with_rep.signals["profile"]
