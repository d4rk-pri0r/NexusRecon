"""Tests for nexusrecon.core.attribution: handle-attribution scoring."""
from __future__ import annotations

import pytest

from nexusrecon.core.attribution import (
    AttributionScore,
    HIGH_CONFIDENCE_THRESHOLD,
    MEDIUM_CONFIDENCE_THRESHOLD,
    filter_actionable,
    score_handle_attribution,
)


# ──────────────────────────────────────────────────────────────────────
# Final score behaviour ── the "John Smith" case
# ──────────────────────────────────────────────────────────────────────


class TestJohnSmithCase:
    """The scoring system exists to defend against the John Smith
    false-positive: a corporate email derives a handle, the handle
    matches on N services because thousands of John Smiths use it,
    naive logic flags it as high confidence. These tests pin the
    correct outcome: the noise gets scored as noise."""

    def test_lone_common_surname_scores_as_noise(self):
        """``smith`` on Reddit, derived from ``john.smith@company.com`` ──
        the most pathological case. Common surname, common handle,
        social network without identity validation, no profile data."""
        result = score_handle_attribution(
            email="john.smith@company.com",
            handle="smith",
            service="Reddit",
        )
        assert result.score < MEDIUM_CONFIDENCE_THRESHOLD
        assert result.confidence_band == "noise"
        assert not result.is_actionable

    def test_full_corporate_dotted_form_scores_well_on_trusted_service(self):
        """An uncommon dotted corporate handle on GitHub. Exact
        derivation match + Tier 1 service + uniqueness signal all
        align ── should clear the actionable threshold even without
        profile evidence."""
        result = score_handle_attribution(
            email="xochitl.vukovic@example.com",
            handle="xochitl.vukovic",
            service="GitHub",
        )
        assert result.is_actionable
        assert result.confidence_band in ("medium", "high")

    def test_placeholder_dotted_handle_alone_is_only_medium(self):
        """``jane.doe`` is both in the common-handles list (placeholder
        name) and the exact email local-part. Without profile evidence
        to disambiguate, this is medium-band ── strong derivation but
        the handle string itself collides with many other Jane Does.
        Adding a bio mention should push it into actionable territory."""
        without_bio = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="GitHub",
        )
        # Strong signals but no corroboration: medium, not actionable.
        assert without_bio.confidence_band == "medium"
        assert not without_bio.is_actionable

        with_bio = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="GitHub",
            profile_data={"bio": "Senior engineer at GitLab"},
        )
        # Bio mentions the employer ── triangulation closes.
        assert with_bio.is_actionable

    def test_distinctive_handle_outscores_common_handle_same_service(self):
        """All else equal, an uncommon handle should outscore a common
        one. Use the same email, same service, just swap the handle."""
        common = score_handle_attribution(
            email="someone@example.com",
            handle="smith",
            service="GitHub",
        )
        distinctive = score_handle_attribution(
            email="someone@example.com",
            handle="xochitl-vukovic-92",
            service="GitHub",
        )
        assert distinctive.score > common.score

    def test_trusted_service_outscores_low_trust_service(self):
        """Same handle, same email, just swap the service. LinkedIn
        should outscore a generic forum."""
        linkedin = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="LinkedIn",
        )
        unknown = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="RandomForum.example.com",
        )
        assert linkedin.score > unknown.score


# ──────────────────────────────────────────────────────────────────────
# Derivation signal
# ──────────────────────────────────────────────────────────────────────


class TestDerivationSignal:
    def test_exact_local_part_match_maxes_derivation(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="GitHub",  # tier doesn't matter for derivation
        )
        assert result.signals["derivation"] >= 0.9

    def test_stripped_local_part_match_scores_high(self):
        """``jane.doe2@example.com`` carrying year/suffix should give
        ``jane.doe`` a high (but not perfect) derivation."""
        result = score_handle_attribution(
            email="jane.doe2@example.com",
            handle="jane.doe",
            service="GitHub",
        )
        assert result.signals["derivation"] >= 0.7
        assert result.signals["derivation"] < 1.0  # not exact

    def test_concat_form_scores_medium(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="janedoe",
            service="GitHub",
        )
        assert 0.5 <= result.signals["derivation"] <= 0.7

    def test_initial_prefix_pattern_scores_lower(self):
        """``jdoe`` from ``jane.doe`` is a real pattern but ambiguous
        ── there are many j*doe humans."""
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jdoe",
            service="GitHub",
        )
        assert 0.3 <= result.signals["derivation"] <= 0.5

    def test_lone_surname_scores_weak(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="doe",
            service="GitHub",
        )
        # ``doe`` is in tokens, so it gets the lone-component rank.
        assert result.signals["derivation"] <= 0.25

    def test_unrelated_handle_scores_weak(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="xyzzy42",
            service="GitHub",
        )
        # No derivation tie; falls to the name-derived-only baseline.
        assert result.signals["derivation"] <= 0.35

    def test_no_email_falls_to_baseline(self):
        result = score_handle_attribution(
            email=None,
            handle="jane.doe",
            service="GitHub",
        )
        # No anchor → fixed 0.3 baseline.
        assert result.signals["derivation"] == 0.3


# ──────────────────────────────────────────────────────────────────────
# Uniqueness signal
# ──────────────────────────────────────────────────────────────────────


class TestUniquenessSignal:
    def test_admin_is_recognised_as_common(self):
        result = score_handle_attribution(
            email="ops@example.com",
            handle="admin",
            service="GitHub",
        )
        assert result.signals["uniqueness"] <= 0.15

    def test_john_is_recognised_as_common(self):
        result = score_handle_attribution(
            email="someone@example.com",
            handle="john",
            service="GitHub",
        )
        assert result.signals["uniqueness"] <= 0.15

    def test_long_uncommon_handle_scores_max(self):
        """Truly-unique handle: all components are absent from Census +
        SSA bundled data. Phase B's name-frequency integration applies
        a uniqueness penalty for handles whose components ARE in the
        bundled data (even at Tier C); this test deliberately uses
        gibberish to exercise the no-penalty path."""
        result = score_handle_attribution(
            email="someone@example.com",
            handle="zoxqwt-flornicus-9442",
            service="GitHub",
        )
        assert result.signals["uniqueness"] >= 0.9

    def test_recognisable_surname_handle_still_gets_modest_penalty(self):
        """Phase B intentionally penalises handles containing
        bundled-data surnames even from Tier C. ``vukovic`` is a real
        US Census surname (~thousands of bearers), so a handle
        containing it should be penalised vs. a truly-unique handle.

        Expected: ~0.80 uniqueness ── still high, but not maximum."""
        result = score_handle_attribution(
            email="xochitl-vukovic@example.com",
            handle="xochitl-vukovic-1984",
            service="GitHub",
        )
        assert 0.7 <= result.signals["uniqueness"] <= 0.85

    def test_dotted_corp_handle_is_distinctive(self):
        result = score_handle_attribution(
            email="someone@example.com",
            handle="jane.doe.engineer",
            service="GitHub",
        )
        # Not in common list, long enough.
        assert result.signals["uniqueness"] >= 0.9

    def test_common_surname_alone_scores_low(self):
        result = score_handle_attribution(
            email="someone@example.com",
            handle="smith",
            service="GitHub",
        )
        assert result.signals["uniqueness"] <= 0.15

    def test_common_initial_surname_pattern_scores_low(self):
        """``jsmith`` is in the common-handles list ── classic corp
        pattern that matches many humans."""
        result = score_handle_attribution(
            email="someone@example.com",
            handle="jsmith",
            service="GitHub",
        )
        assert result.signals["uniqueness"] <= 0.2


# ──────────────────────────────────────────────────────────────────────
# Service-tier signal
# ──────────────────────────────────────────────────────────────────────


class TestServiceTierSignal:
    def test_linkedin_is_tier_1(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="LinkedIn",
        )
        assert result.signals["service_tier"] == 1.0

    def test_github_is_tier_1(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="GitHub",
        )
        assert result.signals["service_tier"] == 1.0

    def test_reddit_is_tier_2(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="Reddit",
        )
        assert result.signals["service_tier"] == 0.7

    def test_steam_is_tier_3(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="Steam",
        )
        assert result.signals["service_tier"] == 0.4

    def test_dating_site_is_tier_4(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="OkCupid",
        )
        assert result.signals["service_tier"] == 0.2

    def test_unknown_service_gets_neutral_default(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="SomeRandomForum",
        )
        assert result.signals["service_tier"] == 0.5

    def test_service_tier_lookup_is_case_insensitive(self):
        result_a = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="github",
        )
        result_b = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="GITHUB",
        )
        assert result_a.signals["service_tier"] == result_b.signals["service_tier"] == 1.0


# ──────────────────────────────────────────────────────────────────────
# Profile-coherence signal
# ──────────────────────────────────────────────────────────────────────


class TestProfileCoherenceSignal:
    def test_no_profile_data_returns_zero(self):
        result = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="GitHub",
            profile_data=None,
        )
        assert result.signals["profile"] == 0.0

    def test_empty_profile_dict_returns_zero(self):
        result = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="GitHub",
            profile_data={},
        )
        assert result.signals["profile"] == 0.0

    def test_bio_mentioning_email_domain_scores_high(self):
        """The 'gitlab' keyword appearing in the bio is the strongest
        coherence signal short of an explicit cross-link."""
        result = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="GitHub",
            profile_data={"bio": "Senior engineer at GitLab. Opinions my own."},
        )
        # Baseline (0.1) + domain match (0.5) = 0.6
        assert result.signals["profile"] >= 0.5

    def test_harvested_name_match_scores_high(self):
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="GitHub",
            profile_data={"name": "Jane Doe"},
            harvested_names=["Jane Doe"],
        )
        # Baseline + name match (0.4)
        assert result.signals["profile"] >= 0.4

    def test_baseline_for_any_profile_string(self):
        """Even an arbitrary string field signals 'real profile vs
        placeholder' weakly."""
        result = score_handle_attribution(
            email="jane.doe@example.com",
            handle="jane.doe",
            service="GitHub",
            profile_data={"username": "jane.doe"},
        )
        # Just baseline, no specific match.
        assert 0.0 < result.signals["profile"] <= 0.15


# ──────────────────────────────────────────────────────────────────────
# AttributionScore behaviour
# ──────────────────────────────────────────────────────────────────────


class TestAttributionScoreObject:
    def test_score_clamped_to_unit_range(self):
        """Every input combination must produce a score in [0, 1]."""
        # Best-case input.
        best = score_handle_attribution(
            email="xochitl-vukovic@uncommondomain.dev",
            handle="xochitl-vukovic",
            service="LinkedIn",
            profile_data={"bio": "Engineer at uncommondomain"},
            harvested_names=["Xochitl Vukovic"],
        )
        assert 0.0 <= best.score <= 1.0
        # Worst-case input.
        worst = score_handle_attribution(
            email=None,
            handle="admin",
            service="UnknownSite",
            profile_data=None,
        )
        assert 0.0 <= worst.score <= 1.0

    def test_confidence_band_thresholds_consistent(self):
        # Mock a score and check band assignment.
        s = AttributionScore(score=0.9)
        assert s.confidence_band == "high"
        s = AttributionScore(score=0.5)
        assert s.confidence_band == "medium"
        s = AttributionScore(score=0.2)
        assert s.confidence_band == "noise"

    def test_is_actionable_threshold(self):
        assert AttributionScore(score=0.6).is_actionable is True
        assert AttributionScore(score=0.59).is_actionable is False

    def test_rationale_mentions_handle_and_service(self):
        result = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="LinkedIn",
        )
        assert "jane.doe" in result.rationale
        assert "LinkedIn" in result.rationale

    def test_signals_carry_all_four_components(self):
        result = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="GitHub",
        )
        assert set(result.signals.keys()) == {
            "derivation", "uniqueness", "service_tier", "profile",
        }


# ──────────────────────────────────────────────────────────────────────
# filter_actionable convenience
# ──────────────────────────────────────────────────────────────────────


class TestFilterActionable:
    def test_filter_keeps_only_actionable_hits(self):
        hits = [
            {"service": "GitHub", "confidence": 0.85},  # high
            {"service": "Reddit", "confidence": 0.65},  # actionable
            {"service": "Steam", "confidence": 0.45},   # medium but not actionable
            {"service": "Forum", "confidence": 0.20},   # noise
        ]
        filtered = filter_actionable(hits)
        assert len(filtered) == 2
        services = {h["service"] for h in filtered}
        assert services == {"GitHub", "Reddit"}

    def test_filter_handles_missing_confidence_field(self):
        """Hits without a confidence field should be treated as 0.0
        (filtered out) rather than crash."""
        hits = [
            {"service": "A", "confidence": 0.9},
            {"service": "B"},  # no confidence field
        ]
        filtered = filter_actionable(hits)
        assert len(filtered) == 1
        assert filtered[0]["service"] == "A"


# ──────────────────────────────────────────────────────────────────────
# End-to-end scenarios
# ──────────────────────────────────────────────────────────────────────


class TestEndToEndScenarios:
    def test_obvious_attribution_clears_actionable_threshold(self):
        """Exact email-derived handle on a Tier 1 service with a bio
        that mentions the company. Should be high confidence."""
        result = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="LinkedIn",
            profile_data={"bio": "Senior engineer at GitLab"},
            harvested_names=["Jane Doe"],
        )
        assert result.is_actionable
        assert result.confidence_band == "high"

    def test_classic_john_smith_collision_filtered(self):
        """The motivating case: ``smith`` on Reddit, derived from
        ``john.smith@company.com``. Common surname, common handle,
        medium-trust service. Must score as noise."""
        result = score_handle_attribution(
            email="john.smith@company.com",
            handle="smith",
            service="Reddit",
        )
        assert not result.is_actionable
        assert result.confidence_band == "noise"

    def test_distinctive_handle_on_high_trust_passes_even_without_profile(self):
        """When the email + handle + service all line up, profile
        evidence is a bonus, not a requirement."""
        result = score_handle_attribution(
            email="xochitl.vukovic@gitlab.com",
            handle="xochitl.vukovic",
            service="GitHub",
        )
        assert result.is_actionable

    def test_handle_match_on_low_trust_service_alone_is_not_actionable(self):
        """Even an exact handle match shouldn't clear actionable on a
        Tier 4 service ── those services have weak attribution
        semantics regardless of the handle quality."""
        result = score_handle_attribution(
            email="jane.doe@gitlab.com",
            handle="jane.doe",
            service="OkCupid",
        )
        # Should be medium at most, not actionable.
        assert result.score < 0.7
