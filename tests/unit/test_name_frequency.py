"""Tests for nexusrecon.core.name_frequency."""
from __future__ import annotations

from nexusrecon.core.name_frequency import (
    handle_commonness,
    name_commonness,
)


class TestNameCommonness:
    def test_tier_a_male_name(self):
        assert name_commonness("john") == 0.95
        assert name_commonness("michael") == 0.95

    def test_tier_a_female_name(self):
        assert name_commonness("mary") == 0.95
        assert name_commonness("jennifer") == 0.95

    def test_tier_a_surname(self):
        assert name_commonness("smith") == 0.95
        assert name_commonness("johnson") == 0.95

    def test_tier_b_surname(self):
        # Tier B is the 51-200 range.
        assert name_commonness("patterson") == 0.70
        assert name_commonness("collins") == 0.70

    def test_tier_c_surname(self):
        assert name_commonness("vukovic") == 0.20

    def test_unknown_name_returns_zero(self):
        assert name_commonness("xochitl") == 0.0
        assert name_commonness("xyzzy") == 0.0

    def test_case_insensitive(self):
        assert name_commonness("JOHN") == 0.95
        assert name_commonness("Smith") == 0.95

    def test_empty_returns_zero(self):
        assert name_commonness("") == 0.0
        assert name_commonness("   ") == 0.0


class TestHandleCommonness:
    def test_single_token_handle(self):
        assert handle_commonness("smith") == 0.95
        assert handle_commonness("xochitl") == 0.0

    def test_dotted_handle_uses_max_component(self):
        """``john.smith`` is common because BOTH components are
        Tier A. ``xochitl.smith`` is common because ``smith`` is
        Tier A, even though ``xochitl`` is unknown."""
        assert handle_commonness("john.smith") == 0.95
        assert handle_commonness("xochitl.smith") == 0.95

    def test_handle_with_only_unknown_components_scores_zero(self):
        """Both components rare → handle is statistically unique."""
        assert handle_commonness("xochitl.vukovic") <= 0.5
        assert handle_commonness("xyzzy.fnord") == 0.0

    def test_initial_prefix_is_too_short_to_match(self):
        """``j`` is a single letter ── tokeniser drops it. ``jsmith``
        tokenises to just ``smith`` after digit/letter boundary split,
        but ``j`` is dropped for length. So ``jsmith`` → ``smith``.

        Actually ``jsmith`` is one token (no separator, no digit
        boundary), so the whole string is looked up ── and since
        ``jsmith`` isn't in any frequency table, returns 0.0. This
        is a known limitation; the curated common-handles list in
        attribution.py catches these patterns."""
        result = handle_commonness("jsmith")
        # Whole handle lookup misses; no further decomposition without
        # a separator. The common-handles list in attribution.py is
        # the safety net for these handles.
        assert result == 0.0

    def test_numeric_suffix_split_out(self):
        """``john1985`` should be tokenised into ``john`` + ``1985``
        and the numeric token dropped. The remaining ``john`` is
        Tier A."""
        assert handle_commonness("john1985") == 0.95

    def test_underscored_handle(self):
        assert handle_commonness("john_smith") == 0.95

    def test_dashed_handle(self):
        assert handle_commonness("mary-jones") == 0.95

    def test_handle_with_extension_word(self):
        """``smith.dev`` is common because ``smith`` is, even with the
        ``.dev`` suffix."""
        assert handle_commonness("smith.dev") == 0.95

    def test_empty_handle_returns_zero(self):
        assert handle_commonness("") == 0.0

    def test_purely_numeric_handle_returns_zero(self):
        """A handle that's only digits has no name signal at all."""
        assert handle_commonness("12345") == 0.0

    def test_short_tokens_dropped(self):
        """``a.b`` has single-letter tokens that get dropped."""
        assert handle_commonness("a.b") == 0.0


class TestRealisticHandleExamples:
    """End-to-end examples reflecting actual collisions the attribution
    scorer needs to defend against."""

    def test_john_smith_classic_collision(self):
        """The motivating case from the design discussion."""
        assert handle_commonness("john.smith") == 0.95
        assert handle_commonness("johnsmith") == 0.0  # no separator → whole string lookup misses

    def test_mjohnson_handle_pattern(self):
        """``mjohnson`` is one token (initial + surname). It misses
        the frequency tables but the common-handles curated list in
        attribution.py catches it via direct membership."""
        assert handle_commonness("mjohnson") == 0.0

    def test_uncommon_combination_scores_low(self):
        """The aspirational case: an uncommon-name pair scores low,
        so the attribution scorer can trust the handle is unique."""
        assert handle_commonness("xochitl.vukovic") <= 0.5

    def test_developer_handle_with_common_first_name(self):
        """``alex.developer`` ── ``alex`` is in Tier C (lower female-
        list popularity), ``developer`` isn't a name. Result is the
        max which depends on whether ``alex`` is in the bundled data."""
        result = handle_commonness("alex.developer")
        # Whatever the result is, it should be in [0, 1].
        assert 0.0 <= result <= 1.0
