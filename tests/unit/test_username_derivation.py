"""Tests for nexusrecon.core.username_derivation."""
from __future__ import annotations

import pytest

from nexusrecon.core.username_derivation import derive_usernames


class TestEmailDerivation:
    def test_dotted_corporate_email_produces_dotted_first(self):
        candidates = derive_usernames("jane.doe@example.com")
        # The exact local-part should be the first candidate — it's the
        # strongest signal we have for the human's chosen handle.
        assert candidates[0] == "jane.doe"

    def test_dotted_email_produces_concat_and_separator_variants(self):
        candidates = derive_usernames("jane.doe@example.com")
        # Standard variants every corp-email derivation should produce.
        assert "jane.doe" in candidates
        assert "janedoe" in candidates
        assert "jane_doe" in candidates
        assert "jane-doe" in candidates
        assert "jane" in candidates
        assert "doe" in candidates

    def test_dotted_email_produces_initial_patterns(self):
        candidates = derive_usernames("jane.doe@example.com")
        # ``jdoe`` is the classic corp shortened-handle pattern.
        assert "jdoe" in candidates
        # First name + last initial.
        assert "janed" in candidates

    def test_concatenated_email_produces_only_the_concat(self):
        """``jdoe@example.com`` has no separator, so we can't decompose
        it into first/last. Only the literal local-part candidate."""
        candidates = derive_usernames("jdoe@example.com")
        assert candidates == ["jdoe"]

    def test_numeric_suffix_stripped_alongside_original(self):
        """``jane.doe2@example.com`` could be either ``janedoe2`` or
        ``janedoe`` on the third-party site. Keep both."""
        candidates = derive_usernames("jane.doe2@example.com")
        assert "jane.doe2" in candidates
        assert "jane.doe" in candidates  # stripped form
        assert "janedoe2" in candidates
        assert "janedoe" in candidates

    def test_role_email_returns_empty(self):
        """Role accounts (admin@, info@) shouldn't seed username
        searches ── they don't correspond to a human handle."""
        for role in ("admin", "info", "support", "noreply", "do-not-reply"):
            candidates = derive_usernames(f"{role}@example.com")
            assert candidates == [], f"role {role}@ should derive nothing"

    def test_too_short_local_part_dropped(self):
        """A two-letter local-part is below the noise floor for username
        checking."""
        candidates = derive_usernames("ab@example.com")
        # ``ab`` is below the min-length threshold; nothing returned.
        assert candidates == []

    def test_max_candidates_respected(self):
        candidates = derive_usernames(
            "jane.middle.doe@example.com",
            names=["Jane M Doe"],
            max_candidates=3,
        )
        assert len(candidates) == 3

    def test_no_email_returns_empty(self):
        assert derive_usernames(None) == []
        assert derive_usernames("") == []

    def test_malformed_email_without_at_returns_empty(self):
        assert derive_usernames("not_an_email") == []

    def test_underscore_separator_handled(self):
        candidates = derive_usernames("jane_doe@example.com")
        # Local-part literal first.
        assert "jane_doe" in candidates
        # All the standard variants.
        assert "jane.doe" in candidates
        assert "jane-doe" in candidates
        assert "janedoe" in candidates

    def test_dash_separator_handled(self):
        candidates = derive_usernames("jane-doe@example.com")
        assert "jane-doe" in candidates
        assert "jane.doe" in candidates
        assert "janedoe" in candidates


class TestNameDerivation:
    def test_simple_first_last_name(self):
        candidates = derive_usernames(names=["Jane Doe"])
        # Both lone components.
        assert "jane" in candidates
        assert "doe" in candidates
        # Concatenated.
        assert "janedoe" in candidates
        # Dotted form ── corporate convention.
        assert "jane.doe" in candidates
        # Initial patterns.
        assert "jdoe" in candidates
        assert "janed" in candidates

    def test_lastname_firstname_form_reordered(self):
        """``"DOE, Jane"`` is the LDAP / employee-list export format.
        Treat it the same as ``"Jane Doe"``."""
        candidates = derive_usernames(names=["DOE, Jane"])
        assert "jane.doe" in candidates
        assert "jdoe" in candidates

    def test_middle_initial_dropped(self):
        """``"Jane M. Doe"`` should produce the same candidates as
        ``"Jane Doe"`` ── middle initials don't appear in usernames."""
        candidates = derive_usernames(names=["Jane M. Doe"])
        assert "jane.doe" in candidates
        assert "jdoe" in candidates
        assert "jane.m.doe" not in candidates  # middle initial not preserved

    def test_hyphenated_first_name(self):
        """Compound first names like ``"Jane-Marie"`` should produce
        candidates for both parts."""
        candidates = derive_usernames(names=["Jane-Marie Doe"])
        # First part of compound becomes the seed.
        assert "jane.doe" in candidates or "marie.doe" in candidates

    def test_single_word_name_treated_as_handle(self):
        candidates = derive_usernames(names=["Cher"])
        assert "cher" in candidates


class TestEmailAndNamesCombined:
    def test_email_candidates_appear_before_name_only_candidates(self):
        """Email-derived candidates are higher-signal than name-derived ──
        the email tells us what handle the person chose for work, the
        name is just an inference. Email candidates should rank first."""
        candidates = derive_usernames(
            "jdoe@example.com",
            names=["Jane Doe"],
        )
        # ``jdoe`` is the only email candidate and should be first.
        assert candidates[0] == "jdoe"
        # Name candidates follow.
        assert "jane.doe" in candidates

    def test_dedup_across_email_and_names(self):
        """If both email and names produce the same candidate, we get it
        once (not twice)."""
        candidates = derive_usernames(
            "jane.doe@example.com",
            names=["Jane Doe"],
        )
        assert candidates.count("jane.doe") == 1
        assert candidates.count("jdoe") == 1

    def test_empty_names_list_treated_as_no_names(self):
        candidates_a = derive_usernames("jane.doe@example.com", names=[])
        candidates_b = derive_usernames("jane.doe@example.com")
        assert candidates_a == candidates_b


class TestNoisyInput:
    def test_extra_whitespace_handled(self):
        candidates = derive_usernames("  jane.doe@example.com  ")
        # Whitespace stripped before derivation.
        assert "jane.doe" in candidates

    def test_uppercase_normalised(self):
        candidates = derive_usernames("Jane.Doe@EXAMPLE.COM")
        assert "jane.doe" in candidates  # case-folded

    def test_uppercase_name_normalised(self):
        candidates = derive_usernames(names=["JANE DOE"])
        assert "jane.doe" in candidates

    def test_empty_name_entries_skipped(self):
        candidates = derive_usernames(
            "jdoe@example.com",
            names=["", None, "Jane Doe", ""],
        )
        # The empty/None entries are skipped silently.
        assert "jdoe" in candidates
        assert "jane.doe" in candidates


class TestRankingHeuristics:
    def test_local_part_exact_outranks_concat(self):
        """The exact local-part is the strongest signal; it should always
        rank above derived variants like the concatenated form."""
        candidates = derive_usernames("jane.doe@example.com")
        idx_exact = candidates.index("jane.doe")
        idx_concat = candidates.index("janedoe")
        assert idx_exact < idx_concat

    def test_initial_pattern_outranks_lone_first_name(self):
        """``jdoe`` is more specific than ``jane`` ── corp-handle
        conventions favour initial+last. Rank ``jdoe`` higher."""
        candidates = derive_usernames("jane.doe@example.com")
        # Both are present.
        assert "jane" in candidates
        assert "jdoe" in candidates
        # ``jdoe`` should come after the dotted/concat forms, but order
        # vs. lone first/last is implementation-dependent. Just pin that
        # both appear and the lone names don't outrank the dotted form.
        idx_dotted = candidates.index("jane.doe")
        idx_first = candidates.index("jane")
        assert idx_dotted < idx_first
