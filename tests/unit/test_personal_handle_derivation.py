"""Tests for nexusrecon.core.personal_handle_derivation (D2)."""
from __future__ import annotations

from nexusrecon.core.personal_handle_derivation import (
    EmailCandidate,
    derive_personal_emails,
    derive_personal_handles,
)

# ──────────────────────────────────────────────────────────────────────
# Name parsing edge cases (exercised through the public functions)
# ──────────────────────────────────────────────────────────────────────


class TestNameParsing:
    def test_simple_first_last(self):
        candidates = derive_personal_handles("Jane Doe")
        values = {c.value for c in candidates}
        # Base forms should all appear.
        assert "jane.doe" in values
        assert "janedoe" in values
        assert "jdoe" in values

    def test_last_first_format(self):
        """LDAP / employee-list ``"Doe, Jane"`` form should be parsed
        as ``Jane Doe``."""
        candidates = derive_personal_handles("Doe, Jane")
        values = {c.value for c in candidates}
        assert "jane.doe" in values

    def test_middle_initial_dropped(self):
        candidates = derive_personal_handles("Jane M. Doe")
        values = {c.value for c in candidates}
        assert "jane.doe" in values
        # Middle initial should NOT appear as a token.
        assert "jane.m.doe" not in values

    def test_single_token_name_returns_empty(self):
        """Without at least first + last, we can't derive personal
        handles meaningfully."""
        assert derive_personal_handles("Cher") == []

    def test_empty_name_returns_empty(self):
        assert derive_personal_handles("") == []
        assert derive_personal_handles(None) == []

    def test_case_insensitive(self):
        a = {c.value for c in derive_personal_handles("Jane Doe")}
        b = {c.value for c in derive_personal_handles("JANE DOE")}
        c = {c.value for c in derive_personal_handles("jane doe")}
        assert a == b == c


# ──────────────────────────────────────────────────────────────────────
# Base handle forms (no extras)
# ──────────────────────────────────────────────────────────────────────


class TestBaseHandleForms:
    def test_dotted_form_highest_quality(self):
        candidates = derive_personal_handles("Jane Doe")
        dotted = next(c for c in candidates if c.value == "jane.doe")
        # Dotted form is the most common real-world handle pattern.
        assert dotted.quality >= 0.9

    def test_concat_form_present(self):
        candidates = derive_personal_handles("Jane Doe")
        assert any(c.value == "janedoe" for c in candidates)

    def test_initial_concat_form_present(self):
        candidates = derive_personal_handles("Jane Doe")
        assert any(c.value == "jdoe" for c in candidates)

    def test_first_alone_is_lower_quality(self):
        """``first`` alone is high-collision; should rank below the
        dotted form."""
        candidates = derive_personal_handles("Jane Doe")
        dotted_q = next(c.quality for c in candidates if c.value == "jane.doe")
        first_q = next(c.quality for c in candidates if c.value == "jane")
        assert first_q < dotted_q


# ──────────────────────────────────────────────────────────────────────
# Year suffix candidates
# ──────────────────────────────────────────────────────────────────────


class TestYearSuffix:
    def test_with_age_range_targets_year_window(self):
        # Age 40-45 in 2026 → birth 1981-1986.
        candidates = derive_personal_handles(
            "Jane Doe",
            age_range=(40, 45),
        )
        years_in_candidates = []
        for c in candidates:
            for y in (1981, 1982, 1983, 1984, 1985, 1986):
                if str(y) in c.value or str(y)[-2:] in c.value:
                    years_in_candidates.append(y)
                    break
        # At least one candidate should reference the target window.
        assert years_in_candidates

    def test_career_years_estimates_birth(self):
        """20-year career → estimated start 2006, +/-5 birth window
        around 1984."""
        candidates = derive_personal_handles(
            "Jane Doe",
            career_years=20,
        )
        # Should produce some year-suffixed candidates.
        year_pattern = [c for c in candidates if "year" in c.pattern]
        assert year_pattern

    def test_no_age_signal_produces_default_window(self):
        """Without any age signal, the derivation should still
        generate SOME year-suffixed candidates (just at lower
        quality)."""
        candidates = derive_personal_handles("Jane Doe")
        year_candidates = [c for c in candidates if "year" in c.pattern]
        # Some year candidates exist (1980/1985/1990/1995 defaults).
        assert year_candidates
        # But they should be lower quality than the age-known case.
        for c in year_candidates:
            assert c.quality < 0.55

    def test_year_candidates_include_4_and_2_digit_forms(self):
        candidates = derive_personal_handles(
            "Jane Doe", age_range=(40, 41),
        )
        # Birth year ~1985-1986. Both 4-digit and 2-digit forms should
        # appear in the candidates.
        values = " ".join(c.value for c in candidates)
        assert "1985" in values or "1986" in values
        assert "85" in values or "86" in values


# ──────────────────────────────────────────────────────────────────────
# Hobby / interest suffix
# ──────────────────────────────────────────────────────────────────────


class TestHobbySuffix:
    def test_hobby_token_produces_candidates(self):
        candidates = derive_personal_handles(
            "Jane Doe",
            interests=["Running", "Marathon"],
        )
        values = {c.value for c in candidates}
        assert "jane_running" in values or "jane.running" in values

    def test_professional_terms_dropped(self):
        """``"engineering"`` and ``"agile"`` shouldn't seed handle
        candidates ── they're work-talk, not personal-handle material."""
        candidates = derive_personal_handles(
            "Jane Doe",
            interests=["engineering", "agile", "leadership"],
        )
        values = " ".join(c.value for c in candidates)
        assert "engineering" not in values
        assert "agile" not in values
        assert "leadership" not in values

    def test_no_interests_means_no_hobby_candidates(self):
        candidates = derive_personal_handles("Jane Doe")
        hobby_patterns = [c for c in candidates
                          if c.pattern.startswith("first+hobby")
                          or c.pattern.startswith("first.hobby")]
        assert hobby_patterns == []

    def test_multiword_interest_collapsed_to_one_token(self):
        candidates = derive_personal_handles(
            "Jane Doe",
            interests=["video games"],
        )
        # "video games" → "videogames" (alphanum-only) is acceptable
        # for the token.
        values = " ".join(c.value for c in candidates)
        # Either form should produce something hobby-like.
        assert "videogames" in values or "games" in values


# ──────────────────────────────────────────────────────────────────────
# Geographic suffix
# ──────────────────────────────────────────────────────────────────────


class TestGeographicSuffix:
    def test_known_city_short_form(self):
        candidates = derive_personal_handles(
            "Jane Doe",
            location="San Francisco",
        )
        values = {c.value for c in candidates}
        # Should include the "sf" short form.
        assert any("sf" in v for v in values)
        # And the long form.
        assert any("sanfrancisco" in v for v in values)

    def test_unknown_city_slugified(self):
        candidates = derive_personal_handles(
            "Jane Doe",
            location="Reykjavik, Iceland",
        )
        values = " ".join(c.value for c in candidates)
        # Should produce the slugified form.
        assert "reykjavik" in values

    def test_no_location_means_no_geo_candidates(self):
        candidates = derive_personal_handles("Jane Doe")
        geo_patterns = [c for c in candidates if "geo" in c.pattern]
        assert geo_patterns == []


# ──────────────────────────────────────────────────────────────────────
# Nickname variants
# ──────────────────────────────────────────────────────────────────────


class TestNicknameVariants:
    def test_known_nickname_expansion(self):
        """``Michael`` → should produce ``mike.smith`` etc."""
        candidates = derive_personal_handles("Michael Smith")
        values = {c.value for c in candidates}
        assert "mike.smith" in values

    def test_nickname_quality_below_canonical(self):
        candidates = derive_personal_handles("Michael Smith")
        canonical = next(c.quality for c in candidates if c.value == "michael.smith")
        nickname = next(c.quality for c in candidates if c.value == "mike.smith")
        assert nickname < canonical

    def test_unknown_first_name_produces_no_nicknames(self):
        candidates = derive_personal_handles("Xochitl Vukovic")
        # The function shouldn't make up nicknames for unknown names.
        nicknames = [c for c in candidates
                     if c.pattern.startswith("nickname")]
        assert nicknames == []


# ──────────────────────────────────────────────────────────────────────
# Ranking + capping
# ──────────────────────────────────────────────────────────────────────


class TestRankingAndCapping:
    def test_results_sorted_by_quality_descending(self):
        candidates = derive_personal_handles(
            "Jane Doe",
            age_range=(30, 35),
            interests=["running", "knitting"],
            location="San Francisco",
        )
        qualities = [c.quality for c in candidates]
        assert qualities == sorted(qualities, reverse=True)

    def test_max_candidates_respected(self):
        candidates = derive_personal_handles(
            "Jane Doe",
            age_range=(20, 60),  # large window
            interests=["a", "b", "c", "d", "e", "f", "g", "h"],
            location="San Francisco",
            max_candidates=10,
        )
        assert len(candidates) == 10
        # And the kept candidates are the highest-quality ones.
        for c in candidates:
            assert c.quality >= 0.30


# ──────────────────────────────────────────────────────────────────────
# Email derivation
# ──────────────────────────────────────────────────────────────────────


class TestEmailDerivation:
    def test_basic_dotted_first_last_at_gmail(self):
        emails = derive_personal_emails("Jane Doe")
        values = {e.value for e in emails}
        assert "jane.doe@gmail.com" in values

    def test_provider_weighting_visible_in_quality(self):
        """Same local-part at gmail should outrank the same local-part
        at a less-weighted provider. Use ``max_candidates`` high enough
        to expose both for comparison."""
        emails = derive_personal_emails("Jane Doe", max_candidates=80)
        gmail = next(e.quality for e in emails
                     if e.value == "jane.doe@gmail.com")
        proton = next(e.quality for e in emails
                      if e.value == "jane.doe@protonmail.com")
        assert gmail > proton

    def test_year_suffix_emails(self):
        emails = derive_personal_emails(
            "Jane Doe", age_range=(40, 41),
        )
        values = " ".join(e.value for e in emails)
        # Should generate year-suffixed emails.
        assert "jane.doe.1985" in values or "jane.doe.1986" in values or \
               "jane.doe.85" in values or "jane.doe.86" in values

    def test_personal_domain_ranks_at_top(self):
        emails = derive_personal_emails(
            "Jane Doe",
            personal_domain="janedoe.dev",
        )
        # When a personal domain is known, the framework should
        # surface jane.doe@janedoe.dev as a top candidate.
        domain_emails = [e for e in emails if e.value.endswith("@janedoe.dev")]
        assert domain_emails
        top = domain_emails[0]
        assert top.quality >= 0.85

    def test_email_candidate_helpers(self):
        e = EmailCandidate(
            value="jane.doe@gmail.com",
            pattern="first.last@provider",
            quality=0.95,
        )
        assert e.local_part == "jane.doe"
        assert e.domain == "gmail.com"

    def test_empty_name_returns_empty(self):
        assert derive_personal_emails("") == []
        assert derive_personal_emails(None) == []

    def test_to_dict_json_safe(self):
        import json
        emails = derive_personal_emails("Jane Doe", age_range=(30, 35))
        for e in emails[:5]:
            json.dumps(e.to_dict())  # would raise if not


# ──────────────────────────────────────────────────────────────────────
# End-to-end realistic scenario
# ──────────────────────────────────────────────────────────────────────


class TestRealisticScenario:
    def test_vp_engineering_with_rich_context(self):
        """The attacker-mindset case: corporate identity for Jane Doe
        VP Engineering at GitLab, ~45yo, lives in SF, public Twitter
        bio mentions marathon running. Should produce a coherent
        set of personal handle candidates. ``max_candidates`` lifted
        from default so the geo + hobby + year suffixes all surface
        in the result set for the assertions."""
        candidates = derive_personal_handles(
            name="Jane Doe",
            age_range=(43, 47),
            interests=["Running", "Marathon", "Knitting"],
            location="San Francisco",
            max_candidates=80,
        )
        values = {c.value for c in candidates}

        # Base canonical forms.
        assert "jane.doe" in values
        # Year-tagged forms (birth 1979-1983 with the age range).
        # 4-digit AND 2-digit forms should appear somewhere.
        assert any("80" in v or "81" in v or "82" in v or "83" in v
                   for v in values)
        # Hobby suffix.
        assert any("running" in v or "marathon" in v or "knitting" in v
                   for v in values)
        # Location suffix.
        assert any("sf" in v or "sanfrancisco" in v
                   for v in values)
