"""Tests for nexusrecon.core.linked_accounts."""
from __future__ import annotations

from nexusrecon.core.linked_accounts import (
    LinkedAccount,
    cross_reference_with_hits,
    extract_linked_accounts,
)


# ──────────────────────────────────────────────────────────────────────
# URL-based extraction
# ──────────────────────────────────────────────────────────────────────


class TestURLPatternExtraction:
    def test_github_url_in_bio(self):
        """GitHub usernames are alphanumeric + single hyphens, max 39
        chars. Dots are NOT permitted (GitHub policy)."""
        refs = extract_linked_accounts(
            source_service="GitLab",
            profile_text="See my code at github.com/jane-doe",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("GitHub", "jane-doe") in services

    def test_twitter_url_in_bio(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="Find me on twitter.com/janedoe",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("Twitter", "janedoe") in services

    def test_x_dot_com_url_treated_as_twitter(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="x.com/janedoe",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("Twitter", "janedoe") in services

    def test_mastodon_url_with_host(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="Posts at hachyderm.io/@jane",
        )
        # Should be detected as Mastodon.
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("Mastodon", "jane") in services

    def test_linkedin_in_url(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="linkedin.com/in/jane-doe-123",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("LinkedIn", "jane-doe-123") in services

    def test_bluesky_url(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="bsky.app/profile/jane.bsky.social",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("Bluesky", "jane.bsky.social") in services

    def test_multiple_services_in_one_bio(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text=(
                "Twitter: twitter.com/janedoe "
                "Mastodon: hachyderm.io/@jane "
                "LinkedIn: linkedin.com/in/jane-doe"
            ),
        )
        target_services = {r.target_service for r in refs}
        # At minimum Twitter, Mastodon, LinkedIn should all be detected.
        assert "Twitter" in target_services
        assert "Mastodon" in target_services
        assert "LinkedIn" in target_services

    def test_self_reference_skipped(self):
        """A GitHub bio mentioning github.com/handle is just the
        canonical self-URL, not a cross-reference. Should be skipped."""
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="My profile: github.com/janedoe",
        )
        github_refs = [r for r in refs if r.target_service == "GitHub"]
        assert len(github_refs) == 0


# ──────────────────────────────────────────────────────────────────────
# Labelled-mention extraction (no URL)
# ──────────────────────────────────────────────────────────────────────


class TestLabelledMentionExtraction:
    def test_twitter_colon_handle(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="Twitter: @janedoe",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("Twitter", "janedoe") in services

    def test_github_label_with_handle(self):
        refs = extract_linked_accounts(
            source_service="LinkedIn",
            profile_text="GitHub: jdoe",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("GitHub", "jdoe") in services

    def test_prose_false_positives_filtered(self):
        """``Twitter: best app ever`` shouldn't extract ``best`` as a
        Twitter handle. The prose-word filter catches these."""
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="Twitter: best app",
        )
        # Should not contain target_handle="best".
        twitter_refs = [r for r in refs if r.target_service == "Twitter"]
        for ref in twitter_refs:
            assert ref.target_handle.lower() != "best"


# ──────────────────────────────────────────────────────────────────────
# Mastodon @user@instance format
# ──────────────────────────────────────────────────────────────────────


class TestMastodonAtAtFormat:
    def test_canonical_at_at_format(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="Contact: @jane@hachyderm.io",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("Mastodon", "jane") in services


# ──────────────────────────────────────────────────────────────────────
# Deduplication
# ──────────────────────────────────────────────────────────────────────


class TestDedup:
    def test_same_target_only_emitted_once(self):
        """If both a URL and a labelled mention point to the same
        target, only one LinkedAccount should be emitted."""
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="twitter.com/janedoe ── also Twitter: @janedoe",
        )
        twitter_refs = [r for r in refs if r.target_service == "Twitter"]
        # One per unique (service, handle) pair.
        assert len(twitter_refs) == 1

    def test_dedup_is_case_insensitive(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="twitter.com/JaneDoe and twitter.com/janedoe",
        )
        twitter_refs = [r for r in refs if r.target_service == "Twitter"]
        assert len(twitter_refs) == 1


# ──────────────────────────────────────────────────────────────────────
# Blog URL handling
# ──────────────────────────────────────────────────────────────────────


class TestBlogUrl:
    def test_blog_url_alone_extracts(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="",
            profile_blog="https://twitter.com/janedoe",
        )
        services = {(r.target_service, r.target_handle) for r in refs}
        assert ("Twitter", "janedoe") in services

    def test_bio_and_blog_both_scanned(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="Find me: linkedin.com/in/jane",
            profile_blog="https://hachyderm.io/@jane",
        )
        services = {r.target_service for r in refs}
        assert "LinkedIn" in services
        assert "Mastodon" in services


# ──────────────────────────────────────────────────────────────────────
# Cross-reference matching against maigret hits
# ──────────────────────────────────────────────────────────────────────


class TestCrossReferenceWithHits:
    def test_match_marks_hit(self):
        hits = [
            {"service": "Twitter", "username": "janedoe", "url": "..."},
            {"service": "Reddit", "username": "jdoe", "url": "..."},
        ]
        refs = [
            LinkedAccount(
                source_service="GitHub",
                target_service="Twitter",
                target_handle="janedoe",
                target_url="https://twitter.com/janedoe",
                raw_match="twitter.com/janedoe",
            ),
        ]
        result = cross_reference_with_hits(refs, hits)
        twitter_hit = next(h for h in result if h["service"] == "Twitter")
        assert "cross_referenced_from" in twitter_hit
        assert twitter_hit["cross_referenced_from"][0]["source_service"] == "GitHub"
        # Reddit hit should NOT be flagged.
        reddit_hit = next(h for h in result if h["service"] == "Reddit")
        assert "cross_referenced_from" not in reddit_hit

    def test_no_match_no_flag(self):
        """An extracted reference to ``Twitter:fakehandle`` with no
        corresponding maigret hit produces no flag (and definitely
        doesn't crash)."""
        hits = [{"service": "Twitter", "username": "realhandle"}]
        refs = [
            LinkedAccount(
                source_service="GitHub",
                target_service="Twitter",
                target_handle="fakehandle",
                target_url="",
                raw_match="Twitter: @fakehandle",
            ),
        ]
        result = cross_reference_with_hits(refs, hits)
        for h in result:
            assert "cross_referenced_from" not in h

    def test_case_insensitive_match(self):
        hits = [{"service": "Twitter", "username": "JaneDoe", "url": ""}]
        refs = [
            LinkedAccount(
                source_service="GitHub",
                target_service="Twitter",
                target_handle="janedoe",
                target_url="",
                raw_match="@janedoe",
            ),
        ]
        result = cross_reference_with_hits(refs, hits)
        assert "cross_referenced_from" in result[0]


# ──────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_input_returns_empty_list(self):
        assert extract_linked_accounts("GitHub", "") == []
        assert extract_linked_accounts("GitHub", "", "") == []

    def test_text_with_no_references_returns_empty(self):
        refs = extract_linked_accounts(
            source_service="GitHub",
            profile_text="Just a normal bio with no social links.",
        )
        assert refs == []

    def test_linked_account_to_dict_round_trips_fields(self):
        la = LinkedAccount(
            source_service="GitHub",
            target_service="Twitter",
            target_handle="x",
            target_url="https://twitter.com/x",
            raw_match="twitter.com/x",
        )
        d = la.to_dict()
        assert d["source_service"] == "GitHub"
        assert d["target_service"] == "Twitter"
        assert d["target_handle"] == "x"
        assert d["target_url"] == "https://twitter.com/x"
        assert d["raw_match"] == "twitter.com/x"
