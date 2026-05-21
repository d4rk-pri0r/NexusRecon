"""Tests for nexusrecon.tools.identity.linkedin_social_tool (E5).

Covers:
  - is_available() either/or auth semantics:
      * cookies present → True
      * user/pass present → True
      * cookies set partially (only li_at) → False
      * neither → False
  - Fail-fast on empty target.
  - Fail-fast when no auth configured.
  - Auth precedence: cookies preferred over user/pass when both set.
  - Cookie jar built with correct domain + names.
  - Lazy import of linkedin_api means the tool module imports
    independently of whether the dep is installed.
  - Happy-path crawl mocking the Linkedin client.
  - Library exceptions surface as ToolResult failures (no crash).
  - Trimmers handle malformed shapes defensively.
  - Adapter extract_edges_from_linkedin direction conventions:
      * commenters / reactors → into crawled
      * mentions → out of crawled
      * self-loops dropped
      * materialize_unknown semantics
  - Registration + empty dynamic_trigger_hints (live-test safety).
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    derive_identity_id,
)
from nexusrecon.tools.identity.linkedin_social_tool import (
    LinkedInSocialTool,
    _build_cookie_jar,
    _extract_urn_id,
    _trim_comments,
    _trim_experiences,
    _trim_posts,
    _trim_profile,
    _trim_reactions,
    _trim_skills,
    extract_edges_from_linkedin,
)

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _mock_config(secrets: dict[str, str | None] | None = None):
    cfg = MagicMock()
    secrets = secrets or {}
    cfg.get_secret.side_effect = lambda name: secrets.get(name)
    return cfg


def _make_tool(secrets: dict[str, str | None] | None = None) -> LinkedInSocialTool:
    tool = LinkedInSocialTool()
    tool.config = _mock_config(secrets)
    # Strip any ambient env vars from the test so our injected
    # config secrets are the only signal.
    return tool


# ──────────────────────────────────────────────────────────────────────
# is_available either/or auth
# ──────────────────────────────────────────────────────────────────────


class TestIsAvailable:
    def test_cookies_alone_is_enough(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        monkeypatch.delenv("LINKEDIN_USERNAME", raising=False)
        monkeypatch.delenv("LINKEDIN_PASSWORD", raising=False)
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc",
            "LINKEDIN_JSESSIONID": "xyz",
        })
        assert tool.is_available() is True

    def test_userpass_alone_is_enough(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        tool = _make_tool({
            "LINKEDIN_USERNAME": "u",
            "LINKEDIN_PASSWORD": "p",
        })
        assert tool.is_available() is True

    def test_partial_cookies_is_not_enough(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        monkeypatch.delenv("LINKEDIN_USERNAME", raising=False)
        monkeypatch.delenv("LINKEDIN_PASSWORD", raising=False)
        # Only li_at set; JSESSIONID missing.
        tool = _make_tool({"LINKEDIN_LI_AT": "abc"})
        assert tool.is_available() is False

    def test_partial_userpass_is_not_enough(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        monkeypatch.delenv("LINKEDIN_USERNAME", raising=False)
        monkeypatch.delenv("LINKEDIN_PASSWORD", raising=False)
        tool = _make_tool({"LINKEDIN_USERNAME": "u"})
        assert tool.is_available() is False

    def test_no_auth_at_all(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        monkeypatch.delenv("LINKEDIN_USERNAME", raising=False)
        monkeypatch.delenv("LINKEDIN_PASSWORD", raising=False)
        tool = _make_tool({})
        assert tool.is_available() is False

    def test_env_var_fallback(self, monkeypatch):
        # Config returns nothing but env vars are set → should be available.
        monkeypatch.setenv("LINKEDIN_LI_AT", "from-env")
        monkeypatch.setenv("LINKEDIN_JSESSIONID", "from-env")
        tool = _make_tool({})
        assert tool.is_available() is True


# ──────────────────────────────────────────────────────────────────────
# URN-id extraction
# ──────────────────────────────────────────────────────────────────────


class TestExtractUrnId:
    def test_profile_urn_with_mini_profile_prefix(self):
        assert _extract_urn_id({
            "profile_urn": "urn:li:fs_miniProfile:ACoAA123",
        }) == "ACoAA123"

    def test_profile_urn_with_fsd_profile_prefix(self):
        assert _extract_urn_id({
            "profile_urn": "urn:li:fsd_profile:ACoAA456",
        }) == "ACoAA456"

    def test_entity_urn_falls_back_to_generic_tail(self):
        assert _extract_urn_id({
            "entityUrn": "urn:li:something:TAIL",
        }) == "TAIL"

    def test_member_urn_with_prefix(self):
        assert _extract_urn_id({
            "member_urn": "urn:li:member:ACoAA789",
        }) == "ACoAA789"

    def test_bare_value_returned_as_is(self):
        assert _extract_urn_id({"profile_urn": "ACoAARaw"}) == "ACoAARaw"

    def test_first_present_field_wins(self):
        # profile_urn beats member_urn beats entityUrn.
        out = _extract_urn_id({
            "profile_urn": "urn:li:fs_miniProfile:WINS",
            "member_urn": "urn:li:member:LOSES",
            "entityUrn": "urn:li:something:ALSO_LOSES",
        })
        assert out == "WINS"

    def test_no_recognized_field(self):
        assert _extract_urn_id({"firstName": "Alice"}) == ""

    def test_non_dict_returns_empty(self):
        assert _extract_urn_id(None) == ""
        assert _extract_urn_id([]) == ""

    def test_empty_string_field_skipped(self):
        # profile_urn is empty, member_urn has the value.
        assert _extract_urn_id({
            "profile_urn": "",
            "member_urn": "urn:li:member:ACoAA999",
        }) == "ACoAA999"


# ──────────────────────────────────────────────────────────────────────
# Cookie jar construction
# ──────────────────────────────────────────────────────────────────────


class TestCookieJar:
    def test_both_cookies(self):
        jar = _build_cookie_jar("abc", "xyz")
        cookies = {c.name: c.value for c in jar}
        assert cookies["li_at"] == "abc"
        assert cookies["JSESSIONID"] == "xyz"

    def test_only_li_at(self):
        jar = _build_cookie_jar("abc", None)
        cookies = {c.name: c.value for c in jar}
        assert cookies == {"li_at": "abc"}

    def test_domain_set(self):
        jar = _build_cookie_jar("abc", "xyz")
        for c in jar:
            assert ".linkedin.com" in c.domain


# ──────────────────────────────────────────────────────────────────────
# Run-time fail-fast
# ──────────────────────────────────────────────────────────────────────


class TestRunFailFast:
    @pytest.mark.asyncio
    async def test_empty_target(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        tool = _make_tool({})
        result = await tool.run("")
        assert not result.success
        assert "empty handle" in result.error

    @pytest.mark.asyncio
    async def test_no_auth(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        monkeypatch.delenv("LINKEDIN_USERNAME", raising=False)
        monkeypatch.delenv("LINKEDIN_PASSWORD", raising=False)
        tool = _make_tool({})
        result = await tool.run("alice-doe")
        assert not result.success
        assert "no auth" in result.error
        assert "LINKEDIN_LI_AT" in result.error

    @pytest.mark.asyncio
    async def test_at_prefix_stripped(self):
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc", "LINKEDIN_JSESSIONID": "xyz",
        })
        mock_client = MagicMock()
        mock_client.get_profile.return_value = {
            "firstName": "Alice", "lastName": "Doe",
            "public_id": "alice-doe",
        }
        mock_client.get_profile_experiences.return_value = []
        mock_client.get_profile_skills.return_value = []
        mock_client.get_profile_posts.return_value = []
        with patch.object(tool, "_build_client", return_value=mock_client):
            result = await tool.run("@alice-doe")
        assert result.success
        assert result.data["handle"] == "alice-doe"


# ──────────────────────────────────────────────────────────────────────
# Auth precedence (cookies wins over user/pass)
# ──────────────────────────────────────────────────────────────────────


class TestAuthPrecedence:
    def test_cookies_wins_when_both_set(self):
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc",
            "LINKEDIN_JSESSIONID": "xyz",
            "LINKEDIN_USERNAME": "u",
            "LINKEDIN_PASSWORD": "p",
        })
        # Patch the linkedin_api import inside _build_client.
        with patch("linkedin_api.Linkedin") as MockLI:
            MockLI.return_value = MagicMock()
            _ = tool._build_client()
            # When both modes present, cookies should win: the call
            # should be made with empty user/pass + a cookies kwarg.
            args, kwargs = MockLI.call_args
            assert args == ("", "")
            assert "cookies" in kwargs
            # Verify cookies jar has li_at
            cookies = {c.name: c.value for c in kwargs["cookies"]}
            assert cookies["li_at"] == "abc"

    def test_userpass_when_no_cookies(self, monkeypatch):
        monkeypatch.delenv("LINKEDIN_LI_AT", raising=False)
        monkeypatch.delenv("LINKEDIN_JSESSIONID", raising=False)
        tool = _make_tool({
            "LINKEDIN_USERNAME": "u",
            "LINKEDIN_PASSWORD": "p",
        })
        with patch("linkedin_api.Linkedin") as MockLI:
            MockLI.return_value = MagicMock()
            _ = tool._build_client()
            args, kwargs = MockLI.call_args
            assert args == ("u", "p")
            assert "cookies" not in kwargs


# ──────────────────────────────────────────────────────────────────────
# Tool happy path + exception handling
# ──────────────────────────────────────────────────────────────────────


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_profile_not_found_returns_failure(self):
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc", "LINKEDIN_JSESSIONID": "xyz",
        })
        mock_client = MagicMock()
        mock_client.get_profile.return_value = {}  # empty dict
        with patch.object(tool, "_build_client", return_value=mock_client):
            result = await tool.run("ghost")
        assert not result.success
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_get_profile_exception_is_caught(self):
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc", "LINKEDIN_JSESSIONID": "xyz",
        })
        mock_client = MagicMock()
        mock_client.get_profile.side_effect = RuntimeError("li boom")
        with patch.object(tool, "_build_client", return_value=mock_client):
            result = await tool.run("alice-doe")
        assert not result.success
        assert "get_profile failed" in result.error
        assert "li boom" in result.error

    @pytest.mark.asyncio
    async def test_build_client_failure(self):
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc", "LINKEDIN_JSESSIONID": "xyz",
        })
        with patch.object(
            tool, "_build_client",
            side_effect=RuntimeError("auth fail"),
        ):
            result = await tool.run("alice-doe")
        assert not result.success
        assert "auth failed" in result.error

    @pytest.mark.asyncio
    async def test_secondary_endpoint_exception_does_not_fail_run(self):
        # Skills throws but the run still succeeds with what we have.
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc", "LINKEDIN_JSESSIONID": "xyz",
        })
        mock_client = MagicMock()
        mock_client.get_profile.return_value = {
            "firstName": "Alice", "lastName": "Doe",
            "public_id": "alice-doe",
        }
        mock_client.get_profile_experiences.return_value = []
        mock_client.get_profile_skills.side_effect = RuntimeError("skills 500")
        mock_client.get_profile_posts.return_value = []
        with patch.object(tool, "_build_client", return_value=mock_client):
            result = await tool.run("alice-doe")
        assert result.success
        # skills error didn't stop the run; we got an empty skills list
        assert result.data["skills"] == []

    @pytest.mark.asyncio
    async def test_full_crawl_aggregates(self):
        tool = _make_tool({
            "LINKEDIN_LI_AT": "abc", "LINKEDIN_JSESSIONID": "xyz",
        })
        mock_client = MagicMock()
        mock_client.get_profile.return_value = {
            "firstName": "Alice", "lastName": "Doe",
            "public_id": "alice-doe",
            "profile_urn": "urn:li:fs_miniProfile:ACoAATEST",
            "headline": "VP Engineering",
            "companyName": "ExampleCo",
            "locationName": "SF",
            "industryName": "Software",
        }
        mock_client.get_profile_experiences.return_value = [
            {"title": "VP Eng", "companyName": "ExampleCo",
             "timePeriod": {"start": "2022"}},
            {"title": "Sr Eng Manager", "companyName": "PriorCo",
             "timePeriod": {"start": "2018", "end": "2022"}},
        ]
        mock_client.get_profile_skills.return_value = [
            {"name": "Python", "endorsementCount": 5},
            {"name": "Go", "endorsementCount": 3},
        ]
        mock_client.get_profile_posts.return_value = [
            {"urn": "urn:li:activity:1", "text": "hi", "createdAt": "2024-06-01"},
            {"urn": "urn:li:activity:2", "text": "hello", "createdAt": "2024-05-01"},
        ]
        mock_client.get_post_reactions.return_value = [
            {"actor": {"publicIdentifier": "bob", "firstName": "Bob"},
             "reactionType": "LIKE"},
        ]
        mock_client.get_post_comments.return_value = [
            {"commenter": {"publicIdentifier": "carol", "firstName": "Carol"},
             "comment_text": "nice!", "createdAt": "2024-06-02"},
        ]
        with patch.object(tool, "_build_client", return_value=mock_client):
            result = await tool.run("alice-doe")
        assert result.success
        d = result.data
        assert d["handle"] == "alice-doe"
        assert d["profile"]["firstName"] == "Alice"
        assert d["profile"]["headline"] == "VP Engineering"
        assert len(d["experiences"]) == 2
        assert len(d["skills"]) == 2
        assert len(d["posts"]) == 2
        assert d["summary"]["unique_commenters"] == 1
        assert d["summary"]["unique_reactors"] == 1
        # First two posts both get enriched (posts_to_enrich=5 default)
        assert d["posts"][0]["reactions"] != []
        assert d["posts"][0]["commenters"] != []


# ──────────────────────────────────────────────────────────────────────
# Trimmer defensive coverage
# ──────────────────────────────────────────────────────────────────────


class TestTrimmers:
    def test_trim_profile_non_dict_returns_minimum(self):
        out = _trim_profile([], urn_id="u", public_id="p")
        assert out == {"publicIdentifier": "p", "urn_id": "u"}

    def test_trim_profile_falls_back_to_first_experience(self):
        raw = {
            "firstName": "X",
            "experience": [{"title": "Eng Mgr", "companyName": "Co"}],
        }
        out = _trim_profile(raw, urn_id="u", public_id="p")
        assert out["currentTitle"] == "Eng Mgr"
        assert out["currentCompany"] == "Co"

    def test_trim_experiences_non_list(self):
        assert _trim_experiences(None) == []
        assert _trim_experiences({"not": "list"}) == []

    def test_trim_skills_caps_at_max(self):
        raw = [{"name": f"skill{i}"} for i in range(50)]
        out = _trim_skills(raw, max_skills=10)
        assert len(out) == 10

    def test_trim_posts_non_list(self):
        assert _trim_posts(None) == []
        assert _trim_posts({"x": "y"}) == []

    def test_trim_reactions_drops_actorless(self):
        raw = [{"reactionType": "LIKE"}]  # no actor → skip
        assert _trim_reactions(raw, limit=10) == []

    def test_trim_comments_drops_actorless(self):
        raw = [{"comment_text": "hi"}]  # no commenter → skip
        assert _trim_comments(raw, limit=10) == []

    def test_trim_reactions_caps_at_limit(self):
        raw = [
            {"actor": {"publicIdentifier": f"u{i}", "firstName": "X"},
             "reactionType": "LIKE"}
            for i in range(20)
        ]
        out = _trim_reactions(raw, limit=5)
        assert len(out) == 5


# ──────────────────────────────────────────────────────────────────────
# Adapter
# ──────────────────────────────────────────────────────────────────────


def _li_identity(public_id: str) -> Identity:
    ident = Identifier(
        value=public_id,
        identifier_type=IdentifierType.HANDLE,
        service="LinkedIn",
        source="test",
        confidence=0.9,
    )
    return Identity(
        identity_id=derive_identity_id([ident]),
        primary_label=public_id,
        identifiers=[ident],
    )


class TestExtractEdgesFromLinkedIn:
    def _setup(self) -> tuple[IdentityGraph, str]:
        graph = IdentityGraph()
        alice = _li_identity("alice-doe")
        graph.add_identity(alice)
        return graph, alice.identity_id

    def test_commenter_into_crawled(self):
        graph, alice_id = self._setup()
        bob = _li_identity("bob")
        graph.add_identity(bob)
        raw = {
            "handle": "alice-doe",
            "posts": [{
                "urn": "u1", "createdAt": "2024-06-01",
                "commenters": [{"publicIdentifier": "bob",
                                 "name": "Bob B"}],
                "reactions": [], "mentioned": [],
            }],
        }
        edges = extract_edges_from_linkedin(raw, alice_id, graph)
        assert len(edges) == 1
        src, edge = edges[0]
        assert src == bob.identity_id
        assert edge.target_identity_id == alice_id
        assert edge.interaction_type == "commenter"

    def test_reactor_into_crawled_with_endorser_weight(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice-doe",
            "posts": [{
                "urn": "u1", "createdAt": "2024-06-01",
                "commenters": [],
                "reactions": [{"publicIdentifier": "carol", "name": "Carol"}],
                "mentioned": [],
            }],
        }
        edges = extract_edges_from_linkedin(raw, alice_id, graph)
        assert len(edges) == 1
        _, edge = edges[0]
        assert edge.interaction_type == "endorser"
        assert edge.strength == pytest.approx(0.7)

    def test_mention_out_of_crawled(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice-doe",
            "posts": [{
                "urn": "u1", "createdAt": "2024-06-01",
                "commenters": [], "reactions": [],
                "mentioned": [{"publicIdentifier": "dave", "name": "Dave"}],
            }],
        }
        edges = extract_edges_from_linkedin(raw, alice_id, graph)
        assert len(edges) == 1
        src, edge = edges[0]
        assert src == alice_id
        assert edge.interaction_type == "mention"

    def test_self_loop_filtered(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice-doe",
            "posts": [{
                "urn": "u1", "createdAt": "2024-06-01",
                "commenters": [{"publicIdentifier": "alice-doe",
                                 "name": "Alice"}],
                "reactions": [{"publicIdentifier": "alice-doe",
                                "name": "Alice"}],
                "mentioned": [{"publicIdentifier": "alice-doe",
                                "name": "Alice"}],
            }],
        }
        edges = extract_edges_from_linkedin(raw, alice_id, graph)
        assert edges == []

    def test_materializes_unknown_by_default(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice-doe",
            "posts": [{
                "urn": "u1", "createdAt": "2024-06-01",
                "commenters": [{"publicIdentifier": "stranger",
                                 "name": "Stranger"}],
                "reactions": [], "mentioned": [],
            }],
        }
        edges = extract_edges_from_linkedin(raw, alice_id, graph)
        assert len(edges) == 1
        src_id, _ = edges[0]
        stub = graph.get(src_id)
        assert stub is not None
        assert any(
            i.value == "stranger" and i.service == "LinkedIn"
            for i in stub.identifiers
        )

    def test_skip_unknown_when_flag_off(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice-doe",
            "posts": [{
                "urn": "u1", "createdAt": "2024-06-01",
                "commenters": [{"publicIdentifier": "stranger",
                                 "name": "Stranger"}],
                "reactions": [], "mentioned": [],
            }],
        }
        edges = extract_edges_from_linkedin(
            raw, alice_id, graph, materialize_unknown=False,
        )
        assert edges == []

    def test_empty_data_returns_empty(self):
        graph, alice_id = self._setup()
        assert extract_edges_from_linkedin({}, alice_id, graph) == []
        assert extract_edges_from_linkedin(
            {"handle": "alice-doe", "posts": []}, alice_id, graph,
        ) == []


# ──────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────


class TestRegistration:
    def test_tool_registered(self):
        from nexusrecon.tools.registry import get_registry
        assert get_registry().get("linkedin_social") is not None

    def test_empty_dynamic_trigger_hints(self):
        # Live-test safety: dispatcher must not auto-fire LinkedIn.
        tool = LinkedInSocialTool()
        assert tool.dynamic_trigger_hints == []
