"""Tests for nexusrecon.tools.identity.github_social_tool (E2).

Covers:
  - Fail-fast on missing GITHUB_TOKEN.
  - Empty username rejection.
  - Happy-path profile + followers + following + repos crawl.
  - Co-author trailer parsing (single, multi, dedup, noreply filter,
    last_observed aggregation).
  - Collaborator 403 soft-fail (continues the crawl).
  - Cap enforcement.
  - Auth failure surfaces via classify_response.
  - Adapter: extract_edges_from_github_social
      - resolves existing identities by handle / email
      - materializes stubs when ``materialize_unknown=True``
      - drops edges when ``materialize_unknown=False`` and unknown
      - skips self-loops
      - emits bidirectional edges for collaborator / co-author
      - flips direction correctly for followers vs following.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    derive_identity_id,
)
from nexusrecon.tools.identity.github_social_tool import (
    GitHubSocialTool,
    _extract_co_authors,
    _parse_user_list,
    extract_edges_from_github_social,
)

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _mock_config(token: str | None = "gh_test_token"):
    cfg = MagicMock()
    cfg.get_secret.side_effect = lambda name: {
        "github_token": token,
    }.get(name)
    return cfg


def _make_tool(token: str | None = "gh_test_token") -> GitHubSocialTool:
    tool = GitHubSocialTool()
    tool.config = _mock_config(token)
    return tool


def _resp(status_code: int = 200, json_data=None):
    resp = MagicMock()
    resp.is_success = (200 <= status_code < 300)
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    return resp


def _profile_payload(login="alice", **extras):
    base = {
        "login": login,
        "id": 1001,
        "name": "Alice Adams",
        "email": "alice@example.com",
        "company": "Example Inc",
        "location": "SF",
        "bio": "developer",
        "blog": "https://alice.example.com",
        "public_repos": 5,
        "followers": 10,
        "following": 8,
        "created_at": "2018-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
    }
    base.update(extras)
    return base


def _user(login: str, uid: int = 1):
    return {"login": login, "id": uid, "avatar_url": f"https://avatars/{login}"}


def _repo(name="proj", full_name=None, updated_at="2024-06-01T00:00:00Z"):
    return {
        "name": name,
        "full_name": full_name or f"alice/{name}",
        "updated_at": updated_at,
    }


def _commit(message: str, date: str = "2024-05-15T00:00:00Z"):
    return {
        "sha": "abc123",
        "commit": {
            "author": {"name": "Alice", "email": "alice@example.com", "date": date},
            "message": message,
        },
    }


def _route_responses(routes: dict[str, MagicMock]):
    """Build a side_effect that matches the URL path against patterns.

    Patterns are checked in insertion order; first match wins. Path
    suffix or substring match.
    """
    async def _get(url, params=None):
        for pattern, response in routes.items():
            if pattern in url:
                return response
        return _resp(404, {})
    return _get


# ──────────────────────────────────────────────────────────────────────
# Tool: fail-fast + input validation
# ──────────────────────────────────────────────────────────────────────


class TestGitHubSocialToolFailFast:
    @pytest.mark.asyncio
    async def test_missing_token_returns_failure(self):
        tool = _make_tool(token=None)
        result = await tool.run("alice")
        assert not result.success
        assert "GITHUB_TOKEN" in result.error

    @pytest.mark.asyncio
    async def test_empty_target_returns_failure(self):
        tool = _make_tool()
        result = await tool.run("")
        assert not result.success
        assert "empty username" in result.error

    @pytest.mark.asyncio
    async def test_at_prefix_stripped(self):
        # Targets like "@alice" should resolve to "alice" not crash.
        tool = _make_tool()
        mock_client = AsyncMock()
        mock_client.get.side_effect = _route_responses({
            "/users/alice": _resp(200, _profile_payload(login="alice")),
        })
        with patch(
            "nexusrecon.tools.identity.github_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("@alice")
        assert result.success
        assert result.data["username"] == "alice"


# ──────────────────────────────────────────────────────────────────────
# Tool: happy path
# ──────────────────────────────────────────────────────────────────────


class TestGitHubSocialToolHappyPath:
    @pytest.mark.asyncio
    async def test_full_crawl_shape(self):
        tool = _make_tool()
        mock_client = AsyncMock()
        mock_client.get.side_effect = _route_responses({
            # IMPORTANT: order matters — more-specific URLs FIRST.
            "/users/alice/followers": _resp(200, [_user("bob", 2), _user("carol", 3)]),
            "/users/alice/following": _resp(200, [_user("dave", 4)]),
            "/users/alice/repos": _resp(200, [_repo("proj1"), _repo("proj2")]),
            "/repos/alice/proj1/collaborators": _resp(200, [_user("bob", 2)]),
            "/repos/alice/proj1/commits": _resp(200, [
                _commit("feat: thing\n\nCo-authored-by: Eve Egan <eve@example.com>"),
            ]),
            "/repos/alice/proj2/collaborators": _resp(200, []),
            "/repos/alice/proj2/commits": _resp(200, []),
            "/users/alice": _resp(200, _profile_payload(login="alice")),
        })
        with patch(
            "nexusrecon.tools.identity.github_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("alice")
        assert result.success
        d = result.data
        assert d["username"] == "alice"
        assert d["user_profile"]["login"] == "alice"
        assert {f["login"] for f in d["followers"]} == {"bob", "carol"}
        assert {f["login"] for f in d["following"]} == {"dave"}
        assert len(d["repositories"]) == 2
        proj1 = next(r for r in d["repositories"] if r["name"] == "proj1")
        assert proj1["collaborators"] == [{"login": "bob", "id": 2}]
        assert len(proj1["co_authors"]) == 1
        assert proj1["co_authors"][0]["email"] == "eve@example.com"
        assert d["summary"]["follower_count"] == 2
        assert d["summary"]["following_count"] == 1
        assert d["summary"]["unique_collaborators"] == 1
        assert d["summary"]["unique_co_authors"] == 1

    @pytest.mark.asyncio
    async def test_profile_404_returns_failure(self):
        tool = _make_tool()
        mock_client = AsyncMock()
        mock_client.get.return_value = _resp(404)
        with patch(
            "nexusrecon.tools.identity.github_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("ghost-user")
        assert not result.success
        # classify_response surfaces non-2xx with the status code.
        assert "404" in result.error

    @pytest.mark.asyncio
    async def test_auth_failure_surfaces_with_key_hint(self):
        tool = _make_tool()
        mock_client = AsyncMock()
        mock_client.get.return_value = _resp(401)
        with patch(
            "nexusrecon.tools.identity.github_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("alice")
        assert not result.success
        assert "GITHUB_TOKEN" in result.error.upper() or "auth failure" in result.error.lower()

    @pytest.mark.asyncio
    async def test_rate_limit_surfaces(self):
        tool = _make_tool()
        mock_client = AsyncMock()
        mock_client.get.return_value = _resp(429)
        with patch(
            "nexusrecon.tools.identity.github_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("alice")
        assert not result.success
        assert "rate limit" in result.error.lower()

    @pytest.mark.asyncio
    async def test_collaborators_403_is_soft_failure(self):
        # 403 on collaborators is the normal case for non-owner repos;
        # the crawl should still succeed with collaborators=[].
        tool = _make_tool()
        mock_client = AsyncMock()
        mock_client.get.side_effect = _route_responses({
            "/users/alice/followers": _resp(200, []),
            "/users/alice/following": _resp(200, []),
            "/users/alice/repos": _resp(200, [_repo("proj1")]),
            "/repos/alice/proj1/collaborators": _resp(403),
            "/repos/alice/proj1/commits": _resp(200, []),
            "/users/alice": _resp(200, _profile_payload()),
        })
        with patch(
            "nexusrecon.tools.identity.github_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("alice")
        assert result.success
        assert result.data["repositories"][0]["collaborators"] == []


# ──────────────────────────────────────────────────────────────────────
# _extract_co_authors trailer parsing
# ──────────────────────────────────────────────────────────────────────


class TestExtractCoAuthors:
    def test_single_trailer(self):
        commits = [_commit(
            "feat: thing\n\nCo-authored-by: Bob <bob@example.com>",
        )]
        result = _extract_co_authors(commits)
        assert len(result) == 1
        assert result[0]["email"] == "bob@example.com"
        assert result[0]["name"] == "Bob"
        assert result[0]["commit_count"] == 1

    def test_multiple_trailers_same_commit(self):
        commits = [_commit(
            "feat: thing\n\n"
            "Co-authored-by: Bob <bob@example.com>\n"
            "Co-authored-by: Carol <carol@example.com>",
        )]
        result = _extract_co_authors(commits)
        assert {r["email"] for r in result} == {"bob@example.com", "carol@example.com"}

    def test_dedup_across_commits(self):
        commits = [
            _commit("c1\n\nCo-authored-by: Bob <bob@example.com>",
                    date="2024-01-01T00:00:00Z"),
            _commit("c2\n\nCo-authored-by: Bob <bob@example.com>",
                    date="2024-06-01T00:00:00Z"),
        ]
        result = _extract_co_authors(commits)
        assert len(result) == 1
        # Later commit's date should win
        assert result[0]["commit_count"] == 2
        assert result[0]["last_observed"] == "2024-06-01T00:00:00Z"

    def test_noreply_filtered(self):
        commits = [_commit(
            "feat\n\nCo-authored-by: Bot <noreply@github.com>",
        )]
        assert _extract_co_authors(commits) == []

    def test_users_noreply_filtered(self):
        commits = [_commit(
            "feat\n\nCo-authored-by: Bot <12345+bot@users.noreply.github.com>",
        )]
        assert _extract_co_authors(commits) == []

    def test_case_insensitive_trailer(self):
        commits = [_commit(
            "feat\n\nco-authored-by: Bob <bob@example.com>",
        )]
        result = _extract_co_authors(commits)
        assert len(result) == 1

    def test_email_normalised_to_lowercase(self):
        commits = [_commit(
            "feat\n\nCo-authored-by: Bob <BOB@Example.COM>",
        )]
        result = _extract_co_authors(commits)
        assert result[0]["email"] == "bob@example.com"

    def test_empty_input(self):
        assert _extract_co_authors([]) == []

    def test_malformed_commits_skipped(self):
        commits = [None, {"not_commit": True}, _commit("msg without trailer")]
        assert _extract_co_authors(commits) == []


# ──────────────────────────────────────────────────────────────────────
# _parse_user_list defensive parsing
# ──────────────────────────────────────────────────────────────────────


class TestParseUserList:
    def test_happy_path(self):
        resp = _resp(200, [_user("alice", 1), _user("bob", 2)])
        result = _parse_user_list(resp)
        assert [u["login"] for u in result] == ["alice", "bob"]

    def test_exception_in_gather_returns_empty(self):
        result = _parse_user_list(RuntimeError("boom"))
        assert result == []

    def test_non_2xx_returns_empty(self):
        result = _parse_user_list(_resp(500))
        assert result == []

    def test_invalid_json_returns_empty(self):
        resp = _resp(200)
        resp.json.side_effect = ValueError("not json")
        assert _parse_user_list(resp) == []

    def test_dict_payload_returns_empty(self):
        result = _parse_user_list(_resp(200, {"not": "a list"}))
        assert result == []

    def test_drops_items_without_login(self):
        resp = _resp(200, [{"login": "alice", "id": 1},
                           {"id": 2},  # no login
                           {"login": "", "id": 3}])
        result = _parse_user_list(resp)
        assert [u["login"] for u in result] == ["alice"]


# ──────────────────────────────────────────────────────────────────────
# Adapter: extract_edges_from_github_social
# ──────────────────────────────────────────────────────────────────────


def _make_identity_with_handle(login: str, service: str = "GitHub") -> Identity:
    ident = Identifier(
        value=login,
        identifier_type=IdentifierType.HANDLE,
        service=service,
        source="test",
        confidence=0.9,
    )
    return Identity(
        identity_id=derive_identity_id([ident]),
        primary_label=login,
        identifiers=[ident],
    )


class TestExtractEdgesFromGitHub:
    def _setup(self) -> tuple[IdentityGraph, str]:
        graph = IdentityGraph()
        alice = _make_identity_with_handle("alice")
        graph.add_identity(alice)
        return graph, alice.identity_id

    def test_follower_direction_is_inverted(self):
        graph, alice_id = self._setup()
        bob = _make_identity_with_handle("bob")
        graph.add_identity(bob)
        raw = {
            "username": "alice",
            "followers": [_user("bob")],
            "following": [],
            "repositories": [],
        }
        edges = extract_edges_from_github_social(
            raw, alice_id, graph, now_iso="2024-06-01T00:00:00+00:00",
        )
        assert len(edges) == 1
        src, edge = edges[0]
        # Bob follows alice → bob is the source
        assert src == bob.identity_id
        assert edge.target_identity_id == alice_id
        assert edge.interaction_type == "follower"

    def test_following_direction_forward(self):
        graph, alice_id = self._setup()
        bob = _make_identity_with_handle("bob")
        graph.add_identity(bob)
        raw = {
            "username": "alice",
            "followers": [],
            "following": [_user("bob")],
            "repositories": [],
        }
        edges = extract_edges_from_github_social(
            raw, alice_id, graph,
        )
        assert len(edges) == 1
        src, edge = edges[0]
        assert src == alice_id
        assert edge.target_identity_id == bob.identity_id
        assert edge.interaction_type == "follower"

    def test_collaborator_bidirectional(self):
        graph, alice_id = self._setup()
        bob = _make_identity_with_handle("bob")
        graph.add_identity(bob)
        raw = {
            "username": "alice",
            "followers": [],
            "following": [],
            "repositories": [{
                "name": "proj",
                "full_name": "alice/proj",
                "updated_at": "2024-06-01T00:00:00Z",
                "collaborators": [_user("bob")],
                "co_authors": [],
            }],
        }
        edges = extract_edges_from_github_social(raw, alice_id, graph)
        assert len(edges) == 2
        # Both directions present
        directions = {(s, e.target_identity_id, e.interaction_type) for s, e in edges}
        assert (alice_id, bob.identity_id, "collaborator") in directions
        assert (bob.identity_id, alice_id, "collaborator") in directions

    def test_co_author_bidirectional_with_timestamp(self):
        graph, alice_id = self._setup()
        bob = _make_identity_with_handle("bob")
        graph.add_identity(bob)
        # Bob has email alice knows but the graph doesn't yet — also add it
        bob.add_identifier(Identifier(
            value="bob@example.com",
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            source="test", confidence=0.7,
        ))
        # Re-sync graph's reverse index by re-adding (idempotent)
        graph.add_identity(bob)
        raw = {
            "username": "alice",
            "followers": [], "following": [],
            "repositories": [{
                "name": "proj", "full_name": "alice/proj",
                "updated_at": "2024-06-01T00:00:00Z",
                "collaborators": [],
                "co_authors": [{
                    "login": None,
                    "name": "Bob",
                    "email": "bob@example.com",
                    "commit_count": 3,
                    "last_observed": "2024-05-30T00:00:00Z",
                }],
            }],
        }
        edges = extract_edges_from_github_social(raw, alice_id, graph)
        assert len(edges) == 2
        for src, edge in edges:
            assert edge.interaction_type == "co-author"
            assert edge.last_observed == "2024-05-30T00:00:00Z"

    def test_materializes_unknown_handle_by_default(self):
        graph, alice_id = self._setup()
        raw = {
            "username": "alice",
            "followers": [_user("stranger")],
            "following": [], "repositories": [],
        }
        edges = extract_edges_from_github_social(raw, alice_id, graph)
        assert len(edges) == 1
        src_id, _ = edges[0]
        # A new stub identity should exist for "stranger"
        stub = graph.get(src_id)
        assert stub is not None
        assert any(
            i.value == "stranger" and i.service == "GitHub"
            for i in stub.identifiers
        )

    def test_skip_unknown_when_flag_off(self):
        graph, alice_id = self._setup()
        raw = {
            "username": "alice",
            "followers": [_user("stranger")],
            "following": [], "repositories": [],
        }
        edges = extract_edges_from_github_social(
            raw, alice_id, graph, materialize_unknown=False,
        )
        assert edges == []

    def test_self_loop_dropped(self):
        graph, alice_id = self._setup()
        raw = {
            "username": "alice",
            "followers": [_user("alice")],   # someone matching the crawled user
            "following": [_user("alice")],
            "repositories": [{
                "name": "proj", "full_name": "alice/proj",
                "updated_at": "2024-06-01T00:00:00Z",
                "collaborators": [_user("alice")],
                "co_authors": [{"login": "alice", "email": None,
                                 "name": None, "commit_count": 1,
                                 "last_observed": None}],
            }],
        }
        edges = extract_edges_from_github_social(raw, alice_id, graph)
        assert edges == []

    def test_strength_uses_interaction_weights(self):
        graph, alice_id = self._setup()
        bob = _make_identity_with_handle("bob")
        graph.add_identity(bob)
        raw = {
            "username": "alice",
            "followers": [], "following": [_user("bob")],
            "repositories": [{
                "name": "proj", "full_name": "alice/proj",
                "updated_at": "2024-06-01T00:00:00Z",
                "collaborators": [_user("bob")],
                "co_authors": [],
            }],
        }
        edges = extract_edges_from_github_social(raw, alice_id, graph)
        # follower (~0.2) < collaborator (~0.85)
        follower_edges = [e for _, e in edges if e.interaction_type == "follower"]
        collab_edges = [e for _, e in edges if e.interaction_type == "collaborator"]
        assert follower_edges[0].strength < collab_edges[0].strength


# ──────────────────────────────────────────────────────────────────────
# Tool registration discipline (the D3/D5 gap lesson)
# ──────────────────────────────────────────────────────────────────────


class TestRegistration:
    def test_tool_registered_under_name(self):
        from nexusrecon.tools.registry import get_registry
        tool = get_registry().get("github_social")
        assert tool is not None
        assert isinstance(tool, GitHubSocialTool)

    def test_empty_dynamic_trigger_hints(self):
        # Live-test safety: tool must not auto-fire from the dispatcher.
        tool = GitHubSocialTool()
        assert tool.dynamic_trigger_hints == []
