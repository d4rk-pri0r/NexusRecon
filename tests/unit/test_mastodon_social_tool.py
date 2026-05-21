"""Tests for nexusrecon.tools.identity.mastodon_social_tool (E3).

Covers:
  - Target parsing (full handle vs bare handle vs leading @).
  - Instance probe list resolution (explicit > override > defaults).
  - 404 on lookup is soft → keeps probing other instances.
  - First-instance-match short-circuits remaining probes.
  - statuses interactions: boost / reply / mention with self-loop filter.
  - Adapter direction conventions + materialize_unknown.
  - Registration + empty dynamic_trigger_hints (live-test safety).
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
from nexusrecon.tools.identity.mastodon_social_tool import (
    DEFAULT_INSTANCES,
    MastodonSocialTool,
    _parse_account_list,
    _parse_statuses_interactions,
    _parse_target,
    _resolve_instance_list,
    extract_edges_from_mastodon,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _resp(status_code: int = 200, json_data=None):
    resp = MagicMock()
    resp.is_success = (200 <= status_code < 300)
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    return resp


def _account(acct="alice@mastodon.social", id_="42", **extras):
    base = {
        "id": id_,
        "username": acct.split("@")[0],
        "acct": acct,
        "display_name": "Alice",
        "url": f"https://mastodon.social/@{acct.split('@')[0]}",
        "followers_count": 100,
        "following_count": 80,
        "statuses_count": 500,
        "created_at": "2018-01-01T00:00:00Z",
        "note": "<p>developer</p>",
        "fields": [],
    }
    base.update(extras)
    return base


def _status(
    id_="s1", reblog=None, in_reply_to_account_id=None, mentions=None,
    created_at="2024-06-01T00:00:00Z",
):
    return {
        "id": id_,
        "url": f"https://mastodon.social/@alice/{id_}",
        "created_at": created_at,
        "reblog": reblog,
        "in_reply_to_account_id": in_reply_to_account_id,
        "mentions": mentions or [],
    }


def _mention(id_, username, acct=None, url=None):
    return {
        "id": id_,
        "username": username,
        "acct": acct or username,
        "url": url or f"https://mastodon.social/@{username}",
    }


# ──────────────────────────────────────────────────────────────────────
# Target parsing
# ──────────────────────────────────────────────────────────────────────


class TestParseTarget:
    def test_full_handle(self):
        handle, instance = _parse_target("alice@mastodon.social")
        assert handle == "alice@mastodon.social"
        assert instance == "mastodon.social"

    def test_leading_at_stripped(self):
        handle, instance = _parse_target("@alice@mastodon.social")
        assert handle == "alice@mastodon.social"
        assert instance == "mastodon.social"

    def test_bare_handle(self):
        handle, instance = _parse_target("alice")
        assert handle == "alice"
        assert instance is None

    def test_empty(self):
        handle, instance = _parse_target("")
        assert handle == ""
        assert instance is None

    def test_instance_lowercased(self):
        _, instance = _parse_target("alice@MASTODON.social")
        assert instance == "mastodon.social"


# ──────────────────────────────────────────────────────────────────────
# Instance list resolution
# ──────────────────────────────────────────────────────────────────────


class TestResolveInstanceList:
    def test_explicit_instance_wins(self):
        assert _resolve_instance_list("infosec.exchange", None) == ["infosec.exchange"]

    def test_override_kwarg(self):
        out = _resolve_instance_list(None, ["custom.example", "other.example"])
        assert out == ["custom.example", "other.example"]

    def test_override_deduplicates(self):
        out = _resolve_instance_list(None, ["a.x", "b.x", "a.x"])
        assert out == ["a.x", "b.x"]

    def test_override_strips_invalid(self):
        out = _resolve_instance_list(None, ["", None, "valid.x"])
        assert out == ["valid.x"]

    def test_defaults_when_no_input(self):
        assert _resolve_instance_list(None, None) == list(DEFAULT_INSTANCES)

    def test_empty_override_falls_back_to_defaults(self):
        # Empty override list → defaults.
        assert _resolve_instance_list(None, []) == list(DEFAULT_INSTANCES)


# ──────────────────────────────────────────────────────────────────────
# Tool: empty target + probe behavior
# ──────────────────────────────────────────────────────────────────────


class TestMastodonSocialToolBasics:
    @pytest.mark.asyncio
    async def test_empty_target(self):
        tool = MastodonSocialTool()
        result = await tool.run("")
        assert not result.success
        assert "empty handle" in result.error

    @pytest.mark.asyncio
    async def test_handle_not_found_anywhere(self):
        tool = MastodonSocialTool()
        # Every instance returns 404 on lookup.
        mock_client = AsyncMock()
        mock_client.get.return_value = _resp(404)
        with patch(
            "nexusrecon.tools.identity.mastodon_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("ghost@nowhere.example",
                                    instances=["mastodon.social"])
        assert not result.success
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_first_match_short_circuits(self):
        tool = MastodonSocialTool()
        call_count = {"count": 0}

        async def _get(url, params=None):
            call_count["count"] += 1
            if "/api/v1/accounts/lookup" in url:
                # First instance returns the account immediately.
                return _resp(200, _account())
            if "/followers" in url:
                return _resp(200, [])
            if "/following" in url:
                return _resp(200, [])
            if "/statuses" in url:
                return _resp(200, [])
            return _resp(404)

        mock_client = AsyncMock()
        mock_client.get.side_effect = _get
        with patch(
            "nexusrecon.tools.identity.mastodon_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run(
                "alice",
                instances=["mastodon.social", "hachyderm.io",
                           "infosec.exchange"],
            )
        assert result.success
        # 1 lookup + 3 fetches (followers/following/statuses) = 4 calls.
        # If short-circuit failed we'd see 3+ lookups.
        assert call_count["count"] == 4
        assert result.data["instance"] == "mastodon.social"

    @pytest.mark.asyncio
    async def test_skips_to_next_instance_on_404(self):
        tool = MastodonSocialTool()

        async def _get(url, params=None):
            if "/api/v1/accounts/lookup" in url:
                # Mastodon.social 404, hachyderm hits
                if "/api/v1/accounts/lookup" in url and "mastodon.social" not in str(mock_client.base_url):
                    return _resp(200, _account(acct="alice@hachyderm.io"))
                # Default: 404
                return _resp(404)
            if "/followers" in url or "/following" in url or "/statuses" in url:
                return _resp(200, [])
            return _resp(404)

        # Simpler: instance-by-instance routing via base_url isn't
        # exposed in the call. Just probe two instances; first 404,
        # second 200.
        responses = iter([
            _resp(404),                                       # mastodon.social lookup
            _resp(200, _account(acct="alice@hachyderm.io")),  # hachyderm lookup
            _resp(200, []),  # followers
            _resp(200, []),  # following
            _resp(200, []),  # statuses
        ])

        async def _seq_get(url, params=None):
            return next(responses)

        mock_client = AsyncMock()
        mock_client.get.side_effect = _seq_get
        with patch(
            "nexusrecon.tools.identity.mastodon_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run(
                "alice",
                instances=["mastodon.social", "hachyderm.io"],
            )
        assert result.success
        assert result.data["instance"] == "hachyderm.io"


# ──────────────────────────────────────────────────────────────────────
# Tool: happy-path shape + interactions
# ──────────────────────────────────────────────────────────────────────


class TestMastodonSocialToolHappyPath:
    @pytest.mark.asyncio
    async def test_followers_following_statuses_aggregation(self):
        tool = MastodonSocialTool()

        followers_payload = [
            {"id": "100", "acct": "bob@mastodon.social",
             "display_name": "Bob", "url": "..."},
            {"id": "101", "acct": "carol@hachyderm.io",
             "display_name": "Carol", "url": "..."},
        ]
        following_payload = [
            {"id": "200", "acct": "dave@mastodon.social",
             "display_name": "Dave", "url": "..."},
        ]
        statuses_payload = [
            # A boost of an external account
            _status(id_="b1", reblog={
                "id": "X1",
                "account": {"id": "300", "acct": "external@example.org",
                            "display_name": "Ext", "url": "...",},
                "created_at": "2024-06-01T10:00:00Z",
            }),
            # A reply
            _status(id_="r1", in_reply_to_account_id="400",
                    mentions=[_mention("400", "ed", "ed@mastodon.social")]),
            # A status with mentions
            _status(id_="m1", mentions=[
                _mention("500", "frank", "frank@mas.to"),
                _mention("600", "grace", "grace@mas.to"),
            ]),
        ]

        responses = iter([
            _resp(200, _account()),
            _resp(200, followers_payload),
            _resp(200, following_payload),
            _resp(200, statuses_payload),
        ])

        async def _seq_get(url, params=None):
            return next(responses)

        mock_client = AsyncMock()
        mock_client.get.side_effect = _seq_get
        with patch(
            "nexusrecon.tools.identity.mastodon_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("alice@mastodon.social")

        assert result.success
        d = result.data
        assert d["instance"] == "mastodon.social"
        assert d["summary"]["follower_count"] == 2
        assert d["summary"]["following_count"] == 1
        assert d["summary"]["boost_count"] == 1
        assert d["summary"]["reply_count"] == 1
        assert d["summary"]["mention_count"] == 2

        interactions = d["interactions"]
        boosts = [i for i in interactions if i["interaction_type"] == "boost"]
        replies = [i for i in interactions if i["interaction_type"] == "reply"]
        mentions = [i for i in interactions if i["interaction_type"] == "mention"]
        assert boosts[0]["target_acct"] == "external@example.org"
        assert replies[0]["target_acct"] == "ed@mastodon.social"
        assert {m["target_acct"] for m in mentions} == {"frank@mas.to", "grace@mas.to"}


# ──────────────────────────────────────────────────────────────────────
# Status parser (unit-level)
# ──────────────────────────────────────────────────────────────────────


class TestParseStatusesInteractions:
    def test_self_boost_dropped(self):
        # Crawled user "42" boosts their OWN status (rare but possible).
        resp = _resp(200, [_status(reblog={
            "id": "X",
            "account": {"id": "42", "acct": "self@x"},
            "created_at": "...",
        })])
        result = _parse_statuses_interactions(resp, self_id="42")
        assert result == []

    def test_self_reply_dropped(self):
        resp = _resp(200, [_status(in_reply_to_account_id="42",
                                    mentions=[_mention("42", "self")])])
        result = _parse_statuses_interactions(resp, self_id="42")
        assert result == []

    def test_mention_dedups_with_reply(self):
        # Mention pointing at the SAME account as the reply target
        # shouldn't fire a separate mention edge.
        resp = _resp(200, [_status(
            in_reply_to_account_id="400",
            mentions=[_mention("400", "bob", "bob@x"),
                       _mention("500", "carol", "carol@x")],
        )])
        result = _parse_statuses_interactions(resp, self_id="42")
        types = [i["interaction_type"] for i in result]
        assert types.count("reply") == 1
        assert types.count("mention") == 1
        # carol is the mention, bob is the reply target
        mention_targets = {i["target_acct"] for i in result if i["interaction_type"] == "mention"}
        assert mention_targets == {"carol@x"}

    def test_malformed_response_returns_empty(self):
        assert _parse_statuses_interactions(_resp(500), self_id="42") == []
        assert _parse_statuses_interactions(RuntimeError("x"), self_id="42") == []

    def test_dict_payload_returns_empty(self):
        # API returned a dict where a list was expected.
        resp = _resp(200, {"unexpected": "shape"})
        assert _parse_statuses_interactions(resp, self_id="42") == []


# ──────────────────────────────────────────────────────────────────────
# _parse_account_list
# ──────────────────────────────────────────────────────────────────────


class TestParseAccountList:
    def test_happy_path(self):
        resp = _resp(200, [
            {"id": "1", "acct": "alice@x", "display_name": "A", "url": "..."},
            {"id": "2", "acct": "bob@y", "display_name": "B", "url": "..."},
        ])
        out = _parse_account_list(resp)
        assert [a["acct"] for a in out] == ["alice@x", "bob@y"]

    def test_drops_items_without_acct(self):
        resp = _resp(200, [{"id": "1", "acct": "ok"},
                            {"id": "2"},
                            {"id": "3", "acct": ""}])
        out = _parse_account_list(resp)
        assert [a["acct"] for a in out] == ["ok"]

    def test_non_list_returns_empty(self):
        assert _parse_account_list(_resp(200, {"not": "list"})) == []

    def test_exception_returns_empty(self):
        assert _parse_account_list(RuntimeError("x")) == []


# ──────────────────────────────────────────────────────────────────────
# Adapter: extract_edges_from_mastodon
# ──────────────────────────────────────────────────────────────────────


def _id_with_mastodon_handle(acct: str) -> Identity:
    ident = Identifier(
        value=acct,
        identifier_type=IdentifierType.HANDLE,
        service="Mastodon",
        source="test",
        confidence=0.9,
    )
    return Identity(
        identity_id=derive_identity_id([ident]),
        primary_label=acct,
        identifiers=[ident],
    )


class TestExtractEdgesFromMastodon:
    def _setup(self) -> tuple[IdentityGraph, str]:
        graph = IdentityGraph()
        alice = _id_with_mastodon_handle("alice@mastodon.social")
        graph.add_identity(alice)
        return graph, alice.identity_id

    def test_follower_inverted_direction(self):
        graph, alice_id = self._setup()
        bob = _id_with_mastodon_handle("bob@mastodon.social")
        graph.add_identity(bob)
        raw = {
            "handle": "alice@mastodon.social",
            "followers": [{"acct": "bob@mastodon.social",
                           "id": "100", "display_name": "Bob"}],
            "following": [],
            "interactions": [],
        }
        edges = extract_edges_from_mastodon(raw, alice_id, graph)
        assert len(edges) == 1
        src, edge = edges[0]
        assert src == bob.identity_id
        assert edge.target_identity_id == alice_id
        assert edge.interaction_type == "follower"

    def test_interaction_types_carry_correct_weights(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice@mastodon.social",
            "followers": [], "following": [],
            "interactions": [
                {"interaction_type": "boost",
                 "target_acct": "x@x", "target_display": "X",
                 "last_observed": "2024-06-01T00:00:00Z"},
                {"interaction_type": "reply",
                 "target_acct": "y@y", "target_display": "Y",
                 "last_observed": "2024-06-02T00:00:00Z"},
                {"interaction_type": "mention",
                 "target_acct": "z@z", "target_display": "Z",
                 "last_observed": "2024-06-03T00:00:00Z"},
            ],
        }
        edges = extract_edges_from_mastodon(raw, alice_id, graph)
        # All three should be outbound from alice
        for src, edge in edges:
            assert src == alice_id
        types_to_strength = {edge.interaction_type: edge.strength for _, edge in edges}
        assert types_to_strength["reply"] > types_to_strength["mention"]
        assert types_to_strength["mention"] > types_to_strength["boost"]

    def test_materializes_unknown_acct(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice@mastodon.social",
            "followers": [{"acct": "stranger@somewhere.example"}],
            "following": [],
            "interactions": [],
        }
        edges = extract_edges_from_mastodon(raw, alice_id, graph)
        assert len(edges) == 1
        src_id, _ = edges[0]
        stub = graph.get(src_id)
        assert stub is not None
        assert any(
            i.value == "stranger@somewhere.example" and i.service == "Mastodon"
            for i in stub.identifiers
        )

    def test_skip_unknown_when_flag_off(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice@mastodon.social",
            "followers": [{"acct": "stranger@somewhere.example"}],
            "following": [], "interactions": [],
        }
        edges = extract_edges_from_mastodon(
            raw, alice_id, graph, materialize_unknown=False,
        )
        assert edges == []

    def test_drops_empty_acct(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice@mastodon.social",
            "followers": [{"acct": None}, {"acct": ""}],
            "following": [], "interactions": [],
        }
        edges = extract_edges_from_mastodon(raw, alice_id, graph)
        assert edges == []

    def test_unknown_interaction_type_skipped(self):
        graph, alice_id = self._setup()
        raw = {
            "handle": "alice@mastodon.social",
            "followers": [], "following": [],
            "interactions": [
                {"interaction_type": "weird_thing",
                 "target_acct": "x@x"},
            ],
        }
        edges = extract_edges_from_mastodon(raw, alice_id, graph)
        assert edges == []


# ──────────────────────────────────────────────────────────────────────
# Registration discipline
# ──────────────────────────────────────────────────────────────────────


class TestRegistration:
    def test_tool_registered(self):
        from nexusrecon.tools.registry import get_registry
        assert get_registry().get("mastodon_social") is not None

    def test_no_required_keys(self):
        tool = MastodonSocialTool()
        assert tool.requires_keys == []

    def test_empty_dynamic_trigger_hints(self):
        tool = MastodonSocialTool()
        assert tool.dynamic_trigger_hints == []

    def test_soft_failure_codes_includes_404(self):
        # 404 must be soft so "not on this instance" doesn't abort.
        tool = MastodonSocialTool()
        assert 404 in tool.soft_failure_codes
