"""Tests for nexusrecon.tools.identity.bluesky_social_tool (E4).

Covers:
  - Empty handle rejection.
  - Profile failures (404 / 401 / 5xx).
  - Happy path with follows, followers, and an authored feed mixing
    replies, reposts, mentions, quotes.
  - AT-URI DID extraction (well-formed + malformed).
  - Self-loop suppression across all interaction types.
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
from nexusrecon.tools.identity.bluesky_social_tool import (
    BlueskySocialTool,
    _extract_did_from_at_uri,
    _parse_actor_list,
    _parse_feed_interactions,
    extract_edges_from_bluesky,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


SELF_DID = "did:plc:alicedid"
BOB_DID = "did:plc:bobdid"
CAROL_DID = "did:plc:caroldid"
DAVE_DID = "did:plc:davedid"


def _resp(status_code: int = 200, json_data=None):
    resp = MagicMock()
    resp.is_success = (200 <= status_code < 300)
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    return resp


def _profile(did=SELF_DID, handle="alice.bsky.social", **extras):
    base = {
        "did": did,
        "handle": handle,
        "displayName": "Alice",
        "description": "developer",
        "avatar": "...",
        "followersCount": 100,
        "followsCount": 80,
        "postsCount": 200,
        "createdAt": "2023-01-01T00:00:00Z",
        "indexedAt": "2024-06-01T00:00:00Z",
    }
    base.update(extras)
    return base


def _actor(did: str, handle: str, displayName: str = ""):
    return {"did": did, "handle": handle, "displayName": displayName}


def _post_uri(did: str, rkey: str = "3jzfcijpj") -> str:
    return f"at://{did}/app.bsky.feed.post/{rkey}"


def _feed_item(
    *,
    self_did: str = SELF_DID,
    self_handle: str = "alice.bsky.social",
    post_text: str = "hi",
    reply_to_did: str | None = None,
    mention_dids: list[str] | None = None,
    quote_did: str | None = None,
    repost_by: dict | None = None,
    created_at: str = "2024-06-01T00:00:00Z",
):
    """Construct a feed item that exercises one or more interaction
    types. ``repost_by`` produces a "reason" entry. Otherwise the
    feed item is the crawled user's original post."""
    if repost_by is not None:
        return {
            "post": {
                "uri": _post_uri(self_did),
                "cid": "cid",
                "author": {"did": self_did, "handle": self_handle},
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": post_text,
                    "createdAt": created_at,
                },
            },
            "reason": {
                "$type": "app.bsky.feed.defs#reasonRepost",
                "by": repost_by,
                "indexedAt": created_at,
            },
        }

    record = {
        "$type": "app.bsky.feed.post",
        "text": post_text,
        "createdAt": created_at,
    }
    if reply_to_did is not None:
        record["reply"] = {
            "root": {"uri": _post_uri(reply_to_did), "cid": "c"},
            "parent": {"uri": _post_uri(reply_to_did), "cid": "c"},
        }
    if mention_dids:
        record["facets"] = [
            {
                "index": {"byteStart": 0, "byteEnd": 5},
                "features": [
                    {"$type": "app.bsky.richtext.facet#mention", "did": d},
                ],
            }
            for d in mention_dids
        ]
    if quote_did:
        record["embed"] = {
            "$type": "app.bsky.embed.record",
            "record": {"uri": _post_uri(quote_did), "cid": "c"},
        }
    return {
        "post": {
            "uri": _post_uri(self_did),
            "cid": "cid",
            "author": {"did": self_did, "handle": self_handle},
            "record": record,
        },
    }


# ──────────────────────────────────────────────────────────────────────
# Tool: input validation
# ──────────────────────────────────────────────────────────────────────


class TestBlueskySocialToolBasics:
    @pytest.mark.asyncio
    async def test_empty_target(self):
        tool = BlueskySocialTool()
        result = await tool.run("")
        assert not result.success
        assert "empty handle" in result.error

    @pytest.mark.asyncio
    async def test_profile_404_returns_failure(self):
        tool = BlueskySocialTool()
        mock_client = AsyncMock()
        mock_client.get.return_value = _resp(404)
        with patch(
            "nexusrecon.tools.identity.bluesky_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("ghost.bsky.social")
        assert not result.success
        assert "404" in result.error

    @pytest.mark.asyncio
    async def test_unexpected_profile_shape(self):
        tool = BlueskySocialTool()
        mock_client = AsyncMock()
        mock_client.get.return_value = _resp(200, {"no_did": True})
        with patch(
            "nexusrecon.tools.identity.bluesky_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("alice.bsky.social")
        assert not result.success
        assert "shape" in result.error.lower()


# ──────────────────────────────────────────────────────────────────────
# Tool: happy path
# ──────────────────────────────────────────────────────────────────────


class TestBlueskySocialToolHappyPath:
    @pytest.mark.asyncio
    async def test_full_crawl_aggregates(self):
        tool = BlueskySocialTool()

        follows_payload = {
            "follows": [
                _actor(BOB_DID, "bob.bsky.social"),
            ],
        }
        followers_payload = {
            "followers": [
                _actor(CAROL_DID, "carol.bsky.social"),
            ],
        }
        feed_payload = {
            "feed": [
                _feed_item(
                    repost_by={
                        "did": DAVE_DID,
                        "handle": "dave.bsky.social",
                        "displayName": "Dave",
                    },
                ),
                _feed_item(reply_to_did=BOB_DID),
                _feed_item(mention_dids=[CAROL_DID, DAVE_DID]),
                _feed_item(quote_did=BOB_DID),
            ],
        }

        responses = iter([
            _resp(200, _profile()),
            _resp(200, follows_payload),
            _resp(200, followers_payload),
            _resp(200, feed_payload),
        ])

        async def _seq_get(url, params=None):
            return next(responses)

        mock_client = AsyncMock()
        mock_client.get.side_effect = _seq_get
        with patch(
            "nexusrecon.tools.identity.bluesky_social_tool.httpx.AsyncClient"
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("alice.bsky.social")

        assert result.success
        d = result.data
        assert d["profile"]["did"] == SELF_DID
        assert d["summary"]["follower_count"] == 1
        assert d["summary"]["following_count"] == 1
        assert d["summary"]["repost_count"] == 1
        assert d["summary"]["reply_count"] == 1
        assert d["summary"]["mention_count"] == 2
        assert d["summary"]["quote_count"] == 1


# ──────────────────────────────────────────────────────────────────────
# AT-URI parsing
# ──────────────────────────────────────────────────────────────────────


class TestExtractDidFromAtUri:
    def test_well_formed_plc(self):
        assert _extract_did_from_at_uri(
            "at://did:plc:abc123/app.bsky.feed.post/3jzfcijpj"
        ) == "did:plc:abc123"

    def test_well_formed_web_did(self):
        assert _extract_did_from_at_uri(
            "at://did:web:example.com/app.bsky.feed.post/x"
        ) == "did:web:example.com"

    def test_handle_authority_rejected(self):
        # Older AT URIs sometimes had handles as authority; we want
        # canonical DIDs only.
        assert _extract_did_from_at_uri(
            "at://alice.bsky.social/app.bsky.feed.post/x"
        ) is None

    def test_malformed(self):
        assert _extract_did_from_at_uri("not a uri") is None

    def test_empty_string(self):
        assert _extract_did_from_at_uri("") is None

    def test_none(self):
        assert _extract_did_from_at_uri(None) is None


# ──────────────────────────────────────────────────────────────────────
# Feed parser (unit-level)
# ──────────────────────────────────────────────────────────────────────


class TestParseFeedInteractions:
    def test_self_repost_dropped(self):
        resp = _resp(200, {"feed": [
            _feed_item(repost_by={"did": SELF_DID, "handle": "alice"}),
        ]})
        assert _parse_feed_interactions(resp, self_did=SELF_DID) == []

    def test_self_reply_dropped(self):
        resp = _resp(200, {"feed": [
            _feed_item(reply_to_did=SELF_DID),
        ]})
        assert _parse_feed_interactions(resp, self_did=SELF_DID) == []

    def test_self_mention_dropped(self):
        resp = _resp(200, {"feed": [
            _feed_item(mention_dids=[SELF_DID]),
        ]})
        assert _parse_feed_interactions(resp, self_did=SELF_DID) == []

    def test_mention_dedup_with_reply(self):
        # Mention DID matches reply target DID → keep only reply edge.
        resp = _resp(200, {"feed": [
            _feed_item(reply_to_did=BOB_DID, mention_dids=[BOB_DID, CAROL_DID]),
        ]})
        result = _parse_feed_interactions(resp, self_did=SELF_DID)
        types = [i["interaction_type"] for i in result]
        assert types.count("reply") == 1
        assert types.count("mention") == 1
        mention_targets = {
            i["target_did"] for i in result if i["interaction_type"] == "mention"
        }
        assert mention_targets == {CAROL_DID}

    def test_repost_skips_feed_item_own_facets(self):
        # A reposted item with mentions in the ORIGINAL author's text
        # should NOT generate mention edges for the crawled user.
        resp = _resp(200, {"feed": [
            {
                "post": {
                    "uri": _post_uri(BOB_DID),
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": "@carol cool",
                        "createdAt": "2024-06-01T00:00:00Z",
                        "facets": [{
                            "features": [
                                {"$type": "app.bsky.richtext.facet#mention",
                                 "did": CAROL_DID},
                            ],
                        }],
                    },
                },
                "reason": {
                    "$type": "app.bsky.feed.defs#reasonRepost",
                    "by": {"did": BOB_DID, "handle": "bob.bsky.social"},
                    "indexedAt": "2024-06-01T00:00:00Z",
                },
            },
        ]})
        result = _parse_feed_interactions(resp, self_did=SELF_DID)
        types = [i["interaction_type"] for i in result]
        assert types == ["repost"]  # NO mention from the original author's text

    def test_quote_embed_extracts_did(self):
        resp = _resp(200, {"feed": [
            _feed_item(quote_did=BOB_DID),
        ]})
        result = _parse_feed_interactions(resp, self_did=SELF_DID)
        assert len(result) == 1
        assert result[0]["interaction_type"] == "quote"
        assert result[0]["target_did"] == BOB_DID

    def test_malformed_response(self):
        assert _parse_feed_interactions(_resp(500), self_did=SELF_DID) == []
        assert _parse_feed_interactions(RuntimeError("x"), self_did=SELF_DID) == []
        # Wrong shape
        assert _parse_feed_interactions(_resp(200, {"feed": "not-a-list"}), self_did=SELF_DID) == []


# ──────────────────────────────────────────────────────────────────────
# _parse_actor_list
# ──────────────────────────────────────────────────────────────────────


class TestParseActorList:
    def test_happy_path(self):
        resp = _resp(200, {"follows": [_actor(BOB_DID, "bob")]})
        out = _parse_actor_list(resp, "follows")
        assert out == [{"did": BOB_DID, "handle": "bob", "displayName": ""}]

    def test_missing_wrapper_key_returns_empty(self):
        resp = _resp(200, {"different_key": []})
        assert _parse_actor_list(resp, "follows") == []

    def test_non_dict_root_returns_empty(self):
        resp = _resp(200, [{"did": BOB_DID}])  # list instead of dict
        assert _parse_actor_list(resp, "follows") == []

    def test_exception_returns_empty(self):
        assert _parse_actor_list(RuntimeError("x"), "follows") == []

    def test_drops_items_without_did_or_handle(self):
        resp = _resp(200, {"follows": [
            _actor(BOB_DID, "bob"),
            {"displayName": "ghost"},  # no did or handle
        ]})
        out = _parse_actor_list(resp, "follows")
        assert len(out) == 1
        assert out[0]["did"] == BOB_DID


# ──────────────────────────────────────────────────────────────────────
# Adapter: extract_edges_from_bluesky
# ──────────────────────────────────────────────────────────────────────


def _id_with_bluesky_handle(handle: str, did: str | None = None) -> Identity:
    idents = [
        Identifier(
            value=handle,
            identifier_type=IdentifierType.HANDLE,
            service="Bluesky",
            source="test",
            confidence=0.9,
        ),
    ]
    if did:
        idents.append(Identifier(
            value=did,
            identifier_type=IdentifierType.OTHER,
            service="Bluesky",
            source="test",
            confidence=0.9,
        ))
    return Identity(
        identity_id=derive_identity_id(idents),
        primary_label=handle,
        identifiers=idents,
    )


class TestExtractEdgesFromBluesky:
    def _setup(self) -> tuple[IdentityGraph, str]:
        graph = IdentityGraph()
        alice = _id_with_bluesky_handle("alice.bsky.social", SELF_DID)
        graph.add_identity(alice)
        return graph, alice.identity_id

    def test_follower_inverted(self):
        graph, alice_id = self._setup()
        bob = _id_with_bluesky_handle("bob.bsky.social", BOB_DID)
        graph.add_identity(bob)
        raw = {
            "actor": "alice.bsky.social",
            "followers": [_actor(BOB_DID, "bob.bsky.social")],
            "follows": [],
            "interactions": [],
        }
        edges = extract_edges_from_bluesky(raw, alice_id, graph)
        assert len(edges) == 1
        src, edge = edges[0]
        assert src == bob.identity_id
        assert edge.target_identity_id == alice_id
        assert edge.interaction_type == "follower"

    def test_follows_forward(self):
        graph, alice_id = self._setup()
        bob = _id_with_bluesky_handle("bob.bsky.social", BOB_DID)
        graph.add_identity(bob)
        raw = {
            "actor": "alice.bsky.social",
            "followers": [],
            "follows": [_actor(BOB_DID, "bob.bsky.social")],
            "interactions": [],
        }
        edges = extract_edges_from_bluesky(raw, alice_id, graph)
        assert len(edges) == 1
        src, edge = edges[0]
        assert src == alice_id
        assert edge.target_identity_id == bob.identity_id

    def test_did_only_target_materializes_stub(self):
        graph, alice_id = self._setup()
        # Reply targets only have DID, no handle.
        raw = {
            "actor": "alice.bsky.social",
            "followers": [], "follows": [],
            "interactions": [{
                "interaction_type": "reply",
                "target_did": BOB_DID,
                "target_handle": None,
                "last_observed": "2024-06-01T00:00:00Z",
            }],
        }
        edges = extract_edges_from_bluesky(raw, alice_id, graph)
        assert len(edges) == 1
        _, edge = edges[0]
        # Stub identity for BOB_DID should now exist
        stub = graph.by_identifier(BOB_DID)
        assert stub is not None
        assert edge.target_identity_id == stub.identity_id

    def test_quote_uses_reply_weight(self):
        graph, alice_id = self._setup()
        raw = {
            "actor": "alice.bsky.social",
            "followers": [], "follows": [],
            "interactions": [
                {"interaction_type": "quote", "target_did": BOB_DID},
                {"interaction_type": "reply", "target_did": CAROL_DID},
                {"interaction_type": "repost", "target_did": DAVE_DID},
            ],
        }
        edges = extract_edges_from_bluesky(raw, alice_id, graph)
        types_to_strength = {edge.interaction_type: edge.strength for _, edge in edges}
        # quote weight == reply weight (both 0.55)
        assert types_to_strength["quote"] == types_to_strength["reply"]
        # repost is weaker
        assert types_to_strength["repost"] < types_to_strength["reply"]

    def test_skip_unknown_when_flag_off(self):
        graph, alice_id = self._setup()
        raw = {
            "actor": "alice.bsky.social",
            "followers": [_actor(BOB_DID, "bob")],
            "follows": [], "interactions": [],
        }
        edges = extract_edges_from_bluesky(
            raw, alice_id, graph, materialize_unknown=False,
        )
        assert edges == []

    def test_self_loop_filtered_by_id(self):
        # Even if interaction includes the crawled identity's own DID,
        # the adapter's defensive check should drop it.
        graph, alice_id = self._setup()
        raw = {
            "actor": "alice.bsky.social",
            "followers": [_actor(SELF_DID, "alice.bsky.social")],
            "follows": [_actor(SELF_DID, "alice.bsky.social")],
            "interactions": [{
                "interaction_type": "reply", "target_did": SELF_DID,
            }],
        }
        edges = extract_edges_from_bluesky(raw, alice_id, graph)
        assert edges == []

    def test_unknown_interaction_type_skipped(self):
        graph, alice_id = self._setup()
        raw = {
            "actor": "alice.bsky.social",
            "followers": [], "follows": [],
            "interactions": [
                {"interaction_type": "weird", "target_did": BOB_DID},
            ],
        }
        edges = extract_edges_from_bluesky(raw, alice_id, graph)
        assert edges == []


# ──────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────


class TestRegistration:
    def test_tool_registered(self):
        from nexusrecon.tools.registry import get_registry
        assert get_registry().get("bluesky_social") is not None

    def test_no_required_keys(self):
        tool = BlueskySocialTool()
        assert tool.requires_keys == []

    def test_empty_dynamic_trigger_hints(self):
        tool = BlueskySocialTool()
        assert tool.dynamic_trigger_hints == []
