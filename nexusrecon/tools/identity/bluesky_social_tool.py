"""Bluesky / AT Protocol per-account social-graph crawler (Phase E4).

Mines the public AT Protocol graph for a single Bluesky account ──
follows, followers, recent posts including replies / reposts /
mentions ── and produces the raw observations Phase E11 will use to
build :class:`RelationshipEdge` entries.

Anonymous reads via the public ``api.bsky.app`` xrpc endpoints. No
SDK dependency: we use ``httpx`` directly, matching the rest of the
codebase. (Decision locked-in 2026-05-21: raw HTTP over the
``atproto`` SDK to avoid adding a transitive dep right before live
testing; the SDK ultimately calls the same xrpc endpoints.)

Target format:

  - ``alice.bsky.social``  — standard handle
  - ``example.com``        — custom-domain handle
  - ``did:plc:...``        — direct DID lookup

API endpoints used:

  - ``GET /xrpc/app.bsky.actor.getProfile?actor={handle}``
  - ``GET /xrpc/app.bsky.graph.getFollows?actor={h}&limit=N``
  - ``GET /xrpc/app.bsky.graph.getFollowers?actor={h}&limit=N``
  - ``GET /xrpc/app.bsky.feed.getAuthorFeed?actor={h}&limit=N``

Per-target hard caps (40 / 40 / 50) keep total xrpc calls bounded.

Shape contract (``ToolResult.data``):

    {
        "actor": "alice.bsky.social",
        "profile": {
            "did", "handle", "displayName", "description",
            "followersCount", "followsCount", "postsCount",
            "createdAt", "indexedAt",
        },
        "follows":   [{"did", "handle", "displayName"}, ...],
        "followers": [{"did", "handle", "displayName"}, ...],
        "interactions": [
            {
                "interaction_type": "repost"|"reply"|"mention"|"quote",
                "target_did":       "did:plc:...",
                "target_handle":    "bob.bsky.social",  # may be None
                "target_display":   "Bob",
                "last_observed":    "ISO-8601",
                "post_uri":         "at://...",
            }, ...
        ],
        "summary": {
            "follower_count", "following_count",
            "repost_count", "reply_count",
            "mention_count", "quote_count",
        },
    }

Adapter: :func:`extract_edges_from_bluesky`.

Reply targets are extracted from the AT-Protocol URI
(``at://{did}/app.bsky.feed.post/{rkey}``). The handle for the
reply target is NOT in the same feed payload, so we leave
``target_handle=None`` and let the edge-extractor materialize a
DID-anchored stub identity. That keeps the tool's wall-clock bounded
── resolving every reply target via getProfile would multiply
API calls by O(replies).

Dispatcher safety: empty ``dynamic_trigger_hints``. The tool fires
only when E11 explicitly invokes it.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
import structlog

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    RelationshipEdge,
    derive_identity_id,
)
from nexusrecon.core.relationship_graph import INTERACTION_WEIGHTS
from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import BaseHTTPTool, Category, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

log = structlog.get_logger(__name__)

_BASE = "https://api.bsky.app"

#: Per-target hard caps.
DEFAULT_MAX_FOLLOWS = 40
DEFAULT_MAX_FOLLOWERS = 40
DEFAULT_MAX_POSTS = 50
DEFAULT_TIMEOUT_SEC = 15.0

# ``at://did:plc:xyz/app.bsky.feed.post/rkey`` — the DID is the
# authority component. Anchored to ``did:`` so we don't accidentally
# match a handle-style authority that some old records used.
_AT_URI_DID_RE = re.compile(r"^at://(?P<did>did:[a-z0-9]+:[^/]+)/")


@register_tool
class BlueskySocialTool(BaseHTTPTool):
    name = "bluesky_social"
    provider_label = "Bluesky"
    tier = Tier.T0
    category = Category.SOCIAL
    # No API key required for public reads.
    requires_keys: list[str] = []
    description = (
        "Bluesky per-account social graph via the AT Protocol xrpc "
        "API — follows, followers, replies, reposts, mentions. Feeds "
        "Phase E relationship graph + pretext scoring."
    )
    target_types = ["handle", "username", "identity"]
    dynamic_trigger_hints: list[str] = []

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        actor = (target or "").strip().lstrip("@").strip()
        if not actor:
            return ToolResult(
                success=False, source=self.name,
                error="bluesky_social: empty handle",
            )

        max_follows = int(kwargs.get("max_follows", DEFAULT_MAX_FOLLOWS))
        max_followers = int(kwargs.get("max_followers", DEFAULT_MAX_FOLLOWERS))
        max_posts = int(kwargs.get("max_posts", DEFAULT_MAX_POSTS))

        headers = {
            "Accept": "application/json",
            "User-Agent": random_ua(),
        }

        try:
            async with httpx.AsyncClient(
                base_url=_BASE,
                headers=headers,
                timeout=DEFAULT_TIMEOUT_SEC,
                follow_redirects=True,
                **self._proxy_kwargs(),
            ) as client:
                # ── Profile ─────────────────────────────────────
                profile_resp = await client.get(
                    "/xrpc/app.bsky.actor.getProfile",
                    params={"actor": actor},
                )
                fail = self.classify_response(profile_resp, "getProfile")
                if fail is not None:
                    return fail
                try:
                    profile_raw = profile_resp.json()
                except Exception:
                    return ToolResult(
                        success=False, source=self.name,
                        error="bluesky_social: profile JSON parse failed",
                    )
                if not isinstance(profile_raw, dict) or not profile_raw.get("did"):
                    return ToolResult(
                        success=False, source=self.name,
                        error="bluesky_social: profile shape unexpected",
                    )

                self_did = profile_raw["did"]
                self_handle = profile_raw.get("handle") or actor

                profile = {
                    "did": self_did,
                    "handle": self_handle,
                    "displayName": profile_raw.get("displayName"),
                    "description": profile_raw.get("description"),
                    "avatar": profile_raw.get("avatar"),
                    "followersCount": profile_raw.get("followersCount"),
                    "followsCount": profile_raw.get("followsCount"),
                    "postsCount": profile_raw.get("postsCount"),
                    "createdAt": profile_raw.get("createdAt"),
                    "indexedAt": profile_raw.get("indexedAt"),
                }

                # ── Follows / Followers / Feed (parallel) ───────
                follows_task = client.get(
                    "/xrpc/app.bsky.graph.getFollows",
                    params={"actor": actor, "limit": max_follows},
                )
                followers_task = client.get(
                    "/xrpc/app.bsky.graph.getFollowers",
                    params={"actor": actor, "limit": max_followers},
                )
                feed_task = client.get(
                    "/xrpc/app.bsky.feed.getAuthorFeed",
                    params={"actor": actor, "limit": max_posts},
                )
                follows_resp, followers_resp, feed_resp = await asyncio.gather(
                    follows_task, followers_task, feed_task,
                    return_exceptions=True,
                )

        except Exception as exc:
            return ToolResult(
                success=False, source=self.name, error=str(exc),
            )

        follows = _parse_actor_list(follows_resp, "follows")[:max_follows]
        followers = _parse_actor_list(followers_resp, "followers")[:max_followers]
        interactions = _parse_feed_interactions(
            feed_resp, self_did=self_did,
        )

        repost_count = sum(
            1 for i in interactions if i["interaction_type"] == "repost"
        )
        reply_count = sum(
            1 for i in interactions if i["interaction_type"] == "reply"
        )
        mention_count = sum(
            1 for i in interactions if i["interaction_type"] == "mention"
        )
        quote_count = sum(
            1 for i in interactions if i["interaction_type"] == "quote"
        )

        data = {
            "actor": self_handle,
            "profile": profile,
            "follows": follows,
            "followers": followers,
            "interactions": interactions,
            "summary": {
                "follower_count": len(followers),
                "following_count": len(follows),
                "repost_count": repost_count,
                "reply_count": reply_count,
                "mention_count": mention_count,
                "quote_count": quote_count,
            },
        }

        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=(
                len(followers) + len(follows) + len(interactions)
            ),
        )


# ──────────────────────────────────────────────────────────────────────
# Internal parsers
# ──────────────────────────────────────────────────────────────────────


def _parse_actor_list(resp: Any, key: str) -> list[dict[str, Any]]:
    """Extract a trimmed actor list from a getFollows/getFollowers response.

    The Bluesky API wraps the array under ``follows`` or ``followers``;
    pass the right key in. Defensive against exceptions / non-2xx /
    JSON failures.
    """
    if isinstance(resp, BaseException):
        return []
    if not getattr(resp, "is_success", False):
        return []
    try:
        raw = resp.json() or {}
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    items = raw.get(key) or []
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        did = item.get("did")
        handle = item.get("handle")
        if not did and not handle:
            continue
        out.append({
            "did": did,
            "handle": handle,
            "displayName": item.get("displayName"),
        })
    return out


def _extract_did_from_at_uri(uri: str | None) -> str | None:
    """Pull the DID out of an ``at://`` URI.

    Example::

        at://did:plc:abc123/app.bsky.feed.post/3jzfcijpj2z2a
        → "did:plc:abc123"

    Returns None for malformed input.
    """
    if not uri or not isinstance(uri, str):
        return None
    m = _AT_URI_DID_RE.match(uri)
    return m.group("did") if m else None


def _parse_feed_interactions(
    resp: Any,
    *,
    self_did: str,
) -> list[dict[str, Any]]:
    """Extract repost / reply / mention / quote interactions from a
    getAuthorFeed response.

    For each feed item:
      - ``reason.$type == "...#reasonRepost"`` → emit "repost"
        directed at ``reason.by`` (the ORIGINAL author whose post
        was reposted by the crawled user).
      - ``record.reply.parent.uri`` present → emit "reply" directed
        at the DID parsed from the parent URI.
      - ``record.embed.record`` present and is a quote-embed →
        emit "quote" directed at the embed DID.
      - ``record.facets[*].features[*]`` of type
        ``app.bsky.richtext.facet#mention`` → emit "mention" for
        each (excluding self-mentions).

    Self-interactions are filtered out.
    """
    out: list[dict[str, Any]] = []
    if isinstance(resp, BaseException):
        return out
    if not getattr(resp, "is_success", False):
        return out
    try:
        raw = resp.json() or {}
    except Exception:
        return out
    if not isinstance(raw, dict):
        return out
    feed = raw.get("feed") or []
    if not isinstance(feed, list):
        return out

    for item in feed:
        if not isinstance(item, dict):
            continue
        post = item.get("post") or {}
        if not isinstance(post, dict):
            continue
        post_uri = post.get("uri")
        record = post.get("record") or {}
        if not isinstance(record, dict):
            record = {}
        created_at = record.get("createdAt")

        # ── Repost (reason on the feed item) ──
        reason = item.get("reason")
        if isinstance(reason, dict) and "reasonRepost" in (reason.get("$type") or ""):
            by = reason.get("by") or {}
            if isinstance(by, dict):
                target_did = by.get("did")
                if target_did and target_did != self_did:
                    out.append({
                        "interaction_type": "repost",
                        "target_did": target_did,
                        "target_handle": by.get("handle"),
                        "target_display": by.get("displayName"),
                        "last_observed": (
                            reason.get("indexedAt") or created_at
                        ),
                        "post_uri": post_uri,
                    })
            # Feed-item-as-repost: don't also scan its facets/replies
            # for the booster ── those belong to the ORIGINAL author.
            continue

        # ── Reply (record.reply.parent.uri → parent DID) ──
        reply = record.get("reply")
        reply_target_did: str | None = None
        if isinstance(reply, dict):
            parent = reply.get("parent")
            if isinstance(parent, dict):
                reply_target_did = _extract_did_from_at_uri(parent.get("uri"))
                if reply_target_did and reply_target_did != self_did:
                    out.append({
                        "interaction_type": "reply",
                        "target_did": reply_target_did,
                        "target_handle": None,  # not in payload
                        "target_display": None,
                        "last_observed": created_at,
                        "post_uri": post_uri,
                    })
                else:
                    reply_target_did = None  # self-reply, ignore

        # ── Quote (record.embed with embed.record) ──
        embed = record.get("embed")
        if isinstance(embed, dict):
            embed_type = (embed.get("$type") or "")
            if "app.bsky.embed.record" in embed_type:
                # Both #record and #recordWithMedia carry a "record" ref
                ref = embed.get("record") or {}
                if isinstance(ref, dict):
                    quote_did = _extract_did_from_at_uri(ref.get("uri"))
                    if quote_did and quote_did != self_did:
                        out.append({
                            "interaction_type": "quote",
                            "target_did": quote_did,
                            "target_handle": None,
                            "target_display": None,
                            "last_observed": created_at,
                            "post_uri": post_uri,
                        })

        # ── Mentions (facets) ──
        facets = record.get("facets") or []
        if isinstance(facets, list):
            for facet in facets:
                if not isinstance(facet, dict):
                    continue
                for feature in (facet.get("features") or []):
                    if not isinstance(feature, dict):
                        continue
                    ftype = feature.get("$type") or ""
                    if "richtext.facet#mention" not in ftype:
                        continue
                    mdid = feature.get("did")
                    if not mdid or mdid == self_did:
                        continue
                    if mdid == reply_target_did:
                        # Already captured as reply
                        continue
                    out.append({
                        "interaction_type": "mention",
                        "target_did": mdid,
                        "target_handle": None,
                        "target_display": None,
                        "last_observed": created_at,
                        "post_uri": post_uri,
                    })

    return out


# ──────────────────────────────────────────────────────────────────────
# Edge-extraction adapter
# ──────────────────────────────────────────────────────────────────────


def _resolve_bluesky_actor(
    identity_graph: IdentityGraph,
    handle: str | None,
    did: str | None,
    *,
    materialize_unknown: bool = True,
) -> str | None:
    """Map a Bluesky actor (handle and/or DID) to an identity_id.

    Lookup order: handle → DID. Stub identities materialize with
    whichever fields are available; handle gets service="Bluesky"
    and DID gets the IdentifierType.OTHER bucket so future tooling
    can still find it.
    """
    if not handle and not did:
        return None
    if handle:
        existing = identity_graph.by_identifier(handle)
        if existing is not None:
            return existing.identity_id
    if did:
        existing = identity_graph.by_identifier(did)
        if existing is not None:
            return existing.identity_id
    if not materialize_unknown:
        return None
    idents: list[Identifier] = []
    if handle:
        idents.append(Identifier(
            value=handle,
            identifier_type=IdentifierType.HANDLE,
            service="Bluesky",
            source="bluesky_social",
            confidence=0.6,
        ))
    if did:
        idents.append(Identifier(
            value=did,
            identifier_type=IdentifierType.OTHER,
            service="Bluesky",
            source="bluesky_social",
            confidence=0.7,  # DID is canonical, slightly higher trust
        ))
    if not idents:
        return None
    ident_id = derive_identity_id(idents)
    if ident_id in identity_graph:
        return ident_id
    stub = Identity(
        identity_id=ident_id,
        primary_label=handle or did or ident_id,
        identifiers=idents,
        metadata={"discovered_via": "bluesky_social"},
    )
    identity_graph.add_identity(stub)
    return ident_id


# Mapping interaction_type → INTERACTION_WEIGHTS key. Bluesky's "repost"
# corresponds to Mastodon's "boost" semantically (rebroadcast), and
# "quote" sits between repost and reply (commentary on someone else's
# content). Map to existing weight keys to keep the scoring axis
# consistent.
_BLUESKY_TYPE_WEIGHTS: dict[str, float] = {
    "repost":  INTERACTION_WEIGHTS.get("repost", 0.35),
    "reply":   INTERACTION_WEIGHTS.get("reply", 0.55),
    "mention": INTERACTION_WEIGHTS.get("mention", 0.40),
    "quote":   INTERACTION_WEIGHTS.get("reply", 0.55),  # commentary
}


def extract_edges_from_bluesky(
    raw_data: dict[str, Any],
    crawled_identity_id: str,
    identity_graph: IdentityGraph,
    *,
    materialize_unknown: bool = True,
) -> list[tuple[str, RelationshipEdge]]:
    """Convert ``BlueskySocialTool`` raw data into edge tuples.

    Direction conventions:

      - Followers list → ``follower → crawled`` (follower edge type)
      - Follows list   → ``crawled → followed`` (follower edge type)
      - Interactions   → ``crawled → target`` (repost / reply / mention / quote)

    Self-loops are dropped during parsing; the adapter is defensive
    too and skips any that slipped through.
    """
    edges: list[tuple[str, RelationshipEdge]] = []

    for follower in (raw_data.get("followers") or []):
        src_id = _resolve_bluesky_actor(
            identity_graph,
            follower.get("handle"),
            follower.get("did"),
            materialize_unknown=materialize_unknown,
        )
        if not src_id or src_id == crawled_identity_id:
            continue
        edges.append((src_id, RelationshipEdge(
            target_identity_id=crawled_identity_id,
            interaction_type="follower",
            strength=INTERACTION_WEIGHTS.get("follower", 0.2),
            last_observed=None,
            sources=["bluesky_social"],
        )))

    for followed in (raw_data.get("follows") or []):
        tgt_id = _resolve_bluesky_actor(
            identity_graph,
            followed.get("handle"),
            followed.get("did"),
            materialize_unknown=materialize_unknown,
        )
        if not tgt_id or tgt_id == crawled_identity_id:
            continue
        edges.append((crawled_identity_id, RelationshipEdge(
            target_identity_id=tgt_id,
            interaction_type="follower",
            strength=INTERACTION_WEIGHTS.get("follower", 0.2),
            last_observed=None,
            sources=["bluesky_social"],
        )))

    for inter in (raw_data.get("interactions") or []):
        itype = inter.get("interaction_type")
        if itype not in _BLUESKY_TYPE_WEIGHTS:
            continue
        tgt_id = _resolve_bluesky_actor(
            identity_graph,
            inter.get("target_handle"),
            inter.get("target_did"),
            materialize_unknown=materialize_unknown,
        )
        if not tgt_id or tgt_id == crawled_identity_id:
            continue
        edges.append((crawled_identity_id, RelationshipEdge(
            target_identity_id=tgt_id,
            interaction_type=itype,
            strength=_BLUESKY_TYPE_WEIGHTS[itype],
            last_observed=inter.get("last_observed"),
            sources=["bluesky_social"],
        )))

    return edges
