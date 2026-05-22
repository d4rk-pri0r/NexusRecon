"""Mastodon per-account social-graph crawler (Phase E3).

Mines the public ActivityPub graph for a single Mastodon account ──
followers, following, recent boosts / replies / mentions ── and
produces the raw observations Phase E11 will use to build
:class:`RelationshipEdge` entries.

Anonymous reads. Mastodon's public API is open: any instance with
default public-profile settings serves accounts.lookup,
accounts.{id}.followers, accounts.{id}.following, and
accounts.{id}.statuses without authentication.

Target format:

  - ``user@instance.example``  — full handle (preferred). Uses that
    instance as the API host.
  - ``user``                   — bare handle. The tool sequentially
    probes the default instance list until a match is found.

Default instance list (locked-in 2026-05-21):

    mastodon.social    — flagship / general-purpose
    hachyderm.io       — tech / SRE community
    infosec.exchange   — security researchers
    fosstodon.org      — OSS developers
    mas.to             — general-purpose
    tech.lgbt          — tech community with intersectional focus

LLM-driven expansion (per the architectural decision) is reserved for
``state["dispatch_mode"] == "full"`` and is handled by Phase E11 ──
not this tool. The tool keeps a stable, predictable behaviour out of
the box for live testing.

API endpoints used (all anonymous):

  - ``GET /api/v1/accounts/lookup?acct={handle}``
  - ``GET /api/v1/accounts/{id}/followers?limit=N``
  - ``GET /api/v1/accounts/{id}/following?limit=N``
  - ``GET /api/v1/accounts/{id}/statuses?limit=N``

Mastodon's ``statuses`` endpoint returns the actor's recent posts,
each carrying:

  - ``reblog`` (non-null on boosts → strong interaction signal)
  - ``in_reply_to_account_id`` + ``in_reply_to_id`` (replies)
  - ``mentions`` list (people @-mentioned in the post)

Shape contract (``ToolResult.data``):

    {
        "handle":   "user@instance",
        "instance": "instance.example",
        "account": {
            "id", "username", "acct", "display_name", "url",
            "followers_count", "following_count", "statuses_count",
            "created_at", "note", "fields": [...],
        },
        "followers":  [{"id", "acct", "display_name", "url"}, ...],
        "following":  [{"id", "acct", "display_name", "url"}, ...],
        "interactions": [
            {
                "interaction_type": "boost"|"reply"|"mention",
                "target_acct":      "other@instance",
                "target_display":   "Other User",
                "target_url":       "...",
                "last_observed":    "ISO-8601",
                "status_url":       "...",
            }, ...
        ],
        "summary": {
            "follower_count", "following_count",
            "boost_count", "reply_count", "mention_count",
        },
    }

Adapter: :func:`extract_edges_from_mastodon`.

Dispatcher safety: empty ``dynamic_trigger_hints`` ── tool only fires
when E11 explicitly invokes it.
"""
from __future__ import annotations

import asyncio
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

#: Hardcoded default instance probe list. Operators can override per
#: call via ``kwargs["instances"]``. The order matters: more-popular
#: instances first → faster typical resolution.
DEFAULT_INSTANCES: tuple[str, ...] = (
    "mastodon.social",
    "hachyderm.io",
    "infosec.exchange",
    "fosstodon.org",
    "mas.to",
    "tech.lgbt",
)

#: Per-target hard caps to bound campaign wall-clock.
DEFAULT_MAX_FOLLOWERS = 40
DEFAULT_MAX_FOLLOWING = 40
DEFAULT_MAX_STATUSES = 40
DEFAULT_TIMEOUT_SEC = 15.0


@register_tool
class MastodonSocialTool(BaseHTTPTool):
    name = "mastodon_social"
    provider_label = "Mastodon"
    tier = Tier.T0
    category = Category.SOCIAL
    # No keys required — public reads work on default Mastodon
    # config. Operators with API tokens can pass ``api_token=...``
    # via kwargs to raise per-instance rate limits.
    requires_keys: list[str] = []
    description = (
        "Mastodon per-account social graph — followers, following, "
        "boosts, replies, mentions across major instances. Feeds "
        "Phase E relationship graph + pretext scoring."
    )
    target_types = ["handle", "username", "identity"]
    dynamic_trigger_hints: list[str] = []

    # Mastodon instances commonly return 404 for "account not on this
    # instance" lookups — that's a normal probe outcome, NOT a tool
    # failure. classify_response should treat it as soft.
    soft_failure_codes: tuple[int, ...] = (404,)

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        handle, explicit_instance = _parse_target(target or "")
        if not handle:
            return ToolResult(
                success=False, source=self.name,
                error="mastodon_social: empty handle",
            )

        instances = _resolve_instance_list(
            explicit_instance, kwargs.get("instances"),
        )
        max_followers = int(kwargs.get("max_followers", DEFAULT_MAX_FOLLOWERS))
        max_following = int(kwargs.get("max_following", DEFAULT_MAX_FOLLOWING))
        max_statuses = int(kwargs.get("max_statuses", DEFAULT_MAX_STATUSES))
        api_token: str | None = kwargs.get("api_token")

        headers = {
            "Accept": "application/json",
            "User-Agent": random_ua(),
        }
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"

        # ── Sequential probe: stop at first instance that finds the account.
        found_instance: str | None = None
        account: dict[str, Any] | None = None

        for instance in instances:
            try:
                async with httpx.AsyncClient(
                    base_url=f"https://{instance}",
                    headers=headers,
                    timeout=DEFAULT_TIMEOUT_SEC,
                    follow_redirects=True,
                    **self._proxy_kwargs(),
                ) as client:
                    resp = await client.get(
                        "/api/v1/accounts/lookup",
                        params={"acct": handle},
                    )
                    # 404 = "not on this instance" → keep probing
                    fail = self.classify_response(resp, "lookup")
                    if fail is not None:
                        # 401/403/429/5xx → don't keep banging this
                        # instance; try the next.
                        log.debug(
                            "mastodon_social lookup error",
                            instance=instance, error=fail.error,
                        )
                        continue
                    if resp.status_code == 404:
                        continue
                    try:
                        body = resp.json()
                    except Exception:
                        continue
                    if not isinstance(body, dict) or not body.get("id"):
                        continue
                    found_instance = instance
                    account = body
                    break
            except Exception as exc:
                log.debug(
                    "mastodon_social probe failed",
                    instance=instance, handle=handle, error=str(exc),
                )
                continue

        if not found_instance or not account:
            return ToolResult(
                success=False,
                source=self.name,
                error=(
                    f"mastodon_social: handle {handle!r} not found on any "
                    f"of {len(instances)} probed instances"
                ),
            )

        account_id = str(account["id"])

        # ── Fetch followers / following / statuses in parallel ──
        try:
            async with httpx.AsyncClient(
                base_url=f"https://{found_instance}",
                headers=headers,
                timeout=DEFAULT_TIMEOUT_SEC,
                follow_redirects=True,
                **self._proxy_kwargs(),
            ) as client:
                f_task = client.get(
                    f"/api/v1/accounts/{account_id}/followers",
                    params={"limit": max_followers},
                )
                fwg_task = client.get(
                    f"/api/v1/accounts/{account_id}/following",
                    params={"limit": max_following},
                )
                s_task = client.get(
                    f"/api/v1/accounts/{account_id}/statuses",
                    params={"limit": max_statuses, "exclude_replies": "false"},
                )
                followers_resp, following_resp, statuses_resp = (
                    await asyncio.gather(
                        f_task, fwg_task, s_task, return_exceptions=True,
                    )
                )
        except Exception as exc:
            return ToolResult(
                success=False, source=self.name, error=str(exc),
            )

        followers = _parse_account_list(followers_resp)[:max_followers]
        following = _parse_account_list(following_resp)[:max_following]
        interactions = _parse_statuses_interactions(
            statuses_resp, self_id=account_id,
        )

        boost_count = sum(
            1 for i in interactions if i["interaction_type"] == "boost"
        )
        reply_count = sum(
            1 for i in interactions if i["interaction_type"] == "reply"
        )
        mention_count = sum(
            1 for i in interactions if i["interaction_type"] == "mention"
        )

        data = {
            "handle": handle if "@" in handle else f"{handle}@{found_instance}",
            "instance": found_instance,
            "account": {
                "id": account_id,
                "username": account.get("username"),
                "acct": account.get("acct"),
                "display_name": account.get("display_name"),
                "url": account.get("url"),
                "followers_count": account.get("followers_count"),
                "following_count": account.get("following_count"),
                "statuses_count": account.get("statuses_count"),
                "created_at": account.get("created_at"),
                "note": account.get("note"),
                "fields": account.get("fields") or [],
            },
            "followers": followers,
            "following": following,
            "interactions": interactions,
            "summary": {
                "follower_count": len(followers),
                "following_count": len(following),
                "boost_count": boost_count,
                "reply_count": reply_count,
                "mention_count": mention_count,
            },
        }

        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=(
                len(followers) + len(following) + len(interactions)
            ),
        )


# ──────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────


def _parse_target(target: str) -> tuple[str, str | None]:
    """Split ``user@instance`` into ``(user_or_full_handle, instance)``.

    Returns ``("user", "instance")`` for full handles, or
    ``("user", None)`` for bare handles. Leading ``@`` is tolerated.
    """
    t = target.strip().lstrip("@").strip()
    if not t:
        return ("", None)
    if "@" in t:
        user_part, _, instance = t.partition("@")
        instance = instance.strip().lower() or None
        if not user_part:
            return ("", instance)
        return (t, instance)
    return (t, None)


def _resolve_instance_list(
    explicit: str | None,
    override: Any,
) -> list[str]:
    """Build the ordered probe list.

    Priority:
      1. ``explicit`` from a full ``user@instance`` handle.
      2. ``override`` kwarg (a list of instance hostnames).
      3. :data:`DEFAULT_INSTANCES`.

    The list is deduplicated while preserving order so an explicit
    instance can be followed by the defaults as a fallback.
    """
    if explicit:
        # Explicit instance wins; fall through to defaults if it 404s,
        # but operators usually want the explicit-only behavior. Trade-
        # off: a more lenient default = better recall on accounts that
        # migrated between instances.
        return [explicit]
    if override and isinstance(override, (list, tuple)):
        clean: list[str] = []
        seen: set[str] = set()
        for inst in override:
            if not isinstance(inst, str):
                continue
            host = inst.strip().lower()
            if host and host not in seen:
                seen.add(host)
                clean.append(host)
        if clean:
            return clean
    return list(DEFAULT_INSTANCES)


def _parse_account_list(resp: Any) -> list[dict[str, Any]]:
    """Convert an accounts-list response into the trimmed shape."""
    if isinstance(resp, BaseException):
        return []
    if not getattr(resp, "is_success", False):
        return []
    try:
        raw = resp.json() or []
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        acct = item.get("acct")
        if not acct:
            continue
        out.append({
            "id": str(item.get("id")) if item.get("id") is not None else None,
            "acct": acct,
            "display_name": item.get("display_name"),
            "url": item.get("url"),
        })
    return out


def _parse_statuses_interactions(
    resp: Any,
    *,
    self_id: str,
) -> list[dict[str, Any]]:
    """Extract boost / reply / mention interactions from a statuses
    response.

    For each status:
      - If ``reblog`` is non-null → emit a "boost" interaction
        (crawled-user boosted ``reblog.account``).
      - If ``in_reply_to_account_id`` is set and is NOT the crawled
        account → emit a "reply" interaction.
      - For each mention NOT pointing at the crawled account →
        emit a "mention" interaction.

    Self-replies and self-mentions are dropped (they're not pretext
    signal).
    """
    out: list[dict[str, Any]] = []
    if isinstance(resp, BaseException):
        return out
    if not getattr(resp, "is_success", False):
        return out
    try:
        raw = resp.json() or []
    except Exception:
        return out
    if not isinstance(raw, list):
        return out

    for status in raw:
        if not isinstance(status, dict):
            continue
        status_url = status.get("url")
        created_at = status.get("created_at")

        # ── Boost ──
        reblog = status.get("reblog")
        if isinstance(reblog, dict):
            reb_acc = reblog.get("account") or {}
            if isinstance(reb_acc, dict):
                target_id = str(reb_acc.get("id")) if reb_acc.get("id") is not None else None
                if target_id and target_id != self_id:
                    out.append({
                        "interaction_type": "boost",
                        "target_acct": reb_acc.get("acct"),
                        "target_id": target_id,
                        "target_display": reb_acc.get("display_name"),
                        "target_url": reb_acc.get("url"),
                        "last_observed": reblog.get("created_at") or created_at,
                        "status_url": status_url,
                    })
            # A boosted status doesn't carry its own reply / mention
            # context for the booster, so stop here.
            continue

        # ── Reply ──
        reply_to = status.get("in_reply_to_account_id")
        if reply_to is not None and str(reply_to) != self_id:
            # Mastodon's API doesn't include the full target account
            # inline; the operator only gets the id. Use the first
            # mention in the status as a best-effort label.
            mentions = status.get("mentions") or []
            target_label = None
            target_url = None
            target_acct = None
            for m in mentions:
                if isinstance(m, dict) and str(m.get("id")) == str(reply_to):
                    target_label = m.get("username")
                    target_acct = m.get("acct")
                    target_url = m.get("url")
                    break
            out.append({
                "interaction_type": "reply",
                "target_acct": target_acct,
                "target_id": str(reply_to),
                "target_display": target_label,
                "target_url": target_url,
                "last_observed": created_at,
                "status_url": status_url,
            })

        # ── Mentions (excluding the reply target above) ──
        for m in (status.get("mentions") or []):
            if not isinstance(m, dict):
                continue
            mid = str(m.get("id")) if m.get("id") is not None else None
            if not mid or mid == self_id:
                continue
            if reply_to is not None and mid == str(reply_to):
                # Already captured as "reply" above
                continue
            out.append({
                "interaction_type": "mention",
                "target_acct": m.get("acct"),
                "target_id": mid,
                "target_display": m.get("username"),
                "target_url": m.get("url"),
                "last_observed": created_at,
                "status_url": status_url,
            })

    return out


# ──────────────────────────────────────────────────────────────────────
# Edge-extraction adapter
# ──────────────────────────────────────────────────────────────────────


def _resolve_mastodon_account(
    identity_graph: IdentityGraph,
    acct: str | None,
    *,
    materialize_unknown: bool = True,
) -> str | None:
    """Map a Mastodon ``acct`` (``user@instance``) to an identity_id.

    Looks up existing identities by the full acct string first, then
    falls back to bare-username matching when the acct has no
    instance suffix. When no match and ``materialize_unknown`` is
    True, creates a stub Identity tagged with service="Mastodon".
    """
    if not acct:
        return None
    acct = acct.strip().lstrip("@")
    if not acct:
        return None
    existing = identity_graph.by_identifier(acct)
    if existing is not None:
        return existing.identity_id
    if not materialize_unknown:
        return None
    ident = Identifier(
        value=acct,
        identifier_type=IdentifierType.HANDLE,
        service="Mastodon",
        source="mastodon_social",
        confidence=0.6,
    )
    ident_id = derive_identity_id([ident])
    if ident_id in identity_graph:
        return ident_id
    stub = Identity(
        identity_id=ident_id,
        primary_label=acct,
        identifiers=[ident],
        metadata={"discovered_via": "mastodon_social"},
    )
    identity_graph.add_identity(stub)
    return ident_id


def extract_edges_from_mastodon(
    raw_data: dict[str, Any],
    crawled_identity_id: str,
    identity_graph: IdentityGraph,
    *,
    materialize_unknown: bool = True,
) -> list[tuple[str, RelationshipEdge]]:
    """Convert ``MastodonSocialTool`` raw data into edge tuples.

    Direction conventions:

      - Followers list: each entry → ``follower → crawled``.
      - Following list: each entry → ``crawled → following`` with
        interaction_type ``follower`` (crawled-user "follows" them).
      - Interactions:
          - boost   → ``crawled → target_acct`` (boost)
          - reply   → ``crawled → target_acct`` (reply)
          - mention → ``crawled → target_acct`` (mention)

    Strength uses :data:`~nexusrecon.core.relationship_graph.INTERACTION_WEIGHTS`
    defaults.
    """
    edges: list[tuple[str, RelationshipEdge]] = []

    for follower in (raw_data.get("followers") or []):
        acct = follower.get("acct")
        src_id = _resolve_mastodon_account(
            identity_graph, acct,
            materialize_unknown=materialize_unknown,
        )
        if not src_id:
            continue
        edges.append((src_id, RelationshipEdge(
            target_identity_id=crawled_identity_id,
            interaction_type="follower",
            strength=INTERACTION_WEIGHTS.get("follower", 0.2),
            last_observed=None,  # Mastodon doesn't expose follow-date
            sources=["mastodon_social"],
        )))

    for followed in (raw_data.get("following") or []):
        acct = followed.get("acct")
        tgt_id = _resolve_mastodon_account(
            identity_graph, acct,
            materialize_unknown=materialize_unknown,
        )
        if not tgt_id:
            continue
        edges.append((crawled_identity_id, RelationshipEdge(
            target_identity_id=tgt_id,
            interaction_type="follower",
            strength=INTERACTION_WEIGHTS.get("follower", 0.2),
            last_observed=None,
            sources=["mastodon_social"],
        )))

    for inter in (raw_data.get("interactions") or []):
        itype = inter.get("interaction_type")
        if itype not in ("boost", "reply", "mention"):
            continue
        target_acct = inter.get("target_acct")
        if not target_acct:
            continue
        tgt_id = _resolve_mastodon_account(
            identity_graph, target_acct,
            materialize_unknown=materialize_unknown,
        )
        if not tgt_id:
            continue
        weight = INTERACTION_WEIGHTS.get(itype, 0.4)
        edges.append((crawled_identity_id, RelationshipEdge(
            target_identity_id=tgt_id,
            interaction_type=itype,
            strength=weight,
            last_observed=inter.get("last_observed"),
            sources=["mastodon_social"],
        )))

    return edges
