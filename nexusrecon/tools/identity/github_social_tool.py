"""GitHub per-user social-graph crawler (Phase E2).

Crawls a GitHub user's public social surface and produces the raw
observations Phase E11 will turn into :class:`RelationshipEdge`
entries.

Distinct from the existing GitHub-flavoured tools:

  - ``github_recon`` (``tools/code/github_tool.py``) searches GitHub
    for secret leakage + code references to the campaign domains.
  - ``github_org_members`` (``tools/pretext/github_org_members_tool.py``)
    enumerates members of a GitHub *org*.
  - ``github_subdomains`` (``tools/domain/github_subdomains_tool.py``)
    pulls subdomain mentions out of public repos.

E2 operates at the per-USER level: given a confirmed handle, what
does their public social graph look like? Output feeds the Phase E
relationship graph + E9 pretext scoring.

Auth: ``GITHUB_TOKEN`` is required (raises the rate limit from 60/hr
to 5000/hr ── any meaningful crawl exhausts the unauthenticated cap
in seconds). The tool fails fast when the secret is absent
(``requires_keys``).

API endpoints used:

  - ``GET /users/{u}``                              — profile
  - ``GET /users/{u}/followers?per_page=N``         — followers of u
  - ``GET /users/{u}/following?per_page=N``         — who u follows
  - ``GET /users/{u}/repos?sort=updated&type=owner``— recent repos
  - ``GET /repos/{owner}/{repo}/collaborators``     — when access permits
  - ``GET /repos/{owner}/{repo}/commits?author=u``  — for co-author trailer parsing

Hard caps (per target):

  - 30 followers, 30 following
  - 5 most-recently-updated owned repos
  - 30 commits parsed per repo for co-author trailers
  - 10 collaborators per repo

Worst case ≈ 5 × (1 + 1) + 4 = ~14 calls (when collaborator endpoints
403 for non-owners we skip). With auth at 5000/hr the tool can crawl
~350 targets/hr safely.

Shape contract (``ToolResult.data``):

    {
        "username": str,
        "user_profile": {
            "login", "id", "name", "email", "company", "location",
            "bio", "blog", "public_repos", "followers", "following",
            "created_at", "updated_at",
        },
        "followers":  [{"login", "id", "avatar_url"}, ...],
        "following":  [{"login", "id", "avatar_url"}, ...],
        "repositories": [
            {
                "name", "full_name", "updated_at",
                "collaborators": [{"login", "id"}, ...],
                "co_authors":   [{"login", "name", "email",
                                   "commit_count", "last_observed"}, ...],
            }, ...
        ],
        "summary": {
            "follower_count", "following_count", "repo_count",
            "unique_co_authors", "unique_collaborators",
        },
    }

The :func:`extract_edges_from_github_social` adapter converts that
payload into ``(source_identity_id, RelationshipEdge)`` tuples ready
for :meth:`RelationshipGraph.add_edge`.

Dispatcher safety: ``dynamic_trigger_hints`` is intentionally empty.
The tool only fires when an upstream phase node invokes it (E11).
Adding hints would let the LLM dispatcher fire it mid-campaign before
E11 is wired, with no place to consume the output ── that would just
burn API budget.
"""
from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
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

_BASE = "https://api.github.com"

# Hard caps to bound campaign wall-clock and API spend.
DEFAULT_MAX_FOLLOWERS = 30
DEFAULT_MAX_FOLLOWING = 30
DEFAULT_MAX_REPOS = 5
DEFAULT_MAX_COMMITS_PER_REPO = 30
DEFAULT_MAX_COLLABORATORS_PER_REPO = 10
DEFAULT_TIMEOUT_SEC = 20.0

# RFC-compliant "Co-authored-by: Name <email>" trailer.
# Docs: https://docs.github.com/en/pull-requests/committing-changes-to-your-project/creating-and-editing-commits/creating-a-commit-with-multiple-authors
_CO_AUTHOR_RE = re.compile(
    r"^Co-authored-by:\s*(?P<name>[^<]+?)\s*<(?P<email>[^>]+)>",
    re.IGNORECASE | re.MULTILINE,
)


@register_tool
class GitHubSocialTool(BaseHTTPTool):
    name = "github_social"
    provider_label = "GitHub"
    tier = Tier.T0
    category = Category.SOCIAL
    requires_keys = ["github_token"]
    description = (
        "GitHub per-user social graph — followers, following, repo "
        "collaborators, commit co-authors. Feeds Phase E relationship "
        "graph + pretext scoring."
    )
    target_types = ["username", "handle", "identity"]
    # Intentionally empty: tool runs only when an upstream phase
    # explicitly invokes it. See module docstring for rationale.
    dynamic_trigger_hints: list[str] = []

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        token = self.config.get_secret("github_token")
        if not token:
            return ToolResult(
                success=False, source=self.name,
                error="GITHUB_TOKEN required for github_social",
            )

        username = (target or "").lstrip("@").strip()
        if not username:
            return ToolResult(
                success=False, source=self.name,
                error="github_social: empty username",
            )

        max_followers = int(kwargs.get("max_followers", DEFAULT_MAX_FOLLOWERS))
        max_following = int(kwargs.get("max_following", DEFAULT_MAX_FOLLOWING))
        max_repos = int(kwargs.get("max_repos", DEFAULT_MAX_REPOS))
        max_commits = int(kwargs.get("max_commits", DEFAULT_MAX_COMMITS_PER_REPO))
        max_collabs = int(kwargs.get(
            "max_collaborators", DEFAULT_MAX_COLLABORATORS_PER_REPO,
        ))

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": random_ua(),
        }

        try:
            async with httpx.AsyncClient(
                base_url=_BASE,
                headers=headers,
                timeout=DEFAULT_TIMEOUT_SEC,
                **self._proxy_kwargs(),
            ) as client:
                # ── Profile ─────────────────────────────────────
                profile_resp = await client.get(f"/users/{username}")
                fail = self.classify_response(profile_resp, "profile")
                if fail is not None:
                    return fail
                profile_raw = profile_resp.json()
                if not isinstance(profile_raw, dict):
                    return ToolResult(
                        success=False, source=self.name,
                        error="github_social: unexpected profile shape",
                    )

                user_profile = {
                    "login": profile_raw.get("login"),
                    "id": profile_raw.get("id"),
                    "name": profile_raw.get("name"),
                    "email": profile_raw.get("email"),
                    "company": profile_raw.get("company"),
                    "location": profile_raw.get("location"),
                    "bio": profile_raw.get("bio"),
                    "blog": profile_raw.get("blog"),
                    "public_repos": profile_raw.get("public_repos"),
                    "followers": profile_raw.get("followers"),
                    "following": profile_raw.get("following"),
                    "created_at": profile_raw.get("created_at"),
                    "updated_at": profile_raw.get("updated_at"),
                }

                # ── Followers + Following (parallel) ────────────
                fol_task = client.get(
                    f"/users/{username}/followers",
                    params={"per_page": max_followers},
                )
                fwg_task = client.get(
                    f"/users/{username}/following",
                    params={"per_page": max_following},
                )
                followers_resp, following_resp = await asyncio.gather(
                    fol_task, fwg_task, return_exceptions=True,
                )

                followers = _parse_user_list(followers_resp)[:max_followers]
                following = _parse_user_list(following_resp)[:max_following]

                # ── Recent owned repos ──────────────────────────
                repos_resp = await client.get(
                    f"/users/{username}/repos",
                    params={
                        "per_page": max_repos,
                        "sort": "updated",
                        "type": "owner",
                    },
                )
                repos_data: list[dict[str, Any]] = []
                if getattr(repos_resp, "is_success", False):
                    try:
                        raw_repos = repos_resp.json() or []
                    except Exception:
                        raw_repos = []
                    if isinstance(raw_repos, list):
                        for repo in raw_repos[:max_repos]:
                            if not isinstance(repo, dict):
                                continue
                            full_name = repo.get("full_name")
                            if not full_name:
                                continue
                            repos_data.append({
                                "name": repo.get("name"),
                                "full_name": full_name,
                                "updated_at": repo.get("updated_at"),
                                "collaborators": [],
                                "co_authors": [],
                            })

                # ── Per-repo enrichment ─────────────────────────
                async def _enrich(repo_record: dict[str, Any]) -> None:
                    full_name = repo_record["full_name"]
                    # Collaborators — 403 expected for non-owner repos,
                    # absorb silently. classify_response is intentionally
                    # NOT used here because 403 is a normal outcome and
                    # we don't want it to short-circuit the whole crawl.
                    try:
                        c_resp = await client.get(
                            f"/repos/{full_name}/collaborators",
                            params={"per_page": max_collabs},
                        )
                        if c_resp.status_code == 200:
                            try:
                                raw_collabs = c_resp.json() or []
                            except Exception:
                                raw_collabs = []
                            if isinstance(raw_collabs, list):
                                repo_record["collaborators"] = [
                                    {"login": c.get("login"),
                                     "id": c.get("id")}
                                    for c in raw_collabs[:max_collabs]
                                    if isinstance(c, dict) and c.get("login")
                                ]
                    except Exception as exc:
                        log.debug(
                            "github_social collaborators fetch failed",
                            repo=full_name, error=str(exc),
                        )

                    # Commits — co-author trailer parsing.
                    try:
                        commits_resp = await client.get(
                            f"/repos/{full_name}/commits",
                            params={
                                "author": username,
                                "per_page": max_commits,
                            },
                        )
                        if commits_resp.status_code == 200:
                            try:
                                raw_commits = commits_resp.json() or []
                            except Exception:
                                raw_commits = []
                            if isinstance(raw_commits, list):
                                repo_record["co_authors"] = (
                                    _extract_co_authors(raw_commits)
                                )
                    except Exception as exc:
                        log.debug(
                            "github_social commits fetch failed",
                            repo=full_name, error=str(exc),
                        )

                await asyncio.gather(
                    *(_enrich(r) for r in repos_data),
                    return_exceptions=True,
                )

        except Exception as exc:
            return ToolResult(
                success=False, source=self.name, error=str(exc),
            )

        # ── Summary ─────────────────────────────────────────────
        all_collabs: set[str] = set()
        all_co_authors: set[str] = set()
        for repo in repos_data:
            for c in repo["collaborators"]:
                login = c.get("login")
                if login and login != username:
                    all_collabs.add(login)
            for ca in repo["co_authors"]:
                key = ca.get("login") or ca.get("email")
                if key and key != username:
                    all_co_authors.add(key)

        data = {
            "username": username,
            "user_profile": user_profile,
            "followers": followers,
            "following": following,
            "repositories": repos_data,
            "summary": {
                "follower_count": len(followers),
                "following_count": len(following),
                "repo_count": len(repos_data),
                "unique_co_authors": len(all_co_authors),
                "unique_collaborators": len(all_collabs),
            },
        }

        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=(
                len(followers) + len(following)
                + len(all_collabs) + len(all_co_authors)
            ),
        )


# ──────────────────────────────────────────────────────────────────────
# Internal parsers
# ──────────────────────────────────────────────────────────────────────


def _parse_user_list(resp: Any) -> list[dict[str, Any]]:
    """Convert a GitHub user-list response into the trimmed shape.

    Defensive: handles exceptions from asyncio.gather, non-2xx
    responses, JSON parse failures, and non-list payloads by
    returning an empty list. Never raises.
    """
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
        login = item.get("login")
        if not login:
            continue
        out.append({
            "login": login,
            "id": item.get("id"),
            "avatar_url": item.get("avatar_url"),
        })
    return out


def _extract_co_authors(commits: list[Any]) -> list[dict[str, Any]]:
    """Parse "Co-authored-by:" trailers from a list of commit objects.

    Returns deduped list of ``{login, name, email, commit_count,
    last_observed}``. GitHub doesn't expose the co-author's login in
    the commit JSON (only the trailer name + email), so ``login`` is
    None ── the edge-extractor maps email → known identities when
    possible.

    Filters out noreply addresses (``noreply@github.com``,
    ``user@users.noreply.github.com``) ── those aren't real personal
    emails and don't represent actionable pretext signal.
    """
    by_email: dict[str, dict[str, Any]] = {}
    for c in commits:
        if not isinstance(c, dict):
            continue
        commit = c.get("commit") or {}
        if not isinstance(commit, dict):
            continue
        message = commit.get("message") or ""
        committed_at = ((commit.get("author") or {}).get("date") or "")
        for m in _CO_AUTHOR_RE.finditer(message):
            name = m.group("name").strip()
            email = m.group("email").strip().lower()
            if not email or "noreply" in email or "no-reply" in email:
                continue
            entry = by_email.get(email)
            if entry is None:
                by_email[email] = {
                    "login": None,
                    "name": name,
                    "email": email,
                    "commit_count": 1,
                    "last_observed": committed_at or None,
                }
                continue
            entry["commit_count"] += 1
            if committed_at and (
                entry["last_observed"] is None
                or committed_at > entry["last_observed"]
            ):
                entry["last_observed"] = committed_at
    return list(by_email.values())


# ──────────────────────────────────────────────────────────────────────
# Edge-extraction adapter
# ──────────────────────────────────────────────────────────────────────


def _resolve_handle(
    identity_graph: IdentityGraph,
    login: str | None,
    email: str | None = None,
    *,
    materialize_unknown: bool = True,
) -> str | None:
    """Map a GitHub handle (or email) to an identity_id.

    Lookup order: email → handle. When neither matches an existing
    identity and ``materialize_unknown`` is True, a stub Identity is
    added to the graph (handle confidence 0.6, personal-email
    confidence 0.5) so the social graph stays connected for E9
    scoring. Returns ``None`` when no resolution is possible.
    """
    if not login and not email:
        return None
    if email:
        existing = identity_graph.by_identifier(email)
        if existing is not None:
            return existing.identity_id
    if login:
        existing = identity_graph.by_identifier(login)
        if existing is not None:
            return existing.identity_id
    if not materialize_unknown:
        return None
    idents: list[Identifier] = []
    if login:
        idents.append(Identifier(
            value=login,
            identifier_type=IdentifierType.HANDLE,
            service="GitHub",
            source="github_social",
            confidence=0.6,
        ))
    if email:
        idents.append(Identifier(
            value=email,
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            source="github_social",
            confidence=0.5,
        ))
    if not idents:
        return None
    ident_id = derive_identity_id(idents)
    if ident_id in identity_graph:
        return ident_id
    stub = Identity(
        identity_id=ident_id,
        primary_label=login or email or ident_id,
        identifiers=idents,
        metadata={"discovered_via": "github_social"},
    )
    identity_graph.add_identity(stub)
    return ident_id


def extract_edges_from_github_social(
    raw_data: dict[str, Any],
    crawled_identity_id: str,
    identity_graph: IdentityGraph,
    *,
    materialize_unknown: bool = True,
    now_iso: str | None = None,
) -> list[tuple[str, RelationshipEdge]]:
    """Convert ``GitHubSocialTool`` raw data into edge tuples.

    Args:
        raw_data: The ``ToolResult.data`` payload.
        crawled_identity_id: Identity ID of the user whose handle was
            crawled (the "from" side for outbound edges).
        identity_graph: Used to resolve other handles / emails to
            existing identities. When ``materialize_unknown`` is True
            (the default) the graph is extended with stub identities
            for handles not yet present.
        materialize_unknown: When False, edges involving unknown
            handles are dropped instead of materialising stubs ──
            useful for tests and cases where the operator wants to
            keep the identity graph strictly bounded.
        now_iso: ``last_observed`` fallback for edges with no explicit
            timestamp (follower / following). Defaults to
            ``datetime.now(UTC)``.

    Returns:
        A list of ``(source_identity_id, RelationshipEdge)`` tuples.
        Some edges have ``crawled_identity_id`` as their source, some
        as their target (follower edges flip the direction). The
        caller passes each tuple to
        :meth:`RelationshipGraph.add_edge` to apply.
    """
    now_iso = now_iso or datetime.now(UTC).isoformat()
    edges: list[tuple[str, RelationshipEdge]] = []
    username = raw_data.get("username")

    # ── Followers: each follower → crawled (follower) ──────────────
    for follower in (raw_data.get("followers") or []):
        login = follower.get("login")
        if not login or login == username:
            continue
        src_id = _resolve_handle(
            identity_graph, login,
            materialize_unknown=materialize_unknown,
        )
        if not src_id:
            continue
        edges.append((src_id, RelationshipEdge(
            target_identity_id=crawled_identity_id,
            interaction_type="follower",
            strength=INTERACTION_WEIGHTS.get("follower", 0.2),
            last_observed=now_iso,
            sources=["github_social"],
        )))

    # ── Following: crawled → each followed (follower) ──────────────
    for followed in (raw_data.get("following") or []):
        login = followed.get("login")
        if not login or login == username:
            continue
        tgt_id = _resolve_handle(
            identity_graph, login,
            materialize_unknown=materialize_unknown,
        )
        if not tgt_id:
            continue
        edges.append((crawled_identity_id, RelationshipEdge(
            target_identity_id=tgt_id,
            interaction_type="follower",
            strength=INTERACTION_WEIGHTS.get("follower", 0.2),
            last_observed=now_iso,
            sources=["github_social"],
        )))

    # ── Repos: collaborators (bidirectional) + co-authors (bi) ──────
    for repo in (raw_data.get("repositories") or []):
        repo_ts = repo.get("updated_at") or now_iso
        for collab in (repo.get("collaborators") or []):
            login = collab.get("login")
            if not login or login == username:
                continue
            other_id = _resolve_handle(
                identity_graph, login,
                materialize_unknown=materialize_unknown,
            )
            if not other_id:
                continue
            edges.append((crawled_identity_id, RelationshipEdge(
                target_identity_id=other_id,
                interaction_type="collaborator",
                strength=INTERACTION_WEIGHTS.get("collaborator", 0.85),
                last_observed=repo_ts,
                sources=["github_social"],
            )))
            edges.append((other_id, RelationshipEdge(
                target_identity_id=crawled_identity_id,
                interaction_type="collaborator",
                strength=INTERACTION_WEIGHTS.get("collaborator", 0.85),
                last_observed=repo_ts,
                sources=["github_social"],
            )))

        for ca in (repo.get("co_authors") or []):
            login = ca.get("login")
            email = ca.get("email")
            if (login and login == username):
                continue
            other_id = _resolve_handle(
                identity_graph, login, email,
                materialize_unknown=materialize_unknown,
            )
            if not other_id:
                continue
            last_obs = ca.get("last_observed") or repo_ts
            edges.append((crawled_identity_id, RelationshipEdge(
                target_identity_id=other_id,
                interaction_type="co-author",
                strength=INTERACTION_WEIGHTS.get("co-author", 0.95),
                last_observed=last_obs,
                sources=["github_social"],
            )))
            edges.append((other_id, RelationshipEdge(
                target_identity_id=crawled_identity_id,
                interaction_type="co-author",
                strength=INTERACTION_WEIGHTS.get("co-author", 0.95),
                last_observed=last_obs,
                sources=["github_social"],
            )))

    return edges
