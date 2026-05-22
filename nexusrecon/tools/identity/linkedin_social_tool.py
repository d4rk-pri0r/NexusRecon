"""LinkedIn per-user social-graph crawler (Phase E5).

Mines a LinkedIn profile's public-facing social surface ── title
history, current role, recent posts (and their reactors / commenters),
skill endorsements, mentioned colleagues ── and produces the raw
observations Phase E11 will use to build :class:`RelationshipEdge`
entries.

Architectural posture (locked-in 2026-05-21):

  - **Aggressive unofficial wrapper.** Uses the ``linkedin-api`` PyPI
    library (tomquirk/linkedin-api). The signal is too valuable to
    leave on the table, and an officially-supported public API does
    not exist. Isolated to this single module so it can be swapped out
    cleanly if LinkedIn's legal posture or the library's reliability
    changes.
  - **Auth: BOTH modes accepted.** Cookies (``LINKEDIN_LI_AT`` +
    ``LINKEDIN_JSESSIONID``) are preferred ── the operator extracts
    them once from their browser session, ban risk is bounded to the
    cookie's lifetime, no captcha / 2FA flow to break. Falls back to
    username/password (``LINKEDIN_USERNAME`` + ``LINKEDIN_PASSWORD``)
    when cookies are not configured. Tool fails fast when neither
    pair is complete.
  - **Empty ``dynamic_trigger_hints``.** Tool runs only when an
    upstream phase explicitly invokes it (E11). The LLM dispatcher
    cannot fire LinkedIn calls mid-campaign and risk the operator's
    account.

linkedin-api is a synchronous library. Every network call is wrapped
in :func:`asyncio.to_thread` so the tool's ``run()`` stays async and
the surrounding event loop / OPSEC rate-limiter behaviour matches the
rest of the framework.

API methods used (linkedin-api 2.x):

  - ``get_profile(public_id)``                    — profile basics
  - ``get_profile_experiences(urn_id)``           — title history
  - ``get_profile_skills(public_id)``             — endorsements
  - ``get_profile_posts(public_id, post_count=N)``— recent activity
  - ``get_post_reactions(urn_id)`` (per post)     — who endorsed
  - ``get_post_comments(post_urn)`` (per post)    — who commented

Per-target hard caps:

  - 20 posts fetched
  - For the top 5 most recent posts: reactions + comments fetched
  - 30 commenter / reactor samples per post

Worst case ≈ 4 + 5×2 = 14 LinkedIn calls per target. With cookie
auth and default OPSEC rate-limiting this is safely under any
plausible per-session throttle.

Shape contract (``ToolResult.data``):

    {
        "handle": str,             # public_id we crawled
        "profile": {
            "publicIdentifier", "urn_id", "firstName", "lastName",
            "headline", "summary", "industryName", "locationName",
            "currentCompany", "currentTitle",
        },
        "experiences": [
            {"title", "companyName", "companyUrn",
             "timePeriod", "locationName"}, ...
        ],
        "skills": [{"name", "endorsement_count"}],
        "posts": [
            {
                "urn", "text", "createdAt",
                "reactions": [{"publicIdentifier", "name",
                                "reaction_type"}],
                "commenters": [{"publicIdentifier", "name",
                                 "comment_text", "createdAt"}],
                "mentioned": [{"publicIdentifier", "name"}],
            }, ...
        ],
        "summary": {
            "title_history_count", "skill_count", "post_count",
            "unique_commenters", "unique_reactors",
            "unique_mentioned",
        },
    }

Adapter: :func:`extract_edges_from_linkedin`.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

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
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

log = structlog.get_logger(__name__)

#: Per-target hard caps.
DEFAULT_MAX_POSTS = 20
DEFAULT_POSTS_TO_ENRICH = 5
DEFAULT_MAX_REACTIONS_PER_POST = 30
DEFAULT_MAX_COMMENTERS_PER_POST = 30
DEFAULT_MAX_SKILLS = 30

# Auth env-var names.
_ENV_LI_AT = "LINKEDIN_LI_AT"
_ENV_JSESSIONID = "LINKEDIN_JSESSIONID"
_ENV_USERNAME = "LINKEDIN_USERNAME"
_ENV_PASSWORD = "LINKEDIN_PASSWORD"


@register_tool
class LinkedInSocialTool(OSINTTool):
    name = "linkedin_social"
    tier = Tier.T0
    category = Category.SOCIAL
    # ``requires_keys`` has AND semantics ── it can't express
    # "cookies OR user/pass". We override ``is_available`` below.
    # We leave the list non-empty to signal in the registry listing
    # that this tool needs auth; the override does the real check.
    requires_keys: list[str] = [_ENV_LI_AT]
    description = (
        "LinkedIn per-user social graph — title history, recent posts, "
        "post reactors / commenters, skill endorsements, mentioned "
        "colleagues. Uses linkedin-api PyPI (cookies preferred, "
        "user/pass fallback). Feeds Phase E relationship graph + "
        "pretext scoring."
    )
    target_types = ["handle", "username", "identity"]
    # Live-test safety: empty hints means the dispatcher cannot fire
    # this tool. Account-ban risk is bounded to deliberate operator
    # invocation only.
    dynamic_trigger_hints: list[str] = []

    def is_available(self) -> bool:
        """True if EITHER cookies OR user/pass are configured.

        Overrides the base behaviour (which AND-s ``requires_keys``)
        because LinkedIn accepts either auth mode. Reads from config
        secrets so .env / TUI-managed values are honoured; falls back
        to ``os.environ`` so direct env-var setups also work.
        """
        if self._has_cookie_auth() or self._has_credential_auth():
            return True
        return False

    def _has_cookie_auth(self) -> bool:
        return bool(self._secret(_ENV_LI_AT)) and bool(self._secret(_ENV_JSESSIONID))

    def _has_credential_auth(self) -> bool:
        return bool(self._secret(_ENV_USERNAME)) and bool(self._secret(_ENV_PASSWORD))

    def _secret(self, name: str) -> str | None:
        """Read a secret from config (preferred) or env (fallback).

        The config wrapper accepts any case; env vars are upper-case
        canonical. Returns None when neither has the value.
        """
        v = self.config.get_secret(name)
        if v:
            return v
        return os.environ.get(name) or None

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        public_id = (target or "").lstrip("@").strip()
        if not public_id:
            return ToolResult(
                success=False, source=self.name,
                error="linkedin_social: empty handle",
            )

        if not self.is_available():
            return ToolResult(
                success=False, source=self.name,
                error=(
                    f"linkedin_social: no auth — set either "
                    f"{_ENV_LI_AT}+{_ENV_JSESSIONID} (preferred) or "
                    f"{_ENV_USERNAME}+{_ENV_PASSWORD}"
                ),
            )

        max_posts = int(kwargs.get("max_posts", DEFAULT_MAX_POSTS))
        posts_to_enrich = int(kwargs.get("posts_to_enrich", DEFAULT_POSTS_TO_ENRICH))
        max_reactions = int(kwargs.get(
            "max_reactions_per_post", DEFAULT_MAX_REACTIONS_PER_POST,
        ))
        max_commenters = int(kwargs.get(
            "max_commenters_per_post", DEFAULT_MAX_COMMENTERS_PER_POST,
        ))
        max_skills = int(kwargs.get("max_skills", DEFAULT_MAX_SKILLS))

        # ── Construct the linkedin-api client off the event loop ────
        try:
            client = await asyncio.to_thread(self._build_client)
        except Exception as exc:
            return ToolResult(
                success=False, source=self.name,
                error=f"linkedin_social: auth failed: {exc}",
            )

        # ── Profile ─────────────────────────────────────────────────
        try:
            profile_raw = await asyncio.to_thread(
                client.get_profile, public_id,
            )
        except Exception as exc:
            return ToolResult(
                success=False, source=self.name,
                error=f"linkedin_social: get_profile failed: {exc}",
            )

        if not isinstance(profile_raw, dict) or not profile_raw:
            return ToolResult(
                success=False, source=self.name,
                error=f"linkedin_social: profile {public_id!r} not found",
            )

        urn_id = _extract_urn_id(profile_raw)
        # Some linkedin-api responses expose URN directly; fall back to
        # an empty string so downstream code can guard with truthiness.

        profile = _trim_profile(profile_raw, urn_id=urn_id, public_id=public_id)

        # ── Experiences ─────────────────────────────────────────────
        experiences: list[dict[str, Any]] = []
        if urn_id:
            try:
                exp_raw = await asyncio.to_thread(
                    client.get_profile_experiences, urn_id,
                )
                experiences = _trim_experiences(exp_raw)
            except Exception as exc:
                log.debug("linkedin_social experiences fetch failed",
                          handle=public_id, error=str(exc))

        # ── Skills ──────────────────────────────────────────────────
        skills: list[dict[str, Any]] = []
        try:
            skills_raw = await asyncio.to_thread(
                client.get_profile_skills, public_id,
            )
            skills = _trim_skills(skills_raw, max_skills=max_skills)
        except Exception as exc:
            log.debug("linkedin_social skills fetch failed",
                      handle=public_id, error=str(exc))

        # ── Posts (recent) ──────────────────────────────────────────
        posts: list[dict[str, Any]] = []
        try:
            posts_raw = await asyncio.to_thread(
                client.get_profile_posts, public_id, None, max_posts,
            )
            posts = _trim_posts(posts_raw)
        except Exception as exc:
            log.debug("linkedin_social posts fetch failed",
                      handle=public_id, error=str(exc))

        # ── Per-post enrichment: reactions + comments ───────────────
        # Synchronous library + ban risk → run these sequentially.
        # The OPSEC rate-limiter applies at the registry level, so the
        # gap between the top-level run() invocations is throttled; we
        # don't double-throttle inside this method.
        for post in posts[:posts_to_enrich]:
            urn = post.get("urn")
            if not urn:
                continue
            try:
                reactions_raw = await asyncio.to_thread(
                    client.get_post_reactions, urn, max_reactions,
                )
                post["reactions"] = _trim_reactions(
                    reactions_raw, limit=max_reactions,
                )
            except Exception as exc:
                log.debug("linkedin_social reactions fetch failed",
                          urn=urn, error=str(exc))
            try:
                comments_raw = await asyncio.to_thread(
                    client.get_post_comments, urn, max_commenters,
                )
                post["commenters"] = _trim_comments(
                    comments_raw, limit=max_commenters,
                )
            except Exception as exc:
                log.debug("linkedin_social comments fetch failed",
                          urn=urn, error=str(exc))

        # ── Aggregate summary ───────────────────────────────────────
        unique_commenters: set[str] = set()
        unique_reactors: set[str] = set()
        unique_mentioned: set[str] = set()
        for post in posts:
            for c in post.get("commenters", []) or []:
                k = c.get("publicIdentifier") or c.get("name")
                if k and k != public_id:
                    unique_commenters.add(k)
            for r in post.get("reactions", []) or []:
                k = r.get("publicIdentifier") or r.get("name")
                if k and k != public_id:
                    unique_reactors.add(k)
            for m in post.get("mentioned", []) or []:
                k = m.get("publicIdentifier") or m.get("name")
                if k and k != public_id:
                    unique_mentioned.add(k)

        data = {
            "handle": public_id,
            "profile": profile,
            "experiences": experiences,
            "skills": skills,
            "posts": posts,
            "summary": {
                "title_history_count": len(experiences),
                "skill_count": len(skills),
                "post_count": len(posts),
                "unique_commenters": len(unique_commenters),
                "unique_reactors": len(unique_reactors),
                "unique_mentioned": len(unique_mentioned),
            },
        }

        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=(
                len(experiences) + len(skills) + len(posts)
                + len(unique_commenters) + len(unique_reactors)
                + len(unique_mentioned)
            ),
        )

    # ── Client construction ─────────────────────────────────────────

    def _build_client(self):
        """Build a ``linkedin_api.Linkedin`` client per the configured
        auth mode. Cookies take priority; user/pass is the fallback.

        Imported lazily so the tool module is importable even when the
        ``linkedin_api`` dep is missing (matters for the test
        environment + ``nexusrecon tools`` listing).
        """
        from linkedin_api import Linkedin  # noqa: PLC0415  (lazy import)

        if self._has_cookie_auth():
            li_at = self._secret(_ENV_LI_AT)
            jsessionid = self._secret(_ENV_JSESSIONID)
            cookies = _build_cookie_jar(li_at, jsessionid)
            # username/password are required positional args but unused
            # in cookie mode (see linkedin_api source).
            return Linkedin("", "", cookies=cookies, authenticate=True)

        username = self._secret(_ENV_USERNAME)
        password = self._secret(_ENV_PASSWORD)
        return Linkedin(username, password, authenticate=True)


# ──────────────────────────────────────────────────────────────────────
# URN-id extraction
# ──────────────────────────────────────────────────────────────────────


def _extract_urn_id(profile_raw: dict[str, Any]) -> str:
    """Best-effort extract the linkedin-api ``urn_id`` (member URN
    tail like ``ACoAA...``) from a get_profile payload.

    linkedin-api versions disagree on the field name and whether the
    value is the bare tail or a fully-qualified ``urn:li:...:tail``
    string. We try every common variant and strip the URN prefix.

    Returns ``""`` when no urn-like field is found ── callers guard
    with truthiness because get_profile_experiences requires this id.
    """
    if not isinstance(profile_raw, dict):
        return ""
    for key in ("profile_urn", "member_urn", "entityUrn", "urn", "profileUrn"):
        v = profile_raw.get(key)
        if not v or not isinstance(v, str):
            continue
        # Strip URN prefix forms.
        for prefix in (
            "urn:li:fs_miniProfile:",
            "urn:li:fsd_profile:",
            "urn:li:member:",
        ):
            if v.startswith(prefix):
                return v[len(prefix):]
        # Generic "urn:...:tail" → return tail.
        if v.startswith("urn:"):
            return v.rsplit(":", 1)[-1]
        # Bare value (already a tail).
        return v
    return ""


# ──────────────────────────────────────────────────────────────────────
# Cookie jar helper
# ──────────────────────────────────────────────────────────────────────


def _build_cookie_jar(li_at: str | None, jsessionid: str | None):
    """Build a ``RequestsCookieJar`` populated with the two cookies
    linkedin-api expects.

    Lazily imports ``requests`` because the module is otherwise only
    used by linkedin-api itself ── no point pulling it in at module
    load time for tools that never need it.
    """
    from requests.cookies import RequestsCookieJar  # noqa: PLC0415

    jar = RequestsCookieJar()
    if li_at:
        jar.set("li_at", li_at, domain=".linkedin.com", path="/")
    if jsessionid:
        # linkedin-api's _set_session_cookies pulls JSESSIONID from
        # session.cookies["JSESSIONID"] and strips surrounding quotes.
        # We supply it as the literal cookie value; if the operator
        # included quotes when copying from devtools, we accept them.
        jar.set("JSESSIONID", jsessionid, domain=".linkedin.com", path="/")
    return jar


# ──────────────────────────────────────────────────────────────────────
# Response-shape trimmers
# ──────────────────────────────────────────────────────────────────────


def _trim_profile(
    raw: dict[str, Any], *, urn_id: str, public_id: str,
) -> dict[str, Any]:
    """Extract the subset of profile fields E9 / E11 actually consume."""
    if not isinstance(raw, dict):
        return {"publicIdentifier": public_id, "urn_id": urn_id}

    # linkedin-api's get_profile flattens many nested fields. The
    # exact keys vary by library version ── we look up several
    # synonyms and fall through to None when nothing matches.
    current_company = (
        raw.get("companyName")
        or raw.get("company_name")
        or raw.get("currentCompany")
        or _first_experience_company(raw)
    )
    current_title = (
        raw.get("headline")
        or raw.get("title")
        or _first_experience_title(raw)
    )

    return {
        "publicIdentifier": raw.get("public_id") or public_id,
        "urn_id": urn_id,
        "firstName": raw.get("firstName") or raw.get("first_name"),
        "lastName": raw.get("lastName") or raw.get("last_name"),
        "headline": raw.get("headline"),
        "summary": raw.get("summary"),
        "industryName": raw.get("industryName") or raw.get("industry_name"),
        "locationName": (
            raw.get("locationName") or raw.get("location_name")
            or raw.get("geoLocationName")
        ),
        "currentCompany": current_company,
        "currentTitle": current_title,
    }


def _first_experience_title(raw: dict[str, Any]) -> str | None:
    exps = raw.get("experience") or []
    if isinstance(exps, list) and exps and isinstance(exps[0], dict):
        return exps[0].get("title")
    return None


def _first_experience_company(raw: dict[str, Any]) -> str | None:
    exps = raw.get("experience") or []
    if isinstance(exps, list) and exps and isinstance(exps[0], dict):
        return exps[0].get("companyName") or exps[0].get("company_name")
    return None


def _trim_experiences(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for exp in raw:
        if not isinstance(exp, dict):
            continue
        out.append({
            "title": exp.get("title"),
            "companyName": exp.get("companyName") or exp.get("company_name"),
            "companyUrn": exp.get("companyUrn") or exp.get("company_urn"),
            "timePeriod": exp.get("timePeriod") or exp.get("time_period"),
            "locationName": exp.get("locationName") or exp.get("location_name"),
            "description": exp.get("description"),
        })
    return out


def _trim_skills(raw: Any, *, max_skills: int) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for s in raw[:max_skills]:
        if not isinstance(s, dict):
            continue
        out.append({
            "name": s.get("name"),
            "endorsement_count": (
                s.get("endorsementCount")
                or s.get("endorsement_count") or 0
            ),
        })
    return out


def _trim_posts(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        # linkedin-api post shapes vary; we accept several aliases.
        urn = (
            p.get("urn")
            or p.get("update_urn")
            or p.get("entityUrn")
            or p.get("backendUrn")
        )
        text = (
            (p.get("commentary") or {}).get("text")
            if isinstance(p.get("commentary"), dict)
            else p.get("commentary")
        ) or p.get("text") or ""
        created = (
            p.get("createdAt") or p.get("created_at")
            or (p.get("actor") or {}).get("subDescription", {}).get("text")
            if isinstance(p.get("actor"), dict) else None
        )
        mentioned = _extract_mentions_from_post(p)
        out.append({
            "urn": urn,
            "text": text if isinstance(text, str) else "",
            "createdAt": created if isinstance(created, str) else None,
            "reactions": [],
            "commenters": [],
            "mentioned": mentioned,
        })
    return out


def _extract_mentions_from_post(post: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull mentioned profiles out of a post's commentary attributes.

    LinkedIn embeds mentions as ``attributes`` on the commentary
    field, each carrying a ``miniProfile`` reference. Shape varies
    across linkedin-api versions; we defensively look for any nested
    ``publicIdentifier`` markers.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    commentary = post.get("commentary")
    if isinstance(commentary, dict):
        attrs = commentary.get("attributes") or []
        if isinstance(attrs, list):
            for a in attrs:
                if not isinstance(a, dict):
                    continue
                mini = a.get("miniProfile") or {}
                if isinstance(mini, dict):
                    pid = mini.get("publicIdentifier")
                    if pid and pid not in seen:
                        seen.add(pid)
                        out.append({
                            "publicIdentifier": pid,
                            "name": (
                                f"{mini.get('firstName', '')} "
                                f"{mini.get('lastName', '')}"
                            ).strip(),
                        })
    return out


def _trim_reactions(raw: Any, *, limit: int) -> list[dict[str, Any]]:
    """Normalise post reactions into a flat list of reactor profiles."""
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for r in raw[:limit]:
        if not isinstance(r, dict):
            continue
        # linkedin-api shape: each reaction has actor info.
        actor = r.get("actor") or r.get("miniProfile") or {}
        if not isinstance(actor, dict):
            continue
        pid = (
            actor.get("publicIdentifier")
            or actor.get("public_identifier")
        )
        name = (
            actor.get("name")
            or (f"{actor.get('firstName', '')} "
                f"{actor.get('lastName', '')}").strip()
            or None
        )
        if not pid and not name:
            continue
        out.append({
            "publicIdentifier": pid,
            "name": name,
            "reaction_type": r.get("reactionType") or r.get("reaction_type"),
        })
    return out


def _trim_comments(raw: Any, *, limit: int) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for c in raw[:limit]:
        if not isinstance(c, dict):
            continue
        actor = c.get("commenter") or c.get("actor") or c.get("miniProfile") or {}
        if not isinstance(actor, dict):
            continue
        pid = (
            actor.get("publicIdentifier")
            or actor.get("public_identifier")
        )
        name = (
            actor.get("name")
            or (f"{actor.get('firstName', '')} "
                f"{actor.get('lastName', '')}").strip()
            or None
        )
        if not pid and not name:
            continue
        out.append({
            "publicIdentifier": pid,
            "name": name,
            "comment_text": (
                (c.get("commentary") or {}).get("text")
                if isinstance(c.get("commentary"), dict)
                else c.get("comment_text") or c.get("text")
            ),
            "createdAt": c.get("createdAt") or c.get("created_at"),
        })
    return out


# ──────────────────────────────────────────────────────────────────────
# Edge-extraction adapter
# ──────────────────────────────────────────────────────────────────────


def _resolve_linkedin_actor(
    identity_graph: IdentityGraph,
    public_id: str | None,
    name: str | None,
    *,
    materialize_unknown: bool = True,
) -> str | None:
    """Map a LinkedIn ``publicIdentifier`` (or display name) to an
    identity_id. Lookup order: public_id → name. Stub identities for
    unknowns carry service="LinkedIn"."""
    if not public_id and not name:
        return None
    if public_id:
        existing = identity_graph.by_identifier(public_id)
        if existing is not None:
            return existing.identity_id
    if name:
        existing = identity_graph.by_identifier(name)
        if existing is not None:
            return existing.identity_id
    if not materialize_unknown:
        return None
    idents: list[Identifier] = []
    if public_id:
        idents.append(Identifier(
            value=public_id,
            identifier_type=IdentifierType.HANDLE,
            service="LinkedIn",
            source="linkedin_social",
            confidence=0.7,  # public_id is canonical & stable on LI
        ))
    if name:
        idents.append(Identifier(
            value=name,
            identifier_type=IdentifierType.REAL_NAME,
            source="linkedin_social",
            confidence=0.5,
        ))
    if not idents:
        return None
    ident_id = derive_identity_id(idents)
    if ident_id in identity_graph:
        return ident_id
    stub = Identity(
        identity_id=ident_id,
        primary_label=public_id or name or ident_id,
        identifiers=idents,
        metadata={"discovered_via": "linkedin_social"},
    )
    identity_graph.add_identity(stub)
    return ident_id


def extract_edges_from_linkedin(
    raw_data: dict[str, Any],
    crawled_identity_id: str,
    identity_graph: IdentityGraph,
    *,
    materialize_unknown: bool = True,
) -> list[tuple[str, RelationshipEdge]]:
    """Convert ``LinkedInSocialTool`` raw data into edge tuples.

    Direction conventions:

      - **Commenters on crawled's posts** → ``commenter → crawled``
        (commenter took the action toward the crawled user).
      - **Reactors on crawled's posts** → ``reactor → crawled``
        (endorsement signal).
      - **Mentioned in crawled's posts** → ``crawled → mentioned``.
      - **Endorsers from skill list**: not always available per skill;
        when present, ``endorser → crawled`` (endorser endorsement
        type).

    Strength uses :data:`~nexusrecon.core.relationship_graph.INTERACTION_WEIGHTS`
    (``commenter`` 0.50, ``endorser`` 0.70, ``mention`` 0.40).
    """
    edges: list[tuple[str, RelationshipEdge]] = []
    crawled_public = raw_data.get("handle")

    for post in (raw_data.get("posts") or []):
        last_obs = post.get("createdAt")

        for commenter in (post.get("commenters") or []):
            pid = commenter.get("publicIdentifier")
            name = commenter.get("name")
            if pid and pid == crawled_public:
                continue
            src_id = _resolve_linkedin_actor(
                identity_graph, pid, name,
                materialize_unknown=materialize_unknown,
            )
            if not src_id or src_id == crawled_identity_id:
                continue
            edges.append((src_id, RelationshipEdge(
                target_identity_id=crawled_identity_id,
                interaction_type="commenter",
                strength=INTERACTION_WEIGHTS.get("commenter", 0.5),
                last_observed=last_obs,
                sources=["linkedin_social"],
            )))

        for reactor in (post.get("reactions") or []):
            pid = reactor.get("publicIdentifier")
            name = reactor.get("name")
            if pid and pid == crawled_public:
                continue
            src_id = _resolve_linkedin_actor(
                identity_graph, pid, name,
                materialize_unknown=materialize_unknown,
            )
            if not src_id or src_id == crawled_identity_id:
                continue
            edges.append((src_id, RelationshipEdge(
                target_identity_id=crawled_identity_id,
                interaction_type="endorser",
                strength=INTERACTION_WEIGHTS.get("endorser", 0.7),
                last_observed=last_obs,
                sources=["linkedin_social"],
            )))

        for mentioned in (post.get("mentioned") or []):
            pid = mentioned.get("publicIdentifier")
            name = mentioned.get("name")
            if pid and pid == crawled_public:
                continue
            tgt_id = _resolve_linkedin_actor(
                identity_graph, pid, name,
                materialize_unknown=materialize_unknown,
            )
            if not tgt_id or tgt_id == crawled_identity_id:
                continue
            edges.append((crawled_identity_id, RelationshipEdge(
                target_identity_id=tgt_id,
                interaction_type="mention",
                strength=INTERACTION_WEIGHTS.get("mention", 0.4),
                last_observed=last_obs,
                sources=["linkedin_social"],
            )))

    return edges
