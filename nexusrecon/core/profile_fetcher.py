"""
Profile-page fetching for attribution corroboration.

Phase A's attribution scorer had a ``profile_coherence`` signal that
returned 0.0 for almost every hit because maigret doesn't extract bio
text. Phase B closes that gap: for hits that landed in HIGH or MEDIUM
confidence bands, fetch the profile page and parse it for
corroborating evidence (bio mentions employer, location matches,
display name matches harvested name, linked-account references).

The fetcher uses provider-specific APIs where they're available
unauthenticated:

  - **GitHub**: ``api.github.com/users/{login}`` ── returns bio,
    location, blog, company. Rate-limited to 60 req/hour without auth.
  - **GitLab**: ``gitlab.com/api/v4/users?username={login}`` ── public
    profile fields.
  - **Reddit**: ``reddit.com/user/{name}/about.json`` ── karma,
    subreddits, account-creation timestamp.
  - **Stack Overflow**: Stack Exchange API ── reputation, badges,
    associated accounts (powerful for cross-service identity).
  - **Generic fallback**: fetch the HTML, extract ``<meta name=
    "description">`` and Open Graph ``og:description``, ``og:title``.

All requests honour ``opsec.context.proxy_kwargs`` so the campaign
proxy is respected. UA rotates per fetch via ``random_ua()``. Errors
are returned in the ``ProfileData.error`` field rather than raised ──
one failed fetch can't bring down the whole re-scoring loop.

Fetches are cheap (~50-500ms each on average) but rate-limited by
the providers, so callers should cap concurrency at ~5 simultaneous
fetches.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
import structlog

from nexusrecon.opsec.context import proxy_kwargs
from nexusrecon.opsec.useragent import random_ua

log = structlog.get_logger(__name__)


@dataclass
class ProfileData:
    """Normalised profile data across services.

    Not every field is populated for every service. Fields are ``None``
    when the service doesn't expose them or extraction failed. Callers
    should treat absent fields as "no signal here," not as "definitely
    empty."
    """

    service: str = ""
    username: str = ""
    url: str = ""

    # Identity fields used by attribution scoring.
    display_name: Optional[str] = None
    bio: Optional[str] = None
    location: Optional[str] = None
    company: Optional[str] = None
    blog_url: Optional[str] = None
    email: Optional[str] = None  # sometimes exposed by GitHub/GitLab

    # Temporal signals (Phase C2 ── timeline clustering).
    created_at: Optional[str] = None
    last_active: Optional[str] = None

    # Reputation / activity signals (Phase C3 ── reputation-weighted
    # scoring). Per-service interpretation lives in the attribution
    # scorer; this field just carries the raw numbers across.
    reputation: Optional[float] = None         # SO rep, Reddit karma, etc.
    follower_count: Optional[int] = None       # GitHub followers, etc.

    # Linked-account references extracted from bio/blog (B4).
    linked_accounts: List[Dict[str, str]] = field(default_factory=list)

    # Avatar URL for Phase C1 cross-service image hashing.
    avatar_url: Optional[str] = None

    # Service-specific raw blob for the agent to read when needed.
    raw_extras: Dict[str, Any] = field(default_factory=dict)

    # When the fetch failed.
    error: Optional[str] = None
    fetched: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe dict suitable for ToolResult.data fields."""
        return {
            "service": self.service,
            "username": self.username,
            "url": self.url,
            "display_name": self.display_name,
            "bio": self.bio,
            "location": self.location,
            "company": self.company,
            "blog_url": self.blog_url,
            "email": self.email,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "reputation": self.reputation,
            "follower_count": self.follower_count,
            "avatar_url": self.avatar_url,
            "linked_accounts": self.linked_accounts,
            "raw_extras": self.raw_extras,
            "fetched": self.fetched,
            "error": self.error,
        }

    def coherence_blob(self) -> str:
        """Concatenated string of identity fields suitable for keyword
        scanning (the attribution scorer uses this for bio/employer
        matching). Joins bio + location + company + display_name into
        a single lowercase string."""
        parts: List[str] = []
        for field_value in (self.display_name, self.bio, self.location, self.company, self.blog_url):
            if field_value:
                parts.append(str(field_value))
        return " ".join(parts).lower()


# ── HTTP helper ──────────────────────────────────────────────────────


async def _http_get_json(url: str, timeout: float = 8.0) -> Optional[Dict[str, Any]]:
    """Fetch a URL expecting JSON. Returns ``None`` on error.

    Uses the campaign proxy (via ``proxy_kwargs``) and a rotated UA.
    Errors are swallowed because individual provider failures must not
    bring down the re-scoring loop ── the caller treats absent profile
    data as "no additional signal," not as "tool failed."
    """
    headers = {
        "User-Agent": random_ua(),
        "Accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
            **proxy_kwargs(),
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            return resp.json()
    except Exception as exc:
        log.debug("profile_fetcher JSON fetch failed", url=url, error=str(exc))
        return None


async def _http_get_text(url: str, timeout: float = 8.0) -> Optional[str]:
    """Fetch a URL expecting HTML/text. Returns ``None`` on error."""
    headers = {
        "User-Agent": random_ua(),
        "Accept": "text/html,application/xhtml+xml",
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
            **proxy_kwargs(),
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            return resp.text
    except Exception as exc:
        log.debug("profile_fetcher text fetch failed", url=url, error=str(exc))
        return None


# ── Per-service fetchers ─────────────────────────────────────────────


async def _fetch_github(username: str) -> ProfileData:
    """GitHub's public users API exposes everything we want without
    auth (subject to a 60 req/hr rate limit, which is plenty for the
    framework's confidence-band-filtered re-scoring loop)."""
    data = await _http_get_json(f"https://api.github.com/users/{username}")
    if not data:
        return ProfileData(
            service="GitHub", username=username,
            url=f"https://github.com/{username}",
            error="GitHub API returned non-200 or network error",
        )
    return ProfileData(
        service="GitHub",
        username=username,
        url=data.get("html_url") or f"https://github.com/{username}",
        display_name=data.get("name"),
        bio=data.get("bio"),
        location=data.get("location"),
        company=data.get("company"),
        blog_url=data.get("blog"),
        email=data.get("email"),
        created_at=data.get("created_at"),
        last_active=data.get("updated_at"),
        # Phase C: GitHub followers is the reputation proxy ── high
        # follower count signals real-engineer activity.
        follower_count=data.get("followers"),
        avatar_url=data.get("avatar_url"),
        raw_extras={
            "public_repos": data.get("public_repos"),
            "followers": data.get("followers"),
            "twitter_username": data.get("twitter_username"),
        },
        fetched=True,
    )


async def _fetch_gitlab(username: str) -> ProfileData:
    """GitLab's users-by-username endpoint returns a single-element
    list (or 404). Lighter than GitHub's data but covers bio + company."""
    data = await _http_get_json(f"https://gitlab.com/api/v4/users?username={username}")
    if not data or not isinstance(data, list) or not data:
        return ProfileData(
            service="GitLab", username=username,
            url=f"https://gitlab.com/{username}",
            error="GitLab API returned non-200 or empty result",
        )
    entry = data[0]
    return ProfileData(
        service="GitLab",
        username=username,
        url=entry.get("web_url") or f"https://gitlab.com/{username}",
        display_name=entry.get("name"),
        bio=entry.get("bio"),
        location=entry.get("location"),
        company=entry.get("organization") or entry.get("work_information"),
        blog_url=entry.get("website_url"),
        email=entry.get("public_email"),
        created_at=entry.get("created_at"),
        avatar_url=entry.get("avatar_url"),
        raw_extras={
            "job_title": entry.get("job_title"),
            "linkedin": entry.get("linkedin"),
            "twitter": entry.get("twitter"),
        },
        fetched=True,
    )


async def _fetch_reddit(username: str) -> ProfileData:
    """Reddit's public about.json endpoint. Subject to Reddit's
    aggressive bot detection ── a UA without a unique app identifier
    can get 429'd. We use the rotation pool, which is fine for small
    fetch volumes but should be respected."""
    data = await _http_get_json(f"https://www.reddit.com/user/{username}/about.json")
    if not data or "data" not in data:
        return ProfileData(
            service="Reddit", username=username,
            url=f"https://reddit.com/u/{username}",
            error="Reddit returned non-200, empty, or 429",
        )
    entry = data["data"]
    # Reddit reputation: comment + link karma combined is the
    # standard "old-Reddit" reputation proxy. Treat as a single
    # number for cross-service comparison.
    total_karma = (entry.get("comment_karma") or 0) + (entry.get("link_karma") or 0)
    # Reddit's avatar lives under subreddit.icon_img usually, sometimes
    # at top-level icon_img. Many users keep the default snoo which
    # gets caught by the identicon filter.
    avatar = (
        entry.get("subreddit", {}).get("icon_img")
        or entry.get("icon_img")
        or entry.get("snoovatar_img")
    )
    return ProfileData(
        service="Reddit",
        username=username,
        url=f"https://reddit.com/u/{username}",
        display_name=entry.get("subreddit", {}).get("title"),
        bio=entry.get("subreddit", {}).get("public_description"),
        created_at=str(entry.get("created_utc")) if entry.get("created_utc") else None,
        reputation=float(total_karma) if total_karma else None,
        avatar_url=avatar,
        raw_extras={
            "comment_karma": entry.get("comment_karma"),
            "link_karma": entry.get("link_karma"),
            "is_employee": entry.get("is_employee"),
            "verified": entry.get("verified"),
        },
        fetched=True,
    )


async def _fetch_stack_exchange(username: str) -> ProfileData:
    """Stack Exchange API lookup by display name. The display name
    isn't guaranteed to match the maigret-discovered handle, so this
    is best-effort. Stack Exchange exposes the strongest cross-account
    identity graph on the web ── one Stack Exchange user maps to N
    Stack Overflow / Server Fault / etc. accounts via account_id."""
    data = await _http_get_json(
        f"https://api.stackexchange.com/2.3/users?inname={username}"
        "&site=stackoverflow&pagesize=1"
    )
    if not data or not data.get("items"):
        return ProfileData(
            service="StackOverflow", username=username,
            url=f"https://stackoverflow.com/users/?tab=Users&q={username}",
            error="Stack Exchange API returned empty",
        )
    entry = data["items"][0]
    return ProfileData(
        service="StackOverflow",
        username=username,
        url=entry.get("link") or "",
        display_name=entry.get("display_name"),
        location=entry.get("location"),
        blog_url=entry.get("website_url"),
        created_at=str(entry.get("creation_date")) if entry.get("creation_date") else None,
        last_active=str(entry.get("last_access_date")) if entry.get("last_access_date") else None,
        # Stack Exchange reputation is the canonical signal here ──
        # >1k rep is a real engineer, >10k is significant activity.
        reputation=float(entry.get("reputation") or 0) or None,
        avatar_url=entry.get("profile_image"),
        raw_extras={
            "reputation": entry.get("reputation"),
            "account_id": entry.get("account_id"),  # cross-SE identity key
            "user_type": entry.get("user_type"),
        },
        fetched=True,
    )


# ── Generic HTML fallback ────────────────────────────────────────────


_META_DESC_RE = re.compile(
    r'<meta\s+[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_OG_DESC_RE = re.compile(
    r'<meta\s+[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_OG_TITLE_RE = re.compile(
    r'<meta\s+[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_OG_IMAGE_RE = re.compile(
    r'<meta\s+[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


async def _fetch_generic(service: str, username: str, url: str) -> ProfileData:
    """Generic HTML fetcher: pulls ``<meta name="description">`` and
    Open Graph tags. Imprecise but works for any web profile, so it's
    the fallback when no specific extractor exists."""
    if not url:
        return ProfileData(
            service=service, username=username, url="",
            error="No URL provided for generic fetch",
        )
    text = await _http_get_text(url)
    if not text:
        return ProfileData(
            service=service, username=username, url=url,
            error="HTML fetch returned non-200 or empty",
        )

    # Extract bio from meta tags. Prefer og:description (richer); fall
    # back to name=description if og isn't set.
    bio = None
    og_match = _OG_DESC_RE.search(text)
    if og_match:
        bio = og_match.group(1).strip()
    else:
        meta_match = _META_DESC_RE.search(text)
        if meta_match:
            bio = meta_match.group(1).strip()

    # Try og:title for display name.
    display_name = None
    title_match = _OG_TITLE_RE.search(text)
    if title_match:
        display_name = title_match.group(1).strip()

    # Try og:image for avatar (Phase C1). Many services use og:image
    # for the profile photo on the user's page.
    avatar = None
    image_match = _OG_IMAGE_RE.search(text)
    if image_match:
        avatar = image_match.group(1).strip()

    return ProfileData(
        service=service,
        username=username,
        url=url,
        display_name=display_name,
        bio=bio,
        avatar_url=avatar,
        fetched=True,
    )


# ── Dispatcher ───────────────────────────────────────────────────────


# Map service name (case-insensitive) to a specialised fetcher.
_SERVICE_FETCHERS: Dict[str, Any] = {
    "github": _fetch_github,
    "gitlab": _fetch_gitlab,
    "reddit": _fetch_reddit,
    "stackoverflow": _fetch_stack_exchange,
    "stack overflow": _fetch_stack_exchange,
}


async def fetch_profile(
    service: str,
    username: str,
    url: str = "",
) -> ProfileData:
    """Fetch profile data for ``username`` on ``service``.

    Dispatches to a service-specific fetcher when available; falls
    back to generic HTML+OG extraction otherwise. Never raises ──
    failures are returned in ``ProfileData.error`` so the caller can
    continue processing other hits in the same campaign.

    Args:
        service: Service name as it appears in maigret output (e.g.
            ``"GitHub"``, ``"Reddit"``). Case-insensitive.
        username: The handle to fetch.
        url: The full profile URL from maigret. Required for the
            generic HTML fallback; ignored by specialised fetchers
            which construct the API URL themselves.

    Returns:
        :class:`ProfileData` with fields populated as available. Check
        ``.fetched`` to confirm a successful fetch.
    """
    if not username:
        return ProfileData(service=service, username="", url=url,
                           error="empty username")

    key = (service or "").strip().lower()
    fetcher = _SERVICE_FETCHERS.get(key)
    if fetcher is not None:
        return await fetcher(username)
    return await _fetch_generic(service, username, url)


async def fetch_profiles_batch(
    hits: List[Dict[str, Any]],
    max_concurrent: int = 5,
) -> List[ProfileData]:
    """Fetch profile data for a list of maigret hits concurrently.

    Each hit is expected to be a dict with ``service``, ``username``,
    and ``url`` fields. Concurrency capped at ``max_concurrent`` to be
    polite to providers ── 5 is a safe default that won't trip
    rate-limit defences on Reddit / GitHub.

    Returns ``ProfileData`` in the same order as input.
    """
    sem = asyncio.Semaphore(max_concurrent)

    async def _one(hit: Dict[str, Any]) -> ProfileData:
        async with sem:
            return await fetch_profile(
                service=hit.get("service", ""),
                username=hit.get("username", ""),
                url=hit.get("url", ""),
            )

    return await asyncio.gather(*(_one(h) for h in hits))
