"""
Linked-account graph extraction.

Many profile bios reference other social accounts ── ``twitter:
@jane.doe``, ``github.com/jdoe``, ``@user@mastodon.social``, etc.
When we find such a reference in service A's bio AND we already
have a maigret hit for that same handle on service B, the graph
closes and attribution confidence approaches certainty: the same
person attested to both accounts.

This module extracts those references from bio text + profile blog
URLs. Each extracted reference carries the source service, target
service, target handle, and a normalised target URL when possible.

Downstream consumers (the attribution scorer, the agent prompt) use
the extracted graph to:

  1. Bump confidence on the target hit when its handle matches the
     extracted reference.
  2. Surface confirmed cross-service identities to the agent for
     reasoning.
  3. Note discrepancies (handle claimed but never found by maigret ──
     either a new lead to pursue or stale profile data).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class LinkedAccount:
    """A single cross-service reference extracted from a bio.

    Attributes:
        source_service: The service whose bio mentioned the reference
            (e.g. ``"GitHub"``).
        target_service: The service being referenced (e.g.
            ``"Twitter"``).
        target_handle: The handle on the target service.
        target_url: The full URL when extractable, empty string when
            the bio just mentions the handle.
        raw_match: The exact substring that matched ── useful for the
            agent to cite verbatim.
    """

    source_service: str
    target_service: str
    target_handle: str
    target_url: str
    raw_match: str

    def to_dict(self) -> dict:
        return {
            "source_service": self.source_service,
            "target_service": self.target_service,
            "target_handle": self.target_handle,
            "target_url": self.target_url,
            "raw_match": self.raw_match,
        }


# ── Service-specific URL patterns ────────────────────────────────────
#
# Each entry: (compiled regex, target_service, group_index_for_handle).
# The regex must capture the handle in a named group ``handle`` or the
# specified positional group. URL patterns are deliberately lenient
# (allow trailing slashes, query strings, etc.) because bio formatting
# is wildly inconsistent.

_URL_PATTERNS = [
    # GitHub: github.com/user, gh.com/user
    (re.compile(r"github\.com/(?P<handle>[a-zA-Z0-9][a-zA-Z0-9_-]{0,38})", re.IGNORECASE), "GitHub"),
    # GitLab: gitlab.com/user
    (re.compile(r"gitlab\.com/(?P<handle>[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254})", re.IGNORECASE), "GitLab"),
    # Twitter / X: twitter.com/user, x.com/user
    (re.compile(r"(?:twitter|x)\.com/(?P<handle>[a-zA-Z0-9_]{1,15})", re.IGNORECASE), "Twitter"),
    # Mastodon: mastodon.social/@user, hachyderm.io/@user, etc.
    (re.compile(r"(?P<host>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/@(?P<handle>[a-zA-Z0-9_]{1,30})"), "Mastodon"),
    # Bluesky: bsky.app/profile/user.bsky.social
    (re.compile(r"bsky\.app/profile/(?P<handle>[a-zA-Z0-9.-]{1,253})", re.IGNORECASE), "Bluesky"),
    # LinkedIn: linkedin.com/in/user
    (re.compile(r"linkedin\.com/in/(?P<handle>[a-zA-Z0-9_-]{1,100})", re.IGNORECASE), "LinkedIn"),
    # Reddit: reddit.com/user/x or /u/x
    (re.compile(r"reddit\.com/(?:user|u)/(?P<handle>[a-zA-Z0-9_-]{1,20})", re.IGNORECASE), "Reddit"),
    # Stack Overflow: stackoverflow.com/users/12345/handle
    (re.compile(r"stackoverflow\.com/users/\d+/(?P<handle>[a-zA-Z0-9_.-]{1,100})", re.IGNORECASE), "StackOverflow"),
    # Instagram: instagram.com/user
    (re.compile(r"instagram\.com/(?P<handle>[a-zA-Z0-9_.]{1,30})", re.IGNORECASE), "Instagram"),
    # Keybase: keybase.io/user
    (re.compile(r"keybase\.io/(?P<handle>[a-zA-Z0-9_]{2,16})", re.IGNORECASE), "Keybase"),
    # Mastodon canonical @user@instance format
    (re.compile(r"@(?P<handle>[a-zA-Z0-9_]{1,30})@(?P<host>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"), "Mastodon"),
    # Dev.to: dev.to/user
    (re.compile(r"dev\.to/(?P<handle>[a-zA-Z0-9_-]{1,40})", re.IGNORECASE), "Dev.to"),
    # Medium: medium.com/@user
    (re.compile(r"medium\.com/@(?P<handle>[a-zA-Z0-9_.-]{1,50})", re.IGNORECASE), "Medium"),
    # Twitch: twitch.tv/user
    (re.compile(r"twitch\.tv/(?P<handle>[a-zA-Z0-9_]{1,25})", re.IGNORECASE), "Twitch"),
    # YouTube: youtube.com/@user, youtube.com/user/x
    (re.compile(r"youtube\.com/@(?P<handle>[a-zA-Z0-9_.-]{1,30})", re.IGNORECASE), "YouTube"),
]


# ── Labelled-mention patterns (no URL, just "twitter: @handle") ──────
#
# These catch the bio style "Twitter: @jane.doe" or "GitHub: jdoe"
# without a full URL. Constrained to specific service labels to avoid
# false-positive noise from arbitrary @-mentions in narrative prose.

_LABELLED_PATTERNS = [
    (re.compile(r"\b(?:twitter|x)\s*[:|=@]\s*@?(?P<handle>[a-zA-Z0-9_]{1,15})\b", re.IGNORECASE), "Twitter"),
    (re.compile(r"\bgithub\s*[:|=@]\s*@?(?P<handle>[a-zA-Z0-9][a-zA-Z0-9_-]{0,38})\b", re.IGNORECASE), "GitHub"),
    (re.compile(r"\bgitlab\s*[:|=@]\s*@?(?P<handle>[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254})\b", re.IGNORECASE), "GitLab"),
    (re.compile(r"\bmastodon\s*[:|=@]\s*@?(?P<handle>[a-zA-Z0-9_]{1,30})@?(?P<host>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?\b", re.IGNORECASE), "Mastodon"),
    (re.compile(r"\b(?:ig|insta|instagram)\s*[:|=@]\s*@?(?P<handle>[a-zA-Z0-9_.]{1,30})\b", re.IGNORECASE), "Instagram"),
    (re.compile(r"\b(?:linkedin|li)\s*[:|=@]\s*@?(?P<handle>[a-zA-Z0-9_-]{1,100})\b", re.IGNORECASE), "LinkedIn"),
    (re.compile(r"\bkeybase\s*[:|=@]\s*@?(?P<handle>[a-zA-Z0-9_]{2,16})\b", re.IGNORECASE), "Keybase"),
]


def extract_linked_accounts(
    source_service: str,
    profile_text: str,
    profile_blog: Optional[str] = None,
) -> List[LinkedAccount]:
    """Extract cross-service references from a profile's bio + blog URL.

    Args:
        source_service: The service whose profile is being parsed
            (e.g. ``"GitHub"``). Recorded on each emitted
            ``LinkedAccount`` so downstream consumers know where the
            claim came from.
        profile_text: The bio text + any other long-form fields.
        profile_blog: The profile's optional website / blog URL ── if
            it's a known social URL (twitter.com/user, etc.), it
            counts as a cross-reference.

    Returns:
        A list of :class:`LinkedAccount` with one entry per unique
        ``(target_service, target_handle)`` pair found. Duplicates
        across the bio and blog URL collapse to a single entry.
    """
    if not profile_text and not profile_blog:
        return []

    haystack_parts: List[str] = []
    if profile_text:
        haystack_parts.append(profile_text)
    if profile_blog:
        haystack_parts.append(profile_blog)
    haystack = "\n".join(haystack_parts)

    out: List[LinkedAccount] = []
    seen: set = set()

    def _add(target_service: str, target_handle: str, target_url: str, raw: str) -> None:
        # Don't claim a service references itself ── a GitHub bio
        # mentioning "github.com/jane" is just the canonical URL, not
        # a cross-reference.
        if target_service.lower() == source_service.lower():
            return
        # Normalise handle for dedup ── case-insensitive.
        key = (target_service, target_handle.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(LinkedAccount(
            source_service=source_service,
            target_service=target_service,
            target_handle=target_handle,
            target_url=target_url,
            raw_match=raw,
        ))

    # URL-based patterns: produce both the handle and a normalised URL.
    for pattern, target_service in _URL_PATTERNS:
        for match in pattern.finditer(haystack):
            handle = match.group("handle")
            if not handle:
                continue
            full_url = _normalise_url(target_service, handle, match)
            _add(target_service, handle, full_url, match.group(0))

    # Labelled-mention patterns: produce just the handle.
    for pattern, target_service in _LABELLED_PATTERNS:
        for match in pattern.finditer(haystack):
            handle = match.group("handle")
            if not handle:
                continue
            # The labelled patterns may match too eagerly; drop
            # obvious false positives (handle that's a common English
            # word like "this", "the", etc.).
            if _looks_like_prose(handle):
                continue
            _add(target_service, handle, "", match.group(0))

    return out


def _normalise_url(service: str, handle: str, match: re.Match) -> str:
    """Build a canonical URL for the target service + handle pair.

    Uses the match's captured groups when available (e.g. Mastodon's
    host) so per-instance distinctions are preserved."""
    s = service.lower()
    if s == "github":
        return f"https://github.com/{handle}"
    if s == "gitlab":
        return f"https://gitlab.com/{handle}"
    if s == "twitter":
        return f"https://twitter.com/{handle}"
    if s == "mastodon":
        host = match.groupdict().get("host")
        if host:
            return f"https://{host}/@{handle}"
        return ""
    if s == "bluesky":
        return f"https://bsky.app/profile/{handle}"
    if s == "linkedin":
        return f"https://linkedin.com/in/{handle}"
    if s == "reddit":
        return f"https://reddit.com/u/{handle}"
    if s == "stackoverflow":
        return ""  # SO URLs include a numeric ID we don't have
    if s == "instagram":
        return f"https://instagram.com/{handle}"
    if s == "keybase":
        return f"https://keybase.io/{handle}"
    if s == "dev.to":
        return f"https://dev.to/{handle}"
    if s == "medium":
        return f"https://medium.com/@{handle}"
    if s == "twitch":
        return f"https://twitch.tv/{handle}"
    if s == "youtube":
        return f"https://youtube.com/@{handle}"
    return ""


# Common English words that the labelled-mention regex might match in
# narrative prose like "GitHub the best" or "Twitter: this is fun." We
# drop these to keep precision high.
_PROSE_WORDS = frozenset((
    "the", "this", "that", "these", "those", "and", "or", "but",
    "not", "for", "with", "from", "into", "onto", "upon", "about",
    "best", "good", "great", "love", "hate", "like", "lol", "haha",
    "yes", "no", "yeah", "nope", "ok", "okay", "sure", "really",
    "true", "false", "here", "there", "now", "then", "soon", "today",
    "tomorrow", "yesterday", "always", "never", "sometimes",
))


def _looks_like_prose(handle: str) -> bool:
    """Heuristic: is this 'handle' actually English prose that the
    regex caught as a false positive? Returns True for common short
    English words."""
    if len(handle) <= 1:
        return True
    return handle.lower() in _PROSE_WORDS


def cross_reference_with_hits(
    extracted: List[LinkedAccount],
    maigret_hits: List[dict],
) -> List[dict]:
    """Match extracted references against known maigret hits.

    For each :class:`LinkedAccount`, check whether ``maigret_hits``
    already contains an entry for ``(target_service, target_handle)``.
    Hits that match get a ``cross_referenced`` flag and a
    ``cross_reference_source`` field for citation.

    Returns the mutated hit list (also mutates in place for caller
    convenience).
    """
    by_key = {
        (h.get("service", "").lower(), h.get("username", "").lower()): h
        for h in maigret_hits
    }
    for ref in extracted:
        key = (ref.target_service.lower(), ref.target_handle.lower())
        if key in by_key:
            hit = by_key[key]
            hit.setdefault("cross_referenced_from", []).append({
                "source_service": ref.source_service,
                "raw_match": ref.raw_match,
            })
    return maigret_hits
