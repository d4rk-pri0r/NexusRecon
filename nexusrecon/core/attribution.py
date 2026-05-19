"""
Handle-attribution confidence scoring.

When the framework finds a username on N third-party services, the
naive "many hits = strong signal" logic falls apart on common names.
``john.smith`` matches 50 services because there are tens of thousands
of John Smiths online ── that's noise, not signal. This module exists
to discriminate.

The scorer combines four cheap, independent signals into a single
``[0.0, 1.0]`` confidence value plus a structured signal breakdown an
LLM agent can cite. Threshold of ~0.6 separates "act on this" from
"probably collision noise."

Signals:

  - **Derivation rank**: how directly the handle ties back to the
    verified email. ``jane.doe`` from ``jane.doe@gitlab.com`` is the
    strongest; ``jdoe`` (initial form) is medium; ``doe`` (lone
    surname) is weak.
  - **Handle uniqueness**: membership in a bundled common-handles
    list. Handles on the list get a uniqueness penalty proportional to
    their length (short generic handles like ``john`` are punished
    harder than longer variants like ``john1985``).
  - **Service trust tier**: the service's identity-validation quality.
    LinkedIn / verified-email GitHub are high-trust; generic forums
    are low-trust; unknown services get a middle default.
  - **Profile coherence**: whether the matched profile carries
    corroborating evidence ── bio mentions the email domain stem,
    profile name matches a harvested name, etc. Currently mostly
    zero because maigret rarely exposes bio text; will gain weight
    as Phase B fetches profile pages.

The weighted sum favours derivation + uniqueness because they're the
signals that exist for every hit. Service tier discriminates the next
10% of false positives; profile coherence the long tail.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


# ── Weights ──────────────────────────────────────────────────────────
# Tunable. Sum to 1.0 so the final score stays in [0, 1].
#
# Derivation is the strongest signal because an exact email→handle
# match is causally meaningful (the person chose the same string), so
# it carries the largest weight. Uniqueness is a prior ── important
# for ranking but not for confirming a specific person. Profile
# evidence (bio mentions employer, name matches harvested name) is
# the strongest corroborating signal when present, so it edges out
# service tier despite being absent from many hits today.
_WEIGHT_DERIVATION = 0.35
_WEIGHT_UNIQUENESS = 0.20
_WEIGHT_SERVICE_TIER = 0.20
_WEIGHT_PROFILE = 0.25

# ── Confidence bands ─────────────────────────────────────────────────
HIGH_CONFIDENCE_THRESHOLD = 0.7    # act on this signal
MEDIUM_CONFIDENCE_THRESHOLD = 0.4  # worth investigating
# below 0.4 = noise


# ──────────────────────────────────────────────────────────────────────
# Service trust tiers
# ──────────────────────────────────────────────────────────────────────
#
# Maigret site names are case-sensitive in its output. We match case-
# insensitively here so any maigret schema change in capitalisation
# doesn't silently drop tier categorisation.

# Tier 1 (1.0): identity-validating services. Real-name policies,
# professional networks, verified-email signals.
_TIER_1_SERVICES = frozenset(s.lower() for s in (
    "LinkedIn", "GitHub", "GitLab", "Bitbucket", "Crunchbase",
    "AngelList", "Wellfound", "StackOverflow", "Stack Overflow",
    "Stack Exchange", "Keybase", "Azure DevOps", "DevOps", "ResearchGate",
    "ORCID", "Patreon", "About.me", "Aboutme", "Indeed",
    "Behance", "Dribbble",
))

# Tier 2 (0.7): real social networks with selectable handles. Person-
# specific but easier to fake or share than Tier 1.
_TIER_2_SERVICES = frozenset(s.lower() for s in (
    "Twitter", "X", "Reddit", "Facebook", "Instagram", "TikTok",
    "Mastodon", "Threads", "Bluesky", "HackerNews", "Hacker News",
    "Medium", "Dev.to", "DevTo", "Hashnode", "Substack",
    "ProductHunt", "Product Hunt", "Discord", "Telegram",
    "Pinterest", "Tumblr", "Quora", "Pleroma",
))

# Tier 3 (0.4): general-interest services where handle collisions are
# very common (gaming, image hosts, music). Person-specific but
# strong false-positive bias.
_TIER_3_SERVICES = frozenset(s.lower() for s in (
    "Steam", "Twitch", "YouTube", "Vimeo", "Spotify", "SoundCloud",
    "Last.fm", "Lastfm", "Bandcamp", "MixCloud", "Imgur", "Flickr",
    "500px", "DeviantArt", "ArtStation", "Pixabay", "Unsplash",
    "Ko-fi", "BuyMeACoffee", "Etsy", "Goodreads", "MyAnimeList",
    "AniList", "Letterboxd", "TripAdvisor", "Yelp", "BattleNet",
    "Origin", "Epic Games", "Roblox", "Minecraft",
))

# Tier 4 (0.2): anonymous/adult/dating sites. Handles are deliberately
# disposable here; matches are weak attribution signals.
_TIER_4_SERVICES = frozenset(s.lower() for s in (
    "Pornhub", "Xvideos", "OnlyFans", "Chaturbate", "Tinder",
    "Bumble", "Match", "OkCupid", "PlentyOfFish", "POF",
    "AdultFriendFinder", "4chan", "8kun", "Voat",
))

# Default tier for services we haven't categorised: 0.5 (neutral).
_DEFAULT_SERVICE_TIER = 0.5


# ──────────────────────────────────────────────────────────────────────
# Common handles (uniqueness penalty)
# ──────────────────────────────────────────────────────────────────────
#
# Bundled top-frequency handles drawn from publicly-known patterns:
# top US given names + surnames (Census), generic role/admin handles,
# common breach-data username patterns. Goal isn't comprehensive ── a
# ~500-entry list catches the top-tier false-positive offenders
# (john, smith, admin, test, jdoe, etc.). Extending it is cheap;
# replacing it with a frequency-weighted dictionary is a Phase B item.

_COMMON_HANDLES = frozenset(h.lower() for h in (
    # Generic/placeholder handles ── most-common-in-the-wild handles
    # that have no specific human identity behind them.
    "admin", "administrator", "root", "user", "test", "tester", "testing",
    "guest", "demo", "sample", "example", "default", "system", "sysadmin",
    "info", "contact", "support", "help", "sales", "marketing", "hello",
    "hi", "dev", "developer", "designer", "owner", "ceo", "cto", "founder",
    "intern", "anon", "anonymous", "noname", "nobody", "someone", "person",
    "webmaster", "postmaster", "abuse", "security", "noreply", "donotreply",
    "mailer", "daemon", "www", "web", "site", "blog", "page", "app", "api",
    "service", "client", "server", "host", "master", "main", "official",

    # Top 100 US male given names (SSA frequency data, top tier).
    "james", "john", "robert", "michael", "william", "david", "richard",
    "joseph", "thomas", "charles", "christopher", "daniel", "matthew",
    "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
    "kenneth", "kevin", "brian", "george", "edward", "ronald", "timothy",
    "jason", "jeffrey", "ryan", "jacob", "gary", "nicholas", "eric",
    "jonathan", "stephen", "larry", "justin", "scott", "brandon",
    "benjamin", "samuel", "gregory", "alexander", "frank", "patrick",
    "raymond", "jack", "dennis", "jerry", "tyler", "aaron", "henry",
    "douglas", "peter", "adam", "noah", "nathan", "zachary", "walter",
    "kyle", "harold", "carl", "jeremy", "keith", "roger", "gerald",
    "ethan", "arthur", "terry", "christian", "sean", "lawrence", "austin",
    "joe", "albert", "willie", "billy", "logan", "alan", "juan", "wayne",
    "elijah", "randy", "roy", "vincent", "ralph", "eugene", "russell",
    "bobby", "mason", "philip", "louis", "bradley", "jordan",

    # Top 100 US female given names.
    "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara",
    "susan", "jessica", "sarah", "karen", "lisa", "nancy", "betty",
    "helen", "sandra", "donna", "carol", "ruth", "sharon", "michelle",
    "laura", "kimberly", "deborah", "dorothy", "amy", "angela", "ashley",
    "brenda", "emma", "olivia", "cynthia", "marie", "janet", "catherine",
    "frances", "christine", "samantha", "debra", "rachel", "carolyn",
    "janet", "virginia", "maria", "heather", "diane", "julie", "joyce",
    "victoria", "kelly", "christina", "joan", "evelyn", "lauren", "judith",
    "megan", "cheryl", "andrea", "hannah", "jacqueline", "martha",
    "gloria", "teresa", "ann", "sara", "madison", "frances", "kathryn",
    "janice", "jean", "abigail", "alice", "julia", "judy", "sophia",
    "grace", "denise", "amber", "doris", "marilyn", "danielle", "beverly",
    "isabella", "theresa", "diana", "natalie", "brittany", "charlotte",
    "marie", "kayla", "alexis", "lori", "stephanie", "rebecca", "anna",

    # Top 50 US surnames (Census).
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
    "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez",
    "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
    "lee", "perez", "thompson", "white", "harris", "sanchez", "clark",
    "ramirez", "lewis", "robinson", "walker", "young", "allen", "king",
    "wright", "scott", "torres", "nguyen", "hill", "flores", "green",
    "adams", "nelson", "baker", "hall", "rivera", "campbell", "mitchell",
    "carter", "roberts",

    # Common initial+surname patterns (top 10 surnames × 5 vowels).
    # These are the patterns that match a huge fraction of corporate
    # handle conventions but match thousands of people.
    "jsmith", "msmith", "asmith", "dsmith", "rsmith", "esmith", "csmith",
    "jjohnson", "mjohnson", "ajohnson", "djohnson", "rjohnson",
    "jwilliams", "mwilliams", "awilliams", "dwilliams",
    "jbrown", "mbrown", "abrown", "dbrown",
    "jjones", "mjones", "ajones", "djones",
    "jgarcia", "mgarcia", "agarcia",
    "jmiller", "mmiller", "amiller", "dmiller",
    "jdavis", "mdavis", "adavis",
    "jlee", "mlee", "alee", "dlee",
    "jdoe", "janedoe", "johndoe",

    # Common firstname.lastname combinations for top names.
    "john.smith", "jane.smith", "michael.smith", "david.smith",
    "john.doe", "jane.doe",
    "john.johnson", "michael.johnson",
    "john.williams", "michael.williams",
    "john.brown", "michael.brown",
    "john.jones", "michael.jones",
    "john.davis", "michael.davis",
    "john.miller", "michael.miller",

    # "Cool" / pop-culture handles that recur in breach data ──
    # gaming, anime, generic interest categories.
    "ninja", "samurai", "warrior", "hunter", "wolf", "fox", "eagle",
    "hawk", "raven", "viper", "dragon", "phoenix", "demon", "ghost",
    "shadow", "hero", "legend", "master", "king", "queen", "prince",
    "princess", "ace", "lucky", "pro", "gamer", "player", "noob", "boss",
    "killer", "slayer", "destroyer", "reaper", "savage", "beast",
    "monster", "devil", "angel", "saint", "wizard", "mage", "witch",
    "ranger", "assassin", "sniper", "soldier", "captain", "commander",
    "general", "chief", "leader", "fighter", "boxer",

    # Tech / generic-handle patterns.
    "coder", "hacker", "programmer", "geek", "nerd", "techie", "engineer",
    "scientist", "researcher", "student", "professor", "doctor", "expert",
    "guru", "wizard", "ninja", "rockstar", "champion",
))


# ──────────────────────────────────────────────────────────────────────
# Derivation rank
# ──────────────────────────────────────────────────────────────────────
#
# How the handle was derived from the email. The derivation utility
# emits candidates in rank order; we map each derivation kind to a
# baseline confidence contribution.


def _derivation_rank(email: Optional[str], handle: str) -> float:
    """Return derivation confidence in ``[0, 1]``.

    Logic:
      - 1.0 if handle == email local-part exactly (most reliable)
      - 0.8 if handle == stripped local-part (jane.doe from jane.doe2)
      - 0.6 if handle is a separator variant (janedoe from jane.doe)
      - 0.5 if handle is a name-collapsed concat (no separator)
      - 0.4 if handle is an initial-pattern (jdoe from jane.doe)
      - 0.3 if handle is a name-derived only (no email correspondence)
      - 0.2 if handle is a lone surname/first name component

    No email → 0.3 (name-derived only).
    """
    if not email or "@" not in email:
        return 0.3

    local, _, _ = email.partition("@")
    local = local.strip().lower()
    handle = handle.strip().lower()

    if not local:
        return 0.3

    if handle == local:
        return 1.0

    # Strip trailing digits to test "stripped form" match.
    import re
    stripped = re.sub(r"\d{1,4}$", "", local)
    if stripped and handle == stripped:
        return 0.8

    # Separator-stripped concat: jane.doe → janedoe
    no_sep_local = re.sub(r"[._-]", "", local)
    no_sep_stripped = re.sub(r"[._-]", "", stripped) if stripped else ""
    if handle == no_sep_local or (no_sep_stripped and handle == no_sep_stripped):
        return 0.6

    # Separator-swapped variant: jane.doe → jane_doe / jane-doe
    if any(handle == local.replace(".", sep) for sep in ("_", "-")):
        return 0.6
    if any(handle == local.replace("_", sep) for sep in (".", "-")):
        return 0.6
    if any(handle == local.replace("-", sep) for sep in (".", "_")):
        return 0.6

    # Initial-prefix pattern: jane.doe → jdoe
    tokens = re.split(r"[._-]+", local)
    tokens = [t for t in tokens if t]
    if len(tokens) >= 2:
        first, last = tokens[0], tokens[-1]
        if handle == first[0] + last:
            return 0.4
        if handle in (f"{first[0]}.{last}", f"{first[0]}_{last}", f"{first[0]}-{last}"):
            return 0.4
        # First + last-initial: jane.doe → janed
        if handle == first + last[0]:
            return 0.4
        # Lone component: jane.doe → jane (or doe)
        if handle in tokens:
            return 0.2

    return 0.3


# ──────────────────────────────────────────────────────────────────────
# Uniqueness
# ──────────────────────────────────────────────────────────────────────


def _uniqueness(handle: str) -> float:
    """Return uniqueness in ``[0, 1]``. Higher = more unique = less
    likely to be a collision.

    Logic:
      - 1.0 if handle is not in the common-handles list
      - 0.3 if on the list, length > 10 (longer variants still
        somewhat distinctive)
      - 0.1 if on the list, length 6-10 (common ground)
      - 0.05 if on the list, length <= 5 (very generic)

    Plus a length bonus: handles >= 12 chars get a small uniqueness
    boost regardless of list membership (long strings collide less).
    """
    handle = handle.strip().lower()
    if not handle:
        return 0.0

    is_common = handle in _COMMON_HANDLES
    length = len(handle)

    if not is_common:
        base = 1.0
    elif length > 10:
        base = 0.3
    elif length >= 6:
        base = 0.1
    else:
        base = 0.05

    # Length bonus for very long handles that aren't on the common
    # list ── these are statistically near-unique.
    if not is_common and length >= 12:
        base = min(1.0, base + 0.05)

    return base


# ──────────────────────────────────────────────────────────────────────
# Service tier
# ──────────────────────────────────────────────────────────────────────


def _service_tier(service: str) -> float:
    """Return service trust score in ``[0, 1]`` based on tier mapping."""
    if not service:
        return _DEFAULT_SERVICE_TIER
    s = service.strip().lower()
    if s in _TIER_1_SERVICES:
        return 1.0
    if s in _TIER_2_SERVICES:
        return 0.7
    if s in _TIER_3_SERVICES:
        return 0.4
    if s in _TIER_4_SERVICES:
        return 0.2
    return _DEFAULT_SERVICE_TIER


# ──────────────────────────────────────────────────────────────────────
# Profile coherence
# ──────────────────────────────────────────────────────────────────────


def _profile_coherence(
    email: Optional[str],
    profile_data: Optional[Dict[str, Any]],
    harvested_names: Optional[Sequence[str]],
) -> float:
    """Return profile-coherence signal in ``[0, 1]``.

    Looks for corroborating evidence in the matched profile:
      - Bio text mentions the email's domain stem (gitlab from
        @gitlab.com): strong signal
      - Profile name field matches a harvested name: strong signal
      - Any identifying metadata present at all: weak baseline

    Maigret rarely exposes bio text directly ── most hits have only a
    ``{"username": handle}`` profile dict ── so this signal returns 0.0
    for the majority of hits today. Phase B will improve coverage by
    fetching profile pages and extracting bios.
    """
    if not profile_data:
        return 0.0

    score = 0.0

    # Concatenate any string-valued profile fields for keyword scan.
    blob = " ".join(
        str(v).lower() for v in profile_data.values()
        if isinstance(v, (str, int, float))
    )
    if not blob:
        return 0.0

    # Baseline: any string content at all suggests a real profile vs.
    # a placeholder.
    score += 0.1

    # Email domain stem mention: e.g. ``gitlab`` for jane.doe@gitlab.com.
    if email and "@" in email:
        domain = email.partition("@")[2].lower()
        # Take the second-level domain part (gitlab from gitlab.com).
        domain_stem = domain.split(".")[0] if "." in domain else domain
        if domain_stem and len(domain_stem) >= 4 and domain_stem in blob:
            score += 0.5

    # Harvested-name match.
    if harvested_names:
        for name in harvested_names:
            if not name:
                continue
            name_lower = name.lower().strip()
            if len(name_lower) >= 4 and name_lower in blob:
                score += 0.4
                break

    return min(1.0, score)


# ──────────────────────────────────────────────────────────────────────
# Top-level scorer
# ──────────────────────────────────────────────────────────────────────


@dataclass
class AttributionScore:
    """Confidence that a matched account belongs to the email's owner.

    Attributes:
        score: Weighted-sum confidence in ``[0.0, 1.0]``.
        signals: Per-signal sub-scores for downstream LLM citation.
        rationale: One-line human-readable explanation.
    """

    score: float
    signals: Dict[str, float] = field(default_factory=dict)
    rationale: str = ""

    @property
    def confidence_band(self) -> str:
        """Categorical band for filtering at threshold boundaries."""
        if self.score >= HIGH_CONFIDENCE_THRESHOLD:
            return "high"
        if self.score >= MEDIUM_CONFIDENCE_THRESHOLD:
            return "medium"
        return "noise"

    @property
    def is_actionable(self) -> bool:
        """``True`` if the score meets the act-on threshold (>= 0.6)."""
        return self.score >= 0.6


def score_handle_attribution(
    email: Optional[str],
    handle: str,
    service: str,
    profile_data: Optional[Dict[str, Any]] = None,
    harvested_names: Optional[Sequence[str]] = None,
) -> AttributionScore:
    """Compute multi-signal attribution confidence for a maigret hit.

    Args:
        email: The verified email this attribution chain started from.
            ``None`` is valid but penalises derivation rank to its
            no-anchor baseline.
        handle: The username found on ``service``.
        service: The third-party service name (e.g. ``"GitHub"``,
            ``"Reddit"``). Matched case-insensitively against the
            bundled tier maps; unknown services fall back to a
            neutral 0.5.
        profile_data: Optional ``{"username": str, "image": url, ...}``
            metadata maigret extracted. Mostly empty in the current
            implementation.
        harvested_names: Optional list of human names harvested in
            this campaign (e.g. via hunter.io). Used by the profile-
            coherence signal.

    Returns:
        :class:`AttributionScore` with the final ``score`` plus
        per-signal contributions for downstream LLM reasoning. The
        ``rationale`` field carries a short human-readable summary
        suitable for citation in a generated report.
    """
    handle = (handle or "").strip()
    service = (service or "").strip()
    if not handle:
        return AttributionScore(
            score=0.0,
            signals={"derivation": 0.0, "uniqueness": 0.0, "service_tier": 0.0, "profile": 0.0},
            rationale="empty handle",
        )

    deriv = _derivation_rank(email, handle)
    uniq = _uniqueness(handle)
    tier = _service_tier(service)
    prof = _profile_coherence(email, profile_data, harvested_names)

    final = (
        deriv * _WEIGHT_DERIVATION
        + uniq * _WEIGHT_UNIQUENESS
        + tier * _WEIGHT_SERVICE_TIER
        + prof * _WEIGHT_PROFILE
    )
    final = round(min(1.0, max(0.0, final)), 3)

    rationale = _build_rationale(handle, service, deriv, uniq, tier, prof)

    return AttributionScore(
        score=final,
        signals={
            "derivation": round(deriv, 3),
            "uniqueness": round(uniq, 3),
            "service_tier": round(tier, 3),
            "profile": round(prof, 3),
        },
        rationale=rationale,
    )


def _build_rationale(
    handle: str,
    service: str,
    deriv: float,
    uniq: float,
    tier: float,
    prof: float,
) -> str:
    """Compose a short human-readable rationale for an LLM to cite."""
    parts: List[str] = []
    if deriv >= 0.9:
        parts.append("handle matches email local-part exactly")
    elif deriv >= 0.7:
        parts.append("handle matches stripped email local-part")
    elif deriv >= 0.5:
        parts.append("handle is a separator variant of email local-part")
    elif deriv >= 0.4:
        parts.append("handle is initial-prefix pattern from email")
    else:
        parts.append("handle has weak derivation tie to email")

    if uniq >= 0.9:
        parts.append(f"`{handle}` is not on the common-handles list (likely unique)")
    elif uniq >= 0.3:
        parts.append(f"`{handle}` is common but long enough to discriminate")
    else:
        parts.append(f"`{handle}` is on the common-handles list (high collision risk)")

    if tier >= 0.9:
        parts.append(f"{service} is a high-trust identity service")
    elif tier >= 0.6:
        parts.append(f"{service} is a social network with handle selection")
    elif tier >= 0.3:
        parts.append(f"{service} is a low-trust handle service")
    else:
        parts.append(f"{service} has weak attribution semantics")

    if prof >= 0.5:
        parts.append("profile data corroborates identity")

    return "; ".join(parts)


def filter_actionable(hits: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return only hits whose ``confidence`` field is at or above the
    actionable threshold. Convenience for callers that don't want to
    spread the threshold logic across the codebase."""
    return [h for h in hits if h.get("confidence", 0.0) >= 0.6]
