"""
Personal handle + email candidate derivation (Phase D2).

The Phase A/B ``username_derivation`` module produces CORPORATE handle
patterns from a corporate email: ``jane.doe@gitlab.com`` →
``[jane.doe, janedoe, jane_doe, jane-doe, jdoe, janed, ...]``.
Those patterns are what someone would use on GitHub or LinkedIn or
their company SSO. They are NOT what most humans use on Spotify,
Reddit, Discord, dating sites, gaming services, or personal email
providers.

This module fills that gap. Given:

  - A confident corporate identity (real name + role + location +
    age signals where available)
  - Optional hobby / interest signals harvested from public profiles
    (Phase E will provide these; D2 accepts them as input)

…it generates plausible PERSONAL handle candidates and personal
email-address candidates that an operator could probe via maigret
(handle) or HIBP / DeHashed / IntelX (email).

## What makes a personal handle different from a corporate one

Corporate handles follow employer conventions: ``jane.doe``, ``jdoe``,
``j.doe`` — picked by HR / IT, designed to be unambiguous within the
company.

Personal handles follow whatever the human picks when registering
for a personal service. Real-world patterns from breach data
analysis:

  - **Name + year**: ``jane85``, ``janedoe1990``, ``jdoe_92``. Year
    is often birth year (-/+ 5 of a guess derived from career
    length).
  - **Name + hobby**: ``jane_runner``, ``jdoe_gaming``, ``jane.knits``.
    Hobby comes from the person's public profile / bio if available.
  - **Nickname variants**: ``janie``, ``jdoe``, ``jdog``, ``jay``,
    ``janedoeofficial``. Hard to predict without explicit data.
  - **Geographic**: ``jane_sf``, ``jdoe_bayarea``, ``jane.chicago``.
    Suffix is city / region from the public profile.
  - **Initial-and-numbers**: ``jd1985``, ``jdoeofficial``, ``j_doe.x``.
  - **Service-specific conventions**: Reddit users often pick
    longer / wordier handles. Gaming users often have gamer-tag
    style names. Dating sites often skew first-name + age.

## Personal email patterns

Personal email addresses go to specific providers (gmail, yahoo,
outlook, icloud, protonmail, etc.) with patterns like:

  - ``jane.doe@gmail.com``
  - ``janedoe@yahoo.com``
  - ``jane.doe.82@gmail.com`` (year suffix)
  - ``jane.m.doe@gmail.com`` (with middle initial — middle initial
    requires a hint we typically don't have)
  - ``jdoe@protonmail.com`` (privacy-conscious people)
  - ``j.doe.SF@gmail.com`` (geographic)
  - ``jane@<personal-domain>.com`` (if they own a personal domain)

The derivation produces ranked candidate lists, NOT confident
attributions. Each candidate carries a heuristic-quality score that
the personal_pivot_tool (D3) uses to decide whether to probe.

## Confidence model

Phase D2 does NOT score "is this handle plausibly attributable to
the target?" — that's the personal_pivot_tool's job once it has
probed the handle and gathered corroborating signals. Phase D2 only
scores "how plausible is this STRING as a personal handle for
someone with this name?":

  - Score 1.0: high-frequency real-world pattern (``jane.doe``)
  - Score 0.7: common-but-noisy pattern (``jdoe``)
  - Score 0.5: needs corroboration (``jane.doe.82`` — birth year
    guessed)
  - Score 0.3: speculative (``jane.knits`` — hobby-based, depends
    on whether the hobby signal is reliable)

The personal_pivot_tool then multiplies these by its own
confidence-once-probed signal.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence


# Common free / consumer email providers. The derivation produces
# ``firstname.lastname@<provider>`` style candidates for each.
_PERSONAL_PROVIDERS = (
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "protonmail.com",
    "proton.me",
    "fastmail.com",
    "aol.com",
)

# Provider weighting ── gmail dominates real-world personal email
# market share, so gmail-pattern candidates score slightly higher
# than equivalent patterns on lesser-used providers.
_PROVIDER_WEIGHT = {
    "gmail.com": 1.0,
    "outlook.com": 0.85,
    "yahoo.com": 0.80,
    "hotmail.com": 0.75,
    "icloud.com": 0.75,
    "protonmail.com": 0.65,   # niche but trending
    "proton.me": 0.65,
    "fastmail.com": 0.45,
    "aol.com": 0.35,           # older demographic
}


@dataclass
class HandleCandidate:
    """One generated personal-handle candidate plus its pattern provenance."""

    value: str
    pattern: str       # e.g. "name+year", "name+hobby", "concat", "initial"
    quality: float     # heuristic plausibility in [0, 1]
    notes: str = ""    # human-readable rationale

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "pattern": self.pattern,
            "quality": round(self.quality, 3),
            "notes": self.notes,
        }


@dataclass
class EmailCandidate:
    """One generated personal-email candidate.

    Separate type from HandleCandidate because the probing pipelines
    are different (HIBP/DeHashed for emails, maigret for handles)."""

    value: str
    pattern: str
    quality: float
    notes: str = ""

    @property
    def local_part(self) -> str:
        return self.value.partition("@")[0]

    @property
    def domain(self) -> str:
        return self.value.partition("@")[2]

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "pattern": self.pattern,
            "quality": round(self.quality, 3),
            "notes": self.notes,
        }


# ──────────────────────────────────────────────────────────────────────
# Name tokenisation
# ──────────────────────────────────────────────────────────────────────


@dataclass
class NameTokens:
    first: str
    last: str
    middle: Optional[str] = None
    nickname_variants: List[str] = field(default_factory=list)


def _parse_name(name: str) -> Optional[NameTokens]:
    """Split a human name into first / last / optional middle.

    Handles common forms: ``"Jane Doe"``, ``"Jane M. Doe"``,
    ``"Doe, Jane"`` (LDAP format). Hyphenated parts kept together.
    Returns ``None`` if we can't extract at least a first + last.
    """
    if not name:
        return None
    s = name.strip()
    if "," in s:
        # LDAP / employee-list form: "Doe, Jane"
        last_first = [p.strip() for p in s.split(",", 1)]
        if len(last_first) == 2 and last_first[0] and last_first[1]:
            s = f"{last_first[1]} {last_first[0]}"
    tokens = [t.replace(".", "").strip() for t in re.split(r"\s+", s) if t]
    tokens = [t.lower() for t in tokens if t]
    if len(tokens) < 2:
        return None
    first = tokens[0]
    last = tokens[-1]
    middle = None
    if len(tokens) >= 3:
        # Take the first non-initial middle name, if any. Single-letter
        # tokens are dropped (middle initials don't show up in handles).
        middles = [t for t in tokens[1:-1] if len(t) >= 2]
        if middles:
            middle = middles[0]
    return NameTokens(first=first, last=last, middle=middle)


# ──────────────────────────────────────────────────────────────────────
# Year / age guessing
# ──────────────────────────────────────────────────────────────────────


def _candidate_birth_years(
    age_range: Optional[Sequence[int]] = None,
    career_years: Optional[int] = None,
) -> List[int]:
    """Generate a small set of plausible birth-year suffix candidates.

    Real personal handles often carry the user's birth year (or
    graduation year, or some life-event year). When age_range is
    known, we generate suffixes for that range. When only career
    length is known, we estimate birth year as ``current_year -
    career_years - 22`` (assumed start age) and bracket ±5.

    Returns 2-digit AND 4-digit forms (``85`` and ``1985``) since
    both appear in the wild.
    """
    years: List[int] = []
    current_year = 2026  # framework's reference epoch

    if age_range and len(age_range) == 2:
        for age in range(age_range[0], age_range[1] + 1):
            birth = current_year - age
            years.append(birth)
    elif career_years is not None:
        # Heuristic: most adult career starts at 22, finance/medicine
        # often later, fast-track tech earlier. Bracket ±5 years.
        est_birth = current_year - career_years - 22
        for delta in (-5, -3, -1, 0, 2, 5):
            years.append(est_birth + delta)
    else:
        # No age signal at all ── return a broad "common adult"
        # window, but with reduced quality scoring downstream.
        for birth in (1980, 1985, 1990, 1995):
            years.append(birth)

    # Deduplicate while preserving order.
    seen = set()
    out: List[int] = []
    for y in years:
        if 1955 <= y <= current_year - 10 and y not in seen:
            seen.add(y)
            out.append(y)
    return out


# ──────────────────────────────────────────────────────────────────────
# Hobby / interest signal
# ──────────────────────────────────────────────────────────────────────


def _hobby_tokens(interests: Optional[Iterable[str]]) -> List[str]:
    """Normalise hobby / interest strings into single-token suffixes
    suitable for handle construction.

    ``["Running", "Marathon", "D&D"]`` →
    ``["running", "marathon", "dnd"]``.

    Multi-word interests are collapsed (``"video games"`` → ``"games"``;
    we prefer the single most identifying token over the literal phrase
    since handles tend to be short). Interests are filtered to those
    a person plausibly puts in their own handle ── corporate /
    professional terms (``"agile"``, ``"engineering"``) are dropped
    because they don't appear in personal handles. Hobby tokens are
    short / fun / personal.
    """
    if not interests:
        return []
    # Tokens we drop because they're work-talk, not personal-handle
    # material.
    professional = frozenset((
        "engineering", "engineer", "software", "developer", "dev",
        "agile", "scrum", "devops", "cloud", "cybersecurity",
        "security", "infosec", "leadership", "management",
        "startups", "product", "design", "ux", "growth",
        "marketing", "sales", "operations",
    ))
    out: List[str] = []
    seen = set()
    for interest in interests:
        if not interest:
            continue
        s = re.sub(r"[^a-zA-Z]+", "", interest).lower()
        if not s or len(s) < 3 or len(s) > 14 or s in professional:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out[:8]  # cap


# ──────────────────────────────────────────────────────────────────────
# Geographic signal
# ──────────────────────────────────────────────────────────────────────


# Common city → short-form mapping for handle suffixes. Real handles
# use both forms; we generate both per candidate.
_CITY_SHORTS = {
    "san francisco": ("sf", "sanfrancisco"),
    "new york": ("nyc", "ny"),
    "los angeles": ("la", "losangeles"),
    "chicago": ("chi", "chicago"),
    "seattle": ("sea", "seattle"),
    "austin": ("atx", "austin"),
    "boston": ("bos", "boston"),
    "berlin": ("berlin",),
    "london": ("london", "ldn"),
    "tokyo": ("tokyo", "tyo"),
    "amsterdam": ("ams", "amsterdam"),
    "denver": ("denver",),
    "miami": ("miami",),
    "portland": ("pdx", "portland"),
    "atlanta": ("atl", "atlanta"),
    "dallas": ("dal", "dallas"),
    "philadelphia": ("philly", "phl"),
    "phoenix": ("phx", "phoenix"),
    "houston": ("hou", "houston"),
    "minneapolis": ("mpls", "minneapolis"),
}


def _location_tokens(location: Optional[str]) -> List[str]:
    """Normalise a city/region string into handle-suffix candidates.

    ``"San Francisco, CA"`` → ``["sf", "sanfrancisco"]``.
    Falls back to a slugified version of any unknown city."""
    if not location:
        return []
    s = location.lower().split(",")[0].strip()
    if s in _CITY_SHORTS:
        return list(_CITY_SHORTS[s])
    # Unknown city ── return the slugified form only.
    slug = re.sub(r"[^a-z]+", "", s)
    if 3 <= len(slug) <= 15:
        return [slug]
    return []


# ──────────────────────────────────────────────────────────────────────
# Top-level derivation
# ──────────────────────────────────────────────────────────────────────


def derive_personal_handles(
    name: str,
    age_range: Optional[Sequence[int]] = None,
    career_years: Optional[int] = None,
    interests: Optional[Iterable[str]] = None,
    location: Optional[str] = None,
    max_candidates: int = 40,
) -> List[HandleCandidate]:
    """Generate ranked personal-handle candidates.

    Args:
        name: Real name (e.g. ``"Jane Doe"`` or ``"Doe, Jane"``).
            Required ── without a name we can't derive personal
            handles meaningfully.
        age_range: Optional ``(min_age, max_age)`` tuple. When
            provided, year-suffix candidates target this window.
        career_years: Optional career length. Used to estimate birth
            year when ``age_range`` is absent.
        interests: Optional list of hobby / interest strings harvested
            from public profiles. Phase E will provide these; D3 can
            pass them in.
        location: Optional home city / region string.
        max_candidates: Cap on returned list. Top-quality candidates
            first.

    Returns:
        Ranked list of :class:`HandleCandidate`.
    """
    tokens = _parse_name(name)
    if tokens is None:
        return []

    candidates: List[HandleCandidate] = []
    seen: set = set()

    def _add(value: str, pattern: str, quality: float, notes: str = "") -> None:
        v = value.lower().strip()
        if not v or v in seen:
            return
        if not (3 <= len(v) <= 30):
            return
        seen.add(v)
        candidates.append(HandleCandidate(
            value=v, pattern=pattern, quality=quality, notes=notes,
        ))

    first = tokens.first
    last = tokens.last
    initial = first[0] if first else ""

    # 1. High-confidence base forms (also produced by the corporate
    #    derivation, but humans do reuse them on personal services).
    _add(f"{first}.{last}", "name.dotted", 0.95, "First.Last")
    _add(f"{first}{last}", "name.concat", 0.85, "FirstLast")
    _add(f"{first}_{last}", "name.underscore", 0.70, "First_Last")
    _add(f"{first}-{last}", "name.dash", 0.55, "First-Last")
    _add(f"{initial}{last}", "initial.concat", 0.65, "InitialLast")
    _add(f"{initial}.{last}", "initial.dotted", 0.45, "I.Last")
    _add(first, "first.alone", 0.40,
         "First name alone (high collision; verify before action)")
    _add(last, "last.alone", 0.30, "Last name alone (very high collision)")

    # 2. Year suffix candidates ── strong real-world pattern.
    year_set = _candidate_birth_years(age_range, career_years)
    year_quality = 0.55 if (age_range or career_years) else 0.35
    for y in year_set:
        # 4-digit year.
        _add(f"{first}{last}{y}", "name+year", year_quality,
             f"FirstLast+{y}")
        _add(f"{first}.{last}.{y}", "name.year", year_quality,
             f"First.Last.{y}")
        _add(f"{first}{y}", "first+year", year_quality - 0.10,
             f"First+{y}")
        # 2-digit form.
        y2 = str(y)[-2:]
        _add(f"{first}.{last}{y2}", "name.year2", year_quality - 0.05,
             f"First.Last+{y2}")
        _add(f"{first}{y2}", "first+year2", year_quality - 0.10,
             f"First+{y2}")
        _add(f"{initial}{last}{y2}", "initial+last+year2", year_quality - 0.10,
             f"I+Last+{y2}")

    # 3. Hobby suffix candidates ── needs a real interest signal.
    hobby_tokens = _hobby_tokens(interests)
    for hobby in hobby_tokens:
        _add(f"{first}_{hobby}", "first+hobby", 0.40,
             f"First+_{hobby}")
        _add(f"{first}.{hobby}", "first.hobby", 0.40, f"First.{hobby}")
        _add(f"{first}{hobby}", "first.hobbyconcat", 0.35,
             f"First{hobby}")
        _add(f"{hobby}_{first}", "hobby+first", 0.30, f"{hobby}_First")
        _add(f"{first}.{last}.{hobby}", "name.hobby", 0.35,
             f"First.Last.{hobby}")

    # 4. Geographic suffix candidates.
    geo_tokens = _location_tokens(location)
    for geo in geo_tokens:
        _add(f"{first}_{geo}", "first+geo", 0.40,
             f"First+_{geo} (location-tagged)")
        _add(f"{first}.{last}.{geo}", "name.geo", 0.40,
             f"First.Last.{geo}")
        _add(f"{first}{geo}", "first.geoconcat", 0.30,
             f"First{geo}")
        _add(f"{initial}{last}.{geo}", "initial.last.geo", 0.35,
             f"InitialLast.{geo}")

    # 5. Common nickname variants ── speculative but real-world
    #    pattern. Diminutive forms.
    nickname_map = {
        "michael": ["mike", "mick"],
        "robert": ["rob", "bob", "robby"],
        "william": ["will", "bill", "billy"],
        "richard": ["rick", "dick", "rich"],
        "james": ["jim", "jimmy", "jamie"],
        "charles": ["charlie", "chuck"],
        "thomas": ["tom", "tommy"],
        "christopher": ["chris", "topher"],
        "matthew": ["matt", "matty"],
        "joshua": ["josh", "joshie"],
        "nicholas": ["nick", "nicky"],
        "alexander": ["alex", "xander", "al"],
        "benjamin": ["ben", "benny"],
        "samuel": ["sam", "sammy"],
        "patrick": ["pat", "patty"],
        "jonathan": ["jon", "johnny"],
        "anthony": ["tony"],
        "joseph": ["joe", "joey"],
        "daniel": ["dan", "danny"],
        "jennifer": ["jen", "jenny"],
        "elizabeth": ["liz", "beth", "lizzy", "betty"],
        "katherine": ["kate", "katie", "kathy"],
        "stephanie": ["steph", "stephie"],
        "alexandra": ["alex", "alexa", "sasha"],
        "samantha": ["sam", "sammy"],
        "rebecca": ["becky", "bec"],
        "susan": ["sue", "suzy"],
        "patricia": ["pat", "patty", "tricia"],
        "deborah": ["debbie", "deb"],
        "amanda": ["mandy", "amy"],
        "victoria": ["vicky", "tori"],
        "andrew": ["andy", "drew"],
    }
    for nickname in nickname_map.get(first, []):
        _add(nickname, "nickname.alone", 0.30, f"Nickname: {nickname}")
        _add(f"{nickname}.{last}", "nickname.last", 0.45,
             f"Nickname.Last: {nickname}.{last}")
        _add(f"{nickname}{last}", "nickname.concat", 0.40,
             f"NicknameLast: {nickname}{last}")
        _add(f"{nickname}_{last}", "nickname.underscore", 0.35,
             f"Nickname_Last")

    # 6. Sort by quality descending and cap.
    candidates.sort(key=lambda c: -c.quality)
    return candidates[:max_candidates]


def derive_personal_emails(
    name: str,
    age_range: Optional[Sequence[int]] = None,
    career_years: Optional[int] = None,
    location: Optional[str] = None,
    personal_domain: Optional[str] = None,
    max_candidates: int = 30,
) -> List[EmailCandidate]:
    """Generate ranked personal-email candidates.

    Emails are constructed by combining derived local-part patterns
    (name-based forms with optional year/location suffixes) against
    common consumer providers (gmail, outlook, etc.), plus the
    person's own ``personal_domain`` when known.

    Args:
        name, age_range, career_years, location: Same semantics as
            ``derive_personal_handles``.
        personal_domain: When the operator (or Phase E) has surfaced
            a personal domain owned by the target, emails at that
            domain rank highly.
        max_candidates: Cap on returned list.

    Returns:
        Ranked list of :class:`EmailCandidate`.
    """
    tokens = _parse_name(name)
    if tokens is None:
        return []

    candidates: List[EmailCandidate] = []
    seen: set = set()

    def _add(local: str, domain: str, pattern: str,
             quality: float, notes: str = "") -> None:
        local = local.lower().strip()
        domain = domain.lower().strip()
        if not local or not domain:
            return
        if not (3 <= len(local) <= 40):
            return
        value = f"{local}@{domain}"
        if value in seen:
            return
        seen.add(value)
        candidates.append(EmailCandidate(
            value=value, pattern=pattern, quality=quality, notes=notes,
        ))

    first = tokens.first
    last = tokens.last
    initial = first[0] if first else ""

    # Local-part forms ranked by real-world frequency in breach data.
    base_locals = [
        (f"{first}.{last}", 0.95, "first.last"),
        (f"{first}{last}", 0.85, "firstlast"),
        (f"{first}_{last}", 0.65, "first_last"),
        (f"{initial}{last}", 0.55, "ilast"),
        (f"{first}.{last[0]}", 0.30, "first.l"),
        (f"{first}{last[0]}", 0.30, "firstl"),
    ]

    # 1. Each base local at each major provider.
    for local, base_q, pattern_kind in base_locals:
        for provider, weight in _PROVIDER_WEIGHT.items():
            _add(local, provider, f"{pattern_kind}@provider",
                 base_q * weight,
                 f"{pattern_kind} at {provider}")

    # 2. Year suffix variants at gmail (the most common case in
    #    breach data).
    year_set = _candidate_birth_years(age_range, career_years)
    year_quality_base = 0.55 if (age_range or career_years) else 0.35
    for y in year_set:
        y2 = str(y)[-2:]
        for local_base, pattern_kind in (
            (f"{first}.{last}.{y}", "first.last.year@gmail"),
            (f"{first}.{last}.{y2}", "first.last.year2@gmail"),
            (f"{first}.{last}{y}", "first.lastyear@gmail"),
            (f"{first}{last}{y}", "firstlastyear@gmail"),
            (f"{first}{y2}", "firstyear2@gmail"),
        ):
            _add(local_base, "gmail.com", pattern_kind,
                 year_quality_base, f"With year={y}")

    # 3. Location-tagged variants (gmail only ── less common at
    #    other providers).
    for geo in _location_tokens(location):
        _add(f"{first}.{last}.{geo}", "gmail.com",
             "first.last.geo@gmail", 0.40,
             f"Location-tagged: {geo}")
        _add(f"{first}{geo}", "gmail.com",
             "firstgeo@gmail", 0.25, f"First+{geo}")

    # 4. Personal domain ── when known, ranks at the top.
    if personal_domain:
        for local_base, q in (
            (first, 0.85),
            (f"{first}.{last}", 0.95),
            ("me", 0.85),
            ("contact", 0.60),
            ("hello", 0.55),
            ("hi", 0.50),
        ):
            _add(local_base, personal_domain,
                 "personal_domain", q,
                 f"Personal domain ({personal_domain})")

    # 5. Sort + cap.
    candidates.sort(key=lambda c: -c.quality)
    return candidates[:max_candidates]
