"""
Email + name → likely-username derivation.

The OSINT loop's most valuable pivot: an email surfaces in phase 2
(``hunter``, ``theharvester``), then we want to expand that single
identity into the broader account footprint via username-input tools
(``maigret``). To do that, we need to guess plausible usernames from
the email's local-part and any harvested employee names.

There's no perfect mapping ── ``jane.doe@gitlab.com`` could be
``janed`` on Stack Overflow, ``j_doe`` on GitHub, and ``jane-doe-123``
on Reddit. The derivation produces a ranked candidate list; downstream
tools (typically ``maigret``) probe each candidate and the hits
confirm which patterns this person actually uses.

Heuristics live in :func:`derive_usernames`. The ranking is by
empirical frequency in corporate naming conventions: dotted form
first, then concatenated, then initial-prefixed variants, then
single-component fallbacks. Adjust the constants below if the demo
data surfaces a different pattern.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence

# Maximum length for a credible username. Beyond this is almost
# certainly an email address that happened to not contain ``@``.
_MAX_USERNAME_LEN = 30
# Minimum length: shorter is too noisy (every two-letter combination
# matches something on a 3000-site checker).
_MIN_USERNAME_LEN = 3

# Characters that act as username separators in the email local-part
# and harvested names. The derivation produces variants with and
# without each separator.
_SEPARATORS = (".", "_", "-")

# Local-part patterns we strip before deriving:
# trailing numeric suffixes like ``jane.doe2`` (job switchers,
# disambiguators) and date stamps like ``john1985``.
_NUMERIC_SUFFIX_RE = re.compile(r"(\d{1,4})$")

# Local-parts we never derive from ── role accounts that wouldn't
# correlate with individual usernames.
_ROLE_LOCALPARTS = frozenset({
    "admin", "administrator", "info", "contact", "support", "help",
    "sales", "marketing", "press", "media", "noreply", "no-reply",
    "donotreply", "do-not-reply", "postmaster", "abuse", "security",
    "webmaster", "hostmaster", "ssl-admin", "billing", "legal",
    "hr", "careers", "jobs", "notifications", "alerts", "team",
    "office", "hello", "hi", "newsletter", "subscribe", "unsubscribe",
})


def _normalise(s: str) -> str:
    """Lowercase + strip whitespace. Usernames are de facto case-
    insensitive on most platforms; we collapse case early so the
    deduplication step doesn't keep ``Jane.Doe`` and ``jane.doe`` as
    separate candidates."""
    return s.strip().lower()


def _strip_trailing_digits(s: str) -> str:
    """Remove a trailing numeric run if any. Returns the same string
    when the local-part has no digits ── used by callers to keep both
    ``jane.doe2`` and ``jane.doe`` in the candidate set."""
    return _NUMERIC_SUFFIX_RE.sub("", s)


def _split_name_parts(name: str) -> List[str]:
    """Tokenise a harvested name into components. Handles common forms:

      - ``"Jane Doe"`` → ``["jane", "doe"]``
      - ``"Jane M. Doe"`` → ``["jane", "doe"]`` (middle initial dropped)
      - ``"DOE, Jane"`` → ``["jane", "doe"]`` (last-first reordering)
      - ``"Jane-Marie Doe"`` → ``["jane", "marie", "doe"]``
    """
    if not name:
        return []
    s = _normalise(name)
    # Last-first form: "Doe, Jane" → swap to "Jane Doe"
    if "," in s:
        parts = [p.strip() for p in s.split(",", 1)]
        if len(parts) == 2 and parts[0] and parts[1]:
            s = f"{parts[1]} {parts[0]}"
    # Split on whitespace and hyphens. Strip dots (middle initials).
    raw = re.split(r"[\s\-]+", s)
    tokens = [t.replace(".", "").strip() for t in raw if t.replace(".", "").strip()]
    # Drop single-letter middle initials but keep ones that look like
    # single-letter first names (rare but real ── e.g. "X Æ A-12" type
    # edge cases). Threshold: keep tokens >= 2 chars OR the first/last.
    if len(tokens) <= 2:
        return tokens
    return [tokens[0]] + [t for t in tokens[1:-1] if len(t) >= 2] + [tokens[-1]]


def _local_part_variants(local: str) -> List[str]:
    """Generate username candidates from the email local-part.

    Input ``"jane.doe"`` produces (in rank order):
        ``["jane.doe", "janedoe", "jane_doe", "jane-doe",
           "jane", "doe", "jdoe", "j.doe", "janed"]``

    Input ``"jdoe"`` (no separator) produces just ``["jdoe"]``.

    Numeric suffixes like ``"jane.doe2"`` produce two parallel candidate
    families: the literal (``jane.doe2, janedoe2, jdoe2, ...``) and the
    stripped form (``jane.doe, janedoe, jdoe, ...``). Numeric suffixes
    often persist across services (someone who's ``jane.doe2`` at work
    is often ``janedoe2`` on GitHub) so we keep both.
    """
    local = _normalise(local)
    if not local:
        return []

    out: List[str] = []

    def _add(candidate: str) -> None:
        if (
            candidate
            and _MIN_USERNAME_LEN <= len(candidate) <= _MAX_USERNAME_LEN
            and candidate not in out
        ):
            out.append(candidate)

    # Extract any trailing numeric suffix once and reuse below.
    m = _NUMERIC_SUFFIX_RE.search(local)
    if m:
        suffix = m.group(1)
        base = local[: -len(suffix)]
    else:
        suffix = ""
        base = local

    # 1. Exact local-part (with suffix if present).
    _add(local)

    # 2. Stripped form as its own candidate.
    if suffix:
        _add(base)

    # 3. Tokenise the base and derive separator/initial variants.
    tokens = re.split(r"[._-]+", base)
    tokens = [t for t in tokens if t]

    if len(tokens) <= 1:
        return out  # nothing further to derive from a single-token local

    concat = "".join(tokens)
    first, last = tokens[0], tokens[-1]

    # 3a. Concatenated, no separator ── plus suffix-bearing twin.
    _add(concat)
    if suffix:
        _add(concat + suffix)

    # 3b. Each documented separator variant ── with optional suffix twin.
    for sep in _SEPARATORS:
        variant = sep.join(tokens)
        _add(variant)
        if suffix:
            _add(variant + suffix)

    # 3c. Individual components (first name, last name alone).
    for token in tokens:
        _add(token)

    # 3d. Initial + last name variants (very common corporate pattern).
    if first and last and first != last:
        _add(first[0] + last)            # jdoe
        if suffix:
            _add(first[0] + last + suffix)  # jdoe2
        for sep in _SEPARATORS:
            _add(first[0] + sep + last)  # j.doe, j_doe, j-doe
        # 3e. First + last initial.
        _add(first + last[0])            # janed

    return out


def _name_variants(names: Sequence[str]) -> List[str]:
    """Generate username candidates from harvested names.

    For each name like ``"Jane Doe"``:
      - jane.doe / jane_doe / jane-doe / janedoe
      - jane / doe (lone first/last)
      - jdoe / j.doe / janed (initial patterns)
    """
    out: List[str] = []

    def _add(candidate: str) -> None:
        if (
            candidate
            and _MIN_USERNAME_LEN <= len(candidate) <= _MAX_USERNAME_LEN
            and candidate not in out
        ):
            out.append(candidate)

    for name in names:
        tokens = _split_name_parts(name)
        if not tokens:
            continue
        if len(tokens) == 1:
            _add(tokens[0])
            continue
        # Two+ tokens: use first + last (ignore middles for username
        # derivation since they rarely show up in handles).
        first = tokens[0]
        last = tokens[-1]
        _add(first)
        _add(last)
        _add(first + last)
        for sep in _SEPARATORS:
            _add(sep.join((first, last)))
        if first and last:
            _add(first[0] + last)
            for sep in _SEPARATORS:
                _add(first[0] + sep + last)
            _add(first + last[0])
            _add(last + first[0])

    return out


def derive_usernames(
    email: Optional[str] = None,
    names: Optional[Iterable[str]] = None,
    max_candidates: int = 12,
) -> List[str]:
    """Return a ranked list of likely usernames for an identity.

    Args:
        email: Corporate email like ``"jane.doe@example.com"``. The
            local-part is the strongest signal we have ── treated as a
            high-confidence base for derivation.
        names: Optional list of harvested human names associated with
            this identity, e.g. from theharvester or LinkedIn scraping.
            Used to expand the candidate set beyond what the email
            local-part alone produces.
        max_candidates: Cap on returned candidates. Default 12 ── matches
            the rate budget of one ``maigret`` run per candidate at
            stealth profile ``high``. Lower for paranoid runs, higher
            (up to ~30) for loud runs.

    Returns:
        Lowercased, deduplicated, frequency-ranked username candidates.
        Empty list when both ``email`` and ``names`` are empty or only
        contain role-account local-parts (admin@, info@, etc.).

    Ranking:
        1. Email local-part exact (jane.doe)
        2. Local-part with numeric suffix stripped (jane.doe from jane.doe2)
        3. Email separator variants (janedoe, jane_doe, jane-doe)
        4. Email component split (jane, doe)
        5. Email initial patterns (jdoe, j.doe, janed)
        6. Name-derived dotted/concat (from harvested names)
        7. Name-derived initial patterns
    """
    candidates: List[str] = []

    def _extend(items: Iterable[str]) -> None:
        for item in items:
            if item and item not in candidates:
                candidates.append(item)

    # 1. Email-derived candidates first (higher signal than names alone).
    if email and "@" in email:
        local, _, _domain = email.partition("@")
        local = _normalise(local)
        if local and local not in _ROLE_LOCALPARTS:
            _extend(_local_part_variants(local))

    # 2. Name-derived candidates next.
    if names:
        _extend(_name_variants([n for n in names if n]))

    return candidates[:max_candidates]
