"""
Reputation-weighted attribution adjustment (Phase C item C3).

Per-service reputation/karma/follower numbers carry meaningful signal
about whether an account belongs to a real human who has used the
service substantively:

  - StackOverflow reputation > 1000 = real engineer who has answered
    questions over years. Very unlikely to be a sockpuppet.
  - Reddit karma > 5000 = sustained activity across many subreddits.
    Real human (or a long-running bot, which is rare for accounts
    matching a corporate email's local-part).
  - GitHub follower count > 100 = real developer with visible work.
  - LinkedIn... we don't have this signal yet, but the principle
    holds for any reputation-bearing service.

The Phase C3 adjustment treats a non-trivial reputation number as a
"this is a real human, not a coincidentally-matching empty account"
signal. It bumps the profile-coherence sub-score by a small amount
proportional to the reputation tier.

## Why not roll this into service-tier?

Service tier (Phase A) measures "how trustworthy is the platform for
identity claims" ── LinkedIn requires real names, gaming forums
don't. Reputation measures "how much has this specific account
actually used the platform" ── a brand-new GitHub account with 0
repos and 0 followers carries weaker identity signal than a 10-year-
old account with 200 repos. The two are independent axes; we score
them separately.

## Thresholds

Per-service maps because reputation numbers are wildly different
scales across services. Stack Overflow reputation of 1000 represents
real engagement; Twitter follower count of 1000 is just a small
audience. The thresholds below were chosen from public per-service
distribution data:

  - GitHub follower_count: 10 = active, 100 = visible, 1000 = popular
  - StackOverflow reputation: 100 = engaged, 1000 = real engineer,
    10000 = expert
  - Reddit total_karma: 100 = engaged, 1000 = active, 10000 = power user
  - Generic / unknown: not used (no reputation signal)

Returned boost values are in ``[0.0, 0.3]`` ── a high-rep account
can add up to 0.3 to the profile_coherence signal, but never more.
This keeps the per-axis weighting balanced; without the cap a single
super-active StackOverflow account could outweigh all other signals
combined.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


# Per-service threshold tables: (low, mid, high) → (boost, boost, boost)
# Pick the highest threshold the reputation meets and use the
# corresponding boost. Below ``low`` → 0.0 (no signal).

_THRESHOLDS: Dict[str, Dict[str, tuple]] = {
    "github": {
        "low":  (10, 0.10),
        "mid":  (100, 0.20),
        "high": (1000, 0.30),
    },
    "stackoverflow": {
        "low":  (100, 0.10),
        "mid":  (1000, 0.20),
        "high": (10000, 0.30),
    },
    "stack overflow": {
        "low":  (100, 0.10),
        "mid":  (1000, 0.20),
        "high": (10000, 0.30),
    },
    "reddit": {
        "low":  (100, 0.10),
        "mid":  (1000, 0.20),
        "high": (10000, 0.30),
    },
    "gitlab": {
        # GitLab doesn't expose follower count in the public API;
        # reputation is treated as project count when available.
        "low":  (3, 0.10),
        "mid":  (10, 0.20),
        "high": (50, 0.30),
    },
}

# Boost cap ── reputation alone never exceeds this contribution to
# the profile-coherence signal. Keeps a single high-rep account from
# saturating the score.
_BOOST_CAP = 0.30


def reputation_boost(service: str, reputation_value: Optional[float]) -> float:
    """Return the reputation boost in ``[0.0, 0.3]`` for one account.

    Args:
        service: Service name (case-insensitive). Unmapped services
            return 0.0 ── no reputation signal applied.
        reputation_value: The service-appropriate reputation number.
            For GitHub this is follower count; for StackOverflow it's
            site reputation; for Reddit it's total karma. ``None`` or
            non-numeric values return 0.0.

    Returns:
        A boost value in ``[0.0, 0.30]`` to add to the
        profile-coherence signal during attribution scoring.

    Examples:
        >>> reputation_boost("StackOverflow", 12450)
        0.30
        >>> reputation_boost("GitHub", 45)
        0.10
        >>> reputation_boost("Reddit", 50)
        0.0
        >>> reputation_boost("UnmappedService", 999999)
        0.0
    """
    if reputation_value is None:
        return 0.0
    try:
        value = float(reputation_value)
    except (TypeError, ValueError):
        return 0.0
    if value <= 0:
        return 0.0

    key = (service or "").strip().lower()
    table = _THRESHOLDS.get(key)
    if table is None:
        return 0.0

    # Walk thresholds from high to low and return the first match.
    for tier_key in ("high", "mid", "low"):
        threshold, boost = table[tier_key]
        if value >= threshold:
            return min(boost, _BOOST_CAP)

    return 0.0


def boost_for_profile(profile: Any) -> float:
    """Compute the reputation boost from a fetched ProfileData (or a
    dict shaped like one).

    Reads ``service`` + ``reputation`` (preferred) or
    ``follower_count`` (GitHub case where the reputation proxy is
    follower count). Treats either dataclass-style attribute access
    or dict-style ``get()`` access uniformly via ``getattr``.

    Returns 0.0 when the profile lacks the relevant fields ── the
    Phase A baseline behaviour is preserved when reputation data
    isn't available.
    """
    if profile is None:
        return 0.0

    def _get(field_name: str) -> Any:
        if isinstance(profile, dict):
            return profile.get(field_name)
        return getattr(profile, field_name, None)

    service = _get("service") or ""
    # Prefer explicit reputation; fall back to follower_count (GitHub).
    value = _get("reputation")
    if value is None:
        value = _get("follower_count")
    return reputation_boost(service, value)
