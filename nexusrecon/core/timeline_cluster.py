"""
Account-creation timeline clustering (Phase C item C2).

When several discovered accounts were created within a short time
window ── say, the same week of 2018 ── that's consistent with one
person setting up their online presence around a single life event
(new job, name change, leaving a previous job). Random matches across
unrelated humans don't cluster temporally; consistent identity does.

This module:

  - Parses creation timestamps from the various formats services use
    (ISO 8601 strings from GitHub/GitLab, Unix timestamps from Reddit
    and Stack Exchange, plain dates).
  - Clusters accounts by creation-time proximity using a configurable
    window (default 30 days).
  - Returns clusters as a list-of-lists for the agent to cite.

The clustering signal complements the avatar / linked-account graph:

  - Avatar match: same image on N services. Strong.
  - Linked-account: service A's bio claims service B's handle. Strong.
  - **Timeline cluster**: N accounts created within the same window.
    Statistical signal, not deterministic ── two unrelated people
    could happen to make accounts the same week. But a cluster of
    4+ accounts in a single week is unlikely to be coincidence.

Reported to the cloud_identity agent as a narrative signal ── not
folded into the per-hit confidence score, because cluster membership
is a property of the SET of hits, not any individual one.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Default cluster window: accounts created within 30 days of each
# other are grouped. Short enough that random coincidence is unlikely
# (4+ accounts in 30 days is statistically meaningful) but wide enough
# that someone setting up their presence over a few weeks still
# clusters.
_DEFAULT_WINDOW_DAYS = 30


# Match a Unix timestamp (numeric string of 10 digits = seconds since
# epoch, or 13 digits = milliseconds). Many services report
# created_utc as a stringified number.
_UNIX_SECONDS_RE = re.compile(r"^\d{9,10}(\.\d+)?$")
_UNIX_MILLIS_RE = re.compile(r"^\d{12,13}$")


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse a service-reported timestamp into a UTC-aware datetime.

    Handles:
      - ISO 8601 strings (``"2014-03-04T12:00:00Z"``,
        ``"2014-03-04T12:00:00+00:00"``).
      - Unix epoch seconds (``"1395849600"``, ``"1395849600.5"``).
      - Unix epoch milliseconds (``"1395849600000"``).
      - Bare dates (``"2014-03-04"``).
      - ``None`` or empty → ``None``.

    Returns ``None`` on parse failure ── callers treat absent
    timestamps as "no temporal signal," not as an error condition.
    """
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None

    # Unix epoch (seconds).
    if _UNIX_SECONDS_RE.match(s):
        try:
            return datetime.fromtimestamp(float(s), tz=UTC)
        except (ValueError, OverflowError, OSError):
            pass

    # Unix epoch (milliseconds).
    if _UNIX_MILLIS_RE.match(s):
        try:
            return datetime.fromtimestamp(int(s) / 1000.0, tz=UTC)
        except (ValueError, OverflowError, OSError):
            pass

    # ISO 8601 ── Python's fromisoformat handles most variants, but
    # GitHub's ``Z`` suffix needs swapping for ``+00:00``.
    iso_candidate = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        pass

    # Bare date.
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        pass

    return None


@dataclass
class AccountTimestamp:
    """One discovered account's identity-temporal coordinates."""

    service: str
    username: str
    created_at: datetime
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "username": self.username,
            "created_at": self.created_at.isoformat(),
            "raw": self.raw,
        }


@dataclass
class TimelineCluster:
    """A group of accounts whose creation times fall within the
    configured window of each other."""

    accounts: list[AccountTimestamp] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.accounts)

    @property
    def earliest(self) -> datetime | None:
        return min((a.created_at for a in self.accounts), default=None)

    @property
    def latest(self) -> datetime | None:
        return max((a.created_at for a in self.accounts), default=None)

    @property
    def span_days(self) -> int:
        if self.earliest is None or self.latest is None:
            return 0
        return (self.latest - self.earliest).days

    def to_dict(self) -> dict[str, Any]:
        return {
            "size": self.size,
            "span_days": self.span_days,
            "earliest": self.earliest.isoformat() if self.earliest else None,
            "latest": self.latest.isoformat() if self.latest else None,
            "accounts": [a.to_dict() for a in self.accounts],
        }


def extract_timestamps_from_hits(
    hits: Sequence[dict[str, Any]],
) -> list[AccountTimestamp]:
    """Pull parseable creation timestamps out of a list of maigret hits.

    Each hit may have a ``fetched_profile`` from Phase B carrying
    ``created_at`` ── we read from there first, falling back to
    ``raw_extras`` if present. Hits without a parseable timestamp are
    silently skipped.
    """
    out: list[AccountTimestamp] = []
    for hit in hits:
        profile = hit.get("fetched_profile") or {}
        raw_ts = profile.get("created_at")
        if not raw_ts:
            raw_ts = (profile.get("raw_extras") or {}).get("created_at")
        if not raw_ts:
            continue
        parsed = parse_timestamp(raw_ts)
        if parsed is None:
            continue
        out.append(AccountTimestamp(
            service=hit.get("service", ""),
            username=hit.get("username", ""),
            created_at=parsed,
            raw=str(raw_ts),
        ))
    return out


def find_timeline_clusters(
    accounts: Sequence[AccountTimestamp],
    window_days: int = _DEFAULT_WINDOW_DAYS,
    min_cluster_size: int = 2,
) -> list[TimelineCluster]:
    """Group accounts whose creation times fall within ``window_days``
    of each other.

    Uses single-link clustering on a sorted-by-time list ── walk the
    list, growing a cluster while consecutive accounts are within
    window, starting a new one when the gap exceeds window. This
    misses clusters that span more than ``window_days`` (e.g. 5
    accounts created across 60 days when window=30 won't all cluster)
    but the alternative (chained linkage) would group too aggressively.

    Returns clusters of size ``>= min_cluster_size`` only. Singletons
    don't carry cross-account signal."""
    if not accounts:
        return []

    sorted_accounts = sorted(accounts, key=lambda a: a.created_at)
    clusters: list[list[AccountTimestamp]] = []
    current: list[AccountTimestamp] = [sorted_accounts[0]]

    for acct in sorted_accounts[1:]:
        delta = (acct.created_at - current[-1].created_at).days
        if delta <= window_days:
            current.append(acct)
        else:
            if len(current) >= min_cluster_size:
                clusters.append(current)
            current = [acct]
    if len(current) >= min_cluster_size:
        clusters.append(current)

    return [TimelineCluster(accounts=c) for c in clusters]


def annotate_hits_with_cluster_ids(
    hits: list[dict[str, Any]],
    clusters: Sequence[TimelineCluster],
) -> None:
    """Mutate hits in place: every hit whose (service, username) is in
    a cluster gets ``timeline_cluster_id`` and ``timeline_cluster_size``
    set."""
    lookup: dict[tuple, tuple] = {}
    for cluster_id, cluster in enumerate(clusters):
        for acct in cluster.accounts:
            key = (acct.service.lower(), acct.username.lower())
            lookup[key] = (cluster_id, cluster.size)

    for hit in hits:
        key = (
            (hit.get("service") or "").lower(),
            (hit.get("username") or "").lower(),
        )
        if key in lookup:
            cluster_id, cluster_size = lookup[key]
            hit["timeline_cluster_id"] = cluster_id
            hit["timeline_cluster_size"] = cluster_size
