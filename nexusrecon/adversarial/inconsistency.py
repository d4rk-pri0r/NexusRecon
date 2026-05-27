"""Evidence inconsistency detector.

Cross-checks individual entity records for internal
contradictions the Phase 2 contradiction detector wouldn't
catch — that one grades pairwise sticky-field conflicts; this
one grades single-record self-inconsistency.

Patterns:

  - **Timing impossibility**: an entity's ``first_seen``
    timestamp is BEFORE the earliest provenance record's
    timestamp. Either clock skew or fabrication.
  - **Repository platform mismatch**: a Repository entity
    with ``platform=github`` but a URL/value that doesn't
    match github.com (or gitlab.com when platform=gitlab,
    etc.).
  - **Cloud asset provider/service mismatch**: a cloud asset
    tagged ``provider=aws`` with a value matching an
    ``azurewebsites.net`` / ``storage.googleapis.com``
    pattern — a tool either misclassified or the
    upstream is bad.
  - **Email/domain disagreement**: a Person entity with an
    email under one domain but a ``works_at`` edge to an
    Organization with a totally different canonical
    domain.

Findings produce a verdict + (via the aggregator) a
confidence downgrade on the inconsistent entity.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

from nexusrecon.adversarial.aggregator import (
    AdversarialFinding,
    append_finding,
    apply_downgrade,
    DEFAULT_DOWNGRADE_FACTOR_BY_SEVERITY,
)

log = structlog.get_logger(__name__)


# Canonical host fingerprints per platform.
_PLATFORM_HOSTS: dict[str, list[str]] = {
    "github": ["github.com", "github.io"],
    "gitlab": ["gitlab.com"],
    "bitbucket": ["bitbucket.org"],
}

# Cloud provider value patterns.
_PROVIDER_PATTERNS: dict[str, list[str]] = {
    "aws": [
        r"\.s3[.-]", r"\.amazonaws\.com",
        r"^arn:aws:", r"\.cloudfront\.net",
    ],
    "azure": [
        r"\.azurewebsites\.net", r"\.blob\.core\.windows\.net",
        r"\.azure\.com", r"\.windows\.net",
    ],
    "gcp": [
        r"\.googleapis\.com", r"\.appspot\.com",
        r"\.cloud\.google\.com",
    ],
}


@dataclass
class InconsistencyVerdict:
    """One inconsistency detection."""

    kind: str
    severity: str
    entity_ids: list[str]
    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "entity_ids": list(self.entity_ids),
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }


class EvidenceInconsistencyDetector:
    """Sweeps the graph for self-inconsistent entities."""

    name: str = "inconsistency"

    def scan(
        self,
        graph: Any,
        state: dict[str, Any] | None = None,
    ) -> list[InconsistencyVerdict]:
        """Run every check + apply downgrade response when
        ``state`` is provided."""
        verdicts: list[InconsistencyVerdict] = []
        for eid, data in graph.graph.nodes(data=True):
            verdicts.extend(self._check_one(eid, data))
        # Cross-entity checks.
        verdicts.extend(self._check_email_org_disagreement(graph))

        if state is not None:
            self._apply_findings(graph, state, verdicts)
        return verdicts

    # ── Per-entity checks ───────────────────────────────────

    def _check_one(
        self, eid: str, data: dict[str, Any],
    ) -> list[InconsistencyVerdict]:
        out: list[InconsistencyVerdict] = []
        out.extend(self._check_timing(eid, data))
        out.extend(self._check_repository_platform(eid, data))
        out.extend(self._check_cloud_provider(eid, data))
        return out

    def _check_timing(
        self, eid: str, data: dict[str, Any],
    ) -> list[InconsistencyVerdict]:
        """``first_seen`` < earliest provenance timestamp is
        physically impossible — either clock skew or
        forgery."""
        first_seen_raw = data.get("first_seen")
        provenance = data.get("provenance") or []
        if not first_seen_raw or not isinstance(provenance, list):
            return []
        first_seen = _parse_ts(first_seen_raw)
        if first_seen is None:
            return []
        earliest: datetime | None = None
        for rec in provenance:
            if not isinstance(rec, dict):
                continue
            ts = _parse_ts(rec.get("timestamp"))
            if ts is None:
                continue
            if earliest is None or ts < earliest:
                earliest = ts
        if earliest is None:
            return []
        # Allow 1 second of slack for serialisation
        # round-trips that might shave sub-second precision.
        if first_seen + _delta_seconds(1) < earliest:
            return [InconsistencyVerdict(
                kind="timing_impossibility",
                severity="high",
                entity_ids=[eid],
                rationale=(
                    f"first_seen={first_seen.isoformat()} "
                    f"precedes earliest provenance "
                    f"timestamp {earliest.isoformat()} — "
                    f"clock skew or fabrication."
                ),
                metadata={
                    "first_seen": first_seen.isoformat(),
                    "earliest_provenance": earliest.isoformat(),
                },
            )]
        return []

    def _check_repository_platform(
        self, eid: str, data: dict[str, Any],
    ) -> list[InconsistencyVerdict]:
        if data.get("entity_type") != "repository":
            return []
        platform = str(data.get("platform", "")).lower()
        if platform not in _PLATFORM_HOSTS:
            return []
        value = str(data.get("value", "")).lower()
        # Repository values are typically ``owner/repo``,
        # not URLs. Only flag when value LOOKS like a host
        # (contains a dot) and the host doesn't match.
        if "." not in value:
            return []
        if any(host in value for host in _PLATFORM_HOSTS[platform]):
            return []
        return [InconsistencyVerdict(
            kind="repository_platform_mismatch",
            severity="medium",
            entity_ids=[eid],
            rationale=(
                f"Repository value {value!r} doesn't match "
                f"declared platform {platform!r}. Expected "
                f"one of: {_PLATFORM_HOSTS[platform]}."
            ),
            metadata={"platform": platform, "value": value},
        )]

    def _check_cloud_provider(
        self, eid: str, data: dict[str, Any],
    ) -> list[InconsistencyVerdict]:
        if data.get("entity_type") != "cloud_asset":
            return []
        provider = str(data.get("provider", "")).lower()
        if provider not in _PROVIDER_PATTERNS:
            return []
        value = str(data.get("value", "")).lower()
        # Match against THIS provider's patterns. If none
        # match AND another provider's patterns do, that's
        # a mismatch.
        my_patterns = _PROVIDER_PATTERNS[provider]
        if any(re.search(p, value) for p in my_patterns):
            return []
        for other_provider, patterns in _PROVIDER_PATTERNS.items():
            if other_provider == provider:
                continue
            if any(re.search(p, value) for p in patterns):
                return [InconsistencyVerdict(
                    kind="cloud_provider_mismatch",
                    severity="medium",
                    entity_ids=[eid],
                    rationale=(
                        f"Cloud asset {value!r} declared as "
                        f"{provider!r} but value matches "
                        f"{other_provider!r} naming pattern."
                    ),
                    metadata={
                        "declared_provider": provider,
                        "value": value,
                        "suggested_provider": other_provider,
                    },
                )]
        return []

    # ── Cross-entity checks ─────────────────────────────────

    def _check_email_org_disagreement(
        self, graph: Any,
    ) -> list[InconsistencyVerdict]:
        """A Person with an email under domain X and a
        WORKS_AT edge to an Organization whose canonical
        domain is clearly Y. Flag when domain mismatch is
        unambiguous."""
        out: list[InconsistencyVerdict] = []
        # Collect each Person's emails + WORKS_AT targets.
        for person_id, person_data in graph.graph.nodes(data=True):
            if person_data.get("entity_type") != "person":
                continue
            email_domains: set[str] = set()
            org_domains: set[str] = set()
            for source, target, edge_data in graph.graph.out_edges(
                person_id, data=True,
            ):
                target_data = graph.graph.nodes.get(target) or {}
                if (
                    edge_data.get("rel_type") == "has_account"
                    and target_data.get("entity_type") == "email"
                ):
                    domain = str(target_data.get("domain", "")).lower()
                    if domain:
                        email_domains.add(domain)
                if (
                    edge_data.get("rel_type") == "works_at"
                    and target_data.get("entity_type") == "organization"
                ):
                    # Organization's canonical_domain field
                    # is the cleanest signal; fall back to
                    # value.
                    od = str(
                        target_data.get("canonical_domain")
                        or target_data.get("value", "")
                    ).lower()
                    if od and "." in od:
                        org_domains.add(od)
            if not email_domains or not org_domains:
                continue
            # If NO email domain matches (or is a subdomain
            # of) ANY org domain, that's a disagreement.
            if any(
                e == o or e.endswith("." + o)
                for e in email_domains for o in org_domains
            ):
                continue
            out.append(InconsistencyVerdict(
                kind="email_org_disagreement",
                severity="medium",
                entity_ids=[person_id],
                rationale=(
                    f"Person email domains "
                    f"{sorted(email_domains)} don't align "
                    f"with linked organization domains "
                    f"{sorted(org_domains)}."
                ),
                metadata={
                    "email_domains": sorted(email_domains),
                    "org_domains": sorted(org_domains),
                },
            ))
        return out

    # ── Apply ────────────────────────────────────────────────

    def _apply_findings(
        self,
        graph: Any,
        state: dict[str, Any],
        verdicts: list[InconsistencyVerdict],
    ) -> None:
        for v in verdicts:
            factor = DEFAULT_DOWNGRADE_FACTOR_BY_SEVERITY.get(
                v.severity, 1.0,
            )
            deltas: list[dict[str, Any]] = []
            if factor < 1.0:
                deltas = apply_downgrade(
                    graph, v.entity_ids,
                    factor=factor,
                    reason=f"inconsistency:{v.kind}",
                )
            append_finding(state, AdversarialFinding(
                detector=self.name,
                severity=v.severity,
                rationale=v.rationale,
                entity_ids=v.entity_ids,
                metadata={"kind": v.kind, **v.metadata},
                downgrade_applied=bool(deltas),
                downgrade_factor=factor,
                confidence_deltas=deltas,
            ))


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _delta_seconds(n: int):
    from datetime import timedelta
    return timedelta(seconds=n)
