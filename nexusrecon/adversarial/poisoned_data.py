"""Poisoned data detector.

Three classes of poisoning the detector flags:

  - **Wildcard DNS**: many subdomains under one parent all
    resolving to the same IP set. Operators see this on
    catch-all DNS servers; attackers exploit it to inflate
    perceived attack surface.
  - **Honeypot / sinkhole IPs**: IPs in known sinkhole
    ranges (0.0.0.0, 127.0.0.0/8, 240.0.0.0/4 — the
    reserved + loopback bands), or commercial sinkhole
    operators' published ranges. A campaign-facing subdomain
    pointing at one of these is unlikely to be legitimately
    in scope.
  - **Suspicious uniformity**: ≥N subdomains arriving with
    identical confidence + a single shared source. Real
    recon produces messy distributions; uniformity is a
    pattern of automated fabrication.

The detector is verifier-shaped: it consumes mutation events
from the graph or runs as a phase-boundary sweep over the
graph. PR C wires the phase-boundary path; the per-mutation
path is a small follow-up.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from nexusrecon.adversarial.aggregator import (
    AdversarialFinding,
    append_finding,
    apply_downgrade,
    DEFAULT_DOWNGRADE_FACTOR_BY_SEVERITY,
)

log = structlog.get_logger(__name__)


# Sinkhole / honeypot IP ranges. Conservative list — only
# ranges that should NEVER appear as a legitimate target
# in OSINT recon.
_SINKHOLE_RANGES: list[str] = [
    "0.0.0.0/8",       # "this network"
    "127.0.0.0/8",     # loopback
    "169.254.0.0/16",  # link-local
    "192.0.0.0/24",    # IETF
    "192.0.2.0/24",    # TEST-NET-1
    "198.51.100.0/24", # TEST-NET-2
    "203.0.113.0/24",  # TEST-NET-3
    "240.0.0.0/4",     # reserved
    "::1/128",         # IPv6 loopback
]
_SINKHOLE_NETS: list[ipaddress._BaseNetwork] = [
    ipaddress.ip_network(r, strict=False) for r in _SINKHOLE_RANGES
]


def _is_sinkhole_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in _SINKHOLE_NETS)


@dataclass
class PoisonVerdict:
    """One detector verdict."""

    kind: str  # "wildcard_dns" | "sinkhole_ip" | "uniform_fabrication"
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


class PoisonedDataDetector:
    """Sweeps a graph for poisoned data patterns."""

    name: str = "poisoned_data"

    def __init__(
        self,
        *,
        wildcard_threshold: int = 8,
        uniform_cluster_threshold: int = 6,
    ) -> None:
        self.wildcard_threshold = wildcard_threshold
        self.uniform_cluster_threshold = uniform_cluster_threshold

    # ── Public sweep ─────────────────────────────────────────

    def scan(
        self,
        graph: Any,
        state: dict[str, Any] | None = None,
    ) -> list[PoisonVerdict]:
        """Run every check + (when state is provided) write
        findings into ``state["adversarial_findings"]`` AND
        apply the downgrade response."""
        verdicts: list[PoisonVerdict] = []
        verdicts.extend(self._check_sinkhole_ips(graph))
        verdicts.extend(self._check_wildcard_dns(graph))
        verdicts.extend(self._check_uniform_clusters(graph))

        if state is not None:
            self._apply_findings(graph, state, verdicts)
        return verdicts

    # ── Checks ───────────────────────────────────────────────

    def _check_sinkhole_ips(self, graph: Any) -> list[PoisonVerdict]:
        out: list[PoisonVerdict] = []
        for eid, data in graph.graph.nodes(data=True):
            if data.get("entity_type") != "ip_address":
                continue
            value = str(data.get("value", ""))
            if _is_sinkhole_ip(value):
                out.append(PoisonVerdict(
                    kind="sinkhole_ip",
                    severity="high",
                    entity_ids=[eid],
                    rationale=(
                        f"IP {value!r} is in a reserved / "
                        f"sinkhole range — unlikely to be a "
                        f"legitimate recon target."
                    ),
                    metadata={"value": value},
                ))
        return out

    def _check_wildcard_dns(self, graph: Any) -> list[PoisonVerdict]:
        """Find IPs that have ≥``wildcard_threshold`` distinct
        subdomain predecessors via ``resolves_to`` edges."""
        ip_to_subs: dict[str, set[str]] = defaultdict(set)
        for source, target, edge_data in graph.graph.edges(data=True):
            if edge_data.get("rel_type") != "resolves_to":
                continue
            target_data = graph.graph.nodes.get(target) or {}
            source_data = graph.graph.nodes.get(source) or {}
            if target_data.get("entity_type") != "ip_address":
                continue
            if source_data.get("entity_type") != "subdomain":
                continue
            ip_to_subs[target].add(source)

        out: list[PoisonVerdict] = []
        for ip_id, subs in ip_to_subs.items():
            if len(subs) < self.wildcard_threshold:
                continue
            # Group subdomains by parent. Wildcard DNS makes
            # all-under-one-parent more likely; cross-parent
            # collisions are stronger signal (deliberate
            # collision / aggregator IP).
            parents: Counter[str] = Counter()
            for sid in subs:
                data = graph.graph.nodes.get(sid) or {}
                parents[str(data.get("parent_domain", ""))] += 1
            top_parent, top_count = parents.most_common(1)[0]
            severity = "high" if top_count >= self.wildcard_threshold * 2 else "medium"
            ip_value = graph.graph.nodes[ip_id].get("value", ip_id)
            out.append(PoisonVerdict(
                kind="wildcard_dns",
                severity=severity,
                entity_ids=sorted(subs) + [ip_id],
                rationale=(
                    f"{len(subs)} subdomains resolve to "
                    f"{ip_value!r}; {top_count} share parent "
                    f"{top_parent!r}. Looks like a wildcard "
                    f"DNS / aggregator response, not real "
                    f"distinct hosts."
                ),
                metadata={
                    "ip_value": ip_value,
                    "subdomain_count": len(subs),
                    "top_parent": top_parent,
                    "top_parent_count": top_count,
                },
            ))
        return out

    def _check_uniform_clusters(self, graph: Any) -> list[PoisonVerdict]:
        """Subdomains sharing parent + single source +
        identical confidence in suspicious lockstep. Real recon
        produces noise; uniformity is a forgery tell."""
        # Bucket by (parent, source, confidence).
        buckets: dict[
            tuple[str, str, float], list[str],
        ] = defaultdict(list)
        for eid, data in graph.graph.nodes(data=True):
            if data.get("entity_type") != "subdomain":
                continue
            sources = data.get("sources") or []
            if len(sources) != 1:
                continue
            key = (
                str(data.get("parent_domain", "")),
                str(sources[0]),
                round(float(data.get("confidence", 0.0)), 3),
            )
            buckets[key].append(eid)

        out: list[PoisonVerdict] = []
        for (parent, source, confidence), eids in buckets.items():
            if len(eids) < self.uniform_cluster_threshold:
                continue
            # Skip scope-derived seeds — those legitimately
            # share source.
            if source == "scope":
                continue
            severity = (
                "high" if len(eids) >= self.uniform_cluster_threshold * 2
                else "medium"
            )
            out.append(PoisonVerdict(
                kind="uniform_fabrication",
                severity=severity,
                entity_ids=sorted(eids),
                rationale=(
                    f"{len(eids)} subdomains of "
                    f"{parent!r} arrived from a single source "
                    f"{source!r} with identical confidence "
                    f"{confidence:.2f}. Real recon distributes "
                    f"more noisily; uniformity is a fabrication "
                    f"tell."
                ),
                metadata={
                    "parent_domain": parent,
                    "source": source,
                    "confidence": confidence,
                    "cluster_size": len(eids),
                },
            ))
        return out

    # ── Findings application ─────────────────────────────────

    def _apply_findings(
        self,
        graph: Any,
        state: dict[str, Any],
        verdicts: list[PoisonVerdict],
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
                    reason=f"poisoned_data:{v.kind}",
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
