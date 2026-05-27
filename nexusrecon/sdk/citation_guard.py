"""Citation guardrails — make agents prove their findings
cite real graph entities.

The problem
- LLM agents routinely produce findings that reference
  ``acme.com``, ``some-bucket``, ``employee-name@acme.com``
  with high confidence — and a meaningful fraction of those
  references don't actually exist anywhere in the campaign's
  Living Graph. The finding is a hallucination dressed up as
  evidence-backed analysis.

The fix
- The agent's output is structured to include a
  ``citations`` list (or a ``CITATIONS:`` JSON block, or
  inline ``[[entity_id]]`` markers). Before the finding
  lands in the report, the guardrail extracts each claimed
  citation + verifies it against the live graph:
    * Does an entity by this ID exist?
    * Does an entity with this value (domain string, email,
      etc.) exist?
    * Is the citation's claimed entity type consistent with
      what the graph holds?

- Each violation is recorded with a *severity*:
    * ``error``: claimed entity_id doesn't exist at all.
    * ``warning``: value exists but type mismatch (e.g.
      cited as ``email`` but graph holds it as
      ``username``).
    * ``info``: stylistic issues (citation list empty when
      the agent made specific claims, etc. — surface but
      don't block).

What this is NOT
- A semantic checker. We verify the citations point at
  real graph state; we don't verify the finding's
  *conclusions* make sense.
- A blocker by default. The guardrail returns a report;
  callers (agent base class, audit pipeline) decide whether
  to filter findings, raise, or merely log. Phase 2's
  contradiction queue is the natural escalation path.

Integration points
- :func:`validate_citations` returns a
  :class:`CitationReport`. The agent executor can call it
  after parsing the agent response.
- ``state["citation_violations"]`` accumulates the audit
  trail; PR D's TUI / report surface will render it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)


_INLINE_CITATION_PATTERN = re.compile(r"\[\[([a-zA-Z0-9_\-:.\/]+)\]\]")


# ──────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────


@dataclass
class CitationViolation:
    """One thing a citation got wrong."""

    citation: str
    """The raw string the agent cited (entity_id or value)."""
    severity: str  # "error" | "warning" | "info"
    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "citation": self.citation,
            "severity": self.severity,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }


@dataclass
class CitationReport:
    """Aggregate verdict for one agent response.

    Used by the agent executor + the audit pipeline. The
    ``violations`` list is intentionally first-class so
    downstream code can filter / route without re-parsing."""

    agent_name: str
    cited_count: int
    verified_count: int
    violations: list[CitationViolation] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Any ``error``-severity violations? Callers that want
        to gate findings on citation quality check this."""
        return any(v.severity == "error" for v in self.violations)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"error": 0, "warning": 0, "info": 0}
        for v in self.violations:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "cited_count": self.cited_count,
            "verified_count": self.verified_count,
            "severity_counts": self.severity_counts,
            "violations": [v.to_dict() for v in self.violations],
        }


# ──────────────────────────────────────────────────────────────────────
# Citation extraction
# ──────────────────────────────────────────────────────────────────────


def extract_citations(text: str) -> list[str]:
    """Pull citation strings out of an agent response.

    Today's contract: ``[[citation]]`` inline markers. Returns
    a list of citation strings in order of appearance,
    deduplicated while preserving order. Generous matching —
    any alphanumeric / ``_-:./`` string between the brackets
    is captured. If a pack-author prefers a JSON block or a
    different convention, they can pre-process before
    handing the text to :func:`validate_citations`."""
    seen: dict[str, None] = {}
    for match in _INLINE_CITATION_PATTERN.finditer(text or ""):
        token = match.group(1)
        if token and token not in seen:
            seen[token] = None
    return list(seen.keys())


# ──────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────


def validate_citations(
    text: str,
    graph: Any,
    *,
    agent_name: str = "agent",
    explicit_citations: list[str] | None = None,
    expected_types: dict[str, str] | None = None,
) -> CitationReport:
    """Validate citations in an agent response against the
    live graph.

    Args
    - ``text``: the agent's raw output. Citations are
      extracted via :func:`extract_citations`.
    - ``graph``: an
      :class:`~nexusrecon.core.entity_graph.EntityGraph`.
      Validates against ``graph.graph.nodes``.
    - ``agent_name``: carried into the report.
    - ``explicit_citations``: optional override — useful when
      the agent already emits a structured citations list (no
      need to re-parse). Skips inline extraction.
    - ``expected_types``: optional dict mapping citation
      string → expected ``entity_type`` value. Mismatches land
      as ``warning``s. Missing types → no constraint.

    Returns a :class:`CitationReport`. Never raises — the
    report's ``has_errors`` flag is the caller's escalation
    signal.
    """
    citations = (
        list(explicit_citations)
        if explicit_citations is not None
        else extract_citations(text)
    )
    expected_types = expected_types or {}

    report = CitationReport(
        agent_name=agent_name,
        cited_count=len(citations),
        verified_count=0,
    )

    if not citations:
        # An empty citations list when the response made
        # specific claims is an ``info``-severity finding.
        # Heuristic: response is non-empty and contains words
        # like "found", "discovered", "identified".
        if text and re.search(
            r"\b(found|discovered|identified|confirmed)\b",
            text, re.IGNORECASE,
        ):
            report.violations.append(CitationViolation(
                citation="",
                severity="info",
                rationale=(
                    "Response makes specific claims but cites "
                    "no graph entities."
                ),
            ))
        return report

    for cite in citations:
        node_data = _lookup(graph, cite)
        if node_data is None:
            report.violations.append(CitationViolation(
                citation=cite,
                severity="error",
                rationale=(
                    f"Citation {cite!r} resolves to no entity in "
                    f"the graph (neither by id nor by value)."
                ),
            ))
            continue

        report.verified_count += 1

        expected = expected_types.get(cite)
        if expected and node_data.get("entity_type") != expected:
            report.violations.append(CitationViolation(
                citation=cite,
                severity="warning",
                rationale=(
                    f"Citation {cite!r} cited as type "
                    f"{expected!r} but graph holds it as "
                    f"{node_data.get('entity_type')!r}."
                ),
                metadata={
                    "expected_type": expected,
                    "actual_type": node_data.get("entity_type"),
                },
            ))

    return report


def _lookup(graph: Any, cite: str) -> dict[str, Any] | None:
    """Resolve a citation string to a graph node. Tries
    entity_id first, then a linear search by ``value``. The
    linear search is acceptable for the typical campaign size
    (low thousands of entities); a value-index optimisation
    is a future PR if telemetry shows hot spots."""
    nodes = graph.graph.nodes
    direct = nodes.get(cite)
    if direct is not None:
        return dict(direct)
    cite_lower = cite.lower()
    for _, data in nodes(data=True):
        value = data.get("value")
        if isinstance(value, str) and value.lower() == cite_lower:
            return dict(data)
    return None
