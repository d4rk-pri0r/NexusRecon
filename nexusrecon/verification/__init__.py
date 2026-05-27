"""Verification & Continuous Confidence Engine — Phase 2.

Phase 2 of ``IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md`` makes
verification a continuously-running background capability
instead of a single ``EvidenceAuditorAgent`` pass at the end.
A campaign's view of "is this finding true?" should sharpen
in real time as new signals land in the graph.

Pieces (split across PRs A–D)

- **Verification Orchestrator** — receives mutation events from
  the :class:`~nexusrecon.core.entity_graph.EntityGraph`, fans
  them out to registered verifiers, and writes a hash-chained
  audit record of every verdict. **(PR A — this PR.)**

- **Corroboration Engine** — boosts confidence when distinct
  *independence classes* of source signals agree on the same
  entity (e.g. ``passive_dns + certificate + active_probe``
  is stronger than three passive-DNS sources). **(PR A.)**

- **Contradiction Detector** — flags when new data directly
  contradicts a prior high-confidence claim, queues for human
  review. **(PR B.)**

- **Confidence Propagation** — downgrade downstream findings
  when an upstream entity loses confidence. **(PR C.)**

- **Adversarial Self-Check** + **Strategic Feedback** —
  periodic "red team the graph" pass; verification metrics
  flow into the strategic reasoning layer so the planner can
  react to under-corroborated clusters. **(PR D.)**

Design tenets

1. **Background, not blocking.** Verifiers run synchronously
   inside the mutation hook for now (the events fire often
   but each verifier is cheap). PR D may move heavy verifiers
   to a worker thread; the interface here doesn't pre-commit.

2. **Read-write the graph cautiously.** A verifier may
   adjust an entity's ``confidence`` field, but never mutate
   ``sources`` / ``provenance`` (those are sacred — see
   ``IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md§Phase 0``).

3. **Auditability first.** Every verdict that changes
   confidence is recorded via
   :meth:`AuditLog.log_agent_action` with structured fields
   so reviewers can reconstruct exactly which signals fired.

4. **Defensive everywhere.** A broken verifier MUST NOT take
   down the campaign that's writing to the graph. The
   orchestrator wraps every verifier call.
"""
from nexusrecon.verification.contradictions import (
    ContradictionDetector,
    ContradictionVerdict,
    resolve_contradiction,
)
from nexusrecon.verification.corroboration import (
    CorroborationEngine,
    CorroborationVerdict,
    SOURCE_INDEPENDENCE_CLASSES,
)
from nexusrecon.verification.orchestrator import (
    VerificationOrchestrator,
    Verifier,
)
from nexusrecon.verification.propagation import (
    ConfidencePropagator,
    PROPAGATING_REL_TYPES,
    PropagationStep,
    PropagationVerdict,
)

__all__ = [
    "ConfidencePropagator",
    "ContradictionDetector",
    "ContradictionVerdict",
    "CorroborationEngine",
    "CorroborationVerdict",
    "PROPAGATING_REL_TYPES",
    "PropagationStep",
    "PropagationVerdict",
    "SOURCE_INDEPENDENCE_CLASSES",
    "VerificationOrchestrator",
    "Verifier",
    "resolve_contradiction",
]
