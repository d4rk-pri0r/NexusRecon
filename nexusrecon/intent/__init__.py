"""Intent-driven entry — Phase 4 PR A.

The Phase 1 planner takes structured inputs (scope_summary,
seeds, mode, dispatch policy) and produces a Strategy. That's
the right entry surface for operators who already know what
they want — but it's a lot of forms for someone who knows
"I want to find leaked credentials at acme.com without
aggressive scanning."

The Intent Planner closes that gap. Operator types a single
sentence; the planner extracts the goal, the targets, the
tier ceiling, and any constraints, then synthesizes:

  - A ``scope.yaml`` stub the operator can review and save.
  - A :class:`Strategy` consistent with the extracted intent.

Operator surfaces (per the Phase 4 architecture decisions —
"all of the above"):

  - **One-shot CLI**: ``nexusrecon plan "<sentence>"`` emits
    a scope + strategy then exits. Scriptable.
  - **Interactive walk-through**: ``nexusrecon plan`` with
    no args runs the same extractor but confirms each
    inferred field via Rich prompts before writing files.
  - **TUI tab**: deferred to PR D polish — same orchestrator
    backs all three surfaces.

Module layout
- ``intent_parser`` — LLM-driven NL → structured intent
  extraction. Has a deterministic regex-based fallback so
  tests + air-gapped operators get useful output even
  without an LLM.
- ``scope_builder`` — turns a parsed :class:`IntentRecord`
  into a scope.yaml stub (in-memory dict, callers serialise).
- ``nl_planner`` — top-level orchestrator that ties intent →
  scope → strategy together.

Design tenets
- **Fall back gracefully.** No LLM key, no problem — the
  regex extractor handles the common cases (domain in the
  sentence, "passive only" → T1, "aggressive" → T3, etc.).
  Output gets tagged with ``confidence`` so callers know
  whether to second-guess.
- **Never auto-execute.** The CLI commands ALWAYS print the
  proposed scope + strategy and require operator
  confirmation before writing. Auto-execution from a
  natural-language sentence is exactly the kind of surface
  the Auditability First principle (METASPLOIT_PLAN §1)
  rejects.
"""
from nexusrecon.intent.intent_parser import (
    IntentRecord,
    extract_intent,
)
from nexusrecon.intent.nl_planner import (
    IntentPlanResult,
    plan_from_intent,
)
from nexusrecon.intent.scope_builder import build_scope_stub

__all__ = [
    "IntentPlanResult",
    "IntentRecord",
    "build_scope_stub",
    "extract_intent",
    "plan_from_intent",
]
