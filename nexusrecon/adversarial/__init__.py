"""Adversarial platform self-defense — Phase 5 PR C.

The audit chain (Phase 1 PR D), confidence engine (Phase 2),
and signed bundles (Phase 5 PR B) all defend against
post-hoc tampering with NexusRecon's own outputs. PR C
defends against a DIFFERENT class of threat: the campaign's
upstream data sources actively feeding NexusRecon
misleading or hostile content.

Four detectors ship in PR A's package (locked in by the
architecture choices: "all of the above"):

  1. :mod:`poisoned_data` — wildcard / sinkhole / honeypot
     responses meant to expand the operator's view with
     useless or trap surfaces.
  2. :mod:`tool_patterns` — analyses the dispatcher log
     for runaway sequences: rapid pivots, low-yield bursts,
     repeat hits, tier escalation that violates scope.
  3. :mod:`inconsistency` — cross-checks entity claims for
     internal contradictions (geographic, timing, platform
     mismatches) the contradiction detector wouldn't catch
     because it grades per-pair, not per-record.
  4. :mod:`prompt_injection` — scans tool output for likely
     jailbreak / role-hijack payloads BEFORE the text lands
     in agent context. Regex + structural anomaly detection
     by default; LLM-based classification in high-spend mode.

Response policy (locked in: "downgrade + flag for review")
- LOW severity: log only, no confidence change.
- MEDIUM: appear in ``state["adversarial_findings"]`` +
  apply a modest confidence multiplier (0.7).
- HIGH: above + a sharper multiplier (0.5), bounded by
  the same 0.05 floor the contradiction detector uses.
- A separate :mod:`aggregator` ties findings together in a
  dedicated state log AND each detector is verifier-shaped
  so the verification orchestrator can pull them in too —
  closing the "both" half of the architecture choice.

What's deliberately NOT in PR C
- Auto-quarantine (rejected — false-positive suppression
  risk too high without a human in the loop).
- Live LLM scanning of every tool result by default
  (cost). Opt-in via ``state["adversarial_use_llm"]``.
- Active deception detection (presenting decoys back to
  the upstream attacker). Out of scope; lives in a
  separate phase.
"""
from nexusrecon.adversarial.aggregator import (
    AdversarialFinding,
    append_finding,
    finding_summary,
)
from nexusrecon.adversarial.inconsistency import (
    EvidenceInconsistencyDetector,
    InconsistencyVerdict,
)
from nexusrecon.adversarial.poisoned_data import (
    PoisonedDataDetector,
    PoisonVerdict,
)
from nexusrecon.adversarial.prompt_injection import (
    InjectionMatch,
    InjectionReport,
    PromptInjectionScanner,
    scan_text,
)
from nexusrecon.adversarial.tool_patterns import (
    PatternVerdict,
    ToolPatternAnalyzer,
)

__all__ = [
    "AdversarialFinding",
    "EvidenceInconsistencyDetector",
    "InconsistencyVerdict",
    "InjectionMatch",
    "InjectionReport",
    "PatternVerdict",
    "PoisonVerdict",
    "PoisonedDataDetector",
    "PromptInjectionScanner",
    "ToolPatternAnalyzer",
    "append_finding",
    "finding_summary",
    "scan_text",
]
