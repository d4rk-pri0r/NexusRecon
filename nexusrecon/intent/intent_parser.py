"""Natural-language → structured intent extraction.

Two-path design
- **LLM path**: invoke the configured LLM with a strict-JSON
  prompt that pulls targets, intent categories, tier ceiling,
  stealth profile, and any constraints out of the operator's
  sentence. Highest-fidelity extraction; the default when an
  LLM is configured.
- **Regex fallback**: deterministic patterns for the common
  cases (domains in the sentence, "passive" / "aggressive"
  keywords, "credentials" / "subdomains" / "cloud" intent
  categories). Always available; tagged ``confidence="low"``
  so callers know the LLM didn't run.

Output shape
- :class:`IntentRecord` carries everything the
  :func:`build_scope_stub` and :class:`Strategy` synthesis
  need. Pydantic for serialisation parity with the rest of
  the SDK.
- Every field has a sensible default so a partial extraction
  is still actionable.

What's deliberately NOT extracted
- Operator identity / authorization markers — those are
  legal/compliance fields the operator MUST fill in before
  running. The NL planner refuses to invent them.
- Engagement dates — same reason. The scope stub leaves
  placeholders.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Record
# ──────────────────────────────────────────────────────────────────────


@dataclass
class IntentRecord:
    """What the parser extracted from one operator sentence.

    Defaults are intentionally conservative: when in doubt
    pick the LESS invasive option (lower tier, higher
    stealth). Operators escalate explicitly, never by
    omission."""

    raw_sentence: str
    """The operator's input verbatim. Carried through so the
    audit log captures what they typed."""

    targets: list[str] = field(default_factory=list)
    """Domain / subdomain / IP strings extracted from the
    sentence. Empty means "no target found" — callers should
    prompt or fail."""

    intent_categories: list[str] = field(default_factory=list)
    """Free-form labels: ``credentials``, ``subdomains``,
    ``cloud``, ``identity``, ``pretext``, ``vulnerabilities``,
    ``executives``. Drives Strategy phase selection."""

    max_tier: str = "T1"
    """Default to T1 — covers passive recon + light HTTP
    probing. Operators saying "aggressive" / "active scanning"
    upgrade to T2 or T3 explicitly."""

    stealth_profile: str = "high"
    """``low`` / ``medium`` / ``high``. Default ``high``
    matches the conservative posture."""

    dispatch_policy_name: str = "lite"

    constraints: dict[str, Any] = field(default_factory=dict)
    """Operator-supplied limits — typically ``{"max_llm_cost_usd":
    5.0}`` or ``{"allow_paid_apis": False}``."""

    rationale: str = ""
    """Free-form explanation from the parser. Survives into
    the scope.yaml comments + the strategy metadata so
    reviewers see why the planner picked what it picked."""

    confidence: str = "low"
    """``high`` when the LLM ran cleanly; ``medium`` when
    fallback patterns produced a reasonable extraction;
    ``low`` when the parser had nothing to work with."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_sentence": self.raw_sentence,
            "targets": list(self.targets),
            "intent_categories": list(self.intent_categories),
            "max_tier": self.max_tier,
            "stealth_profile": self.stealth_profile,
            "dispatch_policy_name": self.dispatch_policy_name,
            "constraints": dict(self.constraints),
            "rationale": self.rationale,
            "confidence": self.confidence,
        }


# ──────────────────────────────────────────────────────────────────────
# Patterns
# ──────────────────────────────────────────────────────────────────────


_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"+[a-z]{2,24}\b",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

#: Maps an operator-keyword → intent category. Order matters
#: only for the rationale text; the same intent can be hit by
#: multiple keywords.
_INTENT_KEYWORDS: dict[str, list[str]] = {
    "credentials": ["credential", "creds", "password", "leak", "breach", "h8mail"],
    "subdomains": ["subdomain", "asset", "attack surface", "footprint"],
    "cloud": ["cloud", "s3", "azure", "gcp", "bucket", "tenant"],
    "identity": ["identity", "employee", "linkedin", "person", "ldap"],
    "pretext": ["pretext", "social", "phishing", "campaign", "spear"],
    "vulnerabilities": ["vuln", "cve", "vulnerability", "exposed", "scan"],
    "executives": ["exec", "ceo", "cfo", "leadership", "vp"],
    "supply_chain": ["supply chain", "vendor", "third party", "partner"],
}

#: Tier escalation keywords → tier override.
_TIER_KEYWORDS: dict[str, str] = {
    "active": "T2",
    "aggressive": "T3",
    "intrusive": "T3",
    "loud": "T3",
    "passive only": "T1",
    "passive": "T1",
    "stealthy": "T1",
    "osint only": "T0",
    "open source only": "T0",
    "read-only": "T0",
}

#: Stealth keywords.
_STEALTH_KEYWORDS: dict[str, str] = {
    "loud": "low",
    "aggressive": "low",
    "fast": "low",
    "stealth": "high",
    "stealthy": "high",
    "quiet": "high",
    "moderate": "medium",
}


# ──────────────────────────────────────────────────────────────────────
# Fallback extractor
# ──────────────────────────────────────────────────────────────────────


def _fallback_extract(sentence: str) -> IntentRecord:
    """Regex / keyword extraction. Used when no LLM is
    available or when LLM extraction failed. Confidence
    starts at ``low`` and lifts to ``medium`` if we
    actually found anything actionable."""
    record = IntentRecord(raw_sentence=sentence)
    low = sentence.lower()

    # Targets: every domain-shaped + IP-shaped token.
    domains = _DOMAIN_PATTERN.findall(sentence)
    ips = _IP_PATTERN.findall(sentence)
    record.targets = [
        t for t in (domains + ips)
        if "." in t  # double-check after findall
    ]
    record.targets = sorted(set(record.targets))

    # Intent categories: keyword hits.
    for category, keywords in _INTENT_KEYWORDS.items():
        if any(k in low for k in keywords):
            record.intent_categories.append(category)

    # Tier — most-specific match wins (longest keyword).
    tier_hits = sorted(
        ((k, v) for k, v in _TIER_KEYWORDS.items() if k in low),
        key=lambda kv: -len(kv[0]),
    )
    if tier_hits:
        record.max_tier = tier_hits[0][1]

    # Stealth — same pattern.
    stealth_hits = sorted(
        ((k, v) for k, v in _STEALTH_KEYWORDS.items() if k in low),
        key=lambda kv: -len(kv[0]),
    )
    if stealth_hits:
        record.stealth_profile = stealth_hits[0][1]

    # Dispatch policy: aggressive → full, passive → lite.
    if record.max_tier in ("T2", "T3"):
        record.dispatch_policy_name = "full"
    elif record.max_tier == "T0":
        record.dispatch_policy_name = "off"

    if record.targets or record.intent_categories:
        record.confidence = "medium"
        rationale_bits: list[str] = []
        if record.targets:
            rationale_bits.append(
                f"Targets parsed from sentence: "
                f"{', '.join(record.targets)}"
            )
        if record.intent_categories:
            rationale_bits.append(
                f"Intent keywords matched: "
                f"{', '.join(record.intent_categories)}"
            )
        rationale_bits.append(
            f"Tier defaulted to {record.max_tier} "
            f"(escalation keywords: "
            f"{', '.join(k for k, _ in tier_hits) or 'none'})"
        )
        record.rationale = "; ".join(rationale_bits)
    else:
        record.rationale = (
            "Regex fallback found no targets or intent "
            "keywords. Operator should refine the sentence."
        )

    return record


# ──────────────────────────────────────────────────────────────────────
# LLM extractor
# ──────────────────────────────────────────────────────────────────────


_LLM_SYSTEM_PROMPT = """\
You are an OSINT engagement planner. The operator will give
you a natural-language description of what they want a
reconnaissance campaign to accomplish. Extract the structured
intent as STRICT JSON with the schema below. Return ONLY the
JSON object — no prose before or after.

Schema:
{
  "targets": ["acme.com", ...],           // domains / IPs found
  "intent_categories": ["credentials", "cloud", ...],
  "max_tier": "T0" | "T1" | "T2" | "T3",  // invasiveness ceiling
  "stealth_profile": "low" | "medium" | "high",
  "dispatch_policy_name": "lite" | "full" | "off",
  "constraints": {"max_llm_cost_usd": 5.0, ...},
  "rationale": "one-paragraph explanation"
}

Rules:
- Default to the LEAST invasive interpretation when unclear.
- "passive only" → T1. "aggressive" / "active scan" → T2 or T3.
- "find leaked creds" → intent_categories includes "credentials".
- If no target domain is mentioned, return targets: [].
- NEVER invent engagement / authorization markers.
"""


def _llm_extract(
    sentence: str,
    executor: Any | None = None,
) -> IntentRecord | None:
    """Call the LLM. Returns ``None`` if no executor is
    available or the call fails — the caller falls back to
    the regex extractor."""
    if executor is None:
        try:
            from nexusrecon.core.config import get_config
            from nexusrecon.graph.agent_executor import AgentExecutor
            executor = AgentExecutor(get_config())
        except Exception as exc:
            log.debug("Intent LLM unavailable", error=str(exc))
            return None

    try:
        # Reuse the planner agent slot — same model + cost
        # tracking. The system prompt + the user sentence go
        # in via the executor's prompt-building path.
        prompt = _LLM_SYSTEM_PROMPT + "\n\nOPERATOR SENTENCE:\n" + sentence
        import asyncio
        result = asyncio.run(executor.run_agent(
            "campaign_planner",
            task_data={"sentence": sentence},
            task_prompt=prompt,
        ))
    except Exception as exc:
        log.warning("Intent LLM call failed", error=str(exc))
        return None

    raw = str(result.get("output", "")) if isinstance(result, dict) else ""
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None

    record = IntentRecord(raw_sentence=sentence, confidence="high")
    record.targets = sorted({
        str(t).lower() for t in (parsed.get("targets") or [])
        if isinstance(t, str)
    })
    record.intent_categories = [
        str(c) for c in (parsed.get("intent_categories") or [])
        if isinstance(c, str)
    ]
    record.max_tier = str(parsed.get("max_tier") or "T1")
    if record.max_tier not in ("T0", "T1", "T2", "T3"):
        record.max_tier = "T1"
    record.stealth_profile = str(parsed.get("stealth_profile") or "high")
    if record.stealth_profile not in ("low", "medium", "high"):
        record.stealth_profile = "high"
    record.dispatch_policy_name = str(
        parsed.get("dispatch_policy_name") or "lite"
    )
    if record.dispatch_policy_name not in ("lite", "full", "off"):
        record.dispatch_policy_name = "lite"
    raw_constraints = parsed.get("constraints") or {}
    record.constraints = (
        dict(raw_constraints) if isinstance(raw_constraints, dict) else {}
    )
    record.rationale = str(parsed.get("rationale") or "")
    return record


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────


def extract_intent(
    sentence: str,
    *,
    executor: Any | None = None,
    prefer_fallback: bool = False,
) -> IntentRecord:
    """Extract :class:`IntentRecord` from ``sentence``.

    ``executor`` lets tests inject a fake. ``prefer_fallback``
    forces the regex path even when an LLM would be
    available — useful for tests + air-gapped operators
    who don't want any LLM round-trip."""
    if prefer_fallback:
        return _fallback_extract(sentence)
    llm_record = _llm_extract(sentence, executor=executor)
    if llm_record is not None and (
        llm_record.targets or llm_record.intent_categories
    ):
        return llm_record
    # LLM didn't extract anything useful → fallback. The
    # fallback record's confidence stays at ``medium`` /
    # ``low`` so the caller knows the LLM didn't help.
    return _fallback_extract(sentence)
