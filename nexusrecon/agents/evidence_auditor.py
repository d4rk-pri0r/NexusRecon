"""Evidence & Citation Auditor agent — validates every finding has required citation."""
from __future__ import annotations

from typing import Any

from nexusrecon.agents.base import BaseNexusAgent

AUDITOR_ROLE = """
Evidence and Citation Auditor. You are the citation-completeness gate for all
intelligence. Every finding MUST carry: source, timestamp, raw_evidence_hash,
and confidence. You drop findings missing any of the four. You enforce that the
citation fields are present and well-formed; you do not certify that a finding's
evidence hash corresponds to independently collected raw evidence, which is the
producing tool's responsibility. Findings whose evidence is self-reported
(evidence_provenance == "self_reported") pass completeness but are not
independently corroborated, and must be labeled as such downstream.
"""

AUDITOR_GOAL = """
Validate that every finding entering the final report has complete citation
fields (source, timestamp, raw_evidence_hash, confidence). Findings missing any
are rejected. This is a structural completeness gate, not a guarantee of
independent corroboration: a present raw_evidence_hash means the field exists,
not that the claim was verified against third-party evidence. Surface
self-reported findings honestly rather than presenting them as evidence-backed.
"""

AUDITOR_BACKSTORY = """
You are a meticulous quality-assurance specialist who ensures every finding in
the final report carries its citation fields. You know that uncited findings
undermine the credibility of the engagement, so you reject anything missing a
required field. You are equally careful not to overclaim: a finding whose
evidence hash is a content hash of the analyst's own prose is complete, but it
is self-reported, not independently verified, and you make that distinction
visible instead of hiding it.
"""


class EvidenceAuditorAgent(BaseNexusAgent):
    agent_name = "evidence_auditor"
    role = AUDITOR_ROLE
    goal = AUDITOR_GOAL
    backstory = AUDITOR_BACKSTORY
    max_steps = 15
    require_citations = True

    def validate_finding(self, finding: dict[str, Any]) -> bool:
        """Return True when a finding carries all four citation fields.

        This is a completeness check (the fields are present and truthy), not a
        verification that ``raw_evidence_hash`` was computed over independently
        collected evidence. A self-reported finding (``evidence_provenance ==
        'self_reported'``) can pass this gate; honesty about that distinction is
        enforced at render time, not here. See ROADMAP.md item 6.
        """
        required = ["source", "timestamp", "raw_evidence_hash", "confidence"]
        return all(finding.get(field) for field in required)

    def audit_findings(self, findings: list[dict[str, Any]]) -> tuple:
        """
        Audit a batch of findings.
        Returns (passed, rejected) lists.
        """
        passed = []
        rejected = []
        for f in findings:
            if self.validate_finding(f):
                passed.append(f)
            else:
                rejected.append(f)
        return passed, rejected
