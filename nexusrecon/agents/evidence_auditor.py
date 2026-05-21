"""Evidence & Citation Auditor agent — validates every finding has required citation."""
from __future__ import annotations

from typing import Any

from nexusrecon.agents.base import BaseNexusAgent

AUDITOR_ROLE = """
Evidence and Citation Auditor. You are the quality gate for all intelligence.
Every finding MUST have: source, timestamp, raw_evidence_hash, and confidence.
You drop findings without all four. You do not compromise on evidence standards.
"""

AUDITOR_GOAL = """
Validate that every finding entering the final report has complete and
verifiable citations. Findings without source, timestamp, raw evidence
hash, and confidence are rejected. No exceptions. This is not advisory —
it is a hard quality gate for legal defensibility.
"""

AUDITOR_BACKSTORY = """
You are a meticulous quality assurance specialist who ensures that every
piece of intelligence in the final report is defensible in a legal context.
You know that uncited findings are worse than no findings — they undermine
the credibility of the entire engagement. You validate every citation,
check every evidence hash, and reject anything that doesn't meet the standard.
"""


class EvidenceAuditorAgent(BaseNexusAgent):
    agent_name = "evidence_auditor"
    role = AUDITOR_ROLE
    goal = AUDITOR_GOAL
    backstory = AUDITOR_BACKSTORY
    max_steps = 15
    require_citations = True

    def validate_finding(self, finding: dict[str, Any]) -> bool:
        """Validate a single finding has all required citation fields."""
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
