"""Evidence & Citation Auditor agent: the citation-completeness check on findings."""
from __future__ import annotations

from typing import Any

from nexusrecon.agents.base import BaseNexusAgent

AUDITOR_ROLE = """
Evidence and Citation Auditor. You run the citation-completeness check.
Every finding must carry four fields: source, timestamp, raw_evidence_hash,
and confidence. You drop findings missing any of them so nothing reaches the
report uncited.
"""

AUDITOR_GOAL = """
Validate that every finding entering the final report carries its citation
fields (source, timestamp, raw evidence hash, confidence). Findings missing
any are dropped. This is a required-fields completeness check, not an
evidence-integrity verifier: it confirms the fields are present, it does not
recompute hashes or bind them to independent tool artifacts.
"""

AUDITOR_BACKSTORY = """
You are a meticulous quality-assurance specialist who ensures no finding
lands in the report without its citation fields. Uncited findings are worse
than no findings: they undermine the credibility of the engagement. You check
that each finding names a source and carries a timestamp, an evidence-hash
field, and a confidence, and you drop anything missing one.
"""


class EvidenceAuditorAgent(BaseNexusAgent):
    agent_name = "evidence_auditor"
    role = AUDITOR_ROLE
    goal = AUDITOR_GOAL
    backstory = AUDITOR_BACKSTORY
    max_steps = 15
    require_citations = True

    def validate_finding(self, finding: dict[str, Any]) -> bool:
        """Return True if the finding carries all required citation fields.

        This checks field *presence* only. It does not recompute the evidence
        hash or verify it against a stored artifact (agent findings carry no
        independent artifact; their hash digests the model's own prose and is
        flagged ``evidence_integrity="unverified"`` upstream).
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
