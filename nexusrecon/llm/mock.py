"""Deterministic mock LLM for air-gapped / test mode.

Moved out of ``nexusrecon/graph/agent_executor.py`` (provider-oauth plan) so
the LLM factory (``nexusrecon/llm/factory.py``) can construct the explicit
``provider=mock`` path without a circular import through the graph layer.
``agent_executor`` re-exports these names, so any existing ``from
nexusrecon.graph.agent_executor import MockLLM`` keeps working.
"""
from __future__ import annotations

import json
from typing import Any


class MockLLM:
    """
    Mock LLM for environments without API keys.

    Produces deterministic analysis summaries based on input data.
    Useful for testing and air-gapped deployments.

    Always appends a FINDINGS_JSON block so the findings pipeline
    (B24) is exercised even without a real LLM.
    """

    def __init__(self):
        self.model_name = "mock_llm"

    def invoke(self, prompt: str) -> Any:
        """Return a structured analysis based on input content."""
        return MockLLMResponse(self._generate_response(prompt))

    def _generate_response(self, prompt: str) -> str:
        """Generate a deterministic analysis from the prompt."""
        # Extract key data points from the prompt
        lines = prompt.split("\n")
        findings_mentioned = 0
        subdomains_mentioned = 0
        emails_mentioned = 0

        for line in lines:
            lower = line.lower()
            if "subdomain" in lower:
                subdomains_mentioned += 1
            if "email" in lower:
                emails_mentioned += 1
            if "finding" in lower or "vuln" in lower or "expos" in lower:
                findings_mentioned += 1

        if findings_mentioned > 3:
            prose = (
                "Analysis: Multiple intelligence findings identified. "
                f"Subdomain indicators: {subdomains_mentioned}. "
                f"Email indicators: {emails_mentioned}. "
                f"Finding indicators: {findings_mentioned}. "
                "Recommendation: Correlate findings across sources for high-confidence attack vectors. "
                "Priority should be given to cloud exposure and credential leak findings."
            )
            finding = {
                "severity": "medium",
                "title": "Multiple intelligence findings identified",
                "description": (
                    f"Analysis identified {findings_mentioned} potential finding indicators "
                    "requiring correlation across sources."
                ),
                "source": "mock_llm",
                "confidence": 0.6,
                "category": "reconnaissance",
            }
        elif subdomains_mentioned > 0 or emails_mentioned > 0:
            prose = (
                f"Analysis: Intelligence data collected. "
                f"Subdomain indicators: {subdomains_mentioned}. "
                f"Email indicators: {emails_mentioned}. "
                "Recommendation: Continue correlation phase to identify connections."
            )
            finding = {
                "severity": "info",
                "title": "Reconnaissance data collected",
                "description": (
                    f"Passive OSINT phase complete. "
                    f"Subdomain indicators: {subdomains_mentioned}, "
                    f"email indicators: {emails_mentioned}."
                ),
                "source": "mock_llm",
                "confidence": 0.5,
                "category": "reconnaissance",
            }
        else:
            prose = (
                "Analysis: No significant intelligence findings detected in current data. "
                "Recommendation: Expand reconnaissance scope or continue to next phase."
            )
            finding = {
                "severity": "info",
                "title": "No significant findings in current phase",
                "description": (
                    "Analysis found no high-confidence intelligence items in the current data set."
                ),
                "source": "mock_llm",
                "confidence": 0.4,
                "category": "reconnaissance",
            }

        # Always emit a FINDINGS_JSON block so the findings pipeline is exercised (B24)
        # B25: FINDINGS_JSON leads — mirrors the prompt structure for real LLMs
        findings_json = json.dumps([finding])
        return f"FINDINGS_JSON:{findings_json}\n\n{prose}"


class MockLLMResponse:
    def __init__(self, content: str):
        self.content = content

    def __str__(self):
        return self.content


__all__ = ["MockLLM", "MockLLMResponse"]
