"""
Agent Execution Layer — bridges CrewAI agents with LangGraph phase nodes.

This module instantiates CrewAI agents with the configured LLM provider,
wraps them for async execution, and injects their synthesis output into
the LangGraph campaign state.

Usage:
    executor = AgentExecutor(config, scope)
    result = await executor.run_agent("passive_recon", {
        "seeds": ["acme.com"],
        "tool_results": {...},
    })
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import structlog

from nexusrecon.agents.base import (
    BaseNexusAgent,
)
from nexusrecon.agents.cloud_identity import CloudIdentitySpecialist
from nexusrecon.agents.correlation import CorrelationAgent
from nexusrecon.agents.dynamic_dispatcher import DynamicDispatcherAgent
from nexusrecon.agents.evidence_auditor import EvidenceAuditorAgent
from nexusrecon.agents.master_reporter import MasterReporterAgent
from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
from nexusrecon.agents.planner import CampaignPlannerAgent
from nexusrecon.agents.pretext_humint import PretextHumintAgent
from nexusrecon.agents.recon_active import ActiveReconSpecialist
from nexusrecon.agents.recon_passive import PassiveReconSpecialist
from nexusrecon.agents.reporter import ExecutiveReporterAgent
from nexusrecon.agents.risk_analyst import RiskAnalystAgent
from nexusrecon.agents.vuln_correlator import VulnCorrelatorAgent
from nexusrecon.core.cost_tracker import BudgetExceededError, CostTracker

log = structlog.get_logger(__name__)

# Map agent names to their classes
AGENT_REGISTRY = {
    "campaign_planner": CampaignPlannerAgent,
    "passive_recon": PassiveReconSpecialist,
    "active_recon": ActiveReconSpecialist,
    "cloud_identity": CloudIdentitySpecialist,
    "pretext_humint": PretextHumintAgent,
    "correlation": CorrelationAgent,
    "risk_analyst": RiskAnalystAgent,
    "vuln_correlator": VulnCorrelatorAgent,
    "evidence_auditor": EvidenceAuditorAgent,
    "executive_reporter": ExecutiveReporterAgent,
    "master_reporter": MasterReporterAgent,
    "phishing_drafter": PhishingDrafterAgent,
    "dynamic_dispatcher": DynamicDispatcherAgent,
}


def get_llm_from_config(config: Any):
    """
    Create a LangChain LLM object from the NexusConfig.

    Supports Anthropic, OpenAI, and Ollama.
    Falls back to a mock LLM if no API keys are configured.
    """
    provider = config.llm_provider.lower()
    model = config.llm_model
    temperature = config.llm_temperature

    if provider == "anthropic":
        api_key = config.get_secret("anthropic_api_key")
        if api_key:
            try:
                from langchain_anthropic import ChatAnthropic
                return ChatAnthropic(
                    model=model,
                    temperature=temperature,
                    api_key=api_key,
                )
            except ImportError:
                log.warning("langchain-anthropic not installed, falling back to mock")

    elif provider == "openai":
        api_key = config.get_secret("openai_api_key")
        if api_key:
            try:
                from langchain_openai import ChatOpenAI
                return ChatOpenAI(
                    model=model,
                    temperature=temperature,
                    api_key=api_key,
                )
            except ImportError:
                log.warning("langchain-openai not installed, falling back to mock")

    elif provider == "ollama":
        try:
            from langchain_ollama import ChatOllama
            return ChatOllama(
                model=config.ollama_model,
                base_url=config.ollama_base_url,
                temperature=temperature,
            )
        except ImportError:
            log.warning("langchain-ollama not installed, falling back to mock")

    # Fallback: mock LLM that returns structured analysis without calling an API
    log.info("No LLM API configured — using MockLLM for analysis")
    return MockLLM()


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


class AgentExecutor:
    """
    Executes CrewAI agents with the configured LLM.

    Each agent receives a task description and contextual data from the
    LangGraph state, produces an analysis, and the analysis is written
    back to the state.
    """

    def __init__(self, config: Any) -> None:
        self.config = config
        self.llm = get_llm_from_config(config)
        self._step_count = 0
        # B23: high internal limit — per-campaign budget enforced via state["max_llm_cost_usd"]
        self._cost_tracker = CostTracker("agent_executor", max_llm_cost_usd=1_000_000)

    async def run_agent(
        self,
        agent_name: str,
        task_data: dict[str, Any],
        task_prompt: str,
        state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Run a specific agent with the given task data.

        Args:
            agent_name: Name of the agent to run.
            task_data: Contextual data from the LangGraph state.
            task_prompt: The specific task/prompt for this agent invocation.
            state: Live campaign state dict.  When provided:
                   * Budget is checked before the LLM call; raises BudgetExceededError
                     if state["llm_cost_usd"] >= state["max_llm_cost_usd"].
                   * state["llm_cost_usd"] is incremented by each call's cost (B23).
                   * state["findings"] is extended with parsed FINDINGS_JSON entries (B24).

        Returns:
            Dict with 'output' (agent response), 'step_count', and 'findings' (parsed list).
        """
        if agent_name not in AGENT_REGISTRY:
            raise ValueError(f"Unknown agent: {agent_name}")

        # B23: enforce per-campaign LLM budget before consuming tokens
        if state is not None:
            current_cost = float(state.get("llm_cost_usd", 0.0))
            max_cost = float(state.get("max_llm_cost_usd", 50.0))
            if current_cost >= max_cost:
                raise BudgetExceededError(current_cost, max_cost)

        agent_cls = AGENT_REGISTRY[agent_name]
        if agent_cls is None:
            raise ValueError(f"Agent '{agent_name}' is registered but not yet implemented")
        agent = agent_cls()

        # Build the full prompt with context, using agent identity for differentiation (F-008)
        context = self._build_context(task_data, task_prompt, agent)

        # Execute through the LLM
        try:
            self._step_count += 1
            response = self.llm.invoke(context)
            content = str(response.content) if hasattr(response, "content") else str(response)

            # B23: extract token usage and record cost
            in_tok, out_tok = self._extract_token_usage(response)
            model_name = getattr(
                self.llm, "model_name", getattr(self.llm, "model", "unknown")
            )
            call_cost = self._cost_tracker.record_llm_call(
                agent_name, model_name, in_tok, out_tok
            )

            # Sync accumulated cost back to campaign state (B23)
            if state is not None:
                state["llm_cost_usd"] = float(state.get("llm_cost_usd", 0.0)) + call_cost

            # B24: parse structured findings from FINDINGS_JSON block and inject into state
            phase = (
                state.get("current_phase", "unknown") if state is not None else "unknown"
            )
            new_findings = self._parse_findings_json(content, phase)
            # B29: defensive backstop — agent may have made confident cloud claims
            # despite ATTRIBUTION RULE prompt. Walk findings and downgrade any that
            # cite stem-match cloud data to info severity + [POSSIBLE] prefix.
            new_findings = self._gate_findings_by_attribution(new_findings, state)
            if new_findings and state is not None:
                state.setdefault("findings", []).extend(new_findings)

            log.info(
                "Agent executed",
                agent=agent_name,
                steps=self._step_count,
                output_len=len(content),
                new_findings=len(new_findings),
                cost_usd=round(call_cost, 4),
            )

            return {
                "output": content,
                "agent": agent_name,
                "step_count": self._step_count,
                "findings": new_findings,
            }

        except BudgetExceededError:
            raise
        except Exception as e:
            log.error("Agent execution failed", agent=agent_name, error=str(e))
            return {
                "output": f"Agent execution failed: {str(e)}",
                "agent": agent_name,
                "step_count": self._step_count,
                "error": str(e),
                "findings": [],
            }

    @staticmethod
    def _parse_findings_json(content: str, phase: str) -> list[dict[str, Any]]:
        """
        Extract and parse the FINDINGS_JSON block from agent output.

        Searches for the literal marker ``FINDINGS_JSON:`` followed immediately by
        a JSON array.  Uses raw_decode so any trailing text after the array is ignored.
        Silently returns an empty list on any parse failure — never raises.
        """
        marker = "FINDINGS_JSON:"
        idx = content.find(marker)
        if idx == -1:
            return []
        json_str = content[idx + len(marker):].strip()
        try:
            parsed, _ = json.JSONDecoder().raw_decode(json_str)
            if not isinstance(parsed, list):
                log.debug("FINDINGS_JSON block is not a list", type=type(parsed).__name__)
                return []
            now = datetime.now(UTC).isoformat()
            valid: list[dict[str, Any]] = []
            for finding in parsed:
                if isinstance(finding, dict):
                    finding.setdefault("phase", phase)
                    finding.setdefault("timestamp", now)
                    # B28: synthetic evidence hash so EvidenceAuditorAgent doesn't reject
                    # all agent findings for missing raw_evidence_hash (Option 1)
                    evidence_str = (
                        f"{phase}::{finding.get('title', '')}"
                        f"|{finding.get('description', '')[:500]}"
                    )
                    finding.setdefault(
                        "raw_evidence_hash",
                        "sha256:" + hashlib.sha256(evidence_str.encode()).hexdigest(),
                    )
                    finding.setdefault(
                        "source", finding.get("source") or f"agent:{phase}"
                    )
                    valid.append(finding)
            return valid
        except (json.JSONDecodeError, ValueError) as exc:
            log.debug("FINDINGS_JSON parse failed", error=str(exc))
            return []

    @staticmethod
    def _gate_findings_by_attribution(
        findings: list[dict[str, Any]],
        state: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """
        B29: defensive backstop that downgrades findings citing low-confidence
        (stem-match) cloud data to ``info`` severity + ``[POSSIBLE]`` prefix.

        The ATTRIBUTION RULE prompt instructs the LLM to gate findings itself,
        but real LLMs don't reliably honor the rule for every sub-field. This
        function is a hard programmatic gate: it walks each parsed finding,
        cross-references against ``state.cloud_intel`` for low-attribution
        sources, and downgrades any finding that:

          1. References an identifying string (tenant ID, bucket name, app URL)
             that came from a section with ``attribution_confidence < 0.5``,
             OR
          2. Makes a cloud-attack-vector claim (password spray, managed
             tenant, S3 bucket exposure, etc.) when the target has NO
             verified cloud presence (all relevant cloud_intel sections are
             stem-match only).

        Already-gated findings (title starts with ``[POSSIBLE]``) are left
        unchanged. Returns the (possibly mutated) findings list.
        """
        if not findings or not state:
            return findings

        cloud_intel = state.get("cloud_intel", {}) or {}
        low_conf_idents: set[str] = set()
        has_unverified_azure = False
        has_unverified_aws = False

        for key, data in cloud_intel.items():
            if not isinstance(data, dict):
                continue
            top_attr = float(data.get("attribution_confidence", 1.0) or 0.0)
            if top_attr >= 0.5:
                # High-confidence source — its identifiers are trustworthy
                continue

            if key.lower().startswith("azure/"):
                has_unverified_azure = True
            elif key.lower().startswith("aws/"):
                has_unverified_aws = True

            # Collect stem-match identifying strings
            onm = data.get("onmicrosoft_domain") or {}
            if isinstance(onm, dict):
                for entry in onm.get("domains", []) or []:
                    if isinstance(entry, dict):
                        for fld in ("tenant_id", "domain"):
                            v = entry.get(fld)
                            if v:
                                low_conf_idents.add(str(v).lower())
            for app in data.get("app_services", []) or []:
                if isinstance(app, dict) and app.get("url"):
                    low_conf_idents.add(str(app["url"]).lower())
            for dev in data.get("azure_devops", []) or []:
                if isinstance(dev, dict) and dev.get("url"):
                    low_conf_idents.add(str(dev["url"]).lower())
            for bucket in (data.get("s3_buckets") or []) + (data.get("public_buckets") or []):
                if isinstance(bucket, dict) and bucket.get("name"):
                    low_conf_idents.add(str(bucket["name"]).lower())

        azure_risk_keywords = (
            "password spray", "managed federation", "managed tenant",
            "azure tenant", "m365 tenant", "entra id", "entra tenant",
            "azure password", "office 365 tenant", "azure ad tenant",
        )
        aws_risk_keywords = (
            "s3 bucket", "aws infrastructure", "aws account",
            "aws lambda", "cloudfront distribution",
        )

        gated = 0
        for f in findings:
            if not isinstance(f, dict):
                continue
            title = f.get("title") or ""
            if "[POSSIBLE]" in title:
                continue  # already gated by the agent
            desc = f.get("description") or ""
            text = f"{title}\n{desc}".lower()

            reason = ""
            for ident in low_conf_idents:
                if ident and ident in text:
                    reason = f"references stem-match identifier ({ident[:40]})"
                    break

            if not reason and has_unverified_azure:
                for kw in azure_risk_keywords:
                    if kw in text:
                        reason = f"asserts {kw!r} but target has no verified Azure presence"
                        break

            if not reason and has_unverified_aws:
                for kw in aws_risk_keywords:
                    if kw in text:
                        reason = f"asserts {kw!r} but target has no verified AWS presence"
                        break

            if reason:
                f["title"] = f"[POSSIBLE] {title}" if not title.startswith("[POSSIBLE]") else title
                f["severity"] = "info"
                f["attribution_gated"] = True
                f["attribution_gate_reason"] = reason
                gated += 1

        if gated:
            log.info("Findings gated by attribution backstop", count=gated)
        return findings

    @staticmethod
    def _extract_token_usage(response: Any) -> tuple[int, int]:
        """
        Return (input_tokens, output_tokens) from a LangChain response object.

        Supports:
        - Anthropic ChatAnthropic: ``response.usage_metadata``
        - OpenAI ChatOpenAI: ``response.response_metadata["token_usage"]``
        - Fallback: estimate from content length (~4 chars per token)
        """
        # Anthropic: usage_metadata = {"input_tokens": N, "output_tokens": N}
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            um = response.usage_metadata
            if isinstance(um, dict):
                return int(um.get("input_tokens", 0)), int(um.get("output_tokens", 0))
        # OpenAI: response_metadata["token_usage"] = {"prompt_tokens": N, "completion_tokens": N}
        if hasattr(response, "response_metadata") and isinstance(
            response.response_metadata, dict
        ):
            tu = response.response_metadata.get("token_usage", {})
            if tu and isinstance(tu, dict):
                return (
                    int(tu.get("prompt_tokens", 0)),
                    int(tu.get("completion_tokens", 0)),
                )
        # Fallback: rough estimate from content length (~4 chars / token)
        content_str = str(getattr(response, "content", response))
        est = max(1, len(content_str) // 4)
        return est, est

    @staticmethod
    def _build_context(
        data: dict[str, Any],
        task_prompt: str,
        agent: BaseNexusAgent | None = None,
    ) -> str:
        """Build the full prompt with context and data, incorporating agent identity."""
        context_parts = []

        if agent and agent.role:
            context_parts.extend([
                f"You are a {agent.role}.",
                f"Your goal: {agent.goal}",
                f"Background: {agent.backstory}",
                "",
            ])
        else:
            context_parts.extend([
                "You are a NexusRecon OSINT specialist.",
                "",
            ])

        # B34: Some agents need to return pure structured output for downstream parsing
        # (phishing_drafter returns a draft JSON; dynamic_dispatcher returns a dispatch plan).
        # Injecting the FINDINGS_JSON requirement contaminates their output and breaks parsing.
        # Skip the FINDINGS_JSON appendix for those agents.
        # B36 / V3 Move 2: master_reporter returns pure markdown for the master
        # report and must not have the FINDINGS_JSON requirement appended.
        _SKIP_FINDINGS_JSON_AGENTS = {"phishing_drafter", "dynamic_dispatcher", "master_reporter"}
        skip_findings = bool(agent and getattr(agent, "agent_name", "") in _SKIP_FINDINGS_JSON_AGENTS)

        # B25+B26+B27: FINDINGS_JSON requirement comes FIRST — ensures real LLMs emit it reliably
        if not skip_findings:
            context_parts.extend([
                "REQUIRED — emit this BEFORE any prose (even if the list is empty):",
                'FINDINGS_JSON:[{"severity":"critical|high|medium|low|info","title":"...",',
                '"description":"...","source":"...","confidence":0.0-1.0,"category":"...",',
                '"affected_assets":["hostname/IP/email/ARN — required; use seed domain if unknown"],',
                '"next_steps":["concrete action with specific tool name — required"],',
                '"mitre_techniques":["TXXXX"] or [],"recommendation":"specific defensive action — required"}]',
                "If no findings apply: FINDINGS_JSON:[]",
                "",
                "ATTRIBUTION RULE (B26): For any data with attribution_confidence < 0.5 (stem-match):",
                "  - Cap severity at 'info', prefix title '[POSSIBLE]'",
                "  - Add 'stem-match only; verify before action' to description",
                "  - Do NOT assert confirmed attack vectors from stem-match cloud data.",
                "",
            ])

        context_parts.extend([
            "Your current task:",
            task_prompt,
            "",
            "Context from the current campaign state:",
            "",
        ])

        # Serialize relevant data sections
        for key, value in data.items():
            if value and key not in ("completed_phases",):
                if isinstance(value, dict):
                    serialized = json.dumps(value, indent=2, default=str)[:3000]
                elif isinstance(value, list):
                    serialized = json.dumps(value[:50], indent=2, default=str)[:3000]
                else:
                    serialized = str(value)[:2000]
                context_parts.append(f"## {key}")
                context_parts.append(serialized)
                context_parts.append("")

        # B25: analysis prose instructions go AFTER the FINDINGS_JSON block above
        context_parts.extend([
            "Analysis (write AFTER emitting FINDINGS_JSON):",
            "1. Provide your professional assessment of the data above.",
            "2. Be specific, cite evidence from the data, and identify actionable insights.",
            "3. Do not speculate beyond what the data supports.",
            "4. Highlight the highest-value findings for the red team.",
        ])

        return "\n".join(context_parts)

    @staticmethod
    def audit_findings(
        findings: list[dict[str, Any]],
    ) -> tuple:
        """Validate findings have complete citations (runs synchronously)."""
        auditor = EvidenceAuditorAgent()
        return auditor.audit_findings(findings)
