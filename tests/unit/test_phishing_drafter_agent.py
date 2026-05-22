"""Dedicated unit tests for the Phase E10 PhishingDrafterAgent.

The agent doesn't run autonomously ── it's invoked by
``phase7_7_pretext_intelligence`` (see ``test_phase_7_7.py`` for the
gating + dossier-shape coverage) and dispatched through
``AgentExecutor.run_agent``. What lives here is the *agent itself*:

  - **Static configuration** — name / role / goal / max_steps /
    require_citations. These fields are load-bearing because the
    executor matches by ``agent_name`` and the CrewAI runtime reads
    role / goal / backstory verbatim.
  - **Backstory invariants** — every construction principle and
    safety rule documented in the backstory has a regression here.
    The backstory is essentially a prompt; if a future edit drops
    the DMARC ``reject`` branch or the do-not-fabricate rule, the
    behaviour silently changes. These tests make those edits fail
    fast in CI.
  - **CrewAI config wiring** — what ``to_crewai_config()`` returns
    must round-trip the agent's tunables to the framework
    correctly.
  - **Registry resolution** — the executor's
    ``AGENT_REGISTRY["phishing_drafter"]`` lookup is the only way
    the Phase 7.7 node reaches this class.
  - **Executor integration** — pilot the executor with a stub LLM
    and assert the standard envelope the rest of the pipeline
    relies on (``output`` / ``agent`` / ``step_count`` /
    ``findings``).

These tests are complementary to ``test_phase_7_7.py::
TestPhishingDrafterAgent`` (which sanity-checks a handful of fields
from the workflow side). Coverage that the workflow tests already
pin — agent_name unchanged, schema fields documented, DMARC + no-
draft fallback present, require_citations True — is intentionally
duplicated here so that *deleting* the workflow-side tests in a
refactor can't quietly remove the regression net for the agent.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nexusrecon.agents.base import BaseNexusAgent
from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
from nexusrecon.graph.agent_executor import AGENT_REGISTRY, AgentExecutor


# ──────────────────────────────────────────────────────────────────────
# Static configuration
# ──────────────────────────────────────────────────────────────────────


class TestStaticConfig:
    """The agent's class attributes are the contract with everything
    else: the executor (matches by ``agent_name``), CrewAI (reads
    ``role`` / ``goal`` / ``backstory`` literally), and the Phase
    7.7 node (assumes ``require_citations`` is True). A drift here
    is silent unless tests pin the values."""

    def test_agent_name_is_phishing_drafter(self):
        assert PhishingDrafterAgent.agent_name == "phishing_drafter"

    def test_inherits_from_base_agent(self):
        """Must inherit BaseNexusAgent so the executor's standard
        invocation path (cost tracker, findings parser, step
        counter) applies."""
        assert issubclass(PhishingDrafterAgent, BaseNexusAgent)

    def test_role_identifies_authorised_red_team(self):
        """The role string surfaces in CrewAI logs and tool
        prompts. It MUST say 'authorised' so an audit reader can
        confirm at a glance this isn't an unsanctioned attack
        agent."""
        role = PhishingDrafterAgent.role
        assert role, "role must not be empty"
        lower = role.lower()
        assert "authorised" in lower or "authorized" in lower
        # Either phrasing of the discipline is acceptable
        assert "red-team" in lower or "red team" in lower
        assert "phishing" in lower

    def test_goal_requires_strict_json_no_prose(self):
        """The goal is the agent's success criterion. It must
        demand strict JSON output ── the Phase 7.7 dossier writer
        downstream tries to parse the agent's response, and prose
        outside JSON breaks that parse."""
        goal = PhishingDrafterAgent.goal.lower()
        assert "json" in goal
        # Either of these phrasings expresses "JSON only".
        assert "no prose outside json" in goal or "strict json" in goal

    def test_goal_demands_specific_osint_citation(self):
        """The "cite specific OSINT" rule is what separates a
        plausible draft from generic phishing boilerplate. Pin
        it so the goal can't be softened without notice."""
        goal = PhishingDrafterAgent.goal.lower()
        assert "osint" in goal
        assert "cite" in goal or "citing" in goal

    def test_max_steps_is_constrained_to_five(self):
        """A drafter shouldn't loop ── one structured JSON output
        per target. max_steps=5 leaves headroom for retries while
        keeping a runaway loop out of the budget. The phase 7.7
        node fans out across all targets, so a per-target loop
        budget that's too high blows the per-campaign limit fast."""
        assert PhishingDrafterAgent.max_steps == 5

    def test_require_citations_true(self):
        """The drafter's output carries audit-trail strings via the
        ``sources`` field. The base agent's citation check is the
        guardrail that fires when the model drops them."""
        assert PhishingDrafterAgent.require_citations is True

    def test_instantiates_with_no_args(self):
        """The executor calls ``agent_cls()`` with zero arguments
        (see ``AgentExecutor.run_agent``). Anything that needs
        kwargs would crash at runtime."""
        agent = PhishingDrafterAgent()
        assert agent.agent_name == "phishing_drafter"

    def test_instance_overrides_via_kwargs(self):
        """``BaseNexusAgent.__init__`` accepts kwargs for tunable
        overrides ── verify max_steps is one of them so an
        operator can extend the budget for a stubborn target."""
        agent = PhishingDrafterAgent(max_steps=8)
        assert agent.max_steps == 8
        # Class default stays untouched (instance-level override only).
        assert PhishingDrafterAgent.max_steps == 5


# ──────────────────────────────────────────────────────────────────────
# Backstory invariants
# ──────────────────────────────────────────────────────────────────────


BACKSTORY = PhishingDrafterAgent.backstory
BACKSTORY_LOWER = BACKSTORY.lower()


class TestBackstoryAuthorizationDisclosure:
    """The backstory is a prompt. It MUST make clear ── to the
    model AND to any auditor reviewing what we sent to the LLM ──
    that this is sanctioned work, not an attack."""

    def test_says_authorised(self):
        assert "authorised" in BACKSTORY_LOWER or "authorized" in BACKSTORY_LOWER

    def test_mentions_written_authorisation(self):
        """A defender reading the prompt should see the operator
        has written authorisation. Adds a paper-trail signal that
        survives prompt logging."""
        assert "written authorisation" in BACKSTORY_LOWER or (
            "written authorization" in BACKSTORY_LOWER
        )

    def test_explicitly_sanctioned_engagement(self):
        """The word 'sanctioned' appears in the goal too; it's
        the safety boilerplate that gates every red-team
        artefact in this codebase."""
        assert "sanctioned" in BACKSTORY_LOWER


class TestBackstorySchema:
    """If the backstory's JSON schema drifts, the downstream
    dossier writer parses garbage. Pin every field name."""

    @pytest.mark.parametrize(
        "field",
        [
            "target_identity_id",
            "subject",
            "sender_display_name",
            "sender_address",
            "body_markdown",
            "rationale",
            "sources",
        ],
    )
    def test_schema_field_documented(self, field: str):
        assert field in BACKSTORY, f"backstory missing schema field {field!r}"

    def test_no_draft_fallback_shape_documented(self):
        """When the pretext signal is too weak we emit a
        ``{"draft": null, ...}`` fallback instead of inventing.
        That shape MUST be documented so the model emits it
        deterministically, not a free-form refusal."""
        assert '"draft": null' in BACKSTORY
        assert "insufficient pretext signal" in BACKSTORY_LOWER

    def test_no_draft_threshold_documented(self):
        """The exact threshold (0.15) lives in the prompt. If
        it changes here it should also change in the scoring
        engine ── and vice versa. This pin makes drift loud."""
        assert "0.15" in BACKSTORY


class TestBackstoryConstructionPrinciples:
    """Each numbered construction principle in the backstory has
    a single load-bearing claim. A future edit that softens one
    of these claims should fail a focused test, not slip in
    behind a 'tidy up the prompt' commit."""

    def test_pick_one_pretext_candidate(self):
        """Principle 1: ONE candidate per draft, no blending."""
        assert "Pick ONE pretext candidate" in BACKSTORY
        assert "Don't blend" in BACKSTORY

    def test_subject_avoids_overtriggering_phrases(self):
        """Principle 2: explicitly steers away from 'URGENT' /
        'Action Required' because mature security training
        flags those words."""
        assert "URGENT" in BACKSTORY
        assert "Action Required" in BACKSTORY

    def test_subject_avoids_all_caps(self):
        # The phrase wraps across a line in the rendered backstory;
        # collapse whitespace before matching so a future re-wrap
        # doesn't silently invalidate the rule.
        import re
        flat = re.sub(r"\s+", " ", BACKSTORY)
        assert "ALL CAPS is not" in flat

    def test_body_paragraph_count_documented(self):
        """Principle 3: short, plausible. The '2-5 short
        paragraphs' phrasing is the operational guideline; a
        rewrite that says 'one paragraph' would change the
        output meaningfully."""
        assert "2-5 short paragraphs" in BACKSTORY

    def test_body_ties_to_timing_anchor(self):
        """Principle 3 cont'd: the lure has to ride on the
        timing anchor (a real news item / talk / commit)."""
        assert "timing anchor" in BACKSTORY_LOWER

    def test_tone_no_exclamation_no_emoji(self):
        """Principle 4: matched to what a real sender at that
        level would actually write."""
        # The backstory says "no exclamation points" (lowercase
        # because it's mid-sentence) and "No emoji" (sentence-
        # start). Collapse whitespace so a line break inside
        # either phrase doesn't trip the assertion.
        import re
        flat = re.sub(r"\s+", " ", BACKSTORY).lower()
        assert "no exclamation points" in flat
        assert "no emoji" in flat

    def test_dmarc_reject_uses_lookalike(self):
        """Principle 5a: DMARC reject → typosquat / homoglyph
        domain. This is the rule that decides whether the
        operator needs to register a lookalike before sending."""
        assert "reject" in BACKSTORY
        assert "lookalike" in BACKSTORY_LOWER
        # Concrete example (gitlab → gitla**b.io**) is what makes
        # the rule actionable, so pin the explanatory pattern.
        assert "typosquat" in BACKSTORY_LOWER or "homoglyph" in BACKSTORY_LOWER

    def test_dmarc_quarantine_branch_present(self):
        """Principle 5b: quarantine allows either lookalike or
        consumer-domain forward, but the operator must note the
        choice in the rationale."""
        assert "quarantine" in BACKSTORY_LOWER

    def test_dmarc_none_or_absent_uses_real_corp(self):
        """Principle 5c: no DMARC enforcement → use the real
        corp email (no spoof-domain needed)."""
        assert "DMARC `none`" in BACKSTORY or "DMARC none" in BACKSTORY
        # Either phrasing of the resulting decision is acceptable.
        assert "no spoof-domain" in BACKSTORY_LOWER or "actual\n     corp email" in BACKSTORY_LOWER

    def test_rationale_names_specific_signals(self):
        """Principle 6: the rationale must NAME the OSINT signals,
        not vaguely claim plausibility."""
        assert "specific OSINT signals" in BACKSTORY

    def test_sources_never_silently_dropped(self):
        """Principle 7: every contributing source string carries
        through. The audit trail is the only way an operator can
        sanity-check a draft before sending."""
        assert "Never\n   silently drop sources" in BACKSTORY or (
            "never silently drop sources" in BACKSTORY_LOWER
        )


class TestBackstoryGuardrails:
    """The "What NOT to do" section is the agent's negative
    space. Each rule here exists because a previous version of
    the agent (or an analogous one) violated it."""

    def test_forbids_inventing_interactions(self):
        """The do-not-fabricate rule. Pinned to two phrasings ──
        the literal contraction the backstory uses today, plus
        an Anglicised variant."""
        assert "Don't invent" in BACKSTORY or "Do not invent" in BACKSTORY

    def test_no_credentials_or_breach_data_in_body(self):
        """The agent receives credential-exposure context from
        Phase D but must NOT echo it into the email body. That
        context informs the *choice* of lure, never the visible
        text."""
        # The "in the body of the email" wording is what limits
        # the rule to body text (rationale can mention exposure).
        assert "credentials or breach data" in BACKSTORY_LOWER
        assert "in the body" in BACKSTORY_LOWER

    def test_no_faked_intimacy(self):
        """"As discussed in our last meeting" is a classic phish
        tell; the rule forbids that whole category."""
        assert "faked intimacy" in BACKSTORY_LOWER or (
            "as discussed in our last meeting" in BACKSTORY_LOWER
        )

    def test_no_script_or_payload(self):
        """The drafter is a *text* drafter. The operator may
        attach a payload separately after review; the agent must
        not embed one."""
        assert "<script>" in BACKSTORY or "malicious attachments" in BACKSTORY_LOWER
        assert "payload" in BACKSTORY_LOWER


# ──────────────────────────────────────────────────────────────────────
# CrewAI config wiring
# ──────────────────────────────────────────────────────────────────────


class TestCrewAIConfig:
    """``to_crewai_config()`` is the bridge between this class and
    the CrewAI Agent constructor. The mapping is small, but a
    drop would silently change runtime behaviour."""

    def test_role_round_trip(self):
        config = PhishingDrafterAgent().to_crewai_config()
        assert config["role"] == PhishingDrafterAgent.role

    def test_goal_round_trip(self):
        config = PhishingDrafterAgent().to_crewai_config()
        assert config["goal"] == PhishingDrafterAgent.goal

    def test_backstory_round_trip(self):
        config = PhishingDrafterAgent().to_crewai_config()
        assert config["backstory"] == PhishingDrafterAgent.backstory

    def test_max_iter_matches_max_steps(self):
        """CrewAI uses ``max_iter``; we store it as ``max_steps``.
        The mapping must be 1:1 ── if these drift the budget
        becomes meaningless."""
        config = PhishingDrafterAgent().to_crewai_config()
        assert config["max_iter"] == PhishingDrafterAgent.max_steps == 5

    def test_no_delegation(self):
        """Drafter doesn't delegate; the executor invokes it
        once per target. Delegation would silently chain LLM
        calls and overrun the budget."""
        config = PhishingDrafterAgent().to_crewai_config()
        assert config["allow_delegation"] is False

    def test_tools_empty(self):
        """Drafter is a synthesis agent ── no tool calls. Empty
        tool list also blocks any future accidental wiring of
        an HTTP-fetcher tool that would let the model invent
        signals."""
        config = PhishingDrafterAgent().to_crewai_config()
        assert config["tools"] == []

    def test_max_rpm_is_none(self):
        """Rate limiting is handled by the OPSEC stack, not
        CrewAI. ``max_rpm=None`` defers to our own limiter
        consistently across every agent class."""
        config = PhishingDrafterAgent().to_crewai_config()
        assert config["max_rpm"] is None


# ──────────────────────────────────────────────────────────────────────
# Executor registry resolution
# ──────────────────────────────────────────────────────────────────────


class TestRegistry:
    """The Phase 7.7 node calls ``executor.run_agent(
    "phishing_drafter", ...)``. That string MUST resolve to
    this class via the executor's registry, or the drafter
    silently never runs."""

    def test_registered_under_phishing_drafter_key(self):
        assert "phishing_drafter" in AGENT_REGISTRY
        assert AGENT_REGISTRY["phishing_drafter"] is PhishingDrafterAgent

    def test_registry_key_matches_agent_name(self):
        """The string used to look up the agent MUST equal the
        agent's own ``agent_name`` attribute. Otherwise the
        executor's logging shows one name while the matcher
        uses another, making bug triage harder."""
        for key, cls in AGENT_REGISTRY.items():
            if cls is PhishingDrafterAgent:
                assert key == PhishingDrafterAgent.agent_name


# ──────────────────────────────────────────────────────────────────────
# Executor integration
# ──────────────────────────────────────────────────────────────────────


def _stub_config():
    """Build the minimal config shape AgentExecutor reads on
    construction. ``llm_provider="mock"`` makes ``get_llm_from_config``
    skip every real-provider branch and fall through to MockLLM."""
    config = MagicMock()
    config.llm_provider = "mock"
    config.llm_model = "mock"
    config.llm_temperature = 0.0
    config.get_secret = MagicMock(return_value=None)
    return config


def _drafter_task_data():
    """A realistic payload approximating what Phase 7.7 passes."""
    return {
        "target_identity_id": "id-target-1",
        "target_label": "Jane Doe — VP Engineering",
        "top_pretext_candidates": [
            {
                "sender_identity_id": "id-sender-1",
                "topic_anchor": "acquisition-announcement",
                "combined_score": 0.72,
                "rationale": "Sender + target co-authored 3 PRs in May.",
                "sources": ["github_social:co_author:repo/x"],
            },
        ],
    }


class TestExecutorIntegration:
    """End-to-end via ``AgentExecutor.run_agent`` with a stubbed
    LLM. The agent's actual JSON output depends on the model ──
    we mock the LLM so these tests assert the *plumbing*, not
    the model behaviour."""

    @pytest.mark.asyncio
    async def test_run_agent_returns_standard_envelope(self):
        """Every executor invocation returns this dict shape.
        Phase 7.7 reads ``result["output"]`` straight into the
        dossier ── pin the keys."""
        executor = AgentExecutor(_stub_config())
        result = await executor.run_agent(
            "phishing_drafter",
            _drafter_task_data(),
            "Produce ONE spear-phishing draft for the target.",
        )
        assert result["agent"] == "phishing_drafter"
        assert "output" in result
        assert "step_count" in result
        assert "findings" in result
        assert isinstance(result["output"], str)

    @pytest.mark.asyncio
    async def test_run_agent_increments_step_count(self):
        """The executor's step counter must tick once per
        invocation. The drafter's per-instance ``max_steps``
        budget caps the inner CrewAI loop; the executor's
        counter caps the outer call count."""
        executor = AgentExecutor(_stub_config())
        r1 = await executor.run_agent(
            "phishing_drafter", _drafter_task_data(), "draft",
        )
        r2 = await executor.run_agent(
            "phishing_drafter", _drafter_task_data(), "draft",
        )
        assert r1["step_count"] == 1
        assert r2["step_count"] == 2

    @pytest.mark.asyncio
    async def test_run_agent_propagates_llm_output(self):
        """When the LLM returns content, the executor passes it
        through unchanged in ``result["output"]``. Pin this by
        stubbing the LLM ── otherwise we're at the mercy of
        MockLLM's heuristic content."""
        executor = AgentExecutor(_stub_config())
        canned = '{"target_identity_id":"id-target-1","draft":null}'
        executor.llm = MagicMock()
        executor.llm.invoke = MagicMock(
            return_value=MagicMock(content=canned),
        )
        result = await executor.run_agent(
            "phishing_drafter", _drafter_task_data(), "draft",
        )
        assert result["output"] == canned

    @pytest.mark.asyncio
    async def test_run_agent_includes_task_data_in_prompt(self):
        """The task data MUST land in the prompt the LLM sees;
        otherwise the drafter has no inputs to ground the lure
        in. Capture the prompt and look for the target_id."""
        executor = AgentExecutor(_stub_config())
        captured: list[str] = []

        def _capture(prompt: str):
            captured.append(prompt)
            return MagicMock(content='{"draft": null}')

        executor.llm = MagicMock()
        executor.llm.invoke = _capture
        await executor.run_agent(
            "phishing_drafter", _drafter_task_data(), "draft",
        )
        assert captured, "LLM was not invoked"
        prompt = captured[0]
        assert "id-target-1" in prompt
        assert "top_pretext_candidates" in prompt

    @pytest.mark.asyncio
    async def test_run_agent_swallows_llm_exception(self):
        """The executor must never raise on LLM failure ── it
        wraps the error in the result envelope so Phase 7.7 can
        log + continue with the next target rather than
        aborting the whole phase."""
        executor = AgentExecutor(_stub_config())
        executor.llm = MagicMock()
        executor.llm.invoke = MagicMock(
            side_effect=RuntimeError("model timed out"),
        )
        result = await executor.run_agent(
            "phishing_drafter", _drafter_task_data(), "draft",
        )
        assert "error" in result
        assert "model timed out" in result["error"]
        assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_run_agent_enforces_budget(self):
        """If state's accumulated cost already exceeds the cap,
        the executor MUST refuse new calls. The drafter runs in
        a per-target loop ── a runaway would burn the whole
        campaign budget on one phase."""
        from nexusrecon.core.cost_tracker import BudgetExceededError

        executor = AgentExecutor(_stub_config())
        state = {"llm_cost_usd": 100.0, "max_llm_cost_usd": 50.0}
        with pytest.raises(BudgetExceededError):
            await executor.run_agent(
                "phishing_drafter", _drafter_task_data(),
                "draft", state=state,
            )

    @pytest.mark.asyncio
    async def test_run_agent_does_not_pollute_findings(self):
        """The drafter doesn't emit FINDINGS_JSON ── its output is
        a per-target draft, not a finding. Without a FINDINGS_JSON
        block, the executor returns an empty findings list and
        leaves ``state["findings"]`` untouched."""
        executor = AgentExecutor(_stub_config())
        executor.llm = MagicMock()
        executor.llm.invoke = MagicMock(
            return_value=MagicMock(content='{"draft": null}'),
        )
        state: dict = {"findings": [{"title": "pre-existing"}]}
        result = await executor.run_agent(
            "phishing_drafter", _drafter_task_data(),
            "draft", state=state,
        )
        assert result["findings"] == []
        # Pre-existing findings remain untouched.
        assert len(state["findings"]) == 1
        assert state["findings"][0]["title"] == "pre-existing"


# Phase 7.7 positive-path integration (drafter IS invoked → output
# lands in dossier) lives in ``test_phase_7_7.py`` alongside the
# negative-gate test ── the wiring is the phase's concern, not the
# agent's. Keeping it there avoids duplicating the heavy mock
# scaffolding the phase needs (identity graph, relationship graph,
# scoring engine, tool fan-out).
