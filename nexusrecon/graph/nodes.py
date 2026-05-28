"""
LangGraph phase nodes — each node implements one campaign phase.

Phase nodes:
1. Execute tools (via tool registry)
2. Feed results to CrewAI agents for synthesis (via AgentExecutor)
3. Write agent analysis + tool results to state
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

import structlog

from nexusrecon.core.config import get_config
from nexusrecon.core.scoring import (
    annotate_next_steps,
    score_findings,
    score_findings_with_coverage,
    unavailable_tools_from_preflight,
    unproductive_tools_from_audit,
)
from nexusrecon.graph.agent_executor import AgentExecutor
from nexusrecon.graph.state import CampaignGraphState
from nexusrecon.opsec.useragent import UserAgentPool
from nexusrecon.tools.registry import get_registry

log = structlog.get_logger(__name__)

# Global agent executor (lazy init per campaign)
_executor: AgentExecutor | None = None


def _get_executor() -> AgentExecutor:
    global _executor
    if _executor is None:
        config = get_config()
        _executor = AgentExecutor(config)
    return _executor


def _reset_executor() -> None:
    global _executor
    _executor = None


def set_executor_cost_tracker(tracker: Any) -> None:
    """Bind a campaign's CostTracker to the shared executor (Wave F-A6).

    Ensures LLM spend recorded by the agents reaches the tracker that
    ``campaign.end_phase`` / ``finalize`` read, instead of the executor's
    private instance. Called once at campaign start by ``run_campaign``.
    """
    _get_executor().bind_cost_tracker(tracker)


def _get_tools_by_tier(max_tier: str, exclude_categories: set = None) -> list[Any]:
    """Get available tools filtered by tier."""
    registry = get_registry()
    tier_limit = int(max_tier[1])
    tools = []
    for t in registry.available_tools():
        tool_tier = int(t.tier.value[1])
        if tool_tier <= tier_limit:
            if exclude_categories and t.category.value in exclude_categories:
                continue
            tools.append(t)
    return tools


# Phase nodes use ``asyncio.gather(return_exceptions=True)`` extensively.
# That call returns BaseException subclasses (e.g. ``asyncio.CancelledError``
# in 3.8+, pytest's ``_pytest.outcomes.Failed`` on timeout) as result items
# rather than re-raising them. ``isinstance(x, Exception)`` returns False
# for those because they inherit from ``BaseException`` directly, so the
# downstream ``x.success`` access crashed the phase. All gather-result
# guards in this file use ``BaseException`` for that reason.
#
# We intentionally treat BaseException-derived results as "skip and
# continue" rather than re-raising: the outer campaign runner wraps the
# workflow and handles aborts at that level, and asyncio's structured
# concurrency means cancellation still propagates correctly through the
# enclosing task.


# ── Phase 1: Passive Footprinting ─────────────────────────────────────────────

async def phase1_passive_footprinting(state: CampaignGraphState) -> CampaignGraphState:
    """T0 passive broad sweep — subdomains, DNS, WHOIS, certs, initial intel."""
    log.info("Phase 1: Passive footprinting")
    state["current_phase"] = "phase1"
    subdomain_intel: dict[str, Any] = {}
    domain_intel: dict[str, Any] = {}

    registry = get_registry()

    for seed in state.get("seeds", []):
        # Subdomain enumeration — all three tools in parallel (F-021: dead dict branch removed)
        sub_results = await asyncio.gather(
            registry.execute("crtsh", seed, "domain"),
            registry.execute("subfinder", seed, "domain"),
            registry.execute("amass", seed, "domain"),
            return_exceptions=True,
        )
        for result in sub_results:
            if isinstance(result, BaseException) or not result.success:
                continue
            for sub in result.data.get("subdomains", []):
                sub_name = sub.get("subdomain", sub) if isinstance(sub, dict) else sub
                if sub_name and sub_name not in subdomain_intel:
                    subdomain_intel[sub_name] = {"sources": [result.source]}
                elif sub_name:
                    subdomain_intel[sub_name]["sources"].append(result.source)

        # DNS, WHOIS, ASN — parallel
        dns_r, whois_r, asn_r = await asyncio.gather(
            registry.execute("dns", seed, "domain"),
            registry.execute("whois", seed, "domain"),
            registry.execute("asn_bgp", seed, "domain"),
            return_exceptions=True,
        )
        if not isinstance(dns_r, BaseException) and dns_r.success:
            domain_intel["dns"] = dns_r.data
        if not isinstance(whois_r, BaseException) and whois_r.success:
            domain_intel["whois"] = whois_r.data
        if not isinstance(asn_r, BaseException) and asn_r.success:
            domain_intel["asn"] = asn_r.data

    # Agent synthesis: Passive Recon Specialist analyzes the raw data
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "passive_recon",
            task_data={
                "seeds": state.get("seeds", []),
                "subdomain_intel": dict(list(subdomain_intel.items())[:200]),
                "domain_intel": domain_intel,
            },
            task_prompt="Analyze the passive reconnaissance results. Identify high-value subdomains, "
                        "DNS anomalies, WHOIS insights, and recommend which findings warrant deeper investigation.",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase1",
            "agent": "passive_recon",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase1", error=str(e))
        state.setdefault("agent_messages", []).append({
            "phase": "phase1",
            "agent": "passive_recon",
            "analysis": f"Agent synthesis skipped: {e}",
            "timestamp": datetime.utcnow().isoformat(),
        })

    # Dark intel: ransomwatch, ahmia, pastebin, certstream — parallel per seed
    dark_intel: dict[str, Any] = {}
    dark_tasks = []
    for seed in state.get("seeds", []):
        dark_tasks.extend([
            registry.execute("ransomwatch", seed, "domain"),
            registry.execute("ahmia", seed, "domain"),
            registry.execute("pastebin_scan", seed, "domain"),
            registry.execute("certstream_recent", seed, "domain"),
        ])
    dark_results = await asyncio.gather(*dark_tasks, return_exceptions=True)
    seeds_list = state.get("seeds", [])
    for i, result in enumerate(dark_results):
        if isinstance(result, BaseException) or not result.success:
            continue
        seed = seeds_list[i // 4]
        tool_keys = ["ransomwatch", "ahmia", "pastebin", "certstream"]
        dark_intel[f"{tool_keys[i % 4]}/{seed}"] = result.data

    state["subdomain_intel"] = subdomain_intel
    state["domain_intel"] = domain_intel
    state["dark_intel"] = dark_intel
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase1"]
    return state


# ── Phase 2: Identity & Cloud ─────────────────────────────────────────────────

async def phase2_identity_cloud(state: CampaignGraphState) -> CampaignGraphState:
    """M365/Entra/AWS/GCP enumeration, email harvesting, federation discovery."""
    log.info("Phase 2: Identity and cloud recon")
    state["current_phase"] = "phase2"
    email_intel: dict[str, Any] = {"emails": {}, "formats": {}}
    cloud_intel: dict[str, Any] = {}

    registry = get_registry()
    seeds = state.get("seeds", [])
    subdomains = list(state.get("subdomain_intel", {}).keys())

    for seed in seeds:
        # Azure/M365 recon
        result = await registry.execute(
            "azure_m365_recon", seed, "domain",
            emails=list(email_intel.get("emails", {}).keys()),
        )
        if result.success:
            cloud_intel[f"azure/{seed}"] = result.data

        # AWS recon
        result = await registry.execute("aws_recon", seed, "domain", subdomains=subdomains)
        if result.success:
            cloud_intel[f"aws/{seed}"] = result.data

        # GCP recon
        result = await registry.execute("gcp_recon", seed, "domain")
        if result.success:
            cloud_intel[f"gcp/{seed}"] = result.data

        # theHarvester
        result = await registry.execute("theharvester", seed, "domain")
        if result.success:
            for em in result.data.get("emails", []):
                email_intel["emails"][em] = {"source": "theharvester", "domain": seed}

        # Hunter.io
        result = await registry.execute("hunter", seed, "domain")
        if result.success:
            for em in result.data.get("emails", []):
                email_val = em.get("email")
                if email_val:
                    email_intel["emails"][email_val] = {
                        "source": "hunter",
                        "position": em.get("position"),
                        "department": em.get("department"),
                    }

    # Email format inference
    emails = list(email_intel["emails"].keys())
    if emails and seeds:
        result = await registry.execute("email_format", seeds[0], "domain", emails=emails)
        if result.success:
            email_intel["format"] = result.data

    # Move 5: playstore — find apps published by the target org
    for seed in seeds:
        ps_result = await registry.execute("playstore", seed, "domain")
        if ps_result.success and ps_result.data.get("apps"):
            cloud_intel[f"playstore/{seed}"] = ps_result.data

    # Holehe — registered services per email (parallelized, cap at 20 emails)
    if emails:
        holehe_sem = asyncio.Semaphore(5)

        async def _run_holehe(em: str) -> tuple[str, Any]:
            async with holehe_sem:
                r = await registry.execute("holehe", em, "email")
                return em, r.data if r.success else None

        holehe_results = await asyncio.gather(
            *(_run_holehe(em) for em in emails[:20]),
            return_exceptions=True,
        )
        for item in holehe_results:
            if isinstance(item, BaseException):
                continue
            em, data = item
            if data is not None:
                email_intel["emails"].setdefault(em, {})["registered_services"] = data.get("registered_services", [])

    # Maigret — expand the email-input account footprint via username
    # derivation. Holehe covers ~121 services; maigret covers ~3000 but
    # is keyed by username, not email. We derive likely handles from
    # the email local-part + any harvested names (from hunter), then
    # probe each derived username with maigret. The two together give
    # the dispatcher the broadest possible account-association signal.
    #
    # Wall-clock budget: maigret per-username ≈ 30-90s at 500 top-sites
    # × 10s timeout. We cap aggressively: top 5 emails × 2 candidates
    # each = 10 maigret invocations, semaphore=2, so ~5 minutes total
    # at stealth profile "normal". Tunable via env if needed.
    if emails:
        maigret_sem = asyncio.Semaphore(2)

        async def _run_maigret(em: str) -> tuple[str, Any]:
            # Build the names list from any hunter metadata for this
            # email. Each email's record in email_intel may carry a
            # position/department/name field; collect what's there.
            email_record = email_intel["emails"].get(em, {})
            harvested_names: list[str] = []
            for key in ("name", "first_name", "last_name"):
                val = email_record.get(key)
                if val and isinstance(val, str):
                    harvested_names.append(val)
            # If we have first+last separately, also build the combined.
            if email_record.get("first_name") and email_record.get("last_name"):
                harvested_names.append(
                    f"{email_record['first_name']} {email_record['last_name']}"
                )

            async with maigret_sem:
                r = await registry.execute(
                    "maigret",
                    em,
                    "email",
                    names=harvested_names,
                    max_candidates=2,
                )
                return em, r.data if r.success else None

        maigret_results = await asyncio.gather(
            *(_run_maigret(em) for em in emails[:5]),
            return_exceptions=True,
        )
        for item in maigret_results:
            if isinstance(item, BaseException):
                continue
            em, data = item
            if data is not None:
                # Attach maigret-discovered accounts under a separate
                # key so the agent can distinguish holehe hits (email-
                # registration confirmed) from maigret hits (handle
                # match across services, less certain attribution).
                email_intel["emails"].setdefault(em, {})["maigret_accounts"] = (
                    data.get("registered_services", [])
                )
                email_intel["emails"][em]["derived_usernames"] = (
                    data.get("candidates", [])
                )

    # B29: commit cloud_intel + email_intel to state BEFORE the agent runs so the
    # attribution gate (which reads state["cloud_intel"]) can downgrade stem-match
    # findings. Previously these assignments happened after the agent — the gate
    # ran blind and missed stem-match identifiers like third-party tenant IDs.
    state["cloud_intel"] = cloud_intel
    state["email_intel"] = email_intel

    # Build account-association summary for the agent. Filters maigret
    # hits to those at "actionable" confidence (>= 0.6) so the
    # cloud_identity agent doesn't reason about noise. Common-name
    # collisions (smith on Reddit derived from john.smith@... etc.)
    # have already been scored down by the attribution scorer; this
    # is just where we threshold.
    account_summary: dict[str, Any] = {
        "per_email_account_count": {},
        "actionable_accounts": [],
        "filtered_noise_count": 0,
    }
    for em, record in email_intel["emails"].items():
        holehe_hits = record.get("registered_services") or []
        maigret_hits = record.get("maigret_accounts") or []

        # Split maigret hits by confidence band ── only actionable
        # (medium + high) feeds the agent prompt. Noise gets counted
        # but not surfaced so the agent isn't tempted to act on it.
        actionable_maigret = [
            h for h in maigret_hits
            if h.get("confidence", 0.0) >= 0.6
        ]
        noise_maigret = [
            h for h in maigret_hits
            if h.get("confidence", 0.0) < 0.6
        ]
        account_summary["filtered_noise_count"] += len(noise_maigret)

        if holehe_hits or actionable_maigret:
            account_summary["per_email_account_count"][em] = {
                "holehe": len(holehe_hits),
                "maigret_actionable": len(actionable_maigret),
                "maigret_noise_filtered": len(noise_maigret),
                "derived_usernames": record.get("derived_usernames", []),
            }

        # Build the per-account "actionable" record carrying enough
        # evidence for the agent to cite (rationale + signals + url +
        # Phase B fetched profile + linked-account cross-references).
        for hit in actionable_maigret:
            entry = {
                "email": em,
                "handle": hit.get("username"),
                "service": hit.get("service"),
                "url": hit.get("url"),
                "confidence": hit.get("confidence"),
                "confidence_band": hit.get("confidence_band"),
                "rationale": hit.get("confidence_rationale"),
                "signals": hit.get("confidence_signals"),
            }
            # Phase B: attach the fetched profile snapshot when
            # available. Includes bio, location, company ── exactly
            # the fields the agent needs to cite for "this looks like
            # the same person because bio mentions X".
            fetched = hit.get("fetched_profile")
            if fetched and fetched.get("fetched"):
                entry["profile"] = {
                    "display_name": fetched.get("display_name"),
                    "bio": fetched.get("bio"),
                    "location": fetched.get("location"),
                    "company": fetched.get("company"),
                    "blog_url": fetched.get("blog_url"),
                    "linked_accounts": fetched.get("linked_accounts", []),
                }
            # Phase B/B4: surface any cross-references that named this
            # account from another service's bio.
            cross_refs = hit.get("cross_referenced_from")
            if cross_refs:
                entry["cross_referenced_from"] = cross_refs
            # Phase C1: avatar cluster membership ── the framework
            # identified the same image on multiple services.
            if hit.get("avatar_cluster_size", 1) >= 2:
                entry["avatar_cluster_size"] = hit.get("avatar_cluster_size")
                entry["avatar_cluster_id"] = hit.get("avatar_cluster_id")
            # Phase C2: timeline cluster ── accounts created within
            # the same window.
            if hit.get("timeline_cluster_size", 1) >= 2:
                entry["timeline_cluster_size"] = hit.get("timeline_cluster_size")
                entry["timeline_cluster_id"] = hit.get("timeline_cluster_id")
            account_summary["actionable_accounts"].append(entry)

    # Sort actionable accounts by confidence descending for the agent.
    account_summary["actionable_accounts"].sort(
        key=lambda a: -a.get("confidence", 0.0),
    )
    # Cap the list for context-window politeness ── top 25 are plenty
    # for the agent to reason about.
    account_summary["actionable_accounts"] = (
        account_summary["actionable_accounts"][:25]
    )

    # Agent synthesis: Cloud & Identity Specialist analyzes
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "cloud_identity",
            task_data={
                "cloud_intel": {k: _summarize_dict(v) for k, v in list(cloud_intel.items())[:10]},
                "email_intel": {"email_count": len(email_intel["emails"]), "format": email_intel.get("format")},
                "account_associations": account_summary,
            },
            task_prompt="Analyze the cloud and identity reconnaissance results. Check "
                        "attribution_confidence on each cloud source — values below 0.5 "
                        "indicate stem-match guesses that may belong to unrelated organizations. "
                        "Identify: "
                        "1. Cloud exposure risks (public buckets, misconfigurations) — only if attribution_confidence >= 0.5 "
                        "2. M365/Azure federation type and its implications for phishing "
                        "3. Email format patterns and their confidence levels "
                        "4. Recommended next steps for identity-based attack vectors "
                        "5. Low-confidence cloud assets (attribution_confidence < 0.5) must be tagged [POSSIBLE] with info severity only "
                        "6. Account-association analysis. The ``account_associations.actionable_accounts`` "
                        "list contains maigret hits that scored >= 0.6 attribution confidence after "
                        "applying derivation-rank + handle-uniqueness + service-tier + profile-coherence "
                        "scoring. Each entry carries its score, confidence_band (high/medium), a "
                        "rationale string, and (when available from Phase B profile fetching) a "
                        "``profile`` field with the actual bio/location/company text from the service. "
                        "Use the bio text to cite SPECIFIC evidence: 'jane.doe on GitHub scored 0.78 "
                        "and the bio says \"Senior engineer at GitLab\" ── that matches the email "
                        "domain.' Don't just restate the score. The ``filtered_noise_count`` field "
                        "reports how many hits the scorer rejected as collisions ── DO NOT speculate "
                        "about those; they are common-name false positives (john.smith on Reddit, "
                        "admin on a forum, etc.). "
                        "If an entry has a ``cross_referenced_from`` field, a SEPARATE service's "
                        "profile bio explicitly mentioned this account ── that's the strongest "
                        "available identity evidence short of explicit auth. Cite it: 'the GitHub "
                        "profile under jane.doe linked to twitter.com/janedoe in its bio, which "
                        "matches the maigret hit on Twitter.' "
                        "If an entry has ``avatar_cluster_size >= 2``, the framework's perceptual "
                        "avatar hashing found the SAME image on multiple services for this account "
                        "── another strong identity confirmation (Phase C1). Cite it: 'the avatar "
                        "on jane's GitHub and Twitter accounts is the same image (cluster id N).' "
                        "If an entry has ``timeline_cluster_size >= 2``, this account was created "
                        "within ~30 days of N-1 other discovered accounts ── consistent with one "
                        "person setting up their professional online presence at a single moment "
                        "(Phase C2). Statistical signal, not certainty: cite as 'jane's GitHub, "
                        "Twitter, and Mastodon accounts were all created within the same month.' "
                        "For each high-band actionable account, cite the rationale + specific "
                        "evidence and recommend a follow-up dispatch (e.g. hibp/intelx/dehashed "
                        "against the confirmed handle as a separate query from the email). For "
                        "medium-band accounts, flag them as tentative. If a medium-band account has "
                        "a fetched profile that confirms identity via bio text, upgrade your "
                        "confidence verbally even though the numeric score doesn't move. Never "
                        "claim a handle belongs to the email's owner without citing at least one "
                        "concrete piece of evidence: exact derivation, Tier 1 service, fetched bio "
                        "text, or a linked-account cross-reference.",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase2",
            "agent": "cloud_identity",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase2", error=str(e))

    state["email_intel"] = email_intel
    state["cloud_intel"] = cloud_intel
    state["identity_intel"] = email_intel
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase2"]
    return state


# ── Phase 3: Deep Subdomain & Code Leakage ────────────────────────────────────

async def phase3_code_leakage(state: CampaignGraphState) -> CampaignGraphState:
    """Recursive subdomain on high-value findings, GitHub/code recon."""
    log.info("Phase 3: Deep subdomain and code leakage")
    state["current_phase"] = "phase3"
    code_intel: dict[str, Any] = {}
    seeds = state.get("seeds", [])

    registry = get_registry()

    async def _run_code_tool(tool_name: str, seed: str, **kwargs: Any) -> tuple[str, Any]:
        result = await registry.execute(tool_name, seed, "domain", **kwargs)
        return f"{tool_name}/{seed}", result.data if result.success else None

    # All code tools run in parallel across all seeds
    code_tasks = []
    for seed in seeds:
        code_tasks.extend([
            _run_code_tool("github_recon", seed),
            _run_code_tool("gitleaks", seed),
            _run_code_tool("trufflehog", seed),
            _run_code_tool("gitdorker", seed),
            _run_code_tool("postman", seed),
            _run_code_tool("dockerhub", seed),
        ])
    code_results = await asyncio.gather(*code_tasks, return_exceptions=True)
    for item in code_results:
        if isinstance(item, BaseException):
            continue
        key, data = item
        if data is not None:
            code_intel[key] = data

    # Agent synthesis
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "passive_recon",
            task_data={
                "code_intel": {k: _summarize_dict(v) for k, v in list(code_intel.items())[:10]},
            },
            task_prompt="Analyze code and secret leakage findings. Identify: "
                        "1. Active/severe credential leaks (AWS keys, API tokens, database passwords)"
                        "2. Repositories with the highest exposure risk"
                        "3. Patterns in leaked secrets (what types, which services)"
                        "4. Recommended immediate remediation actions",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase3",
            "agent": "passive_recon",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase3", error=str(e))

    state["code_intel"] = code_intel
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase3"]
    return state


# ── Phase 4: Correlation & Hypothesis ─────────────────────────────────────────

async def phase4_correlation(state: CampaignGraphState) -> CampaignGraphState:
    """Cross-source validation, entity linking, lead generation."""
    log.info("Phase 4: Correlation and hypothesis testing")
    state["current_phase"] = "phase4"

    subdomain_intel = state.get("subdomain_intel", {})
    email_intel = state.get("email_intel", {})
    cloud_intel = state.get("cloud_intel", {})
    code_intel = state.get("code_intel", {})

    hypotheses = []
    confirmed_leads = []
    open_questions = []

    emails = email_intel.get("emails", {})
    if emails:
        hypotheses.append(f"Found {len(emails)} email addresses — correlate with LinkedIn and breach data")
        for em, info in emails.items():
            pos = str(info.get("position", "")).lower() if isinstance(info, dict) else ""
            if any(x in pos for x in ["ceo", "cfo", "cto", "ciso", "vp", "director", "executive"]):
                confirmed_leads.append(f"Executive email: {em} ({pos})")

    if cloud_intel:
        for key, data in cloud_intel.items():
            # B26: skip low-confidence stem-match data — only promote to confirmed_leads
            # when attribution_confidence >= 0.5 (default 1.0 for tools that don't set it)
            attr_conf = data.get("attribution_confidence", 1.0) if isinstance(data, dict) else 1.0
            if attr_conf < 0.5:
                open_questions.append(
                    f"{key}: Possible cloud presence (stem-match only, "
                    f"attribution_confidence={attr_conf:.1f}; verify ownership before acting)"
                )
                continue
            if isinstance(data, dict) and data.get("s3_buckets"):
                for b in data["s3_buckets"]:
                    if b.get("public"):
                        confirmed_leads.append(f"Public S3 bucket: {b.get('name', 'unknown')} in {key}")
            if isinstance(data, dict) and data.get("user_realm", {}).get("is_federated"):
                confirmed_leads.append(f"{key}: Federated (ADFS) — targeted phishing possible")
            if isinstance(data, dict) and data.get("user_realm", {}).get("found") and not data.get("user_realm", {}).get("is_federated"):
                confirmed_leads.append(f"{key}: Managed federation — password spray viable")

    if code_intel:
        for key, data in code_intel.items():
            leaks = data.get("data", {}).get("leaks", data.get("findings", []))
            if leaks:
                confirmed_leads.append(f"{key}: {len(leaks)} secrets found")

    if not emails:
        open_questions.append("No emails found — expand identity harvesting")
    if not cloud_intel:
        open_questions.append("No cloud intel found — check M365/AWS/GCP tool availability")

    # ── Step 0.0 (METASPLOIT_PLAN): build the real EntityGraph from
    # the state buckets BEFORE invoking the correlation agent, so the
    # agent receives a graph-derived summary in its task_data instead
    # of just the flat name lists. The graph is also serialized into
    # state["entity_graph"] (replacing the previous truncated
    # name-list assignment) so downstream phases + the TUI can
    # consume it.
    state["hypotheses"] = hypotheses
    state["confirmed_leads"] = confirmed_leads
    state["open_questions"] = open_questions

    from nexusrecon.core.entity_graph import EntityGraph
    from nexusrecon.core.graph_context import GraphContext

    entity_graph = EntityGraph.from_state(state)
    graph_context = GraphContext(entity_graph)

    # Agent synthesis: Correlation Agent
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "correlation",
            task_data={
                "hypotheses": hypotheses,
                "confirmed_leads": confirmed_leads,
                "open_questions": open_questions,
                "subdomain_count": len(subdomain_intel),
                "email_count": len(emails),
                "cloud_sources": list(cloud_intel.keys()),
                "code_sources": list(code_intel.keys()),
                # Step 0.0 wired graph_summary into task_data;
                # Phase 0.1 upgrades to ``for_phase`` so the
                # summary subsets to entity types the
                # correlation agent actually reasons over +
                # adds the ``most_cited`` ranking.
                **graph_context.for_phase("phase4_correlation"),
            },
            task_prompt="Correlate all intelligence findings. When using cloud intel, "
                        "check attribution_confidence — values below 0.5 indicate stem-match "
                        "data that should NOT be used to build confirmed attack chains. "
                        "Generate new hypotheses, identify confirmed attack leads, and highlight "
                        "gaps in coverage. Be specific about which findings connect to form "
                        "attack chains, using only high-confidence data (attribution_confidence >= 0.5) "
                        "for confirmed leads. The graph_summary in your context lists every "
                        "entity NexusRecon has surfaced so far — cite them by value when "
                        "building chains.",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase4",
            "agent": "correlation",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase4", error=str(e))

    # Step 0.0: serialize the REAL graph (not a name-list
    # truncation). Carries every entity surfaced so far +
    # CITES / BLOCKS edges from reasoning artifacts back to the
    # entities they're based on. Downstream phases consume this
    # via EntityGraph.from_dict().
    state["entity_graph"] = entity_graph.to_dict()
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase4"]
    return state


# ── Phase 5: Light Active (T2 gated) ─────────────────────────────────────────

async def phase5_light_active(state: CampaignGraphState) -> CampaignGraphState:
    """T2 active probing, screenshots, fingerprinting (if authorized)."""
    log.info("Phase 5: Light active probing")
    state["current_phase"] = "phase5"
    infra_intel = dict(state.get("infra_intel", {}))
    subdomains = list(state.get("subdomain_intel", {}).keys())

    registry = get_registry()

    # httpx — parallelize with Semaphore(20) (F-016)
    httpx_sem = asyncio.Semaphore(20)

    async def _probe_sub(sub: str) -> tuple[str, Any]:
        async with httpx_sem:
            r = await registry.execute("httpx", sub, "domain")
            return sub, r.data if r.success else None

    probe_results = await asyncio.gather(
        *(_probe_sub(sub) for sub in subdomains[:100]),
        return_exceptions=True,
    )
    for item in probe_results:
        if isinstance(item, BaseException):
            continue
        sub, data = item
        if data is not None:
            infra_intel[sub] = data

    # Shodan and VirusTotal per seed
    for seed in state.get("seeds", []):
        result = await registry.execute("shodan", seed, "domain")
        if result.success:
            infra_intel[f"shodan/{seed}"] = result.data

        result = await registry.execute("virustotal", seed, "domain")
        if result.success:
            infra_intel[f"vt/{seed}"] = result.data

    # GreyNoise — run on IPs found in infra_intel from httpx probes (F-002)
    gn_seen: set[str] = set()
    gn_items: list[tuple[str, str]] = []
    for sub_key, sub_data in infra_intel.items():
        if isinstance(sub_data, dict):
            ip = sub_data.get("ip")
            if ip and ip not in gn_seen:
                gn_seen.add(ip)
                gn_items.append((sub_key, ip))

    if gn_items:
        gn_results = await asyncio.gather(
            *(registry.execute("greynoise", ip, "ip") for _, ip in gn_items[:50]),
            return_exceptions=True,
        )
        for (_, ip), result in zip(gn_items[:50], gn_results):
            if not isinstance(result, BaseException) and result.success:
                infra_intel[f"gn/{ip}"] = result.data

    # Agent synthesis: Active Recon Specialist
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "active_recon",
            task_data={
                "infra_intel": {k: _summarize_dict(v) for k, v in list(infra_intel.items())[:10]},
                "subdomains_probed": len(subdomains[:100]),
            },
            task_prompt="Analyze active reconnaissance results. Identify: "
                        "1. Live subdomains and their technologies"
                        "2. IP reputation findings (GreyNoise, AbuseIPDB)"
                        "3. Shodan/VirusTotal exposure data"
                        "4. High-value targets for further investigation",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase5",
            "agent": "active_recon",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase5", error=str(e))

    # Move 5 tools: subdomain_takeover, wafw00f, sslyze — run against top 50 subdomains
    top_subs = subdomains[:50]
    if top_subs:
        takeover_result = await registry.execute(
            "subdomain_takeover", state.get("seeds", [top_subs[0]])[0], "domain",
            subdomains=top_subs,
        )
        if takeover_result.success:
            infra_intel["subdomain_takeover"] = takeover_result.data

    for seed in state.get("seeds", []):
        waf_result = await registry.execute("wafw00f", seed, "domain")
        if waf_result.success:
            infra_intel[f"waf/{seed}"] = waf_result.data

        ssl_result = await registry.execute("sslyze", seed, "domain")
        if ssl_result.success:
            infra_intel[f"ssl/{seed}"] = ssl_result.data

    state["infra_intel"] = infra_intel
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase5"]
    return state


# ── Phase 6: Active (T3 gated) ────────────────────────────────────────────────

async def phase6_active(state: CampaignGraphState) -> CampaignGraphState:
    """T3 active probing — content fuzzing, alt-port probes, screenshots."""
    log.info("Phase 6: Active enumeration (T3)")
    state["current_phase"] = "phase6"
    infra_intel = dict(state.get("infra_intel", {}))
    subdomains = list(state.get("subdomain_intel", {}).keys())

    import httpx as _httpx

    registry = get_registry()
    ua_pool = UserAgentPool()
    sem = asyncio.Semaphore(25)  # F-017: shared semaphore caps concurrent HTTP connections

    # Alt-port probing — parallelized with semaphore, rotated UA
    alt_ports = [8080, 8443, 3000, 8000, 9090, 9443, 5000, 4443, 10443]

    async def _probe_alt_port(sub: str, port: int) -> tuple[str, int, dict | None]:
        async with sem:
            try:
                async with _httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        f"https://{sub}:{port}",
                        headers={"User-Agent": ua_pool.get()},
                    )
                    if resp.status_code < 500:
                        return sub, port, {
                            "port": port,
                            "status": resp.status_code,
                            "server": resp.headers.get("server", ""),
                            "title": _extract_title(resp.text),
                        }
            except Exception:
                pass
        return sub, port, None

    port_tasks = [
        _probe_alt_port(sub, port)
        for sub in subdomains[:30]
        for port in alt_ports
    ]
    port_results = await asyncio.gather(*port_tasks, return_exceptions=True)
    for item in port_results:
        if isinstance(item, BaseException):
            continue
        sub, _port, data = item
        if data:
            infra_intel.setdefault(sub, {}).setdefault("alt_ports", []).append(data)

    # Content discovery — parallelized with semaphore, rotated UA
    common_paths = [
        "/admin", "/login", "/api", "/v1", "/v2", "/graphql",
        "/.git/config", "/.env", "/backup", "/wp-admin", "/administrator",
        "/phpinfo.php", "/info.php", "/.well-known/security.txt",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/swagger.json", "/api-docs", "/openapi.json",
        "/actuator/health", "/health", "/healthcheck",
        "/console", "/jenkins", "/.gitignore", "/Dockerfile",
    ]

    async def _probe_path(sub: str, path: str) -> tuple[str, str, dict | None]:
        async with sem:
            try:
                async with _httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                    resp = await client.get(
                        f"https://{sub}{path}",
                        headers={"User-Agent": ua_pool.get()},
                    )
                    if resp.status_code not in (404, 410):
                        return sub, path, {
                            "path": path,
                            "status": resp.status_code,
                            "size": len(resp.content),
                        }
            except Exception:
                pass
        return sub, path, None

    path_tasks = [
        _probe_path(sub, path)
        for sub in subdomains[:20]
        for path in common_paths
    ]
    path_results = await asyncio.gather(*path_tasks, return_exceptions=True)
    for item in path_results:
        if isinstance(item, BaseException):
            continue
        sub, _path, data = item
        if data:
            infra_intel.setdefault(sub, {}).setdefault("discovered_paths", []).append(data)

    # gowitness screenshots
    for sub in subdomains[:50]:
        result = await registry.execute("gowitness", sub, "domain")
        if result.success:
            shots = result.data.get("screenshots", result.data.get("data", {}).get("screenshots", []))
            if shots:
                infra_intel.setdefault(sub, {}).setdefault("screenshots", []).extend(shots)

    # Agent synthesis: Active Recon Specialist
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "active_recon",
            task_data={
                "infra_intel": {k: _summarize_dict(v) for k, v in list(infra_intel.items())[:10]},
                "subdomains_probed": len(subdomains[:30]),
                "paths_checked": len(common_paths),
            },
            task_prompt="Analyze active enumeration results. Identify: "
                        "1. Interesting HTTP endpoints and directories "
                        "2. Alternative ports with web services "
                        "3. Admin panels and sensitive paths discovered "
                        "4. Screenshot evidence of live services "
                        "5. Findings for further exploitation",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase6",
            "agent": "active_recon",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase6", error=str(e))

    state["infra_intel"] = infra_intel
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase6"]
    return state


# ── Phase 7: Pretext & Vulnerability Correlation ──────────────────────────────

async def phase7_vuln_pretext(state: CampaignGraphState) -> CampaignGraphState:
    """Pretexting research, CVE correlation against fingerprinted tech."""
    log.info("Phase 7: Pretext and vulnerability correlation")
    state["current_phase"] = "phase7"
    vuln_intel: dict[str, Any] = {}

    registry = get_registry()

    # KEV check
    result = await registry.execute("kev", "", "domain")
    if result.success:
        vuln_intel["kev"] = result.data

    kev_ids: set[str] = set()
    for entry in (vuln_intel.get("kev", {}).get("vulnerabilities", []) or []):
        cve = entry.get("cveID") or entry.get("cve")
        if cve:
            kev_ids.add(cve.upper())

    # NVD — check for CVEs matching found technologies
    infra_intel = state.get("infra_intel", {})
    tech_names: set[str] = set()
    for key, data in infra_intel.items():
        if isinstance(data, dict):
            for host_data in data.get("data", {}).get("search", {}).get("hosts", []):
                if host_data.get("product"):
                    tech_names.add(host_data["product"])
            # Nuclei / webtech fingerprints
            for t in data.get("technologies", []):
                if isinstance(t, dict) and t.get("name"):
                    tech_names.add(t["name"])

    nvd_results = await asyncio.gather(
        *(registry.execute("nvd", tech, "domain", product=tech) for tech in list(tech_names)[:5]),
        return_exceptions=True,
    )
    for tech, res in zip(list(tech_names)[:5], nvd_results):
        if not isinstance(res, BaseException) and res.success:
            vuln_intel[f"nvd/{tech}"] = res.data

    # Collect all CVE IDs from NVD results
    all_cve_ids: dict[str, str] = {}  # cve_id → tech_name
    for tech, res in zip(list(tech_names)[:5], nvd_results):
        if isinstance(res, BaseException) or not res.success:
            continue
        cves = res.data.get("vulnerabilities", res.data.get("cves", []))
        for cve in (cves or []):
            if isinstance(cve, dict):
                cid = cve.get("id") or cve.get("cveId")
                if cid:
                    all_cve_ids[cid] = tech

    # CVE enrichment — for each CVE, run exploit/template lookups in parallel
    enriched_cves: dict[str, Any] = {}

    async def _enrich_cve(cve_id: str, tech: str) -> tuple[str, dict[str, Any]]:
        enrich_tasks = [
            registry.execute("exploitdb", cve_id, "cve"),
            registry.execute("github_advisory", cve_id, "cve"),
            registry.execute("osv", cve_id, "cve"),
            registry.execute("nuclei_template", cve_id, "cve"),
        ]
        # Add vulners if key available (it handles missing key gracefully)
        enrich_tasks.append(registry.execute("vulners", cve_id, "cve"))

        results_list = await asyncio.gather(*enrich_tasks, return_exceptions=True)

        exploitdb_r, ghsa_r, osv_r, template_r, vulners_r = results_list

        enriched: dict[str, Any] = {"tech": tech, "sources": ["nvd"]}

        # EPSS
        epss_r = await registry.execute("epss", cve_id, "cve")
        if not isinstance(epss_r, BaseException) and epss_r.success:
            enriched["epss"] = epss_r.data.get("epss_score", 0.0)
            enriched["epss_percentile"] = epss_r.data.get("epss_percentile", 0.0)

        # CVSS from NVD
        nvd_entry = vuln_intel.get(f"nvd/{tech}", {})
        for cve in (nvd_entry.get("vulnerabilities", nvd_entry.get("cves", [])) or []):
            if isinstance(cve, dict) and (cve.get("id") or cve.get("cveId")) == cve_id:
                enriched["cvss"] = cve.get("cvss_score") or cve.get("cvssV3", {}).get("baseScore", 0.0)
                enriched["description"] = cve.get("description", "")[:300]
                break

        enriched["in_kev"] = cve_id.upper() in kev_ids

        # ExploitDB / PoC
        if not isinstance(exploitdb_r, BaseException) and exploitdb_r.success:
            enriched["has_exploit"] = exploitdb_r.data.get("exploit_count", 0) > 0 or len(exploitdb_r.data.get("github_pocs", [])) > 0
            enriched["has_metasploit"] = exploitdb_r.data.get("has_metasploit", False)
            enriched["sources"].append("exploitdb")

        # Vulners Metasploit flag
        if not isinstance(vulners_r, BaseException) and vulners_r.success:
            enriched["has_metasploit"] = enriched.get("has_metasploit") or vulners_r.data.get("has_metasploit", False)

        # Nuclei template
        if not isinstance(template_r, BaseException) and template_r.success:
            enriched["has_nuclei_template"] = template_r.data.get("has_template", False)
            enriched["nuclei_hint"] = template_r.data.get("nuclei_run_hint", "")

        # GHSA package ecosystems
        if not isinstance(ghsa_r, BaseException) and ghsa_r.success:
            enriched["affected_packages"] = ghsa_r.data.get("affected_packages", [])

        return cve_id, enriched

    if all_cve_ids:
        enrich_results = await asyncio.gather(
            *(_enrich_cve(cid, tech) for cid, tech in list(all_cve_ids.items())[:20]),
            return_exceptions=True,
        )
        for item in enrich_results:
            if isinstance(item, BaseException):
                continue
            cid, enriched = item
            enriched_cves[cid] = enriched

    vuln_intel["enriched_cves"] = enriched_cves

    # Run nuclei against live targets if binary is available
    for seed in state.get("seeds", []):
        nuclei_r = await registry.execute("nuclei", seed, "domain")
        if nuclei_r.success:
            vuln_intel["nuclei_scan"] = nuclei_r.data
            break  # one nuclei scan covers the primary target

    # Agent synthesis: Vuln Correlator
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "vuln_correlator",
            task_data={
                "vuln_intel": {k: _summarize_dict(v) for k, v in list(vuln_intel.items())[:10]},
                "infra_intel": {k: _summarize_dict(v) for k, v in list(infra_intel.items())[:5]},
                "enriched_cve_count": len(enriched_cves),
                "exploitable_cves": [
                    cid for cid, e in enriched_cves.items()
                    if e.get("has_exploit") or e.get("has_metasploit") or e.get("in_kev")
                ][:10],
            },
            task_prompt="Correlate fingerprinted technologies with known vulnerabilities. "
                        "Identify: 1. KEV-listed vulnerabilities (actively exploited) "
                        "2. High-CVSS CVEs with public Metasploit modules or PoC exploits "
                        "3. CVEs with nuclei templates — runnable right now "
                        "4. End-of-life software and patch gaps "
                        "5. Which CVEs to prioritize first given the target's exposure",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase7",
            "agent": "vuln_correlator",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase7", error=str(e))

    state["vuln_intel"] = vuln_intel
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase7"]
    return state


# ── Phase 2.5: Personal Identity Pivot ───────────────────────────────────────


async def phase2_5_personal_identity_pivot(state: CampaignGraphState) -> CampaignGraphState:
    """Bridge corporate identities to personal identity + breach credential exposure.

    Runs after Phase 2 (which builds ``email_intel``) and before Phase 3.

    Steps:
      1. Build an IdentityGraph from Phase 2's ``email_intel``.
      2. For each identity with a name, execute the personal_pivot tool
         (D3) via the registry (OPSEC stack applies: rate limiting, proxy,
         audit log).
      3. Extend the graph with discovered personal identifiers +
         credential exposures.
      4. Run the D4 credential correlation engine against the graph +
         cloud_intel to produce the operator punch list.
      5. Commit the graph + punch list to state for Phase 8/9 consumers.

    Wall-clock budget: Semaphore(3) caps concurrent pivot calls.
    At most 20 identities are pivoted to bound campaign runtime.
    """
    log.info("Phase 2.5: Personal identity pivot")
    state["current_phase"] = "phase2_5"

    from nexusrecon.core.credential_correlation import correlate_credentials
    from nexusrecon.core.identity_graph import (
        IdentifierType,
        build_from_email_intel,
    )
    from nexusrecon.tools.identity.personal_pivot_tool import apply_extensions_to_graph

    registry = get_registry()
    email_intel: dict[str, Any] = state.get("email_intel") or {}
    cloud_intel: dict[str, Any] = state.get("cloud_intel") or {}

    # Build the graph from Phase 2 output.
    graph = build_from_email_intel(email_intel)

    if not graph.all():
        log.info("Phase 2.5: no identities in graph, skipping pivot")
        state["identity_graph"] = graph.to_dict()
        state["credential_punch_list"] = []
        state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase2_5"]
        return state

    pivot_sem = asyncio.Semaphore(3)
    pivot_results: dict[str, Any] = {}  # identity_id → pivot ToolResult.data

    async def _pivot_one(identity: Any) -> None:
        corp_id = identity.best_identifier_for(IdentifierType.CORP_EMAIL)
        if not corp_id:
            return

        email = corp_id.value
        name_id = identity.best_identifier_for(IdentifierType.REAL_NAME)
        name = name_id.value if name_id else None

        if not name:
            # derive_personal_handles requires first + last name.
            log.debug(
                "Phase 2.5: no name for identity, skipping pivot",
                identity_id=identity.identity_id,
            )
            return

        async with pivot_sem:
            result = await registry.execute(
                "personal_pivot",
                email,
                "identity",
                name=name,
                age_range=identity.metadata.get("age_range"),
                interests=identity.metadata.get("interests"),
                location=identity.metadata.get("location"),
            )

        if result.success and result.data:
            pivot_results[identity.identity_id] = result.data
            apply_extensions_to_graph(graph, identity.identity_id, result.data)

    # Cap at 20 identities to bound wall-clock.
    await asyncio.gather(
        *(_pivot_one(i) for i in graph.all()[:20]),
        return_exceptions=True,
    )

    # D4 correlation — pure function, no network.
    punch_list = correlate_credentials(graph, cloud_intel)

    # Agent synthesis — summarise for report narrative.
    pivot_summary = {
        "identities_pivoted": len(pivot_results),
        "identities_total": len(graph.all()),
        "credential_candidates": len(punch_list),
        "identities_with_credentials": len(graph.identities_with_credentials()),
        "identities_with_personal_email": len(graph.identities_with_personal_email()),
    }
    executor = _get_executor()
    try:
        agent_result = await executor.run_agent(
            "correlation",
            task_data={
                "pivot_summary": pivot_summary,
                "top_candidates": [c.to_dict() for c in punch_list[:5]],
                "endpoint_types": list({c.endpoint_type for c in punch_list}),
            },
            task_prompt=(
                "Analyze the personal identity pivot results. "
                "The framework correlated corporate identities with personal accounts and "
                "surfaced credential exposures from breach databases and infostealer logs. "
                "Key questions: "
                "1. Which identities have the strongest credential exposure paths? "
                "2. Which auth endpoints are most targetable given the MFA + lockout signals? "
                "3. Are there breach patterns (same source hitting multiple identities)? "
                "4. What does MFA coverage look like across discovered endpoints? "
                "Produce a brief summary for the credential exposure report. "
                "DO NOT recommend executing any credential tests automatically — "
                "the operator reviews and decides."
            ),
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase2_5",
            "agent": "correlation",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase2_5", error=str(e))

    # Commit to state.  Credentials are redacted in the serialised graph;
    # unredacted values stay in memory only within the current session.
    state["identity_graph"] = graph.to_dict(redact_credentials=True)
    state["credential_punch_list"] = [c.to_dict() for c in punch_list]
    state["personal_pivot_results"] = pivot_results
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase2_5"]
    return state


# ── Phase 7.5: Credential Harvest ────────────────────────────────────────────

async def phase7_5_harvest(state: CampaignGraphState) -> CampaignGraphState:
    """Extract and optionally validate credentials from all intel sources."""
    log.info("Phase 7.5: Credential harvest")
    state["current_phase"] = "phase7_5"

    from nexusrecon.core.credential_harvester import harvest_credentials
    creds = await harvest_credentials(state, validate=state.get("validate_credentials", False))
    state["harvested_credentials"] = [c.__dict__ for c in creds]
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase7_5"]
    return state


# ── Phase 7.7: Pretext Intelligence (E11) ────────────────────────────────────


# Per-target hard caps for Phase 7.7. Matches Phase 2.5's discipline of
# bounding wall-clock by capping fan-out. A 50-employee org × 5 social
# tools = 250 calls; capping at 20 identities keeps it to ~100.
_PHASE_7_7_MAX_IDENTITIES = 20


async def phase7_7_pretext_intelligence(
    state: CampaignGraphState,
) -> CampaignGraphState:
    """Phase 7.7 — Pretext intelligence (relationship graph + scoring +
    optional drafts).

    Locked-in slot between Phase 7.5 (credential harvest) and Phase 8
    (attack-surface scoring) so pretext quality feeds the attack-
    surface ranking.

    Steps:
      1. Reload the :class:`IdentityGraph` from state (Phase 2.5 wrote
         it as ``state["identity_graph"]``). Falls back to building
         from ``email_intel`` when 2.5 didn't run.
      2. Build a fresh :class:`RelationshipGraph` attached to the
         graph and orchestrate the E2-E8 tools:
         - Per identity (capped at 20): fire the social tools
           (github / mastodon / bluesky / linkedin) when matching
           handle identifiers exist; fire conference_speaker when a
           real-name identifier exists.
         - Per unique corp-email domain: fire business_partner +
           news_intel once.
         Each tool's edge-extraction adapter feeds the
         RelationshipGraph; news_intel's RecentActivity records go
         to the scoring engine.
      3. Score pretext candidates via :func:`score_pretext_candidates`,
         honoring the optional ``pretext_targets`` narrowing.
      4. Build per-target dossiers (one dict per target with sender
         summary + top pretexts + activity timeline). When
         ``generate_phishing_drafts`` is set, invoke the
         phishing_drafter agent to populate the per-target ``draft``
         field.
      5. Commit state slots: ``relationship_graph``, ``pretext_scores``,
         ``spear_phishing_intelligence``.

    Wall-clock budget: 20 identity caps + per-tool internal limits
    keep total HTTP calls in the low hundreds. The OPSEC rate limiter
    applies per registry.execute() so the throttle is whatever the
    operator's stealth profile dictates.
    """
    log.info("Phase 7.7: Pretext intelligence")
    state["current_phase"] = "phase7_7"

    from nexusrecon.core.identity_graph import (
        IdentifierType,
        IdentityGraph,
        build_from_email_intel,
    )
    from nexusrecon.core.pretext_scoring import (
        group_candidates_by_target,
        score_pretext_candidates,
        summarise_candidates,
    )
    from nexusrecon.core.recent_activity import RecentActivity
    from nexusrecon.core.relationship_graph import RelationshipGraph
    from nexusrecon.tools.identity.bluesky_social_tool import (
        extract_edges_from_bluesky,
    )
    from nexusrecon.tools.identity.github_social_tool import (
        extract_edges_from_github_social,
    )
    from nexusrecon.tools.identity.linkedin_social_tool import (
        extract_edges_from_linkedin,
    )
    from nexusrecon.tools.identity.mastodon_social_tool import (
        extract_edges_from_mastodon,
    )
    from nexusrecon.tools.intel.business_partner_tool import (
        extract_org_edges_from_business_partner,
    )
    from nexusrecon.tools.pretext.conference_speaker_tool import (
        extract_edges_from_conference_speaker,
    )

    registry = get_registry()

    # ── 1. Reload IdentityGraph ─────────────────────────────────────
    identity_graph_data = state.get("identity_graph") or {}
    if identity_graph_data.get("identities"):
        identity_graph = IdentityGraph.from_dict(identity_graph_data)
    else:
        # Fallback: Phase 2.5 didn't run. Build from email_intel.
        email_intel = state.get("email_intel") or {}
        identity_graph = build_from_email_intel(email_intel)

    identities = identity_graph.all()
    if not identities:
        log.info("Phase 7.7: no identities, skipping")
        state["relationship_graph"] = RelationshipGraph().to_dict()
        state["pretext_scores"] = []
        state["spear_phishing_intelligence"] = {
            "summary": summarise_candidates([]),
            "targets": {},
        }
        state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase7_7"]
        return state

    # Cap on identity-level fan-out.
    crawl_identities = identities[:_PHASE_7_7_MAX_IDENTITIES]

    relationship_graph = RelationshipGraph(identity_graph=identity_graph)
    recent_activities: list[RecentActivity] = []
    fan_sem = asyncio.Semaphore(3)  # bound concurrent tool calls

    # ── 2a. Per-identity social-tool fan-out ────────────────────────

    async def _fire_social_tools_for(identity: Any) -> None:
        # GitHub
        gh_handles = [
            i for i in identity.identifiers
            if i.identifier_type == IdentifierType.HANDLE
            and (i.service or "").lower() == "github"
        ]
        if gh_handles:
            async with fan_sem:
                result = await registry.execute(
                    "github_social", gh_handles[0].value, "handle",
                )
            if result.success and result.data:
                for src_id, edge in extract_edges_from_github_social(
                    result.data, identity.identity_id, identity_graph,
                ):
                    relationship_graph.add_edge(src_id, edge)

        # Mastodon
        mast_handles = [
            i for i in identity.identifiers
            if i.identifier_type == IdentifierType.HANDLE
            and (i.service or "").lower() == "mastodon"
        ]
        if mast_handles:
            async with fan_sem:
                result = await registry.execute(
                    "mastodon_social", mast_handles[0].value, "handle",
                )
            if result.success and result.data:
                for src_id, edge in extract_edges_from_mastodon(
                    result.data, identity.identity_id, identity_graph,
                ):
                    relationship_graph.add_edge(src_id, edge)

        # Bluesky
        bsky_handles = [
            i for i in identity.identifiers
            if i.identifier_type == IdentifierType.HANDLE
            and (i.service or "").lower() == "bluesky"
        ]
        if bsky_handles:
            async with fan_sem:
                result = await registry.execute(
                    "bluesky_social", bsky_handles[0].value, "handle",
                )
            if result.success and result.data:
                for src_id, edge in extract_edges_from_bluesky(
                    result.data, identity.identity_id, identity_graph,
                ):
                    relationship_graph.add_edge(src_id, edge)

        # LinkedIn — only fires if auth is configured (is_available()
        # returns False when both auth pairs are missing, so the
        # registry returns the prereqs-not-met error and we skip).
        li_handles = [
            i for i in identity.identifiers
            if i.identifier_type == IdentifierType.HANDLE
            and (i.service or "").lower() == "linkedin"
        ]
        if li_handles:
            async with fan_sem:
                result = await registry.execute(
                    "linkedin_social", li_handles[0].value, "handle",
                )
            if result.success and result.data:
                for src_id, edge in extract_edges_from_linkedin(
                    result.data, identity.identity_id, identity_graph,
                ):
                    relationship_graph.add_edge(src_id, edge)

        # Conference speaker — by name
        name_ident = identity.best_identifier_for(IdentifierType.REAL_NAME)
        if name_ident and name_ident.value:
            async with fan_sem:
                result = await registry.execute(
                    "conference_speaker", name_ident.value, "name",
                )
            if result.success and result.data:
                for src_id, edge in extract_edges_from_conference_speaker(
                    result.data, identity.identity_id, identity_graph,
                ):
                    relationship_graph.add_edge(src_id, edge)

    await asyncio.gather(
        *(_fire_social_tools_for(i) for i in crawl_identities),
        return_exceptions=True,
    )

    # ── 2b. Per-corp-domain org tools (business_partner + news) ─────

    corp_domains: set[str] = set()
    for identity in crawl_identities:
        corp_ident = identity.best_identifier_for(IdentifierType.CORP_EMAIL)
        if corp_ident and "@" in corp_ident.value:
            corp_domains.add(corp_ident.value.split("@", 1)[1].lower())

    async def _fire_org_tools_for(domain: str) -> None:
        # business_partner
        async with fan_sem:
            bp_result = await registry.execute(
                "business_partner", domain, "domain",
            )
        if bp_result.success and bp_result.data:
            # Org edges are between organisations. Use the domain-stub
            # identity as the "target" of edges. We materialise a
            # bare org identity here so the graph stays connected.
            from nexusrecon.core.identity_graph import (
                Identifier,
                Identity,
                derive_identity_id,
            )
            org_ident = Identifier(
                value=domain,
                identifier_type=IdentifierType.DOMAIN,
                source="business_partner",
                confidence=0.9,
            )
            org_id = derive_identity_id([org_ident])
            if org_id not in identity_graph:
                identity_graph.add_identity(Identity(
                    identity_id=org_id,
                    primary_label=domain,
                    identifiers=[org_ident],
                    metadata={"entity_type": "org"},
                ))
            for src_id, edge in extract_org_edges_from_business_partner(
                bp_result.data, org_id, identity_graph,
            ):
                relationship_graph.add_edge(src_id, edge)

        # news_intel — collect RecentActivity records
        async with fan_sem:
            news_result = await registry.execute(
                "news_intel", domain, "domain",
            )
        if news_result.success and news_result.data:
            for rec_dict in (news_result.data.get("recent_activity_records") or []):
                try:
                    recent_activities.append(RecentActivity.from_dict(rec_dict))
                except (KeyError, TypeError) as exc:
                    log.debug(
                        "Phase 7.7: malformed recent_activity record skipped",
                        error=str(exc),
                    )

    await asyncio.gather(
        *(_fire_org_tools_for(d) for d in corp_domains),
        return_exceptions=True,
    )

    # ── 3. Score pretext candidates ─────────────────────────────────

    pretext_targets = state.get("pretext_targets") or None
    candidates = score_pretext_candidates(
        identity_graph=identity_graph,
        relationship_graph=relationship_graph,
        recent_activities=recent_activities,
        target_ids=pretext_targets,
    )

    # ── 4. Per-target dossiers + optional drafter agent ─────────────

    grouped = group_candidates_by_target(candidates)
    target_dossiers: dict[str, Any] = {}
    for target_id, target_candidates in grouped.items():
        target_identity = identity_graph.get(target_id)
        target_dossiers[target_id] = {
            "target_identity_id": target_id,
            "target_label": (
                target_identity.primary_label if target_identity else target_id
            ),
            "top_candidates": [c.to_dict() for c in target_candidates],
            "draft": None,
        }

    # Drafter is gated on --generate-phishing.
    if state.get("generate_phishing_drafts") and target_dossiers:
        executor = _get_executor()
        for target_id, dossier in target_dossiers.items():
            try:
                agent_result = await executor.run_agent(
                    "phishing_drafter",
                    task_data={
                        "target_identity_id": target_id,
                        "target_label": dossier["target_label"],
                        "top_pretext_candidates": dossier["top_candidates"][:3],
                    },
                    task_prompt=(
                        "Produce ONE spear-phishing draft for the target "
                        "identity, following the JSON schema in your "
                        "backstory. Use only the supplied OSINT signals; "
                        "do not invent prior interactions. If the "
                        "top pretext candidate has combined_score < 0.15, "
                        "return the no-draft fallback shape."
                    ),
                    state=state,
                )
                dossier["draft"] = agent_result.get("output", "")
            except Exception as exc:
                log.warning(
                    "Phase 7.7 drafter failed",
                    target_id=target_id, error=str(exc),
                )

    # ── 5. Commit state ─────────────────────────────────────────────

    state["identity_graph"] = identity_graph.to_dict(redact_credentials=True)
    state["relationship_graph"] = relationship_graph.to_dict()
    state["pretext_scores"] = [c.to_dict() for c in candidates]
    state["spear_phishing_intelligence"] = {
        "summary": summarise_candidates(candidates),
        "targets": target_dossiers,
    }
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase7_7"]
    return state


# ── Phase 8: Attack Surface Prioritization ────────────────────────────────────

async def phase8_attack_surface(state: CampaignGraphState) -> CampaignGraphState:
    """Scoring, ranking, PRE-ATT&CK mapping, and top-10 threads generation."""
    log.info("Phase 8: Attack surface prioritization")
    state["current_phase"] = "phase8"

    # Run the scoring engine across all intel sources. Deduped + partitioned:
    # ranked_findings is the real attack surface; coverage is the
    # absence-of-evidence / below-floor noise that used to pad the report
    # (Wave F-B1/B2/B3), surfaced separately as "what we checked".
    ranked_findings, coverage_findings = score_findings_with_coverage(state)

    # F-B7: annotate next-steps that recommend tools which either can't run
    # this campaign (uninstalled / no key / policy-disabled, from preflight)
    # or already ran without result (empty / degraded / errored, from the
    # audit log), so the report stops generating busywork ("run theHarvester",
    # "run amass") for tools that won't help.
    flagged = dict(unavailable_tools_from_preflight(state.get("preflight")))
    try:
        from nexusrecon.core.run_health import read_entries
        from nexusrecon.tools.registry import get_registry
        audit = get_registry().audit_log
        if audit is not None and getattr(audit, "log_path", None):
            unproductive = unproductive_tools_from_audit(read_entries(audit.log_path))
            # Preflight reasons (can't run at all) take precedence over
            # "ran but empty" when a tool somehow appears in both.
            for tool, reason in unproductive.items():
                flagged.setdefault(tool, reason)
    except Exception:
        pass
    if flagged:
        for rf in ranked_findings:
            rf.next_steps = annotate_next_steps(rf.next_steps, flagged)

    # Store as ranked_threads (top 10 actionable items)
    top_threads = [rf.to_dict() for rf in ranked_findings[:10]]
    state["ranked_threads"] = top_threads
    state["coverage_items"] = [rf.to_dict() for rf in coverage_findings]

    # Agent synthesis: Risk Analyst — gets the full ranked picture
    executor = _get_executor()
    top_thread_summaries = [
        f"[{rf.get('severity', '?').upper()}] {rf.get('title', '')} (score: {rf.get('score', 0):.2f})"
        for rf in top_threads
    ]
    # Step 0.0 (METASPLOIT_PLAN): rebuild the EntityGraph from state
    # so the risk analyst sees graph-derived context (every entity,
    # hypotheses, blocking open-questions) alongside the ranked
    # threads. Lets the agent answer "which entity in the graph
    # carries the most-cited lead" without re-deriving from
    # flat buckets.
    from nexusrecon.core.entity_graph import EntityGraph
    from nexusrecon.core.graph_context import GraphContext

    eg = EntityGraph.from_state(state)
    graph_context = GraphContext(eg)

    try:
        agent_result = await executor.run_agent(
            "risk_analyst",
            task_data={
                "top_threads": top_thread_summaries,
                "total_scored": len(ranked_findings),
                "confirmed_leads": state.get("confirmed_leads", []),
                "enriched_cve_count": len(state.get("vuln_intel", {}).get("enriched_cves", {})),
                # Phase 0.1: phase-aware subset for the risk
                # analyst focuses on attack-surface entity
                # types (subdomains, cloud assets, CVEs, URLs)
                # rather than the full graph.
                **graph_context.for_phase("phase8_attack_surface"),
            },
            task_prompt="You have been given the top 10 ranked attack threads produced by the scoring engine. "
                        "For each thread, provide: 1. The most likely exploitation path "
                        "2. The MITRE PRE-ATT&CK or ATT&CK technique it maps to "
                        "3. Your confidence in successful exploitation "
                        "4. The single most important next action the operator should take. "
                        "Conclude with a one-paragraph executive summary of the overall attack surface posture. "
                        "Cite specific entities from the graph_summary (by value) when the chain "
                        "uses them — operators triage faster when the chain names what it touches.",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase8",
            "agent": "risk_analyst",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Agent synthesis failed", phase="phase8", error=str(e))

    # Re-sort all findings (including those added by the risk_analyst agent above)
    state["findings"] = sorted(
        state.get("findings", []),
        key=lambda f: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                f.get("severity", "info"), 0
            ),
            f.get("confidence", 0.0),
        ),
        reverse=True,
    )
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase8"]
    return state


# ── Phase 9: Report Generation ────────────────────────────────────────────────

async def phase9_reporting(state: CampaignGraphState) -> CampaignGraphState:
    """Final deliverable generation with Evidence Auditor + Executive Reporter."""
    log.info("Phase 9: Reporting")
    state["current_phase"] = "phase9"

    # Evidence Auditor pass
    executor = _get_executor()
    try:
        findings = state.get("findings", [])
        passed, rejected = executor.audit_findings(findings)
        state["findings"] = passed
        state["rejected_findings"] = rejected

        audit_summary = (
            f"Evidence Audit: {len(passed)} findings passed citation validation, "
            f"{len(rejected)} findings rejected (incomplete citations)."
        )
        log.info("Evidence audit complete", passed=len(passed), rejected=len(rejected))

        state.setdefault("agent_messages", []).append({
            "phase": "phase9",
            "agent": "evidence_auditor",
            "analysis": audit_summary,
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Evidence audit failed", error=str(e))

    # Executive Reporter synthesis
    try:
        agent_result = await executor.run_agent(
            "executive_reporter",
            task_data={
                "findings": state.get("findings", [])[:20],
                "agent_messages": state.get("agent_messages", [])[-5:],
                "confirmed_leads": state.get("confirmed_leads", []),
                "entity_graph": state.get("entity_graph", {}),
            },
            task_prompt="Synthesize all campaign findings into a cohesive executive summary. "
                        "Highlight the top 5 findings for immediate action, summarize the overall "
                        "attack surface posture, and provide strategic recommendations for the client.",
            state=state,
        )
        state.setdefault("agent_messages", []).append({
            "phase": "phase9",
            "agent": "executive_reporter",
            "analysis": agent_result.get("output", ""),
            "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        log.warning("Reporter synthesis failed", error=str(e))

    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase9"]
    return state


# ── Reflection Node ───────────────────────────────────────────────────────────

# Phases that trigger the dispatcher in lite mode
_LITE_DISPATCH_PHASES = {"phase1", "phase4", "phase7"}


async def reflection_node(state: CampaignGraphState) -> CampaignGraphState:
    """
    Between phases: enforce step budget, log open hypotheses,
    and run the dynamic dispatcher when warranted.

    Dispatch modes:
    - "off"  : skip dispatcher entirely
    - "lite" : only dispatch after phases in _LITE_DISPATCH_PHASES
    - "full" : dispatch after every phase
    """
    current = state.get("current_phase", "")
    open_hyps = state.get("hypotheses", [])

    # Step budget guard
    step_count = state.get("step_count", 0)
    if step_count > 100:
        state.setdefault("errors", []).append(f"Step budget exceeded: {step_count}")

    if open_hyps:
        log.info("Open hypotheses during reflection", count=len(open_hyps))
        state["reflection_notes"] = state.get("reflection_notes", []) + [
            f"After {current}: {len(open_hyps)} open hypotheses remain"
        ]

    # Dynamic dispatch — Phase 1 PR A: eligibility check + caps
    # come from the active DispatchPolicy (resolved via
    # state["dispatch_policy_name"] or the legacy
    # state["dispatch_mode"]). Module-level constants like
    # _LITE_DISPATCH_PHASES survive as documentation; the
    # policy is the source of truth.
    try:
        from nexusrecon.strategy.policy import get_policy
        policy = get_policy(
            str(state.get("dispatch_policy_name")
                or state.get("dispatch_mode") or "lite"),
        )
    except Exception:
        # Defensive: never let policy resolution kill the
        # workflow. Fall back to lite-equivalent behavior.
        policy = None

    if policy is None:
        # Legacy path preserved for the worst case.
        dispatch_mode = state.get("dispatch_mode", "lite")
        if dispatch_mode == "off":
            return state
        if dispatch_mode == "lite" and current not in _LITE_DISPATCH_PHASES:
            return state
        dispatch_log = state.get("dynamic_dispatch_log", [])
        if len(dispatch_log) >= 30:
            log.info("Total dispatch cap reached", total=len(dispatch_log))
            return state
    else:
        if not policy.should_dispatch_for_phase(current):
            return state
        dispatch_log = state.get("dynamic_dispatch_log", [])
        if len(dispatch_log) >= policy.max_total:
            log.info("Total dispatch cap reached",
                     total=len(dispatch_log), policy=policy.name)
            return state

    try:
        from nexusrecon.graph.dynamic_dispatcher import run_dynamic_dispatch
        state = await run_dynamic_dispatch(state)
    except Exception as exc:
        log.warning("Dynamic dispatcher failed", error=str(exc))
        state.setdefault("errors", []).append(f"Dynamic dispatcher error: {exc}")

    return state


# ── Phase Router ──────────────────────────────────────────────────────────────

def route_to_next_phase(state: CampaignGraphState) -> str:
    """Determine the next phase based on current state."""
    completed = set(state.get("completed_phases", []))
    phase_order = [
        "phase1", "phase2", "phase2_5", "phase3", "phase4",
        "phase5", "phase6", "phase7", "phase7_5", "phase8", "phase9",
    ]

    for phase in phase_order:
        if phase not in completed:
            return phase

    return "__end__"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _summarize_dict(data: Any, max_len: int = 500) -> str:
    """Summarize a dict for agent context."""
    if isinstance(data, dict):
        return json.dumps({k: str(v)[:200] for k, v in data.items()}, default=str)[:max_len]
    return str(data)[:max_len]


def _extract_title(html: str) -> str:
    """Extract <title> from HTML."""
    import re
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""
