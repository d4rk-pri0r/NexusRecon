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
from typing import Any, Dict, List

import structlog

from nexusrecon.core.config import get_config
from nexusrecon.core.scoring import score_findings
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


def _get_tools_by_tier(max_tier: str, exclude_categories: set = None) -> List[Any]:
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
    subdomain_intel: Dict[str, Any] = {}
    domain_intel: Dict[str, Any] = {}

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
    dark_intel: Dict[str, Any] = {}
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
    email_intel: Dict[str, Any] = {"emails": {}, "formats": {}}
    cloud_intel: Dict[str, Any] = {}

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
            harvested_names: List[str] = []
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
    account_summary: Dict[str, Any] = {
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
    code_intel: Dict[str, Any] = {}
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
            },
            task_prompt="Correlate all intelligence findings. When using cloud intel, "
                        "check attribution_confidence — values below 0.5 indicate stem-match "
                        "data that should NOT be used to build confirmed attack chains. "
                        "Generate new hypotheses, identify confirmed attack leads, and highlight "
                        "gaps in coverage. Be specific about which findings connect to form "
                        "attack chains, using only high-confidence data (attribution_confidence >= 0.5) "
                        "for confirmed leads.",
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

    state["hypotheses"] = hypotheses
    state["confirmed_leads"] = confirmed_leads
    state["open_questions"] = open_questions
    state["entity_graph"] = {
        "subdomains": list(subdomain_intel.keys())[:500],
        "emails": list(emails.keys())[:500],
    }
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
    vuln_intel: Dict[str, Any] = {}

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
    all_cve_ids: Dict[str, str] = {}  # cve_id → tech_name
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
    enriched_cves: Dict[str, Any] = {}

    async def _enrich_cve(cve_id: str, tech: str) -> tuple[str, Dict[str, Any]]:
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

        enriched: Dict[str, Any] = {"tech": tech, "sources": ["nvd"]}

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


# ── Phase 8: Attack Surface Prioritization ────────────────────────────────────

async def phase8_attack_surface(state: CampaignGraphState) -> CampaignGraphState:
    """Scoring, ranking, PRE-ATT&CK mapping, and top-10 threads generation."""
    log.info("Phase 8: Attack surface prioritization")
    state["current_phase"] = "phase8"

    # Run the scoring engine across all intel sources
    ranked_findings = score_findings(state)

    # Store as ranked_threads (top 10 actionable items)
    top_threads = [rf.to_dict() for rf in ranked_findings[:10]]
    state["ranked_threads"] = top_threads

    # Agent synthesis: Risk Analyst — gets the full ranked picture
    executor = _get_executor()
    top_thread_summaries = [
        f"[{rf.get('severity', '?').upper()}] {rf.get('title', '')} (score: {rf.get('score', 0):.2f})"
        for rf in top_threads
    ]
    try:
        agent_result = await executor.run_agent(
            "risk_analyst",
            task_data={
                "top_threads": top_thread_summaries,
                "total_scored": len(ranked_findings),
                "confirmed_leads": state.get("confirmed_leads", []),
                "enriched_cve_count": len(state.get("vuln_intel", {}).get("enriched_cves", {})),
            },
            task_prompt="You have been given the top 10 ranked attack threads produced by the scoring engine. "
                        "For each thread, provide: 1. The most likely exploitation path "
                        "2. The MITRE PRE-ATT&CK or ATT&CK technique it maps to "
                        "3. Your confidence in successful exploitation "
                        "4. The single most important next action the operator should take. "
                        "Conclude with a one-paragraph executive summary of the overall attack surface posture.",
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

    # Dynamic dispatch
    dispatch_mode = state.get("dispatch_mode", "lite")
    if dispatch_mode == "off":
        return state

    if dispatch_mode == "lite" and current not in _LITE_DISPATCH_PHASES:
        return state

    # Total cap check — fast path before spinning up LLM
    dispatch_log = state.get("dynamic_dispatch_log", [])
    if len(dispatch_log) >= 30:
        log.info("Total dispatch cap reached", total=len(dispatch_log))
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
        "phase1", "phase2", "phase3", "phase4",
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
