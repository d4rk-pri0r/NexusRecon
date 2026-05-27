# NexusRecon: Architecture & Goals

A wiki-style explainer of what NexusRecon is, what its parts do, and why
the design makes it materially different from running a stack of OSINT
tools in sequence.

**Audience:** security or IT professionals with moderate familiarity with
OSINT, LLMs, and red-team workflows. No prior knowledge of LangGraph,
CrewAI, or any specific tool integration required.

**If you're new here**, read sections 1-4 to understand the platform's
purpose and shape. Sections 5-9 are deep-dives on specific components.
Section 10 is honest about what's automated vs. What still needs you.

---

## 1. Why this exists

A modern OSINT engagement against any non-trivial target requires running
30-60 tools, subdomain enumerators, certificate-transparency searchers,
cloud-recon scripts, secret-scanners, breach-DB queries, vulnerability
correlators, screenshot capturers, network mappers, then **synthesizing
their output into something an operator can act on**.

The synthesis step is where most operator time goes. The tools produce
JSON, CSV, and free-text in dozens of different shapes. Some are
authoritative, some are name-collision noise. Some findings are duplicates
of others. Some confirm each other; some contradict. Working from raw
tool output to a prioritized list of attack paths takes a senior operator
several hours per engagement.

NexusRecon's premise: **the synthesis step can be done by an LLM running a
fixed set of analysis personas, given the right structured inputs and the
right output gates.** The result is a platform where an operator enters a
seed domain plus an authorization scope, walks away, and returns to a
campaign-ready deliverable with a ranked attack surface, not a folder of
raw tool dumps.

The platform also does the discovery part: it orchestrates the 30-60
tools, manages their rate limits and credentials, and decides which to
run when based on what's been found so far. The LLM-driven loop in the
middle is the difference between "an automation framework" and "an
agentic OSINT platform."

---

## 2. The core idea

Traditional OSINT automation is **pipeline-shaped**: a fixed sequence of
tools runs in a predetermined order, each producing output the next stage
consumes. If your pipeline is well-tuned the output covers what you
asked for; if it isn't, you get gaps. Either way the tool order doesn't
adapt to what's being discovered.

NexusRecon is **state-shaped**. There's a shared mutable state object
(the "campaign state") that every tool writes into and every agent reads
from. Phases are checkpoints rather than steps, at each checkpoint, a
dispatcher LLM looks at what's in state, decides if anything is missing,
and runs additional tools to fill the gaps before the next phase.

Two concrete examples from real runs:

- **Discovery-driven follow-up.** After phase 1 against a real corporate
  target, the dispatcher noticed "subdomain_intel: 0 entries" in state.
  Its rationale: *"Zero subdomains found for seed domain; subdomain
  enumeration is a critical phase1 gap."* It then dispatched
  `subfinder`, `crtsh`, `theharvester`, `shodan`, and `virustotal` to
  fill the gap. Phase 2 ran with 78 subdomains instead of 0.

- **Attribution caution.** When the cloud-recon tool found that
  `<stem>.onmicrosoft.com` had a registered Azure tenant for an
  unrelated party, the platform tagged the finding `attribution_confidence: 0.2`
  and a downstream "agent backstop" downgraded any finding citing that
  tenant to `info` severity with a `[POSSIBLE]` prefix. The operator sees
  *"[POSSIBLE] Azure Cloud Presence - Stem-Match Only"* instead of a
  confident-but-wrong claim about the target's Azure infrastructure.

Both of those behaviors are emergent properties of the agentic loop, not
hardcoded. They're not "if subdomains=0 then run subfinder"; they're "an
LLM looked at the state and made a judgment call." That generalizes to
targets and intel types the platform's authors never anticipated.

---

## 3. Architecture map

At ~30,000 feet:

```
┌──────────────────────────────────────────────────────────────────────┐
│                          OPERATOR                                    │
│              (provides: scope YAML + seed domain)                    │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │   CLI / Campaign Manager    │
                  │  (scope guard, audit log,    │
                  │   cost tracker, lifecycle)  │
                  └──────────────┬──────────────┘
                                 │
       ┌─────────────────────────┴─────────────────────────┐
       │                                                   │
       │              CAMPAIGN STATE (dict)                │
       │  ┌──────────────────────────────────────────────┐ │
       │  │ seeds, subdomain_intel, domain_intel,        │ │
       │  │ email_intel, cloud_intel, code_intel,        │ │
       │  │ infra_intel, vuln_intel, dark_intel,         │ │
       │  │ findings, ranked_threads, agent_messages,    │ │
       │  │ harvested_credentials, dispatch_log, costs,  │ │
       │  │ entity_graph, completed_phases               │ │
       │  └──────────────────────────────────────────────┘ │
       │                                                   │
       │   Reads/writes from:                               │
       │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
       │  │  TOOLS      │  │  AGENTS     │  │ DISPATCHER │ │
       │  │  (OSINT     │  │  (8 LLM     │  │ (LLM-      │ │
       │  │   registry) │  │   personas) │  │  driven)   │ │
       │  └─────────────┘  └─────────────┘  └────────────┘ │
       │                                                   │
       └─────────────────────────┬─────────────────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │       REPORT ENGINE         │
                  │   (17 deliverable types)    │
                  └──────────────┬──────────────┘
                                 │
       ┌─────────────────────────▼─────────────────────────┐
       │  Markdown · JSON · CSV · HTML · PDF · PPTX       │
       │  (executive summary, top threads, phishing       │
       │  drafts, attack surface matrix, jira tracker,    │
       │  entity graph, ...)                              │
       └───────────────────────────────────────────────────┘
```

Key invariants the architecture enforces:

- **Tools never modify each other's output**: only the state.
- **Agents never call tools directly**: only read state and produce
  analysis (which gets parsed into findings + prose).
- **Every tool invocation is audit-logged** with the scope hash and
  hash-chained for tamper evidence.
- **Every tool invocation is scope-gated**: out-of-scope targets are
  silently dropped at the registry layer.
- **Every LLM call's cost is tracked** against the scope's
  `max_llm_cost_usd` budget cap. Exceeded budget → campaign aborts.

---

## 4. The phase pipeline

A campaign runs 9 numbered phases (plus a credential-harvest interlude).
Phases aren't sequential dependencies, they're checkpoints where the
state accumulates layered intel. The dispatcher fires between certain
phases to fill gaps.

| Phase | Role | What it discovers |
|-------|------|-------------------|
| **1, Passive Footprinting** | T0 broad sweep | Subdomains, DNS records, WHOIS, cert transparency, ASN/BGP, dark-web mentions |
| **2, Identity & Cloud** | T0-T1 identity & cloud recon | M365/Azure tenant, AWS recon, GCP recon, harvested emails, email patterns |
| **3, Code & Secret Leakage** | T0 code surface | GitHub repos, leaked secrets via gitleaks/trufflehog/gitdorker, Postman workspaces, Docker Hub images |
| **4, Correlation & Hypothesis** | T0 synthesis | Cross-source validation, lead generation, confirmed_leads vs. Open_questions |
| **5, Light Active** | T2 fingerprinting | HTTP probing (httpx), screenshots (gowitness), tech fingerprinting, favicon hashing, CMS detect, WAF detect, TLS analysis |
| **6, Active (T3)** | T3 intrusive | Brute force, content fuzzing, exploit verification. **Skipped unless scope authorizes T3.** |
| **7, Vuln & Pretext Correlation** | T0 vuln intel | NVD lookups, KEV check, EPSS scoring, ExploitDB, nuclei templates, pretext mining (news, jobs, SEC, LinkedIn dorks) |
| **7.5, Credential Harvest** | T0 cred extraction | Parses exposed `.env`, `.git/config`, infostealer hits, GitHub Actions leaks into structured credential records; optionally validates them read-only |
| **8, Attack Surface Prioritization** | T0 scoring | Runs the scoring engine; produces `ranked_threads` (top 10 attack paths) |
| **9, Reporting** | T0 synthesis | Generates 17 deliverables across MD/JSON/CSV/HTML/PDF/PPTX formats |

Between phases, the **reflection node** runs. In default `lite` dispatch
mode it invokes the dispatcher after phases 1, 4, and 7, the three
points where new intel changes what's worth pursuing next. In `full`
mode it dispatches after every phase. In `off` mode it never dispatches.

---

## 5. The agents

Each agent is an LLM-driven persona with a fixed system prompt that
defines its role, goal, and backstory. Agents don't call tools, they
read the accumulated campaign state and emit (a) free-form analysis
prose and (b) structured findings via a `FINDINGS_JSON:[...]` block.

| Agent | Phase | What it does | Why it matters |
|-------|-------|--------------|----------------|
| **passive_recon** | 1, 3 | Analyzes subdomain/DNS/WHOIS/cert data. Identifies high-value subdomains, DNS anomalies, registration patterns, ownership signals. | Translates raw tool dumps into operator-facing observations, *"these three subdomains pattern-match dev/staging environments and weren't found by certificate transparency, suggesting internal-only intent that leaked."* |
| **cloud_identity** | 2 | Analyzes cloud and identity reconnaissance. Identifies federation type, M365 attack vectors, email format patterns, AWS/GCP exposure. | Cloud attack chains depend on federation type (managed vs. ADFS), tenant verification, and email format. This agent translates `openid_config` + `user_realm` raw fields into "password spray is viable here, with this caveat." |
| **correlation** | 4 | Cross-references findings across all prior phases. Promotes hypotheses to confirmed_leads or moves them to open_questions. | Eliminates the human work of "looking at three findings that point to the same conclusion", corroborates intel from independent sources. |
| **active_recon** | 5 | Analyzes T2 active probing results, HTTP responses, tech fingerprints, screenshots, TLS posture, CMS/WAF identification. | Operator-relevant interpretation of probe results: *"this admin panel responds 200; this CMS version is end-of-life; this WAF appears to be misconfigured."* |
| **vuln_correlator** | 7 | Maps fingerprinted technologies to CVEs via NVD, KEV, EPSS, ExploitDB, nuclei-templates. Prioritises by exploit availability. | Translates a generic tech inventory into a CVE list filtered by *what's actually exploitable* (not just "this is a high CVSS"). |
| **pretext_humint** | 7 | Aggregates pretext intel (news, jobs, SEC filings, LinkedIn dorks, Crunchbase, Wikipedia) for social engineering preparation. | Crafts the "why would this employee fall for this lure" narrative, recent acquisitions, layoffs, executive changes, software migrations. |
| **risk_analyst** | 8 | Reviews scored findings, ranks them by exploitability × impact × asset exposure, maps to MITRE PRE-ATT&CK / ATT&CK techniques. | This is the "what should the operator do first" step. Produces the top 10 attack paths with rationale. |
| **executive_reporter** | 9 | Synthesises everything into the executive summary's top findings + analyst assessment prose. | The deliverable a client sees; the agent that has to write *for* a non-OSINT audience. |

There are also three **utility agents** that don't fit a single phase:

| Agent | Where it runs | What it does |
|-------|---------------|--------------|
| **dynamic_dispatcher** | Between phases (lite: after 1/4/7; full: after every phase) | Decides which 0-5 follow-up tools to run before the next phase. Capped at 30 total dispatches per campaign. |
| **phishing_drafter** | During phase 9 reporting (if `--generate-phishing` is set) | Generates per-target spearphishing draft emails with role-specific lures, sender-domain strategy based on DMARC posture, OSINT citations, and an authorization banner. One LLM call per target. |
| **evidence_auditor** | During phase 9 | Validates every finding has required citation fields (source, timestamp, evidence_hash, confidence). Filters out malformed findings before they reach reports. |

### How an agent run actually works

For a single agent invocation (the heart of every phase):

1. **`AgentExecutor.run_agent(role, task_data, task_prompt, state)`** is called.
2. The executor builds a prompt: agent's role/goal/backstory + a
   universal `FINDINGS_JSON:` schema requirement + an `ATTRIBUTION RULE`
   block + the task-specific prompt + serialized state slices.
3. The LLM (Anthropic Claude by default; OpenAI or local Ollama
   supported) is called.
4. The response is parsed: `FINDINGS_JSON:[...]` block is extracted and
   each entry validated; the remainder is preserved as analysis prose.
5. Each parsed finding is annotated with a synthetic evidence hash
   (sha256 of phase + title + description excerpt) so it passes the
   evidence auditor.
6. An **attribution backstop** runs: any finding citing data from a
   low-confidence cloud source (e.g., a stem-match Azure tenant) gets
   its severity capped at `info` and `[POSSIBLE]` prefixed to the title.
7. Findings are appended to `state["findings"]`; analysis prose is
   appended to `state["agent_messages"]`; LLM cost is added to
   `state["llm_cost_usd"]` and checked against the budget cap.

Specific agents (`phishing_drafter`, `dynamic_dispatcher`) bypass the
FINDINGS_JSON requirement because they return clean structured output
for downstream parsing rather than analysis-with-findings.

---

## 6. The tools

The platform integrates an **extensible OSINT tool registry** organised
into category buckets, subdomain enumeration, DNS / certificate
transparency, breach data, code-leakage scanners, cloud posture
(AWS / Azure / GCP), threat intel (Shodan / Censys / VT / GreyNoise /
urlscan), vuln intel (NVD / KEV / EPSS / ExploitDB / GH Advisory),
mobile, and HUMINT / pretext. Tools are added and retired each
release; run `nexusrecon tools` for the live catalogue. Every tool is
a subclass of `OSINTTool` with a uniform interface:

```python
class SomeTool(OSINTTool):
    name = "tool_name"
    tier = Tier.T0                    # T0 passive, T1 fingerprinting, T2 active scan, T3 intrusive
    category = Category.SUBDOMAIN
    requires_keys = ["api_key_name"]  # env vars / .env keys needed
    binary_required = "external_bin"   # if applicable
    target_types = ["domain", "ip"]
    description = "..."

    async def run(self, target, **kwargs) -> ToolResult: ...
```

The `ToolResult` is a standardized envelope every tool returns:

```python
ToolResult(
    success=bool,
    source=str,              # tool name
    data=dict,               # tool-specific structured output
    error=Optional[str],
    runtime_ms=int,
    cached=bool,
    result_count=int,        # meaningful count of findings
    tier=str,
    metadata=dict,           # e.g., attribution_confidence, warnings
)
```

The registry layer wraps every `run()` call with:

- **Scope guard:** target is checked against the scope's `in_scope` /
  `out_of_scope` lists before the tool runs. Out-of-scope drops the call.
- **Cache:** identical (tool, target) calls within the TTL return cached
  results without re-running.
- **Audit log:** start/end/result/error events recorded with the scope
  hash, hash-chained for tamper evidence.
- **Cost tracking:** API costs (where the tool reports them) added to
  the campaign's running cost total.

### Tool categories (and what they're for)

| Category | Examples | Used by |
|----------|----------|---------|
| `subdomain` | crtsh, subfinder, amass, otx_subdomains, chaos, github_subdomains | Phase 1, dispatcher follow-up |
| `dns` | dns, passive_dns, dnsx, hackertarget | Phase 1 |
| `domain` | whois, rdap, dnstwist, cdn_detect | Phase 1 |
| `certificate` | crtsh, certspotter, certstream_recent | Phase 1 |
| `cloud_aws` | aws_recon, bucket_enum | Phase 2 |
| `cloud_azure` | azure_m365_recon, azure_tenant_enum | Phase 2 |
| `cloud_gcp` | gcp_recon | Phase 2 |
| `code` | github_recon, github_actions_leaks, postman, dockerhub | Phase 3 |
| `secret` | gitleaks, trufflehog, gitdorker | Phase 3 |
| `email` | theharvester, hunter, email_format, email_sec, phonebook | Phase 2 |
| `identity` | maigret, holehe | Phase 2, dispatcher |
| `breach` | hudsonrock, emailrep, leakcheck, breach_lookup | Phase 2 |
| `infrastructure` | shodan, censys, virustotal, greynoise, abuseipdb, urlscan, binaryedge, fullhunt, zoomeye, netlas, leakix, ipinfo, ransomwatch, ahmia, pastebin_scan | Phase 1, dispatcher |
| `web` | httpx, gowitness, webtech, favicon, nuclei, katana, arjun, linkfinder, cms_detect, subdomain_takeover, wafw00f, sslyze, wayback, gau, dorks, metadata | Phase 5 |
| `vulnerability` | nvd, kev, epss, exploitdb, vulners, github_advisory, osv, nuclei_template | Phase 7 |
| `pretext` | news_intel, jobs_intel, sec_edgar, github_org_members, linkedin_dorks, crunchbase, wikipedia, public_collab | Phase 7 |
| `mobile` | playstore, apk_analyzer | Phase 2, dispatcher |

Roughly half work without API keys (passive sources, public services).
The other half are key-gated, tools whose API requires authentication.
The platform degrades gracefully: missing keys mean specific tools are
skipped, but the campaign still completes.

---

## 7. The dispatcher (the agentic loop)

This is the component that makes the platform "agentic" rather than
"automated."

### Why a fixed pipeline isn't enough

Imagine a campaign against a target where the subdomain-enumeration
phase finds nothing. A fixed pipeline runs the next phase (identity
recon) regardless, but identity recon depends on having subdomains
to look at. Without them, phase 2 produces minimal output, phase 3 the
same, and the campaign accumulates gaps.

A senior operator running this manually would notice the gap after
phase 1 and try additional subdomain sources before moving on. The
dispatcher automates exactly that judgment.

### How it decides

After each gated phase (1, 4, 7 in `lite` mode), the dispatcher LLM is
called with:

- Recent findings (so far)
- The full tool catalog (each tool's description, category, tier,
  required keys, and `dynamic_trigger_hints`, keywords that suggest
  when the tool is relevant)
- Recent agent_messages (analytical context from prior phases)

It returns a JSON list of 0-5 tools to dispatch, each with a target and
a rationale. The dispatcher rationale is preserved in `dynamic_dispatch_log`
so the operator can audit *why* each follow-up tool ran.

Example from a real run, after phase 1:

```
[
  {"tool": "subfinder", "target": "acme.com",
   "rationale": "Zero subdomains found for seed domain;
                 subdomain enumeration is a critical phase1 gap."},
  {"tool": "crtsh", "target": "acme.com",
   "rationale": "Certificate transparency logs may reveal additional
                 subdomains and infrastructure not found by active
                 enumeration."},
  ...
]
```

### Caps

The dispatcher is bounded:

- **5 dispatches per cycle** (per gated phase). If the LLM proposes
  more, the rest are dropped.
- **30 dispatches across the whole campaign.** When the global cap
  hits, the reflection node logs and proceeds without dispatching.
- **Cost protection:** every dispatch is a tool call, but the dispatcher
  LLM call itself is a single API request per cycle. Total dispatcher
  cost in `lite` mode is typically $0.05-$0.15 per campaign.

### Where dispatched results land

The dispatcher's selected tool runs through the normal registry path
(scope guard, audit log, cache). Its result is then merged back into
state at `state[<intel_key>][f"dynamic/{tool_name}/{target}"]`, the
`dynamic/` prefix marks it as dispatcher-sourced so it's distinguishable
from phase-sourced data.

The category-to-intel-slot mapping (`CATEGORY_TO_STATE_KEY` in
`dynamic_dispatcher.py`) ensures results land in the right slot.
subdomain tools land in `subdomain_intel`, cloud tools in `cloud_intel`,
and so on.

---

## 8. From findings to ranked threats

Producing a list of findings is the easy part. Producing a *ranked*
list where the top 10 are actually the most consequential threats.
that's the scoring engine's job.

### What "scoring" actually means here

The scoring engine in `nexusrecon/core/scoring.py` reads the campaign
state and produces a list of `RankedFinding` dataclass objects, sorted
by score descending. Each finding gets a score from 0.0 to 1.0,
combining:

- **CVSS / severity** of the underlying vulnerability or exposure
- **EPSS** (Exploit Prediction Scoring System), likelihood of
  exploitation in 30 days
- **CISA KEV** boost, multiplied if the CVE is in the Known Exploited
  Vulnerabilities catalogue
- **Exploit availability boost**: Metasploit module > public PoC >
  nuclei template > no exploit
- **Asset exposure boost**: public S3 buckets, exposed admin panels,
  identified-tenant cloud presence
- **Breach addends**: `+0.1` per breached employee, capped at `0.3`
- **Secret addends**: `+0.3` per leaked credential set
- **Bucket addends**: `+0.2` per public cloud bucket

Findings sourced from agents (the FINDINGS_JSON output) are also
included via `_score_agent_findings()`, so analyst observations like
"executive email cluster identified" or "no email security controls"
are scored alongside tool-derived findings.

All scores are normalised to [0, 1] within the campaign so the top
finding is always at 1.0 and downstream rankings are relative.

### The top-10 deliverable

The top 10 ranked findings become `state["ranked_threads"]` and render
into `top_threads.md`, the platform's headline operator-facing
deliverable. Each thread includes:

- Priority score (% of max)
- Severity, confidence, category
- Description with provenance
- Risk indicators (KEV, Metasploit available, nuclei template available,
  cloud no-auth-required)
- Affected assets
- Recommended next steps in order

The `top_threads.md` is what the operator opens *first* after a
campaign completes. It's the answer to "where do I start tomorrow."

---

## 9. Reports

A campaign produces 17 deliverables across formats, generated by
`ReportEngine` in `nexusrecon/reports/engine.py`. Each report has a
specific audience and purpose.

### Operator-facing (read these first)

| File | Purpose | When to use |
|------|---------|-------------|
| `top_threads.md` | Top 10 ranked attack paths with rationale + next steps | Daily-driver document, open this first |
| `top_threads.json` | Same data, structured for tooling | Pipeline integrations, dashboards |
| `findings.json` | Full raw findings export with hashes | Programmatic consumption, evidence chain |
| `attack_surface.md` | Severity × confidence × MITRE technique matrix | Mid-engagement triage; client meetings |
| `audit_log.jsonl` (`logs/`) | Hash-chained record of every tool call + scope hash | Legal/compliance, dispute resolution |
| `state.json` | Complete campaign state at termination | Debugging, comparing campaigns |

### Client-facing (deliverables)

| File | Purpose | Audience |
|------|---------|----------|
| `executive_summary.md` | One-page summary with key findings + analyst assessment | Client engagement lead |
| `report.pdf` (or HTML fallback) | Full PDF report | Client deliverable |
| `executive_briefing.pptx` | PowerPoint deck | Client executive presentation |
| `full_report.md` | Complete engagement report with methodology, findings, recommendations | Client technical team |

### Specialised

| File | Purpose |
|------|---------|
| `phishing_drafts.md` + per-target files + `phishing_campaign.json` | Per-target spearphishing email drafts with OSINT citations + GoPhish-compatible export. Generated only with `--generate-phishing`. |
| `harvested_credentials.md` + `.json` | Exposed credentials with redaction + validation status. Generated only with `--validate-creds`. |
| `people_identity_map.md` | Org chart synthesis: employees by department/role, executive targets flagged |
| `cloud_posture.md` | M365 federation status, AWS surface, public storage, DMARC/SPF |
| `vulnerability_correlation.md` | CVE-to-asset mapping with exploit availability |
| `vendor_supply_chain.md` | Third-party services detected, CDN providers, dependencies |
| `asset_inventory.md` + `.json` + `.csv` | Complete asset listing (subdomains, IPs, emails, cloud) |
| `jira_tracker.csv` | Findings formatted for Jira import |
| `entity_graph.html` | Interactive entity graph (pyvis) |

The same campaign state powers all of them. The `state.json` is the
single source of truth; the reports are different views on it.

---

## 10. What's automated, what isn't, and where you fit in

Honest framing matters. The platform is powerful, but it isn't an
operator. Specifically:

### What is automated

- **Tool orchestration.** Running 30-60 tools across 9 phases without
  forgetting any or running them in the wrong order.
- **Cross-tool synthesis.** Translating raw tool output into a unified
  state model the agents can analyse.
- **Analysis prose.** LLM-driven interpretation of tool output.
  *"this means X for an attacker; that means Y for a defender."*
- **Finding extraction.** Structured findings (severity, title,
  description, affected assets, next steps, MITRE techniques) emitted
  per phase.
- **Scoring + ranking.** Top 10 attack paths with priority score and
  rationale, generated automatically.
- **Attribution gating.** Stem-match cloud data downgraded with
  `[POSSIBLE]` prefix and `info` severity so confident-but-wrong claims
  don't slip through.
- **Per-target phishing drafts.** Role-tailored email drafts with
  DMARC-aware sender strategy and OSINT-cited rationale (with explicit
  authorization banners).
- **Provenance.** Every finding has an evidence hash; every tool call
  has an audit log entry tied to the scope hash.

### What is NOT automated

- **Authorization.** The platform won't sign your SOW or get you
  permission. It enforces the scope you provide; it can't validate that
  your scope is genuinely authorized.
- **Operator judgment.** The top thread is the highest-scored finding,
  not necessarily the most consequential for *your* engagement context.
  An "Identity Intelligence Gap - No Emails Harvested" finding may be
  the most important thing on a target where email-based attacks are
  the goal, or completely irrelevant on a target where you're after
  unauthenticated API access.
- **Exploitation.** The platform identifies attack paths and confirms
  their viability (via nuclei templates, KEV, exploit existence). It
  does NOT exploit them. T3 phase exists for intrusive ops but defaults
  off and requires explicit scope authorization.
- **Phishing send.** Drafts are *drafts.* Every per-target file starts
  with `⚠ AUTHORIZATION REQUIRED ⚠`. Sending requires your decision,
  your infrastructure, and your engagement contract.
- **Legal compliance.** The audit log records what happened; you decide
  whether what happened was within your authorization.

### Where the operator adds value

A skilled operator using this platform is roughly 5-10× more efficient
than running the same tools manually, *because* the synthesis step is
done for them. But they still:

- Choose the target and the engagement scope
- Review the top threads for context the platform can't have (client's
  business priorities, regulatory concerns, prior engagement history)
- Decide which attack paths to actually pursue
- Operate the post-recon steps (exploitation, lateral movement,
  reporting back to the client)
- Verify findings before client delivery (the platform is accurate but
  not infallible)

If you're approaching this as "I want a button that does the recon for
me so I can focus on the interesting parts", that's exactly the goal.
The interesting parts are operator judgment, exploitation, and client
communication. The boring parts are tool orchestration and synthesis.
NexusRecon does the boring parts.

---

## 11. Glossary

| Term | Definition |
|------|------------|
| **Agentic** | Refers to systems where an LLM makes decisions about what to do next based on observed state, rather than following a fixed script. NexusRecon is agentic in the dispatcher layer; the rest is structured automation. |
| **Attribution confidence** | A 0.0-1.0 score on cloud-recon findings indicating how strongly the data ties to the target (vs. A name-stem collision with an unrelated party). High confidence (≥ 0.5) feeds normal findings; low confidence triggers `[POSSIBLE]` downgrade. |
| **Audit chain** | The hash-chained log of every tool invocation. Each entry's hash includes the previous entry's hash, tampering with any entry invalidates everything after it. |
| **Campaign** | A single end-to-end run against a scope. Identified by a `campaign_id` (e.g. `nr-20260513-184341-d8ae58b2`). All artifacts land under `campaigns/<client_slug>/<engagement_id>/<campaign_id>/`. |
| **Dispatcher** | The LLM-driven decision-maker that runs between phases and selects 0-5 follow-up tools based on what's missing from state. |
| **EPSS** | Exploit Prediction Scoring System, FIRST.org's data feed estimating the probability a given CVE will be exploited in the next 30 days. |
| **Evidence hash** | A sha256 hash tying a finding to its source data (a tool output, an agent's response, or a synthetic deterministic hash for LLM-derived findings). Used by the evidence auditor. |
| **Finding** | A structured record: `{severity, title, description, source, confidence, category, affected_assets, next_steps, mitre_techniques, recommendation, evidence_hash, phase, timestamp}`. Produced by agents (via FINDINGS_JSON) or by the scoring engine from tool data. |
| **KEV** | CISA Known Exploited Vulnerabilities catalogue, CVEs confirmed exploited in the wild. |
| **Phase** | A campaign checkpoint with a defined role (passive recon, identity & cloud, etc.). 9 numbered phases plus phase 7.5. |
| **Ranked thread** | An entry in `ranked_threads`, sourced from the scoring engine's normalised + sorted findings. The top 10 form the operator's "where to start" list. |
| **Scope** | The YAML file authorizing what the platform may scan. Contains the engagement metadata, in-scope/out-of-scope domains, IP ranges, cloud tenants, and constraints (max tier, stealth profile, budget cap). |
| **State** | The shared dict object that accumulates everything across the campaign. Tools write to it; agents read from it; the dispatcher reads it to decide; the report engine renders from it. |
| **Stem-match** | A weak attribution signal, e.g., the platform tested `<seed_stem>.onmicrosoft.com` and got a hit, but that tenant may belong to a completely unrelated party. Tagged `attribution_confidence: 0.2`. |
| **Tier** | A tool's intrusiveness level. T0 passive (no target traffic), T1 fingerprinting (light touch), T2 active scanning (visible in logs), T3 intrusive (brute force, exploitation). Phases enforce tier ceilings per scope. |
| **Tool** | A subclass of `OSINTTool` integrating one external data source. Categories range from subdomain enumeration to mobile APK analysis. Run `nexusrecon tools` for the live registry. |

---

## 12. Where to read next

- **`README.md`**: quick-start: install, configure, run
- **`MANUAL.md`**: full operator manual (1100+ lines)
- **`BETA_TESTING_GUIDE.md`**: closed-beta tester onboarding
- **`TESTING_RUNBOOK.md`**: end-to-end test procedure
- **`CONFIGURATION_GUIDE.md`**: every env var, every API key, what each unlocks
- **`nexusrecon/docs/AGENT_LOOP.md`**: dispatcher deep-dive
- **`nexusrecon/docs/REPORT_GUIDE.md`**: which deliverable is for which audience
- **`DISCLAIMER.md`**: legal framing, authorization requirements

The codebase itself is organised so each component is in one place:
- `nexusrecon/tools/`, every tool in the registry, organised by category
- `nexusrecon/agents/`, the 11 agent personas (roles, prompts, backstories)
- `nexusrecon/graph/`, the phase pipeline, dispatcher, agent executor
- `nexusrecon/core/`, campaign manager, scoring engine, credential harvester, audit log
- `nexusrecon/reports/`, the report engine + phishing draft generator
- `nexusrecon/models/`, pydantic data models for scope, findings, entities

Post-0.5 layers (sections 13-22 below describe each):

- `nexusrecon/strategy/`, Strategy package. Strategy dataclass,
  DispatchPolicy interface, simulation, bounded agency, planner
  orchestration.
- `nexusrecon/verification/`, Continuous Confidence Engine , 
  orchestrator, corroboration, contradiction, propagation,
  adversarial self-check.
- `nexusrecon/packs/`, Recon Pack format. Manifest schema,
  loader, registry, git distribution, marketplace.
- `nexusrecon/sdk/`, Contribution SDK. Prompt versioning,
  citation guardrails, agent / tool / policy scaffolders.
- `nexusrecon/intent/`, Intent-driven entry. NL → Strategy
  orchestrator.
- `nexusrecon/export/`, STIX 2.1 export + downstream-consumer
  emitters (Jira / Nuclei / Cobalt Strike).
- `nexusrecon/ingest/`, Bidirectional import. STIX, Nessus,
  Nuclei, generic CSV.
- `nexusrecon/watch/`, Watch Mode. Sensors, severity
  classifier, tiered action policy.
- `nexusrecon/crypto/`, Ed25519 signing. Keypair lifecycle,
  bundle signing, verification.
- `nexusrecon/adversarial/`, Platform self-defense. Poisoned
  data, tool patterns, inconsistency, prompt injection
  detectors.
- `nexusrecon/vision/`, Multi-modal pipeline. Backend protocol,
  preprocessing, extractor, cost gate.
- `packs/burp/`, First-party Burp Suite XML handoff pack.
- `scripts/nexusrecon-verify.py`, Standalone single-file
  verifier for signed STIX bundles.

---

# Post-0.5 Architecture Additions

Sections 13-22 cover the major layers added in 0.6.x / 0.7.x.
Each follows the same shape: *what problem it solves, the public
surface, the invariants it preserves, what's deliberately out of
scope.*

---

## 13. Living Intelligence Graph (Phase 0)

**Problem.** The original `EntityGraph` carried domain / subdomain /
IP entities and a handful of relationships, but most intelligence
still lived in flat dictionaries (`subdomain_intel`, `cloud_intel`,
`findings`). Agents reasoned over the dicts; the graph was a
sidecar. That left no first-class place for hypotheses, leads, open
questions, provenance per claim, or path-finding queries an
adversary would actually trace.

**What landed.** `EntityGraph` (still in
`nexusrecon/core/entity_graph.py`) became the canonical reasoning
substrate. The Phase D / E IdentityGraph + RelationshipGraph were
collapsed into it. A `LivingGraph` alias documents the architectural
intent.

Concretely:

- **17+ entity types**: domain, subdomain, IP, ASN, certificate,
  email, person, organization, cloud asset, repository, secret,
  technology, CVE, social account, username, URL, file artifact,
  plus three reasoning-artifact types: `HYPOTHESIS`, `LEAD`,
  `OPEN_QUESTION`.
- **Per-source provenance.** Every entity carries a list of
  `ProvenanceRecord{source, timestamp, evidence_hash, tool_name}`.
  Joins to the hash-chained audit log via `evidence_hash`.
- **Relationship vocabulary.** Standard recon edges (`resolves_to`,
  `has_subdomain`, `owns`, `belongs_to`, `has_cve`, …) plus
  reasoning edges: `CITES` (hypothesis / lead → evidence),
  `BLOCKS` (open question → downstream lead), and identity-graph
  rollups (`KNOWS`, `COLLABORATES_WITH`, `FOLLOWS`,
  `FEDERATED_WITH`).
- **Query surface.** `find_paths`, `get_neighbors_filtered`,
  `get_attack_surface_nodes`, plus a per-phase `GraphContext`
  wrapper (`nexusrecon.core.graph_context`) that lets each agent
  see a scoped slice of the graph (`PHASE_FOCUS_TYPES` +
  `most_cited_entities`).
- **Mutation events.** `register_mutation_listener(cb)` lets
  downstream code react to `entity_added` / `entity_merged` /
  `relationship_added` / `confidence_changed` /
  `sticky_field_conflict` / `exclusive_rel_conflict`. The
  verification orchestrator (§14) is the primary consumer.
- **Confidence as a managed property.** `set_confidence(entity_id,
  value, *, reason, source)` is the single seam. Emits a
  `confidence_changed` event the propagator listens for.
- **Backward compatibility.** `EntityGraph.from_state(state)`
  tolerates the old truncated `{"subdomains": […], "emails": […]}`
  shape; `scripts/migrate_state_to_living_graph.py` eagerly
  upgrades old `state.json` files.

**Invariants preserved.**

- Evidence hashes remain immutable references into the audit log.
- The flat state buckets still exist as materialized views, so the
  TUI + reports + older tests keep working.
- `state["entity_graph"]` round-trips through `to_dict()` /
  `from_dict()`; schema version pinned in `GRAPH_SCHEMA_VERSION`.

**Out of scope.** Versioning / time-travel (deferred per the
architecture lock-in during Phase 0.1); a graph database backend
(NetworkX in-memory still covers the campaign sizes operators see).

---

## 14. Continuous Confidence Engine (Phase 2)

**Problem.** Confidence on entities was hand-set by tool wrappers
and never re-evaluated. New corroborating evidence didn't lift
confidence; contradictions didn't lower it; a downgraded asset's
dependent leads stayed "high" until the operator noticed.

**What landed.** `nexusrecon/verification/` ships an
**orchestrator** that subscribes to the graph's mutation events
and fans them out to registered verifiers. Four verifiers ship:

1. **`CorroborationEngine`**: maps source identifiers
   (`subfinder`, `crtsh`, `naabu`, `h8mail`, …) to **independence
   classes** (`passive_dns`, `certificate`, `active_probe`,
   `breach_corpus`, …). When N ≥ 2 distinct classes vouch for the
   same entity, confidence rises:
   `new = old + (CAP - old) × (1 - DECAY^(n-1))` with
   `CAP = 0.99`, `DECAY = 0.5`. Two classes lifts 0.5 → 0.745;
   three to 0.871; four to 0.934.
2. **`ContradictionDetector`**: fires on
   `sticky_field_conflict` (merge-time scalar disagreement on
   fields like `cloud_provider`, `platform`, `parent_domain`) and
   `exclusive_rel_conflict` (a second `belongs_to` / `owns` /
   `part_of` edge from the same source). Severity grades off the
   existing claim's confidence; medium+ findings are queued in
   `state["contradictions"]`, low findings just downgrade
   silently. Downgrade factor 0.6, floor 0.05.
3. **`ConfidencePropagator`**: listens to `confidence_changed`
   events and cascades downgrades through edges with reliance
   semantics (`cites`, `belongs_to`, `part_of`, `hosted_on`,
   `registered_by`, `blocks`). Decay per depth = 0.5; max depth
   3; cycle-safe via a visited set + `source="propagation"`
   short-circuit so its own writes don't re-enter. Upgrades
   aren't propagated (one-way ratchet).
4. **`AdversarialSelfCheck`**: on-demand graph audit producing
   four `WeakLink` kinds: `single_source_high_confidence`,
   `citation_cycle`, `disconnected_island`, `source_monoculture`.
   Heuristic-driven, runs in O(n+e). Writes to
   `state["weak_links"]` and the audit log.

**Health surface.** `compute_verification_health(graph, state)`
gives a per-campaign snapshot. Corroboration coverage,
contradiction density, low-confidence entity count, weak-link
severity counts. The Phase 1 planner reads this snapshot from
state and biases toward verification tools when coverage is low.

**Invariants preserved.**

- Verifier exceptions are caught at three layers (graph emit,
  verifier body, orchestrator dispatch). A broken verifier
  never breaks a campaign.
- Audit chain remains hash-chained; verdicts ride the existing
  `log_agent_action` event type.
- All confidence writes go through `set_confidence` so the
  propagator observes them.

**Out of scope.** LLM-driven semantic contradiction detection,
adversarial confidence-poisoning by a co-resident pack (packs
run unsandboxed per the locked-in trust model).

---

## 15. Strategic Reasoning Engine (Phase 1)

**Problem.** Phase selection, dispatch policy, and follow-up
budgets were hardcoded in `nodes.py`. The dispatcher's caps
(`MAX_PER_CYCLE=5`, `MAX_TOTAL=30`) were module-level constants.
Adding a new dispatch posture meant editing the dispatcher itself;
auditing "why did we pick this strategy" required reading the
code.

**What landed.** `nexusrecon/strategy/` is the home of the
strategic engine.

- **`Strategy` dataclass.** Declarative campaign plan: `name`,
  `phases[]`, `dispatch_policy_name`, `tool_budgets{}`,
  `success_criteria[]`, `kill_criteria[]`, `metadata{}`.
  Round-trips through `to_dict()` / `from_dict()` with default
  restoration on missing keys.
- **`DispatchPolicy` interface** + three bundled policies.
  `LitePolicy` (caps 5/cycle, 30/total; eligible after phases
  1, 4, 7. Preserves pre-0.6 behavior byte-for-byte),
  `FullPolicy` (5/cycle, 50/total, every phase),
  `OffPolicy` (zero). `register_policy(name, cls)` lets
  community packs ship custom policies (e.g. `aggressive`,
  `conservative`, `corp_red_team`).
- **`CampaignPlannerAgent`** is now operational. The previously
  dormant agent runs through a `plan_campaign(sentence|inputs)`
  orchestrator that calls the LLM with a strict-JSON prompt,
  parses the response, validates phase identifiers, and falls
  back to `Strategy.default()` on any failure (tagged
  `metadata.planner_response_kind="fallback"` so the audit trail
  shows when the planner couldn't help).
- **`--plan-only` CLI flag** + interactive walk-through.
  Operator previews the proposed scope.yaml + Strategy before
  any tool fires. Confirmation gates every disk write.
- **Simulation.** `simulate_dispatch_plan(plan, state)` runs
  between validate and execute on every dispatcher call.
  Forecasts cost (sum of per-tool `cost_per_run_usd`), expected
  new graph entities (per-category heuristic), and scope-creep
  flags (tier > scope ceiling, pivot to entity not yet in
  graph). Recommendation `proceed` / `warn` / `abort`. Opt-in
  gating via `state["simulation_gating"]`.
- **Bounded agency.** `route_plan_items(plan, default_policy)`
  splits a validated dispatch plan into execute / deep-pivot /
  human-approval routes. Deep-pivot items
  (`deep_pivot: "full"` on a plan item) get a per-item policy
  override that REFUSES to narrow agency. Human-approval items
  (`requires_human_approval: true`) land in
  `state["pending_approvals"]` with `queue_for_approval()`;
  the operator resolves via `resolve_approval()` which appends
  to `state["approval_log"]`.
- **Strategic audit.** Seven new `AuditLog.log_*` methods , 
  `log_strategy_generated`, `log_strategy_replan`,
  `log_dispatch_policy_resolved`, `log_simulation`,
  `log_deep_pivot_grant`, `log_human_approval_queued`,
  `log_human_approval_decision`. Each rides the existing hash
  chain.

**State surface.** `state["strategy"]`,
`state["strategy_history"]`, `state["dispatch_policy_name"]`,
`state["pending_approvals"]`, `state["approval_log"]`,
`state["simulation_log"]`.

**Invariants preserved.**

- Default behavior on a campaign that doesn't author a Strategy
  matches pre-0.6 (`Strategy.default()` returns the lite-equivalent
  shape).
- Policy resolution precedence in the dispatcher:
  `state["dispatch_policy_name"]` → legacy
  `state["dispatch_mode"]` → `lite` default.
- The hash chain remains unbroken; new event types share
  `_compute_entry_hash`.

---

## 16. Intent-Driven Entry (Phase 4 PR A)

**Problem.** The structured Strategy is the right entry surface
for operators who already know what they want. But a senior
operator on a new engagement wants to type *"find leaked
credentials at acme.com, passive only"* and get a scope.yaml +
Strategy out the other side.

**What landed.** `nexusrecon/intent/` provides a two-path NL →
Strategy translation.

- **LLM path**: strict-JSON prompt extracts targets, intent
  categories (`credentials`, `subdomains`, `cloud`, `identity`,
  `pretext`, `vulnerabilities`, `executives`, `supply_chain`),
  tier ceiling, stealth profile, and operator-supplied
  constraints (`max_llm_cost_usd`, `allow_paid_apis`, …).
- **Regex fallback**: deterministic patterns for the common
  cases. Always available. Tagged `confidence="medium"` when
  anything actionable matches, `"low"` otherwise. Air-gapped
  operators + CI use this via `--no-llm`.
- **Scope builder**: `build_scope_stub(intent)` produces a
  scope.yaml-shaped dict. REFUSES to invent authorization
  markers (client name, authorized_by, SOW hash). Placeholders
  left as `REPLACE_ME`.
- **Phase + policy mapping**: `_PHASES_BY_INTENT` maps each
  intent category to the canonical phase set
  (`credentials` → 1, 2, 3, 4, 8, 9; `cloud` adds 5; `pretext`
  adds 6, 7, 7_5, 7_7).

**CLI surface.** `nexusrecon plan "<sentence>"` (one-shot) and
`nexusrecon plan` (interactive Rich walk-through). Both gate
disk writes behind operator confirmation per the Auditability
First principle.

**What's NOT here.** TUI tab (deferred. Same orchestrator backs
all surfaces, the tab is mechanical follow-up).

---

## 17. Recon Pack format + Contribution SDK (Phase 3)

**Problem.** Adding a new tool was straightforward (subclass
`OSINTTool`, decorate with `@register_tool`). Adding a new
agent, dispatch policy, or report template required forking the
repo. There was no community contribution surface.

**What landed.** Two packages.

### Pack format (`nexusrecon/packs/`)

- **Directory layout.** `~/.nexusrecon/packs/<pack-name>/`
  (overridable via `NEXUSRECON_PACK_DIR`). Required:
  `manifest.yaml` at the root.
- **Manifest schema v1** (Pydantic):

  ```yaml
  name: corp-red-team
  version: 1.0.0
  schema_version: 1
  description: …
  author: …
  license: MIT
  manifest_hash: sha256:…   # optional; loader warns on mismatch
  contributes:
    tools:    [{module: corp_tools.x}]
    agents:   [{module: …, class_name: …, registry_name: …}]
    policies: [{module: …, class_name: …, name: …}]
    report_templates: [{name: …, path: …}]
    entity_types:     [{name: BUSINESS_PARTNER, value: business_partner}]
    relationship_types: [{name: SUPPLY_CHAINS_TO, value: supply_chains_to}]
  ```

- **Loader.** `load_packs(pack_dir, audit_log)` walks the packs
  root, parses each manifest, imports declared modules, binds
  agents into `AGENT_REGISTRY`, registers policies + custom
  entity / rel types. Per-pack + per-contribution failure
  isolation: one broken tool import doesn't sink the rest of
  the pack; a broken manifest goes to `failed` status without
  raising.
- **Trust model.** Unsigned + manifest_hash. Loader recomputes
  the hash and warns on mismatch. Operators inspect before
  activating. No execution gate (trusting by inspection is the
  v1 locked-in decision).
- **Distribution.** `nexusrecon packs install gh:owner/repo[@ref]`
  (shallow clone), `packs update`, `packs uninstall`,
  `packs search` against a configurable marketplace JSON index
  (`NEXUSRECON_MARKETPLACE_URL`).
- **Custom types coexist with the StrEnum built-ins.** The
  runtime extension registry (`_CUSTOM_ENTITY_TYPES` /
  `_CUSTOM_REL_TYPES`) carries pack-contributed type values;
  `is_known_entity_type(value)` checks both built-in + custom in
  one call.

### Contribution SDK (`nexusrecon/sdk/`)

- **Prompt versioning.** `register_prompt(name, version, body)`
  stores a process-wide record. Re-registering the same body is
  idempotent; a silent hot-edit (same name+version, different
  body) raises `PromptVersionMismatch`. Optional `expected_hash`
  pin for plugin authors.
- **Citation guardrails.** `validate_citations(text, graph)`
  extracts `[[citation]]` inline markers, verifies each against
  the graph by id and by value, grades violations
  (`error` missing / `warning` type mismatch / `info`
  claim-without-citation), returns a structured
  `CitationReport`.
- **Three scaffolders**: each writes a Python module +
  manifest entry (new or existing pack) + smoke test:
  - `nexusrecon agent new`. Agent module with
    `register_prompt(…)` + a `review_citations(…)` method.
  - `nexusrecon tool new`. Interactive picker for category ×
    tier × target_types, generates an `@register_tool`
    decorated stub.
  - `nexusrecon policy new`. Interactive picker for eligible
    phases + caps, generates a `DispatchPolicy` subclass.

### First-party reference pack

`packs/burp/` ships an in-tree pack as a dogfooding example.
Loads via the same `load_packs()` path community packs use.
Provides:

- `BurpXmlImporter` tool (Burp Suite site map XML → entities,
  dedup by (host, port, path), tolerant of malformed items).
- `render_scope_to_burp_xml()` + `export_campaign_scope_to_burp()`
  helpers for exporting the campaign's in-scope domains as a
  Burp-importable scope XML.

---

## 18. Watch Mode (Phase 5 PR A)

**Problem.** A campaign is a single run. Real engagements need a
continuous posture. Alert me when a new subdomain appears, when
an existing finding's confidence shifts materially, when a new
vuln-source entity lands.

**What landed.** `nexusrecon/watch/` provides sensors + severity
classifier + tiered action policy + per-watch persistence.

- **Three sensor types.**
  - `EntitySensor`. Watches one entity by id. Fingerprint hashes
    confidence + sources + tags + edge degrees; any change fires.
  - `ScopeSensor`. Watches every entity matching an
    `entity_type` / `parent_domain` / `value_contains` filter
    (AND semantics). Refuses construction with no filters so
    operators can't accidentally watch the whole graph.
  - `TimedSensor`. Fires on a cadence regardless of graph state
    (re-running a passive recon footprint every N hours).
- **Severity classifier**: rules cascade in priority:
  vuln-source addition → HIGH, new high-confidence entity →
  HIGH, new CITES edge into a Lead / Hypothesis → HIGH,
  in-place change on near-high-confidence entity → MEDIUM, any
  addition / removal → MEDIUM, else LOW.
- **Tiered action policy** (locked in by the architecture
  choice):
  - LOW → `alerts.jsonl` append.
  - MEDIUM → above + `notifications.jsonl` append.
  - HIGH → above + `micro_campaigns.jsonl` queue with seed
    entities + suggested phases. V1 does NOT auto-execute;
    operators review + dispatch.
- **Persistence under** `~/.nexusrecon/watch/<watch-id>/`:
  `config.yaml`, `fingerprints/<sensor-id>.json`,
  `alerts.jsonl`, `notifications.jsonl`,
  `micro_campaigns.jsonl`, `tick.log`.
- **CLI.** `nexusrecon watch create / list / tick / alerts /
  remove`. `tick` is synchronous + one-shot; production
  deployments wrap it in cron or systemd-timer.

---

## 19. Provenance Cryptography (Phase 5 PR B)

**Problem.** The audit chain is tamper-evident WITHIN a campaign,
but an auditor with only the exported STIX bundle has no way to
prove it came from a specific NexusRecon instance at a specific
time. Hot-patching a prompt three weeks after delivery silently
breaks the meaning of archived findings' provenance.

**What landed.** `nexusrecon/crypto/` provides Ed25519 keypair
lifecycle + bundle signing + verification + a standalone
single-file verifier.

- **`generate_keypair(key_id, passphrase, label=…)`** writes
  three files under `~/.nexusrecon/keys/<key-id>/`:
  `private.pem` (PKCS8 + passphrase-encrypted via
  `BestAvailableEncryption`), `public.pem` (plain),
  `metadata.json`. Directory mode 0o700, private key file mode
  0o600 (best-effort on Windows).
- **`sign_bundle(path, keypair)`** writes a sidecar
  `<bundle>.receipt.json`. Receipt v1.0 schema:

  ```json
  {
    "version": "1.0",
    "signed_at": "2026-05-27T...",
    "signer": {"key_id": "...", "fingerprint": "sha256:..."},
    "bundle": {"filename": "...", "hash_algorithm": "sha256",
               "hash": "sha256:..."},
    "signature_algorithm": "ed25519",
    "signature": "<base64url>"
  }
  ```

- **Signed message.** `"ed25519|<bundle_hash>"`. The algorithm
  tag in the payload defeats algorithm-substitution attacks in
  future multi-algorithm verifiers.
- **`verify_bundle(bundle, receipt, public_key)`** walks four
  checks (algorithm support, public-key fingerprint match,
  bundle hash match, signature verify). Optional
  `expected_key_id` + `expected_fingerprint` pins fail loudly
  when an auditor's known-good signer doesn't match.
- **Standalone verifier**: `scripts/nexusrecon-verify.py` is a
  ~250-line single file that depends ONLY on `cryptography`.
  Auditors download one file + verify; no NexusRecon install
  required.
- **CLI.** `nexusrecon keys generate / list / export-public`,
  `nexusrecon sign`, `nexusrecon verify`.

---

## 20. Adversarial Platform Self-Defense (Phase 5 PR C)

**Problem.** Phase 2 defends against tampering with NexusRecon's
own outputs. PR C defends against the inverse threat: upstream
data sources actively feeding NexusRecon misleading or hostile
content meant to inflate attack surface, derail the dispatcher,
fabricate findings, or hijack agent prompts.

**What landed.** `nexusrecon/adversarial/` ships four detectors
that produce findings into `state["adversarial_findings"]` and
apply a tiered confidence downgrade (medium ×0.7, high ×0.5,
floor 0.05). Downgrades route through `set_confidence` so the
Phase 2 propagator cascades them naturally.

1. **`PoisonedDataDetector`**: sinkhole IPs (reserved + test-net
   + loopback ranges), wildcard DNS (≥N subdomains resolving to
   one IP), uniform fabrication clusters (subdomains sharing
   parent + single source + identical confidence).
2. **`ToolPatternAnalyzer`**: sweeps
   `state["dynamic_dispatch_log"]` for rapid pivots (≥N distinct
   target_types in a W-call window), low-yield bursts, repeat
   hits (same (tool, target) ≥ N times), tier escalation
   attempts (dispatches above
   `scope.constraints.max_tier`).
3. **`EvidenceInconsistencyDetector`**: timing impossibility
   (`first_seen` < earliest provenance timestamp), repository
   platform mismatch (`github` platform with gitlab URL), cloud
   provider mismatch (AWS-tagged with azure value pattern),
   email / org domain disagreement.
4. **`PromptInjectionScanner`**: regex+structural mode
   (default): ~10 known jailbreak phrases + structural anomalies
   (long single lines, long base64 blobs, hidden HTML
   instruction comments, `<|im_start|>` markers). Opt-in
   LLM-classifier mode via `state["adversarial_use_llm"]` for
   high-spend campaigns. Cache by content hash so identical tool
   output pays the LLM cost once.

**CLI.** `nexusrecon adversarial scan` runs all four detectors
against a campaign's graph; `adversarial show` prints the
findings log; `adversarial scan-text` runs the prompt-injection
scanner on a single text file or stdin.

---

## 21. Vision Pipeline (Phase 5 PR D)

**Problem.** Campaigns routinely involve visual artifacts , 
screenshots of login portals + dashboards + slide decks, leaked
PDFs, brand logos, QR codes embedded in posters. Today none of
those flowed into the graph.

**What landed.** `nexusrecon/vision/` ships a backend protocol +
default langchain-driven implementation, image / PDF / QR
preprocessing helpers, a cost gate keyed to the Phase 1
Strategy's `tool_budgets["vision_calls"]`, and the extractor
that orchestrates the whole pipeline.

- **`VisionBackend` Protocol.** Minimal contract: `describe_image`
  + `describe_text` + a `name`. Default
  `LangChainVisionBackend` picks up whichever model the
  operator's config selected, so Anthropic / OpenAI / any
  provider with langchain vision support works unchanged.
  `NoopVisionBackend` returns an empty JSON shape for `--noop`
  plumbing verification and tests.
- **Preprocessing**: `extract_pdf_pages` (pypdf optional dep,
  graceful skip), `decode_qr_codes` (pyzbar optional dep,
  graceful skip). Operators on stripped-down systems still get
  the screenshot path.
- **Strict-JSON prompt contract.** Two top-level keys:
  `description` (1-3 sentence narrative) + `entities` (urls /
  emails / persons / organizations / brands / technologies /
  domains). "Surface only things you can actually see. No
  speculation."
- **Graph integration.** Structured entities flow through the
  standard graph builders with `imported_from:vision` source tag
  + a narrative `HypothesisEntity` citing the extracted entities
  (CITES edges). QR-decoded URLs ALWAYS flow (no LLM cost).
- **Cost control.** `CostGate` consults
  `state["strategy"]["tool_budgets"]["vision_calls"]` (no key
  set → budget 0 → skip). Defaults are opt-in only.
- **CLI.** `nexusrecon vision scan` (one artifact) and
  `vision scan-dir` (directory walk). `--noop` runs the pipeline
  without paying for the LLM call.

---

## 22. Glossary additions (post-0.5)

| Term | Definition |
|------|------------|
| **Living Graph** | The post-0.5 evolution of `EntityGraph`. First-class hypothesis / lead / open-question nodes, provenance per claim, mutation events the verification engine subscribes to. |
| **Strategy** | A declarative campaign plan (phases, dispatch policy, success / kill criteria, tool budgets, metadata). Authored by the operator or synthesised by the planner. |
| **DispatchPolicy** | Pluggable rules for "when does the dispatcher fire and how much can it do?". `LitePolicy` / `FullPolicy` / `OffPolicy` ship; community packs add more. |
| **Verifier** | A component that subscribes to graph-mutation events and produces verdicts (corroboration / contradiction / propagation / adversarial). Verdicts land in `state["verification_log"]` + the audit chain. |
| **Corroboration class** | Independence class for source signals (`passive_dns`, `certificate`, `active_probe`, `breach_corpus`, `code_intel`, `cloud_enum`, `social`, `scope`, `manual`). Same-class sources collapse to one signal. |
| **Recon pack** | Community-contributed bundle of tools / agents / policies / report templates / custom entity-and-rel types. Lives at `~/.nexusrecon/packs/<name>/manifest.yaml`. |
| **Bounded agency** | Per-item dispatch escalation: deep-pivot (per-item policy override that refuses to narrow) + human-approval queue (high-tier items wait for operator). |
| **Watch sensor** | A configured monitor (Entity / Scope / Timed) that fires when its fingerprint changes or its cadence elapses; tiered actions follow. |
| **Receipt** | The sidecar JSON file produced by `sign_bundle`. Carries algorithm tags, bundle hash, signer fingerprint, base64url signature. V1.0 schema. |
| **Adversarial finding** | A detector verdict (poisoned data / tool pattern / inconsistency / prompt injection) with severity + downgrade record. |
| **Vision call** | One backend-driven multi-modal LLM invocation. Counted against `Strategy.tool_budgets["vision_calls"]`. |
