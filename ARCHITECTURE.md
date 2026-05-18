# NexusRecon: Architecture & Goals

A wiki-style explainer of what NexusRecon is, what its parts do, and why
the design makes it materially different from running a stack of OSINT
tools in sequence.

**Audience:** security or IT professionals with moderate familiarity with
OSINT, LLMs, and red-team workflows. No prior knowledge of LangGraph,
CrewAI, or any specific tool integration required.

**If you're new here**, read sections 1-4 to understand the platform's
purpose and shape. Sections 5-9 are deep-dives on specific components.
Section 10 is honest about what's automated vs. what still needs you.

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
consumes. If your pipeline is well-tuned, the output is comprehensive;
if it's not, you get gaps. Either way, the tool order doesn't adapt to
what's being discovered.

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
| **4, Correlation & Hypothesis** | T0 synthesis | Cross-source validation, lead generation, confirmed_leads vs. open_questions |
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
| **Attribution confidence** | A 0.0-1.0 score on cloud-recon findings indicating how strongly the data ties to the target (vs. a name-stem collision with an unrelated party). High confidence (≥ 0.5) feeds normal findings; low confidence triggers `[POSSIBLE]` downgrade. |
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
- **`MANUAL.md`**: comprehensive operator manual (1100+ lines)
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
