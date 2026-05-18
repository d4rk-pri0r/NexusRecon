# NexusRecon: Operator Manual

This document is the **operator reference** for NexusRecon, every CLI flag,
every config knob, every module, every scope-file field, every troubleshooting
recipe. New to the project? Start at [`README.md`](README.md) for a one-screen
overview and then come back here.

> **Primary entry point is the TUI.** Run `nexusrecon` with no arguments to
> open the interactive Textual UI, new-campaign wizard, masked `.env` editor,
> past-campaign browser, tool catalogue. The CLI commands documented in §5 are
> what the TUI orchestrates under the hood, and remain the right tool for
> scripted / headless / CI use.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Configuration Reference](#3-configuration-reference)
4. [Scope File Format](#4-scope-file-format)
5. [CLI Reference](#5-cli-reference)
6. [Module Walkthrough](#6-module-walkthrough)
7. [Tool Inventory](#7-tool-inventory)
8. [Campaign Modes and Tier System](#8-campaign-modes-and-tier-system)
9. [What Happens During a Campaign](#9-what-happens-during-a-campaign)
10. [Manual Testing Guide](#10-manual-testing-guide)
11. [Output Structure](#11-output-structure)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisites

Python 3.11, 3.12, or 3.13, **not 3.14** (CrewAI is not yet 3.14-compatible).
On macOS with Homebrew the default `python3` may now be 3.14; install 3.13 via
`brew install python@3.13` and pass `PYTHON=python3.13 ./install.sh`.

| Requirement | Minimum Version | Check |
|---|---|---|
| Python | 3.11-3.13 | `python3 --version` |
| pip | 23+ | `pip3 --version` |

### Optional: Binary Tools

These are CLI binaries that certain tools wrap. NexusRecon skips any tool whose binary is missing; the campaign still runs with whatever is available.

| Binary | Used by | Install |
|---|---|---|
| `subfinder` | subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| `httpx` | HTTP probing (Phase 5) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `gitleaks` | secret scanning | `brew install gitleaks` or GitHub releases |
| `trufflehog` | secret scanning | `brew install trufflehog` or GitHub releases |
| `gowitness` | screenshots (Phase 6) | `go install github.com/sensepost/gowitness@latest` |
| `gau` | URL enumeration | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `maigret` | username OSINT | `pip install maigret` |

None of these are required for your first test run. `crt.sh`, DNS, WHOIS, ASN/BGP, urlscan, and NVD/KEV/EPSS work without any binaries or API keys.

---

## 2. Installation

README §Quick Start covers the recommended path (`./install.sh` → `source venv/bin/activate`).
This section is for non-default installs and operator reference.

> **Why a venv?** PEP 668 prevents global `pip install` on most modern Python
> distributions (Homebrew, Debian 12+, Ubuntu 23+, Fedora 38+). A virtual
> environment is mandatory, `install.sh` creates one for you automatically.

### Manual path (bring your own venv)

```bash
python3.13 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
./install.sh --skip-python   # installs Go binaries + gitleaks only
```

### Installer flags

```bash
./install.sh --skip-system   # Python install only (binaries assumed present)
./install.sh --skip-python   # Binary install only (Python deps assumed present)
./install.sh --yes           # Non-interactive
./install.sh --help          # Usage
```

### Verify

```bash
source venv/bin/activate
nexusrecon --help        # Typer help screen
nexusrecon tools         # full tool catalogue
nexusrecon               # Launches the TUI (TTY only)
```

The `[dev]` extra installs pytest, black, ruff, and mypy. For PDF report generation add `[pdf]`:

```bash
pip3 install -e ".[dev,pdf]"
```

---

## 3. Configuration Reference

Two paths to set keys and toggles:

- **TUI (recommended):** `nexusrecon` → press `c` for the Configuration screen.
  Every variable below is editable in a masked, atomic-write editor backed by
  the same `.env` file. The file is `chmod 0o600`'d on save.
- **Manual:** `cp .env.example .env` and edit in `$EDITOR`.

The tool works with zero API keys configured, tools that need keys are automatically skipped, and the LLM synthesis step falls back to a deterministic `MockLLM` that produces keyword-based analysis summaries.

For the full env-var → unlocked-tool reverse lookup see
[`CONFIGURATION_GUIDE.md`](CONFIGURATION_GUIDE.md).

### LLM Settings

```env
NEXUS_LLM_PROVIDER=anthropic   # anthropic | openai | ollama
NEXUS_LLM_MODEL=claude-opus-4-5
NEXUS_LLM_TEMPERATURE=0.1
ANTHROPIC_API_KEY=sk-ant-...   # Required for Anthropic
OPENAI_API_KEY=sk-...          # Required for OpenAI
OLLAMA_BASE_URL=http://localhost:11434  # Required for local Ollama
OLLAMA_MODEL=llama3.1:8b
```

Setting `ANTHROPIC_API_KEY` enables the full LLM synthesis pipeline. Without any key, analysis is still generated by `MockLLM`, campaigns complete successfully, findings are still reported, but the "Agent analysis" sections will be generic keyword-counted summaries rather than reasoned prose.

### API Keys: Priority Order

Keys that produce the most value per campaign phase:

| Phase | Key | Service | Free Tier |
|---|---|---|---|
| 1, 5 | `SHODAN_API_KEY` | Shodan host search | Yes (limited) |
| 3 | `GITHUB_TOKEN` | GitHub code search | Yes (required for auth) |
| 2 | `HUNTER_API_KEY` | Email harvesting | Yes (25 req/mo) |
| 5 | `VIRUSTOTAL_API_KEY` | Domain/IP reputation | Yes (500 req/day) |
| 2 | `HAVEIBEENPWNED_API_KEY` | Breach data | Paid only |
| 1 | `SECURITYTRAILS_API_KEY` | Passive DNS | Paid |
| 5 | `GREYNOISE_API_KEY` | IP noise classification | Yes (community) |
| 5 | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Internet scan data | Yes (limited) |
| | `ABUSEIPDB_API_KEY` | IP abuse reports | Yes |

### Storage Settings

```env
NEXUS_OUTPUT_DIR=./campaigns   # Where campaign directories are created
NEXUS_DB_PATH=./nexusrecon.db  # Path for the SQLite cache/state DB
NEXUS_LOG_LEVEL=INFO           # DEBUG | INFO | WARNING | ERROR
NEXUS_LOG_FORMAT=json          # json | console
```

### OPSEC Settings

```env
NEXUS_PROXY_URL=http://user:pass@proxy:3128   # HTTP proxy for all outbound
NEXUS_TOR_PROXY=socks5h://127.0.0.1:9050     # Tor SOCKS proxy
NEXUS_DNS_RESOLVERS=1.1.1.1,8.8.8.8         # Comma-separated resolvers
NEXUS_DRY_RUN=false                           # true = validate only, no tool runs
```

---

## 4. Scope File Format

Every campaign requires a scope YAML file. The tool hard-fails if the file is
missing, malformed, or the engagement date range is invalid.

### Start here: minimal scope

Copy the minimal template for new engagements, it only needs one domain:

```bash
cp examples/scopes/minimal_seed.yaml my-scope.yaml
# Edit client, engagement_id, authorized_by, dates, and your target domain
```

```yaml
engagement:
  client: "Acme Corp"
  engagement_id: "ACM-2026-Q2-RT01"
  authorized_by: "Jane Smith, CISO"
  authorization_date: "2026-05-01"
  signed_sow_hash: "sha256:0000..."
  start_date: "2026-05-01"
  end_date: "2026-05-30"

scope:
  in_scope:
    domains:
      - "acme.com"

constraints:
  max_tier: "T1"
  stealth_profile: "high"
  max_llm_cost_usd: 10.0
```

NexusRecon discovers subdomains, cloud assets, employees, and related infrastructure
from that single seed domain automatically. You do **not** need to enumerate
them upfront.

See `examples/scopes/*_completed_example.yaml` for fully-populated examples
showing every optional field (IP ranges, ASNs, cloud tenants, etc.).

### Full schema reference

This is the full schema with all supported fields:

```yaml
# ── Engagement metadata ──────────────────────────────────────────────────────
engagement:
  client: "Acme Corp"                         # Required. Client or org name.
  engagement_id: "ACM-2026-Q2-RT01"          # Required. Unique engagement ID.
  authorized_by: "Jane Smith, CISO"           # Required. Who authorized it.
  authorization_date: "2026-04-15"            # Required. ISO date.
  signed_sow_hash: "sha256:abc123..."         # Optional. Hash of signed SOW PDF.
  start_date: "2026-05-01"                    # Required. Campaign not valid before.
  end_date: "2026-05-30"                      # Required. Campaign not valid after.
  rules_of_engagement_doc: "./roe.pdf"        # Optional. Path to ROE document.

# ── Scope definitions ────────────────────────────────────────────────────────
scope:
  in_scope:
    domains:                                  # Apex domains. Subdomains are included.
      - "acme.com"
      - "acme-corp.io"
    ip_ranges:                                # CIDR blocks.
      - "198.51.100.0/24"
    asns:                                     # Autonomous System Numbers.
      - "AS64500"
    cloud_tenants:
      m365:                                   # M365/Azure tenant domains.
        - "acme.onmicrosoft.com"
      aws_accounts:                           # AWS account IDs.
        - "123456789012"
    github_orgs:                              # GitHub organizations.
      - "acme-corp"
    email_domains:                            # Email domains for identity tools.
      - "acme.com"

  out_of_scope:
    domains:                                  # Wildcards supported with *.
      - "*.partner.acme.com"
      - "acquired-company.com"
    ip_ranges:
      - "198.51.100.200/29"                   # Subnets within in-scope CIDR.
    third_parties:                            # Human-readable exclusion notes.
      - "Shared Salesforce infrastructure"

# ── Execution constraints ─────────────────────────────────────────────────────
constraints:
  max_tier: "T1"                              # T0 | T1 | T2 | T3. Controls which phases run.
  stealth_profile: "high"                     # paranoid | high | normal | loud
  allow_breach_db_lookup: true                # Whether to query HaveIBeenPwned / dehashed.
  allow_paid_apis: true                       # Whether to use APIs with per-call billing.
  max_llm_cost_usd: 50.0                      # Hard cap on LLM spend for this campaign.
```

**Minimum viable scope file** (everything else is optional):

```yaml
engagement:
  client: "Test Corp"
  engagement_id: "TEST-2026-001"
  authorized_by: "Self"
  authorization_date: "2026-05-01"
  start_date: "2026-05-01"
  end_date: "2026-12-31"

scope:
  in_scope:
    domains: ["example.com"]

constraints:
  max_tier: "T1"
  stealth_profile: "normal"
  max_llm_cost_usd: 5.0
```

---

## 5. CLI Reference

The TUI (`nexusrecon` with no args) is the primary entry point for interactive
use; the commands below are the headless / scripted interface and what the TUI
calls internally. Every command also accepts `--help`.

### `nexusrecon run`

Launch a new campaign.

```
nexusrecon run [OPTIONS]

Options:
  --scope / -s       PATH    Required. Path to scope YAML file.
  --seeds            TEXT    Comma-separated initial targets. Defaults to in_scope domains from scope file.
                             Seeds must be a subset of scope.in_scope.domains (exact match or subdomain).
                             Seeds outside the scope envelope are refused with a hard error, the scope
                             YAML is the legal boundary; --seeds is only the starting point within it.
  --mode / -m        TEXT    Campaign depth: light | medium | deep | monitor. Default: medium.
  --resume / -r      TEXT    Campaign ID to resume from checkpoint.
  --dry-run                  Validate scope and print plan. No tool invocations.
  --use-graph                Use the LangGraph workflow engine instead of sequential phase runner.
  --dispatch-mode    TEXT    Dynamic dispatch: lite (default) | full | off.
                             See "Dispatch Modes" below.
  --validate-creds           After Phase 7.5, attempt read-only validation of harvested credentials
                             via official APIs (AWS STS, GitHub /user, etc.). Off by default.
                             See "Credential Validation" below.
  --generate-phishing        Generate per-target phishing email drafts in the phishing package.
                             Authorized engagements only. See "Phishing Drafts" below.
```

#### `--seeds` precedence rules

When `--seeds` is omitted, `scope.in_scope.domains` becomes the seed list
(always in-scope by definition). When `--seeds` is provided:

1. Each seed is validated against `scope.in_scope.domains`. A seed passes if it
   is an exact match for a scope domain (e.g. `acme.com`) **or** a subdomain
   of one (e.g. `mail.acme.com`).
2. Any seed outside the scope envelope causes a hard error before any tool runs.
3. Valid seeds take priority over the scope domain list as the starting targets
   for Phase 1 passive footprinting.

Examples:

```bash
# Minimal run
nexusrecon run --scope examples/scopes/minimal_seed.yaml

# Specify seeds explicitly, must be in scope
nexusrecon run --scope my-scope.yaml --seeds "acme.com,mail.acme.com"

# This would hard-fail, "evil.com" is not in scope.in_scope.domains
# nexusrecon run --scope my-scope.yaml --seeds "acme.com,evil.com"

# Light mode, only T0 passive tools, fastest
nexusrecon run --scope my-scope.yaml --mode light

# Full dynamic dispatch, LLM selects targeted follow-up tools between every phase
nexusrecon run --scope my-scope.yaml --dispatch-mode full

# Credential harvest with validation + phishing drafts
nexusrecon run --scope my-scope.yaml --validate-creds --generate-phishing

# Dry run, validate scope, show plan, exit without running
nexusrecon run --scope my-scope.yaml --seeds "acme.com" --dry-run
```

> `--use-graph` switches to the LangGraph workflow engine (with SQLite
> checkpointing) instead of the sequential phase runner. Experimental, only
> use if you specifically need graph-state checkpointing for very long runs.

---

### Dispatch Modes

The **Dynamic Dispatcher** is a self-steering agent loop that asks the LLM to
propose additional targeted tool calls based on what the preceding phase found.

| Mode | Behaviour |
|------|-----------|
| `lite` | Runs after phases 1, 4, and 7 only (default) |
| `full` | Runs after every phase |
| `off` | Never runs, maximum determinism, minimum LLM cost |

Hard caps, always enforced regardless of mode:
- **Per-cycle cap**: at most 5 tools dispatched per invocation
- **Total cap**: at most 30 items in `dynamic_dispatch_log` per campaign

See `nexusrecon/docs/AGENT_LOOP.md` for the full dispatcher reference.

---

### Credential Validation

When `--validate-creds` is set, Phase 7.5 harvests credentials from exposed files
and then calls official read-only API endpoints to check each credential's validity:

| Credential type | Validation endpoint |
|----------------|---------------------|
| `aws_access_key` | `sts:GetCallerIdentity` (dry run, no actions taken) |
| `github_token` | `GET https://api.github.com/user` |
| `slack_token` | `GET https://slack.com/api/auth.test` |
| `azure_client_secret` | Azure login endpoint token exchange attempt |

Credentials are **never written to disk in plain text**. The `harvested_credentials.md`
report contains only masked values (`AKIA***KE`) and SHA-256 hashes.

To validate via Tor (hides the operator's IP from cloud provider logs), set:
```env
NEXUS_VALIDATE_VIA_TOR=true
NEXUS_TOR_PROXY=socks5h://127.0.0.1:9050
```

---

### Phishing Drafts

When `--generate-phishing` is set, the phishing package report is enriched with:
- Per-target email drafts tailored to the employee's inferred role
- Pretext hooks based on discovered job postings, recent company news, and tech stack
- Spear-phishing subject line options
- Recommended lure documents and pretexts

This flag is intended for authorized red team engagements only. The flag is
deliberately off by default to prevent accidental phishing asset generation.

### `nexusrecon validate`

Validate a scope YAML file and print a summary. No campaign is created.

```bash
nexusrecon validate examples/scopes/m365_enterprise.yaml
```

### `nexusrecon resume`

Resume a campaign from its last completed phase. Reads the saved state from the campaign directory.

```bash
nexusrecon resume nr-20260501-120000-abc12345
```

The campaign ID is printed at the start of every `run` command and is also the directory name inside `./campaigns/<client>/<engagement_id>/`.

### `nexusrecon diff`

Compare findings between two campaign runs to see what changed.

```bash
nexusrecon diff \
  ./campaigns/acme/ACM-Q1/nr-20260401-run1 \
  ./campaigns/acme/ACM-Q1/nr-20260501-run2
```

Output is JSON with new findings, count deltas, and entity changes.

### `nexusrecon tools`

List every registered tool with tier, category, and availability (based on current `.env` keys and installed binaries).

```bash
nexusrecon tools
```

### `nexusrecon config`

Show the current resolved configuration and which API keys are set.

```bash
nexusrecon config
```

### `nexusrecon campaign-list`

List all past campaigns found in the output directory.

```bash
nexusrecon campaign-list
nexusrecon campaign-list --client "Acme"   # Filter by client name
```

### `nexusrecon export`

Export campaign findings to CSV, JSON, or Markdown.

```bash
nexusrecon export nr-20260501-120000-abc12345 --format csv
nexusrecon export nr-20260501-120000-abc12345 --format markdown --output ./my-report.md
```

### `nexusrecon smoke`

Run the integration smoke test suite against synthetic data. Tests exercise real
module code (phase nodes, report engine, dispatcher) without requiring API keys or
network access. Skips are soft (missing network/LLM); hard failures indicate real
integration bugs.

```bash
nexusrecon smoke              # default, short tracebacks
nexusrecon smoke --verbose    # -v: show each test name
nexusrecon smoke --tb long    # full traceback on failure
nexusrecon smoke -k creds     # run only tests matching "creds"
```

Equivalent shell script: `./smoke_test.sh`

---

## 6. Module Walkthrough

The codebase lives entirely inside `nexusrecon/`. Here is every package and what it does.

---

### `nexusrecon/cli/`: Command-Line Interface

**`main.py`**, Typer application. Defines all CLI commands. Each command:
1. Loads and validates the scope file
2. Creates a `ScopeGuard` and wires it into the global `ToolRegistry` via `set_campaign_context()`
3. Builds an initial state dict (`CampaignGraphState`)
4. Runs phases sequentially inside a single `asyncio.run()` call (one event loop for the entire campaign)
5. Syncs the final state back to the `CampaignManager` Pydantic model
6. Calls `ReportEngine.generate_all()` then `campaign.finalize()`

The `use_graph` flag switches from the sequential phase runner to the LangGraph `run_workflow()` path, which supports checkpointing and the reflection node.

---

### `nexusrecon/core/`: Campaign Infrastructure

**`config.py`**, `NexusConfig` is a Pydantic BaseSettings class. It reads from environment variables and `.env` with `NEXUS_` prefix. The singleton is accessed via `get_config()` (LRU-cached). Call `config.get_secret("shodan_api_key")` to get decrypted secret values.

**`scope.py`**, Two classes:
- `ScopeModel`, Pydantic model that parses the scope YAML. Provides `scope_hash`, `tier_value()`, and `summary()`.
- `ScopeGuard`, Validates every tool invocation against the scope. Raises `OutOfScopeError` or `TierViolationError`. Called by `ToolRegistry.execute()` before any tool runs.
- `preflight_check(scope_model)`, Returns a list of `(level, message)` warnings before a campaign starts (e.g., expired engagement, shared infrastructure).

**`campaign.py`**, `CampaignManager` handles the full campaign lifecycle: directory creation, component initialization, phase checkpointing, and finalization. Key methods:
- `setup()`, Creates directory structure, initializes audit log, cache, entity graph, and cost tracker.
- `begin_phase(name)` / `end_phase(name, count, entities)`, Checkpoint boundaries.
- `finalize()`, Saves state, verifies audit chain, returns summary dict.

**`audit.py`**, `AuditLog` writes a hash-chained JSONL file to `logs/audit.jsonl`. Each entry SHA-256 hashes the previous entry so the chain can be verified for tampering. Used for legal defensibility. Key methods: `log_tool_start`, `log_tool_result`, `log_scope_violation`, `verify_chain()`.

**`cache.py`**, `Cache` is a SQLite-backed TTL store. Keys are `sha256(source + "|" + json(query))`. Each source type has its own TTL (e.g., crt.sh: 24h, Shodan: 6h, breach DBs: 7d). Shared with the LangGraph checkpoint database.

**`entity_graph.py`**, `EntityGraph` builds a NetworkX DiGraph of discovered entities (domains, subdomains, IPs, emails, cloud assets, repositories, secrets, CVEs, people). Supports `add_domain()`, `add_email()`, `add_subdomain()`, etc. Can export to pyvis HTML for interactive visualization and to CSV for Maltego.

**`cost_tracker.py`**, Tracks LLM token usage and API call costs. Enforces `max_llm_cost_usd` from the scope constraints.

---

### `nexusrecon/models/`: Pydantic Data Models

**`campaign.py`**, `CampaignState` is the canonical Pydantic model for serialized campaign state (written to `state.json`). `CampaignMode` enum: `light`, `medium`, `deep`, `monitor`. `PhaseStatus` enum.

**`scope.py`**, Pydantic models that mirror the scope YAML: `EngagementInfo`, `ScopeTargets`, `EngagementConstraints`, `ScopeModel`.

**`findings.py`**, `Finding` model. Fields: `title`, `severity` (critical/high/medium/low/info), `confidence` (0.0-1.0), `category`, `description`, `affected_assets`, `evidence`, `citations`, `mitre_techniques`.

---

### `nexusrecon/tools/`: OSINT Tool Library

**`base.py`**, `OSINTTool` is the abstract base class. Every tool must implement `async def run(self, target: str, **kwargs) -> ToolResult`. Class attributes: `name`, `tier`, `category`, `requires_keys`, `binary_required`, `target_types`.

`ToolResult` is a dataclass: `success`, `source`, `data` (dict), `error`, `runtime_ms`, `cached`, `result_count`.

**`registry.py`**, `ToolRegistry` is a singleton (`get_registry()`). It stores tool instances and provides `execute()`, the sole correct way to run a tool:
```python
result = await registry.execute("crtsh", "acme.com", "domain")
```
The `execute()` method: validates scope → checks cache → logs audit start → calls `tool.run()` → stores cache → logs audit result. The `@register_tool` decorator automatically registers a tool class at import time.

**`__init__.py`**, Imports all tool subpackages, triggering `@register_tool` on each class. Without this import, the registry would be empty.

**Category subpackages** (each `__init__.py` simply re-exports its tools):

| Package | Tools |
|---|---|
| `domain/` | crtsh, subfinder, amass, dns, whois, asn_bgp, passive_dns, email_sec, dnstwist |
| `cloud/` | azure_m365_recon, aws_recon, gcp_recon, cdn_detect |
| `identity/` | theharvester, hunter, email_format, breach_lookup, maigret |
| `intel/` | shodan, censys, virustotal, greynoise, urlscan, abuseipdb |
| `code/` | github_recon, gitleaks, trufflehog, gitdorker, postman, dockerhub |
| `web/` | httpx, gowitness, wayback, webtech, favicon, gau, dorks, metadata |
| `vuln/` | kev, nvd, epss |
| `pretext/` | news_intel, jobs_intel, sec_edgar |

---

### `nexusrecon/graph/`: LangGraph Workflow Engine

**`state.py`**, `CampaignGraphState` is a TypedDict defining the keys the graph passes between nodes. All phase functions accept and return this type.

**`nodes.py`**, One async function per phase (including `phase7_5_harvest` for
credential extraction). Each function:
1. Calls `registry.execute(tool_name, target, target_type)` for each applicable tool
2. Collects results into the relevant state keys (`subdomain_intel`, `email_intel`, etc.)
3. Calls `AgentExecutor.run_agent()` for LLM synthesis
4. Appends an `agent_messages` entry with the analysis
5. Appends the phase to `completed_phases` and returns the updated state

A `reflection_node` runs between phases, invoking the dynamic dispatcher when
`dispatch_mode` is `lite` or `full`.

**`dynamic_dispatcher.py`**, The self-steering dispatch loop. Key exports:
- `run_dynamic_dispatch(state)`, top-level entry point
- `MAX_PER_CYCLE = 5`, per-invocation tool cap
- `MAX_TOTAL = 30`, campaign-wide tool cap
- `CATEGORY_TO_STATE_KEY`, maps tool category → state dict key for result merging

See `nexusrecon/docs/AGENT_LOOP.md` for the full dispatcher reference.

**`workflow.py`**, `build_campaign_workflow(db_path, mode)` constructs the LangGraph `StateGraph`. Only adds phase nodes within the `mode`'s tier limit. Uses a local routing function `_route_next()` that routes among active phases based on `completed_phases`. `run_workflow()` compiles the graph with a SQLite checkpointer and streams results.

**`agent_executor.py`**, `AgentExecutor` bridges the LLM and the phase nodes. `run_agent(agent_name, task_data, task_prompt)` instantiates the named agent class, builds a prompt incorporating the agent's `role`, `goal`, and `backstory`, calls the LLM, and returns the analysis string. Falls back to `MockLLM` if no LLM keys are configured.

---

### `nexusrecon/agents/`: LLM Agent Personas

Each file defines an agent class inheriting from `BaseNexusAgent`. The class-level attributes (`role`, `goal`, `backstory`, `max_steps`) are used to prime the LLM prompt in `AgentExecutor._build_context()`.

| Agent Class | Agent Name | Role |
|---|---|---|
| `CampaignPlannerAgent` | campaign_planner | Designs reconnaissance strategy |
| `PassiveReconSpecialist` | passive_recon | Analyzes passive footprinting results |
| `ActiveReconSpecialist` | active_recon | Analyzes live probing results |
| `CloudIdentitySpecialist` | cloud_identity | M365/Azure/AWS/GCP exposure analysis |
| `PretextHumintAgent` | pretext_humint | HUMINT and social engineering research |
| `CorrelationAgent` | correlation | Cross-source finding correlation |
| `RiskAnalystAgent` | risk_analyst | Attack surface prioritization |
| `VulnCorrelatorAgent` | vuln_correlator | CVE/KEV matching against fingerprints |
| `EvidenceAuditorAgent` | evidence_auditor | Citation validation (blocks uncited findings) |
| `ExecutiveReporterAgent` | executive_reporter | Synthesizes final executive summary |

**`base.py`**, `BaseNexusAgent` is a plain class (not a dataclass). Key attributes: `role`, `goal`, `backstory`, `max_steps`, `tools`. `sanitize_scraped_content()` strips common prompt injection patterns before passing web-scraped content to the LLM.

---

### `nexusrecon/opsec/`: Operational Security

**`useragent.py`**, `UserAgentPool` rotates User-Agent strings. Strategies: `random`, `round_robin`. Used in Phase 6 HTTP probes.

**`rate_limiter.py`**, `SourceRateLimiter` implements async token bucket rate limiting per source. Prevents API bans from burst requests.

**`proxy.py`**, Proxy configuration management. Reads `NEXUS_PROXY_URL` and `NEXUS_TOR_PROXY` from config.

**`profiles.py`**, Stealth profile definitions (paranoid/high/normal/loud) controlling concurrency, delays, and proxy usage.

---

### `nexusrecon/reports/`: Report Engine

**`engine.py`**, `ReportEngine.generate_all(state)` generates every report from the final campaign state dict (17 deliverables total, see [`nexusrecon/docs/REPORT_GUIDE.md`](nexusrecon/docs/REPORT_GUIDE.md) for the index). Reports are pure Python string templating (no Jinja2 used for the core reports). The PDF report requires `weasyprint` (optional dependency, prints a console hint if missing). Reports are written to `./campaigns/<client>/<engagement_id>/<campaign_id>/reports/`.

---

## 7. Tool Inventory

Tools that require **no API keys and no binaries** work out of the box:

| Tool | What it does |
|---|---|
| `crtsh` | Certificate Transparency log search, subdomains from crt.sh |
| `dns` | DNS record sweep (A, AAAA, MX, NS, TXT, SOA, CNAME) |
| `whois` | Domain registration data |
| `asn_bgp` | ASN / BGP prefix lookup via bgpview.io |
| `azure_m365_recon` | M365 tenant/federation discovery (no-auth endpoints) |
| `aws_recon` | Public S3 bucket enumeration |
| `gcp_recon` | GCS bucket enumeration |
| `email_format` | Email format inference from collected addresses |
| `theharvester` | Email and subdomain harvesting (public sources) |
| `urlscan` | URL scan and screenshot data (public API, no key needed) |
| `wayback` | Wayback Machine URL enumeration |
| `kev` | CISA Known Exploited Vulnerabilities catalog |
| `nvd` | NVD CVE data |
| `epss` | EPSS exploit probability scores |
| `news_intel` | News API search for company intelligence |
| `jobs_intel` | Job listing intelligence (Adzuna) |
| `sec_edgar` | SEC EDGAR company filings |
| `dockerhub` | DockerHub image enumeration |
| `postman` | Postman public workspace enumeration |
| `cdn_detect` | CDN/WAF detection |
| `email_sec` | SPF / DMARC / DKIM record checks |
| `passive_dns` | Passive DNS (falls back gracefully without key) |
| `dnstwist` | Domain typosquatting enumeration |
| `webtech` | Web technology fingerprinting |
| `favicon` | Favicon hash matching (Shodan icon search) |
| `metadata` | Document metadata extraction |
| `dorks` | Google/Bing dork generation |

Tools requiring **API keys only** (no binary install):

| Tool | Required Keys |
|---|---|
| `shodan` | `SHODAN_API_KEY` |
| `censys` | `CENSYS_API_ID` + `CENSYS_API_SECRET` |
| `virustotal` | `VIRUSTOTAL_API_KEY` |
| `greynoise` | `GREYNOISE_API_KEY` |
| `abuseipdb` | `ABUSEIPDB_API_KEY` |
| `hunter` | `HUNTER_API_KEY` |
| `breach_lookup` | `HAVEIBEENPWNED_API_KEY` |
| `github_recon` | `GITHUB_TOKEN` |
| `gitdorker` | `GITHUB_TOKEN` |
| `passive_dns` | `SECURITYTRAILS_API_KEY` |

Tools requiring **binaries** (no API keys):

| Tool | Binary | Install |
|---|---|---|
| `subfinder` | `subfinder` | go install projectdiscovery/subfinder |
| `amass` | `amass` | go install owasp-amass/amass |
| `httpx` | `httpx` | go install projectdiscovery/httpx |
| `gitleaks` | `gitleaks` | brew install gitleaks |
| `trufflehog` | `trufflehog` | brew install trufflehog |
| `gowitness` | `gowitness` | go install sensepost/gowitness |
| `gau` | `gau` | go install lc/gau |
| `maigret` | `maigret` | pip install maigret |

---

## 8. Campaign Modes and Tier System

The full **tier definition table** (T0-T3, contact level, examples) lives in
[`README.md`](README.md#tier-system). This section documents how `--mode` maps
those tiers onto the phase runner.

### Mode → tier-cap and phase coverage

| Mode | Tier cap | Phases Run | Typical Time |
|---|---|---|---|
| `light` | T0 | 1-4, 7-9 | 5-15 min |
| `medium` | T2 | 1-5, 7-9 | 30-90 min |
| `deep` | T3 | All 9 | 2-6 hours |
| `monitor` | T0 | 1-4, 7-9 | 5-15 min (scheduled) |

**T2 and T3 phases only run if `max_tier` in the scope file allows it.** A scope with `max_tier: T1` will never execute Phase 5 (httpx) or Phase 6 (content discovery), regardless of the `--mode` flag, the scope file is the legal boundary, `--mode` is just an upper envelope below that boundary.

---

## 9. What Happens During a Campaign

### Phase 1: Passive Footprinting
Tools: `crtsh`, `subfinder`, `amass` (parallel), then `dns`, `whois`, `asn_bgp` (parallel per seed).  
Produces: `subdomain_intel` dict and `domain_intel` dict. The Passive Recon Specialist agent synthesizes the findings.

### Phase 2: Identity & Cloud
Tools: `azure_m365_recon`, `aws_recon`, `gcp_recon`, `theharvester`, `hunter`, `email_format`.  
Produces: `email_intel` (emails + inferred format) and `cloud_intel` (M365 federation type, S3 buckets, GCS buckets).

### Phase 3: Code Leakage
Tools: `github_recon`, `gitleaks`, `trufflehog`, `gitdorker`, `postman`, `dockerhub`, all run in parallel across seeds.  
Produces: `code_intel` (repos, secrets, API exposure).

### Phase 4: Correlation
No tool calls. Pure logic: correlates Phase 1-3 findings. Identifies executive emails, public buckets, M365 federation type, secret leaks. Produces `hypotheses`, `confirmed_leads`, `open_questions`, and a simple `entity_graph` dict (subdomains + emails lists). The Correlation Agent synthesizes.

### Phase 5: Light Active (T2 required)
Tools: `httpx` (parallel, Semaphore(20)), `shodan`, `virustotal`, `greynoise` (on IPs from httpx results).  
Produces: live host data in `infra_intel`. Skipped entirely if scope `max_tier` < T2.

### Phase 6: Active (T3 required)
No tool registry calls. Direct httpx probes with `UserAgentPool` and `Semaphore(25)`: alt-port sweep (30 subs × 9 ports) and content discovery (20 subs × 24 paths). Then `gowitness` screenshots.  
Produces: `alt_ports`, `discovered_paths`, and `screenshots` in `infra_intel`. Skipped entirely if scope `max_tier` < T3.

### Phase 7: Vulnerability Correlation
Tools: `kev` (CISA catalog), `nvd` (CVEs for fingerprinted products, parallel).  
Produces: `vuln_intel` with `enriched_cves` dict.

### Phase 7.5: Credential Harvest
Runs immediately after Phase 7, before attack surface scoring. Scans every
`infra_intel` discovered-paths entry for credential patterns:
- `.env` files: `KEY=VALUE` pairs matched against 25+ credential type patterns
- Git config files, CI/CD configs, log files  
- AWS access keys (`AKIA...`), GitHub tokens (`ghp_...`), JWTs, database URLs, etc.

Each credential is **masked** (`AKIA***KE`) and **hashed** (SHA-256 of the original
value). The original value is never stored. Set `--validate-creds` to attempt
read-only validation against official APIs.

Produces: `harvested_credentials` list of dicts.

### Phase 8: Attack Surface Prioritization
No tool calls. Scores all discovered CVEs using:

```
score = (cvss / 10) × max(epss, 0.05) × kev_multiplier × msf_multiplier
```

Where `kev_multiplier = 3.0` (CISA KEV) and `msf_multiplier = 2.5` (Metasploit module exists).
Scores are normalized to [0, 1]. Top 10 findings become `ranked_threads`.

Risk Analyst agent produces PRE-ATT&CK mapped attack surface matrix.

### Phase 9: Reporting
Evidence Auditor validates citations. Executive Reporter synthesizes the final summary. Then `ReportEngine.generate_all()` writes all report files.

### Between Phases: Reflection Node + Dynamic Dispatcher
A `reflection_node` runs between phases (both in `--use-graph` mode and in the
sequential runner). It:
1. Checks the step budget
2. Logs open hypothesis counts
3. Invokes the **Dynamic Dispatcher** if `dispatch_mode` is `lite` or `full`

The Dynamic Dispatcher asks the LLM to propose up to 5 additional targeted tool
calls, validates them against the tool registry, executes them, and merges results
back into the appropriate state keys. See `nexusrecon/docs/AGENT_LOOP.md` for full
documentation of the dispatch loop.

---

## 10. Manual Testing Guide

Work through these tests in order. Each section is self-contained and builds on the previous.

---

### Test 0: Installation Check

```bash
cd /Users/waifumachine/agentic-osint

# Verify the package is installed
pip3 show nexusrecon
# Expected: Name: nexusrecon: Location: ...

# Verify CLI is available
nexusrecon --help
# Expected: Usage: nexusrecon [OPTIONS] COMMAND [ARGS]...

# List the full tool catalogue. Most rows will show Available: False
# until you populate .env with API keys / install optional binaries.
nexusrecon tools
```

---

### Test 1: Scope Validation

```bash
# Valid scope, should print summary and no errors
nexusrecon validate examples/scopes/m365_enterprise.yaml

# Minimal test scope, create this file:
cat > /tmp/test-scope.yaml << 'EOF'
engagement:
  client: "Test Corp"
  engagement_id: "TEST-001"
  authorized_by: "Tester"
  authorization_date: "2026-01-01"
  start_date: "2026-01-01"
  end_date: "2027-12-31"

scope:
  in_scope:
    domains: ["example.com"]

constraints:
  max_tier: "T1"
  stealth_profile: "normal"
  max_llm_cost_usd: 5.0
EOF

nexusrecon validate /tmp/test-scope.yaml
# Expected: "Scope file is valid!" + scope summary
```

**What to look for:** No ERROR lines in the preflight warnings. If the engagement date is in the past, you'll see a WARNING but the campaign can still run.

---

### Test 2: Dry Run

```bash
nexusrecon run --scope /tmp/test-scope.yaml --seeds "example.com" --dry-run
```

**Expected output:**
```
Dry run, scope is valid, campaign ready.
Campaign ID: nr-YYYYMMDD-HHMMSS-xxxxxxxx
Output: ./campaigns/test_corp/TEST-001/nr-...
```

**What to check:** No exceptions. Campaign ID is printed. No `./campaigns/` directory is created yet (dry run writes nothing to disk).

---

### Test 3: Config Check

```bash
# Show what keys are configured
nexusrecon config
```

**Expected output:** A table listing all settings. API keys marked "Set" (green) or "Not set" (red). Without a `.env` file, all keys show "Not set", this is fine.

---

### Test 4: Light Mode Run (No API Keys Required)

This exercises Phases 1-4 and 7-9 using only public, no-key tools: crt.sh, DNS, WHOIS, ASN/BGP, KEV/NVD. It runs fully without any `.env` configuration.

```bash
nexusrecon run \
  --scope /tmp/test-scope.yaml \
  --seeds "example.com" \
  --mode light
```

**Expected behaviour:**
- Phase 1 runs: crt.sh, dns, whois, asn_bgp complete. subfinder/amass skip (binary not installed, that is fine).
- Phase 2 runs: azure_m365_recon, aws_recon, email_format complete. hunter skips (no key).
- Phase 3 runs: dockerhub, postman complete. github_recon skips (no token). gitleaks/trufflehog skip (no binary).
- Phase 4 runs: correlation logic on collected data.
- Phase 5 skips: httpx requires binary. But phase 5 only runs in medium/deep mode anyway.
- Phase 6 skips: T3 not permitted.
- Phase 7 runs: kev + nvd complete.
- Phase 8 runs: attack surface ranking.
- Phase 9 runs: reports generated.

**After the run, check the output:**
```bash
# Find your campaign ID from the run output, then:
ls ./campaigns/test_corp/TEST-001/
# Should contain one directory named nr-YYYYMMDD-...

ls ./campaigns/test_corp/TEST-001/nr-*/reports/
# Should contain: master_report.md, executive_summary.md, full_report.md,
# top_threads.md, asset_inventory.md, phishing_package.md, cloud_posture.md,
# attack_surface.md, vuln_correlation.md, findings.json, campaign_meta.json,
# and more (17 deliverables total, see nexusrecon/docs/REPORT_GUIDE.md).

cat ./campaigns/test_corp/TEST-001/nr-*/reports/executive_summary.md
cat ./campaigns/test_corp/TEST-001/nr-*/reports/findings.json
```

**What to check:**
- `findings.json` exists and is valid JSON.
- `campaign_meta.json` contains the correct scope hash and campaign ID.
- `audit.jsonl` exists in the `logs/` directory.
- No Python tracebacks in the terminal output. Phase errors are logged as `[red]Error in Phase N[/red]` inline but the campaign continues.

---

### Test 5: Verify Audit Chain

```bash
# Find your campaign's audit log
cat ./campaigns/test_corp/TEST-001/nr-*/logs/audit.jsonl | head -5
# Each line should be a JSON object with a "prev_hash" field

# The audit chain can be verified programmatically:
python3 -c "
import json, hashlib
from pathlib import Path

logs = list(Path('./campaigns').rglob('audit.jsonl'))
if not logs:
    print('No audit logs found')
else:
    log = logs[0]
    print(f'Checking: {log}')
    lines = [l for l in log.read_text().splitlines() if l.strip()]
    prev = 'genesis'
    ok = True
    for i, line in enumerate(lines):
        entry = json.loads(line)
        if entry.get('prev_hash') != prev and i > 0:
            print(f'CHAIN BROKEN at line {i}')
            ok = False
            break
        prev = hashlib.sha256(line.encode()).hexdigest()
    if ok:
        print(f'Audit chain VALID ({len(lines)} entries)')
"
```

---

### Test 6: Cache Behaviour

Run the same campaign twice. The second run should be significantly faster because tool results are cached in SQLite.

```bash
# First run (populates cache)
time nexusrecon run --scope /tmp/test-scope.yaml --seeds "example.com" --mode light

# Second run (reads from cache, should be faster)
time nexusrecon run --scope /tmp/test-scope.yaml --seeds "example.com" --mode light
```

The second run will produce a new campaign directory (new campaign ID). Results should come back faster because crt.sh, DNS, WHOIS, etc. return cached data.

---

### Test 7: Tool Registry Unit Check

Directly inspect the registry to confirm all tools are registered:

```bash
python3 -c "
from nexusrecon.tools import get_registry
registry = get_registry()
tools = registry.list_tools()
print(f'Total registered tools: {len(tools)}')
for t in sorted(tools, key=lambda x: x['name']):
    avail = 'YES' if t['available'] == 'True' else '---'
    print(f'  [{avail}] {t[\"name\"]:30s}  tier={t[\"tier\"]}  cat={t[\"category\"]}')
"
```

**Expected:** the full tool registry listed, grouped across the
category buckets (subdomain enumeration, breach data, code-leakage,
cloud posture, vuln intel, mobile, pretext, etc.). Without API keys or
binaries configured, most rows will show `---` for availability, that
is correct; the framework selects the keyed-up subset at runtime.

---

### Test 8: Scope Enforcement Unit Check

Verify that out-of-scope targets are blocked:

```bash
python3 -c "
from nexusrecon.core.scope import ScopeGuard, OutOfScopeError, ScopeModel

scope = ScopeModel.from_yaml('/tmp/test-scope.yaml')
guard = ScopeGuard(scope)

# This should pass (example.com is in scope)
try:
    guard.validate_target('example.com', 'domain', 'crtsh', 'T0')
    print('PASS: example.com is in scope')
except Exception as e:
    print(f'FAIL: {e}')

# This should raise OutOfScopeError (not-in-scope.com is not in scope)
try:
    guard.validate_target('not-in-scope.com', 'domain', 'crtsh', 'T0')
    print('FAIL: should have raised OutOfScopeError')
except OutOfScopeError as e:
    print(f'PASS: out-of-scope correctly blocked: {e}')
"
```

---

### Test 9: Cache Unit Check

```bash
python3 -c "
from nexusrecon.core.cache import Cache

cache = Cache(':memory:')

# Store a value
cache.set('crtsh', {'target': 'example.com'}, {'subdomains': ['api.example.com']})

# Retrieve it
result = cache.get('crtsh', {'target': 'example.com'})
assert result == {'subdomains': ['api.example.com']}, f'Got: {result}'
print('PASS: cache set/get works')

# Check stats
stats = cache.stats()
print(f'Cache stats: {stats}')
"
```

---

### Test 10: Run Existing Unit Tests

```bash
cd /Users/waifumachine/agentic-osint

# Run all unit tests
python3 -m pytest tests/unit/ -v

# Run a specific test file
python3 -m pytest tests/unit/test_scope.py -v
python3 -m pytest tests/unit/test_tool_registry.py -v
python3 -m pytest tests/unit/test_cache.py -v
```

**Expected:** All tests pass. Some may require mocked HTTP calls (handled by `respx` in the test suite).

---

### Test 11: Resume a Campaign

```bash
# Start a campaign
nexusrecon run --scope /tmp/test-scope.yaml --seeds "example.com" --mode light
# Note the campaign ID from the output: nr-YYYYMMDD-HHMMSS-xxxxxxxx

# Resume it (will skip already-completed phases)
nexusrecon resume nr-YYYYMMDD-HHMMSS-xxxxxxxx
```

**Expected:** The resume command prints the completed phases and skips them, then runs any incomplete phases. Since all phases likely completed on the first run, the resume may print "Skipped (done)" for each phase and go straight to report generation.

---

### Test 12: Adding a GitHub Token (if available)

```bash
# Add to .env:
echo "GITHUB_TOKEN=ghp_your_token_here" >> .env

# Reload config (run a new command to pick up the change)
nexusrecon config
# Should show github_token: Set

# Run a medium mode campaign, github_recon and gitdorker will now execute
nexusrecon run --scope /tmp/test-scope.yaml --seeds "example.com" --mode medium
```

---

### Test 13: Export Findings

```bash
CAMPAIGN_ID=$(ls ./campaigns/test_corp/TEST-001/ | head -1)

# Export to CSV
nexusrecon export $CAMPAIGN_ID --format csv --output /tmp/findings.csv
cat /tmp/findings.csv

# Export to Markdown
nexusrecon export $CAMPAIGN_ID --format markdown --output /tmp/findings.md
cat /tmp/findings.md
```

---

### Test 14: Diff Two Campaigns

```bash
RUNS=($(ls ./campaigns/test_corp/TEST-001/))
if [ ${#RUNS[@]} -ge 2 ]; then
  nexusrecon diff \
    ./campaigns/test_corp/TEST-001/${RUNS[0]} \
    ./campaigns/test_corp/TEST-001/${RUNS[1]}
fi
```

---

### Test 15: LangGraph Mode

```bash
nexusrecon run \
  --scope /tmp/test-scope.yaml \
  --seeds "example.com" \
  --mode light \
  --use-graph
```

**Expected:** Same output as the sequential runner but using LangGraph's state graph internally. The SQLite checkpointer writes state to `nexusrecon.db` in the campaign directory, enabling mid-run resume via LangGraph's built-in checkpointing.

---

## 11. Output Structure

Every campaign creates a directory tree under `NEXUS_OUTPUT_DIR` (default `./campaigns/`):

```
campaigns/
└── <client_name>/                  ← e.g. test_corp
    └── <engagement_id>/            ← e.g. TEST-001
        └── nr-YYYYMMDD-HHMMSS-xxxx/   ← campaign ID
            ├── state.json              ← Full LangGraph state (all intel dicts)
            ├── scope_metadata.json     ← Scope + engagement metadata + scope hash
            ├── nexusrecon.db           ← SQLite: cache + LangGraph checkpoint
            ├── logs/
            │   └── audit.jsonl         ← Hash-chained audit trail
            ├── artifacts/              ← Tool output artifacts (screenshots, etc.)
            └── reports/
                ├── master_report.md            ← Single cohesive client deliverable
                ├── executive_summary.md
                ├── full_report.md
                ├── top_threads.md              ← Top 10 ranked attack paths
                ├── asset_inventory.md
                ├── asset_inventory.json
                ├── asset_inventory.csv
                ├── phishing_package.md
                ├── cloud_posture.md
                ├── attack_surface.md
                ├── vuln_correlation.md
                ├── people_map.md
                ├── vendor_supply_chain.md
                ├── harvested_credentials.md    ← Only if creds were found (Secret)
                ├── findings.json
                ├── campaign_meta.json
                ├── maltego_export.csv
                └── report.pdf                  ← Only if weasyprint is installed
```

The canonical index with content schemas is
[`nexusrecon/docs/REPORT_GUIDE.md`](nexusrecon/docs/REPORT_GUIDE.md).

### Key Files

**`state.json`**, The complete serialized `CampaignGraphState`. Contains all raw intelligence: every subdomain, email, cloud finding, code leak, infra probe result, hypothesis, confirmed lead, and finding. This is the source of truth for resume and diff operations.

**`audit.jsonl`**, Every tool invocation logged with timestamps, response hashes, and hash-chained signatures. Line-by-line JSON. Verify chain integrity with `verify_chain()`.

**`findings.json`**, Array of `Finding` objects with severity, confidence, MITRE techniques, affected assets, and evidence citations.

**`campaign_meta.json`**, Scope hash, engagement metadata, campaign ID, timestamps.

---

## 12. Troubleshooting

### `ModuleNotFoundError: No module named 'nexusrecon'`

The package is not installed. Run:
```bash
pip3 install -e ".[dev]"
```

### `nexusrecon: command not found`

The pip scripts directory is not in your `PATH`. Either use `python3 -m nexusrecon.cli.main` or add `~/.local/bin` (or your virtualenv's `bin/`) to `PATH`.

### `Scope validation failed: engagement period has expired`

Your scope YAML's `end_date` is in the past. Either update the date or use one of the example scopes which have future-dated end dates.

### Campaign completes but `findings.json` is empty

This is expected on a first run with no API keys and well-known public test domains like `example.com`, the site is extremely minimal with almost no attack surface to report. Try with a real domain that has complex infrastructure. Findings are produced by agent synthesis, which requires interesting input data.

### All phases show `[red]Error in Phase N: Tool 'X' not registered[/red]`

The tool modules failed to import, leaving the registry empty. Check for import errors:
```bash
python3 -c "import nexusrecon.tools"
```

### `asyncio.run() cannot be called from a running event loop`

You are calling the CLI from within a Jupyter notebook or another async context that already has a running event loop. Use `nest_asyncio`:
```python
import nest_asyncio
nest_asyncio.apply()
```
Or run the CLI from a plain terminal.

### Tool X always skipped even though I set the API key

The key is read at tool instantiation (which happens at import time via `@register_tool`). If you set the key in `.env` after import, the old `get_config()` singleton was already cached without the key. Restart your Python process after changing `.env`.

### Weasyprint error on PDF report

Install the optional dependency:
```bash
pip3 install "nexusrecon[pdf]"
```
On macOS this also requires Pango/Cairo via Homebrew:
```bash
brew install pango
```

### The audit chain shows BROKEN

This should not happen in normal operation. It can happen if you manually edited `audit.jsonl` or if a crash interrupted a write mid-line. The chain being broken does not prevent the campaign from running, it only affects legal defensibility of the log.

### ToolResult.success is False for every tool

Check `nexusrecon config` to confirm API keys are set. Also check that the target is in scope, a scope violation returns a failed `ToolResult` rather than raising an exception.

### `error: externally-managed-environment`

PEP 668. You ran `pip install` outside a venv on a modern OS (Homebrew Python,
Debian 12+, Ubuntu 23+, Fedora 38+). Solution:

```bash
python3.13 -m venv venv
source venv/bin/activate
pip install -e .
```

Or just run `./install.sh`, it creates the venv automatically.

### `ERROR: Could not find a version that satisfies the requirement crewai>=0.80.0`

Your Python is too new. CrewAI requires Python <3.14. Solution:

```bash
brew install python@3.13        # macOS
# or: apt-get install python3.13 python3.13-venv   (Debian/Ubuntu)
deactivate 2>/dev/null; rm -rf venv
PYTHON=python3.13 ./install.sh
```

### `nexusrecon: command not found` after install

The venv is not activated in your current shell. Every new terminal session requires:

```bash
source venv/bin/activate
which nexusrecon   # should show .../venv/bin/nexusrecon
```

Add `source /path/to/agentic-osint/venv/bin/activate` to your shell's rc file
(`~/.zshrc`, `~/.bashrc`) to activate automatically.

---

*This manual covers NexusRecon v0.5.0 (pre-beta, extensible tool registry, dynamic dispatch, credential harvest, attack surface scoring, interactive TUI). Authorized use only, see DISCLAIMER.md.*
