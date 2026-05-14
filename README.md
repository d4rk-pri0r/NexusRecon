# NexusRecon

**Agentic OSINT Orchestration Framework** — production-grade reconnaissance for professional red team engagements.

> **Authorized use only.** Requires a signed scope file before any tool runs. Every tool invocation is validated against scope and logged to a tamper-evident audit chain.

---

## What's New in v2

- **89 OSINT tools** — 39 new tools across breach, mobile, social, vulnerability, and web categories
- **Dynamic Dispatch Agent** — self-steering reconnaissance loop; an LLM agent proposes and executes targeted follow-up tool calls between phases (`--dispatch-mode lite|full|off`)
- **Phase 7.5 — Credential Harvest** — extracts, masks, and hashes credentials found in exposed `.env` files, config files, and code repositories; optional read-only validation (`--validate-creds`)
- **Phase 8 — Attack Surface Ranking** — scores every finding with `(cvss/10) × EPSS × KEV-boost × Metasploit-boost` and emits a ranked `top_threads.md`
- **Phishing Package generation** — `--generate-phishing` enriches the phishing package with per-employee bundles and breach cross-references (authorized engagements only)
- **Smoke test suite** — `nexusrecon smoke` / `./smoke_test.sh` runs 6 integration tests against synthetic data in ~2 seconds
- **New state keys**: `breach_intel`, `mobile_intel`, `social_intel`, `dark_intel`, `ranked_threads`, `harvested_credentials`, `dynamic_dispatch_log`
- **New reports**: `top_threads.md`, `harvested_credentials.md`

---

## Architecture

```mermaid
graph TB
    CLI["CLI (Typer)"] --> Scope[Scope Guard]
    Scope --> Planner[Campaign Planner Agent]
    Planner --> LG[LangGraph Workflow]

    subgraph "CrewAI Agents"
        P1[Passive Recon]
        P2[Active Recon]
        P3[Cloud & Identity]
        P4[Pretext & HUMINT]
        P5[Correlation]
        P6[Risk Analyst]
        P7[Vuln Correlator]
        P8[Evidence Auditor]
        P9[Reporter]
    end

    LG --> P1
    LG --> P2
    LG --> P3
    LG --> P4
    LG --> P5
    LG --> P6
    LG --> P7
    LG --> P8
    LG --> P9

    subgraph "Tools (89)"
        T1[crt.sh, Subfinder, Amass]
        T2[WHOIS, DNS, Passive DNS]
        T3[Azure/M365, AWS, GCP]
        T4[Shodan, Censys, VT]
        T5[GitHub, gitleaks, TruffleHog]
        T6[Email, Breach, Hunter]
        T7[httpx, gowitness (T2)]
    end

    P1 --> T1
    P1 --> T2
    P3 --> T3
    P2 --> T7
    P1 --> T4
    P1 --> T5
    P1 --> T6

    LG --> EntityGraph[(Entity Graph)]
    EntityGraph --> Reports[Report Engine]
    Reports --> MD[Markdown + JSON]
    Reports --> CSV[Maltego CSV]
    Reports --> HTML[pyvis HTML]

    LG --> SQLite[(SQLite State)]
    SQLite -.->|resume| LG

    subgraph "Guardrails"
        SG[Scope Enforcement]
        AL[Audit Chain]
        CT[Cost Tracking]
        RL[Rate Limiter]
    end

    Scope --> SG
    SG --> AL
    SG --> CT
    SG --> RL
```

## Quick Start

### 1. Install

**Recommended path** (handles Python venv + system binaries automatically):

```bash
git clone <repo> && cd agentic-osint
./install.sh
source venv/bin/activate
```

**Python 3.13 is required** (not 3.14 — CrewAI compatibility). If your
default `python3` is 3.14, override:

```bash
PYTHON=python3.13 ./install.sh
```

**Manual install** (if you prefer to manage your own venv):

```bash
python3.13 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
./install.sh --skip-python    # binaries only
```

After install, you must `source venv/bin/activate` in every new shell
session before running `nexusrecon`.

**Or use Docker:**

```bash
docker compose up -d
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your API keys (SHODAN_API_KEY, ANTHROPIC_API_KEY, etc.)
```

### 3. Create a Scope File

Start from the minimal template — it only requires a single seed domain:

```bash
cp examples/scopes/minimal_seed.yaml my-scope.yaml
# Edit: set client, engagement_id, authorized_by, dates, and your target domain
```

The minimal scope (`minimal_seed.yaml`) is the recommended starting point.
Fully-populated examples (with IP ranges, cloud account IDs, etc.) are in
`examples/scopes/*_completed_example.yaml` — they show what a mature engagement
scope looks like, but you do **not** need all those fields to start a campaign.
NexusRecon discovers assets from your single seed domain automatically.

### 4. Validate and Run

```bash
# Validate scope
nexusrecon validate my-scope.yaml

# Dry run (no tool execution)
nexusrecon run --scope my-scope.yaml --seeds "acme.com" --dry-run

# Light mode (T0 only, ~5-10 min)
nexusrecon run --scope my-scope.yaml --seeds "acme.com" --mode light

# Medium mode (default, T0-T1, ~30-60 min)
nexusrecon run --scope my-scope.yaml --seeds "acme.com" --mode medium

# Full dynamic dispatch — LLM selects follow-up tools between every phase
nexusrecon run --scope my-scope.yaml --seeds "acme.com" --dispatch-mode full

# Credential harvest + phishing drafts (authorized engagements only)
nexusrecon run --scope my-scope.yaml --seeds "acme.com" --validate-creds --generate-phishing

# Deep mode (T0-T2, ~2-6 hrs)
nexusrecon run --scope my-scope.yaml --seeds "acme.com" --mode deep
```

### 5. Resume a Campaign

```bash
nexusrecon resume nr-20260501-120000-abc12345
```

### 6. Diff Campaigns

```bash
nexusrecon diff ./campaigns/acme/run1 ./campaigns/acme/run2
```

---

## Commands

| Command | Description |
|---|---|
| `nexusrecon run --scope <file>` | Launch a campaign |
| `nexusrecon validate <file>` | Validate scope file |
| `nexusrecon resume <id>` | Resume from checkpoint |
| `nexusrecon diff <old> <new>` | Compare two campaigns |
| `nexusrecon tools` | List registered tools |
| `nexusrecon config` | Show current configuration |
| `nexusrecon smoke` | Run the integration smoke test suite |

---

## Campaign Modes

| Mode | Tier | Depth | Time | Cost |
|---|---|---|---|---|
| `light` | T0 only | 1 | 5-10 min | $ |
| `medium` | T0-T1 | 2 | 30-60 min | $$ |
| `deep` | T0-T2/T3 | 4 | 2-6 hrs | $$$ |
| `monitor` | Configurable | Configurable | Scheduled | $$ |

---

## Deliverables

Every campaign automatically produces:

1. `executive_summary.md` — 1-page red-team summary
2. `full_report.md` — Complete findings with methodology
3. `top_threads.md` — Top 10 ranked attack threads (KEV × EPSS × CVSS scored)
4. `asset_inventory.md` + `.json` + `.csv` — All discovered assets
5. `phishing_package.md` — Validated emails, pretext hooks, DMARC gaps
6. `cloud_posture.md` — M365 federation, AWS account, public cloud assets
7. `attack_surface.md` — Likelihood × impact matrix, PRE-ATT&CK mapped
8. `vuln_correlation.md` — CVE/KEV findings matched to fingerprinted tech
9. `harvested_credentials.md` — Masked + hashed exposed credentials (**Secret**)
10. `findings.json` — Raw findings with full provenance and evidence hashes
11. `campaign_meta.json` — Campaign metadata and scope hash
12. `maltego_export.csv` — Maltego-compatible entity CSV

See `nexusrecon/docs/REPORT_GUIDE.md` for the full report file index.

Output path: `./campaigns/<client>/<engagement_id>/<campaign_id>/reports/`

---

## Tier System

| Tier | Name | Description | Examples |
|---|---|---|---|
| T0 | Pure Passive | Zero contact with target infrastructure | crt.sh, Shodan, GitHub, breach DBs, WHOIS |
| T1 | Semi-Passive | DNS resolution, passive DNS, indirect probing | DNS sweep, SecurityTrails, urlscan |
| T2 | Light Active | HTTP probes, screenshots, fingerprinting | httpx, gowitness, favicon hashing |
| T3 | Active | Brute force, content fuzzing | ffuf, gobuster, recursive amass |

**Default is T1.** T2 and T3 require explicit scope authorization.

---

## Stealth Profiles

| Profile | Concurrency | Delay | Proxy | UA Rotation |
|---|---|---|---|---|
| `paranoid` | 1 thread | 3-10s | Tor | Every request |
| `high` | 3 threads | 1-3s | Proxy | Every 5 requests |
| `normal` | 10 threads | 0.2-0.8s | None | Every 10 requests |
| `loud` | 20 threads | 0s | None | Disabled |

---

## Adding a New Tool

```python
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

@register_tool
class MyTool(OSINTTool):
    name = "my_tool"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = ["MY_API_KEY"]
    description = "Does something useful"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs) -> ToolResult:
        # Your tool logic here
        return ToolResult(success=True, source=self.name, data={})
```

See `plugins/example/my_tool.py` for a complete annotated example.

---

## LLM Providers

| Provider | Env Var | Notes |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | Primary — best quality |
| OpenAI | `OPENAI_API_KEY` | Alternative |
| Ollama | `OLLAMA_BASE_URL` | Local, air-gapped friendly |
| llama.cpp | Via Ollama | Local, resource-constrained |

Set via `NEXUS_LLM_PROVIDER` and `NEXUS_LLM_MODEL` in `.env`.

---

## Legal & Scope Enforcement

- **Hard fail** on missing or unsigned scope
- **Pre-flight validation** checks date range, SOW hash, shared infrastructure
- **Every tool call** validated against scope before execution
- **Out-of-scope targets** are dropped with audit log entry
- **ROE banner** displayed at every campaign start
- **Scope hash** embedded in every output artifact
- **Tamper-evident audit log** (hash-chained JSONL)

---

## Project Structure

```
nexusrecon/
├── cli/              # Typer CLI (run, validate, resume, diff, tools, smoke, ...)
├── core/             # Scope, audit, cache, entity graph, cost tracker
├── models/           # Pydantic data models
├── opsec/            # Stealth profiles, rate limiter, UA pool, proxy
├── tools/            # 89 OSINT tools organized by category
│   ├── domain/       # WHOIS, DNS, crt.sh, subfinder, amass, etc.
│   ├── cloud/        # Azure/M365, AWS, GCP, CDN, bucket_enum
│   ├── identity/     # theHarvester, Hunter, email format, breach, holehe
│   ├── breach/       # HaveIBeenPwned, HudsonRock, EmailRep, LeakCheck
│   ├── code/         # GitHub, gitleaks, TruffleHog, gitdorker, Postman, DockerHub
│   ├── intel/        # Shodan, Censys, VT, GreyNoise, BinaryEdge, Netlas, …
│   ├── web/          # Wayback, httpx, gowitness, WAF/CMS/TLS detection, …
│   ├── vuln/         # NVD, KEV, EPSS, ExploitDB, Vulners, GitHub Advisory
│   ├── mobile/       # Play Store, APK Analyzer
│   └── pretext/      # News, jobs, SEC EDGAR, GitHub org, LinkedIn dorks, …
├── agents/           # LLM agent personas (passive recon, cloud, dispatch, …)
├── graph/            # LangGraph workflow (nodes, workflow, dynamic_dispatcher)
├── reports/          # Report engine
├── docs/             # AGENT_LOOP.md, REPORT_GUIDE.md
├── ui/               # Streamlit dashboard
plugins/              # Example plugin
configs/              # Defaults and per-client overlays
examples/scopes/      # Sample scope files
tests/
├── unit/             # 180+ unit tests
└── smoke/            # 6 end-to-end smoke tests (synthetic data)
```

---

## License

Proprietary — authorized use only. See DISCLAIMER.md.

---

*Built for defenders who test like attackers — with permission.*
