```
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
           R E C O N   v 0 . 5 . 0
```

# NexusRecon

**Agentic OSINT orchestration framework for authorized red-team reconnaissance.**

[![status](https://img.shields.io/badge/status-pre--beta-orange)](#status)
[![version](https://img.shields.io/badge/version-0.5.0-blue)](nexusrecon/__init__.py)
[![python](https://img.shields.io/badge/python-3.11--3.13-blue)](pyproject.toml)
[![tools](https://img.shields.io/badge/tools-89-green)](MANUAL.md#7-tool-inventory)
[![license](https://img.shields.io/badge/license-proprietary-red)](DISCLAIMER.md)

NexusRecon plans, executes, and reports on a full passive-to-light-active OSINT
campaign against a scope you authorize — running 89 reconnaissance tools across
a 9-phase pipeline, steered between phases by an LLM dispatcher that proposes
targeted follow-up queries based on what the previous phase actually found.

> ⚠ **Authorized use only.** Every tool invocation is validated against a signed
> scope file. Out-of-scope targets are silently dropped and logged. Use only
> against systems you have explicit written permission to test. See
> [DISCLAIMER.md](DISCLAIMER.md).

---

## What it does

You hand NexusRecon a scope file and a seed domain. It hands you back:

- A **ranked attack-thread report** (`top_threads.md`) — the 10 most actionable
  paths into the target, scored by `CVSS × EPSS × KEV-boost × Metasploit-boost`.
- A **master narrative report** (`master_report.md`) — one cohesive document
  written by an LLM that walks a client through what was found and what it means.
- An **asset inventory**, **phishing package**, **cloud posture report**, an
  **attack-surface matrix**, **vuln correlation**, and a **Maltego CSV** export
  — every artifact tagged with the scope hash and a hash-chained audit log.

Between phases an LLM **dynamic dispatcher** inspects what's been collected and
fires extra targeted tool runs to fill gaps the static pipeline missed — for
example, if Phase 1 turns up an Android app, the dispatcher will queue the APK
analyzer against that package before Phase 2 begins.

---

## How it works

```
   ┌──────────┐    ┌─────────────┐    ┌──────────────────┐
   │  Scope   ├───►│  Campaign   ├───►│  9-phase pipeline │
   │  YAML    │    │  Manager    │    │  + dispatcher    │
   └──────────┘    └─────────────┘    └────────┬─────────┘
                                               │
       ┌───────────────────────────────────────┘
       │
       ▼
  ┌─────────────────────────────────────────────────────────┐
  │  Campaign state (subdomains · emails · cloud · code     │
  │  · infra · vulns · breaches · creds · findings · ...)   │
  └────────┬──────────────────┬────────────────────┬────────┘
           │                  │                    │
           ▼                  ▼                    ▼
     ┌──────────┐       ┌──────────┐         ┌──────────────┐
     │ 89 tools │       │ 8 LLM    │         │  Dynamic     │
     │ T0–T3    │       │ phase    │         │  dispatcher  │
     │ (passive │       │ agents   │         │  (between    │
     │ → active)│       │          │         │   phases)    │
     └──────────┘       └──────────┘         └──────────────┘
           │                  │                    │
           └────────────┬─────┴────────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │   Report engine    │
              │   17 deliverables  │
              │   MD · JSON · CSV  │
              │   HTML · PDF       │
              └───────────────────┘
```

For the full architecture — phase pipeline, agent personas, dispatcher loop,
state-key conventions, scoring formula — see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Quick start

### 1. Install

```bash
git clone https://github.com/d4rk-pri0r/NexusRecon.git
cd NexusRecon
./install.sh                  # creates venv, installs Python deps + system binaries
source venv/bin/activate
```

**Python 3.13 is recommended** (3.11–3.13 supported; **not 3.14** — CrewAI
incompatibility). If `python3` points at 3.14:

```bash
PYTHON=python3.13 ./install.sh
```

### 2. Launch the TUI

```bash
nexusrecon
```

Running with no arguments opens an interactive Textual UI:

```
   ┌─ NexusRecon — Agentic OSINT Orchestration ─────────────────┐
   │                                                            │
   │              [ N E X U S R E C O N    v 0.5.0 ]            │
   │                                                            │
   │       89 tools registered · 0 campaigns · LLM: anthropic   │
   │                                                            │
   │       🎯  New Campaign      (n)                            │
   │       🔄  Resume Campaign   (r)                            │
   │       📊  Past Campaigns    (p)                            │
   │       🔧  Configuration     (c)                            │
   │       🛠   Tools             (t)                            │
   │       ❌  Quit               (q)                            │
   │                                                            │
   │     ↑/↓ navigate · Enter select · letter shortcut quick    │
   └────────────────────────────────────────────────────────────┘
```

From the TUI you can:

- Walk a **new-campaign wizard** that builds the scope file for you
- **Edit API keys** in `.env` via a masked editor (the Configuration screen)
- **Browse the tool catalogue** and see which tools are unlocked by which keys
- **Resume** or **diff** prior campaigns

### 3. Or use the CLI directly

```bash
# Validate a scope file
nexusrecon validate examples/scopes/minimal_seed.yaml

# Dry-run (validate scope + show plan, no tools fired)
nexusrecon run --scope examples/scopes/minimal_seed.yaml --dry-run

# Light passive sweep (T0 only, ~5–10 min)
nexusrecon run --scope my-scope.yaml --seeds acme.com --mode light

# Default run with the dispatcher running in lite mode (T0+T1, ~30–60 min)
nexusrecon run --scope my-scope.yaml --seeds acme.com

# Full agentic dispatch — LLM picks follow-up tools between every phase
nexusrecon run --scope my-scope.yaml --seeds acme.com --dispatch-mode full

# Credential harvest + phishing drafts (authorized engagements only)
nexusrecon run --scope my-scope.yaml --seeds acme.com \
  --validate-creds --generate-phishing

# Resume from a checkpoint
nexusrecon resume nr-20260514-120000-abc12345
```

`nexusrecon --help` lists every command. The full reference is in
[`MANUAL.md`](MANUAL.md#5-cli-reference).

---

## Capabilities

| Phase | What it does | Sample tools |
|-------|-------------|--------------|
| **1. Passive footprint** | Subdomain harvest, cert transparency, WHOIS, DNS | crt.sh, Subfinder, Amass, SecurityTrails |
| **2. Active surface** | HTTP probing, screenshotting, tech fingerprint | httpx, gowitness, WAF/CMS/TLS detection |
| **3. Cloud & identity** | M365 federation, S3/GCS buckets, AWS account ID | Azure/M365 enumerator, bucket_enum, AWS recon |
| **4. Correlation** | Cross-source asset linking, attribution scoring | (LLM agent, no tools) |
| **5. People & pretext** | Org chart inference, breach lookup, HUMINT leads | Hunter, HIBP, EmailRep, news, SEC EDGAR |
| **6. Threat intel** | Shodan, Censys, GreyNoise, VirusTotal, urlscan | (intel category, 12 sources) |
| **7. Vuln correlation** | NVD + KEV + EPSS + ExploitDB + GH Advisory | CVE matcher, KEV lookup, EPSS scorer |
| **7.5. Cred harvest** | Mask + hash creds in exposed `.env` / configs | gitleaks, TruffleHog, infra_probe |
| **8. Attack surface rank** | `CVSS × EPSS × KEV × Metasploit` scoring | (scoring engine) |
| **9. Reporting** | LLM-synthesized narrative + 17 deliverables | (master_reporter agent) |

**89 tools across 17 categories** — see [`MANUAL.md`](MANUAL.md#7-tool-inventory)
for the full catalogue.

---

## Tier system

| Tier | Name | Contact with target | Examples |
|------|------|---------------------|----------|
| T0 | Pure passive | None — public datasets only | crt.sh, Shodan, GitHub, breach DBs, WHOIS |
| T1 | Semi-passive | DNS resolution, passive DNS | DNS sweep, SecurityTrails, urlscan |
| T2 | Light active | HTTP probes, screenshots | httpx, gowitness, favicon hashing |
| T3 | Active | Brute force, fuzzing | ffuf, gobuster, recursive amass |

**Default ceiling is T1.** T2 and T3 require explicit scope authorization.
Out-of-tier tools are dropped with an audit-log entry, not executed silently.

---

## Deliverables

Every campaign writes to `./campaigns/<client>/<engagement>/<campaign-id>/reports/`:

- `master_report.md` — single cohesive narrative for the client
- `executive_summary.md` — one-page exec-level brief
- `top_threads.md` — top 10 ranked attack paths
- `attack_surface.md` — likelihood × impact matrix, PRE-ATT&CK mapped
- `phishing_package.md` — validated emails, pretext hooks, DMARC gaps
- `cloud_posture.md` — M365 federation, AWS account, public buckets
- `vuln_correlation.md` — CVE/KEV findings matched to fingerprinted tech
- `harvested_credentials.md` — masked + hashed exposed creds (treat as **Secret**)
- `asset_inventory.md` / `.json` / `.csv` — discovered assets
- `findings.json` — every `Finding` with severity, confidence, MITRE, evidence
- `maltego_export.csv` — Maltego-compatible entity import
- `report.pdf` — full report as PDF (requires `weasyprint`)

Full index with content schemas: [`nexusrecon/docs/REPORT_GUIDE.md`](nexusrecon/docs/REPORT_GUIDE.md).

---

## Configuration

NexusRecon reads secrets and toggles from a `.env` file in the project root.

The fastest path is the TUI: launch `nexusrecon`, press `c`, and the
Configuration screen presents every editable variable in 11 categories
(LLM provider, intel APIs, email/identity, vuln intel, OPSEC, cloud, storage,
debug, vault, etc.). Values are masked, saved atomically, and the file is
`chmod 0o600`'d on disk.

Manual edit is also fine:

```bash
cp .env.example .env
$EDITOR .env
```

Required for any meaningful run:

- One LLM provider key — `ANTHROPIC_API_KEY` (recommended) or `OPENAI_API_KEY`,
  or set `NEXUS_LLM_PROVIDER=ollama` for a local model.

Recommended:

- `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, `HUNTER_API_KEY`,
  `HAVEIBEENPWNED_API_KEY`, `GITHUB_TOKEN`.

Per-key tool-unlock matrix: [`CONFIGURATION_GUIDE.md`](CONFIGURATION_GUIDE.md).

---

## Documentation

| Doc | Audience | What's in it |
|-----|----------|--------------|
| [`README.md`](README.md) (this) | First-time visitor | What is it, how to start |
| [`MANUAL.md`](MANUAL.md) | Operator | Install, scope, CLI ref, tool inventory, troubleshooting |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Engineer / curious operator | Phase pipeline, agents, dispatcher, scoring, invariants |
| [`CONFIGURATION_GUIDE.md`](CONFIGURATION_GUIDE.md) | Operator setting up keys | Every env var, which tools each unlocks |
| [`BETA_TESTING_GUIDE.md`](BETA_TESTING_GUIDE.md) | Beta tester | First campaign walkthrough, what to file as bugs |
| [`DISCLAIMER.md`](DISCLAIMER.md) | Everyone | Authorized-use policy, legal terms |
| [`nexusrecon/docs/AGENT_LOOP.md`](nexusrecon/docs/AGENT_LOOP.md) | Engineer | Dynamic dispatcher internals |
| [`nexusrecon/docs/REPORT_GUIDE.md`](nexusrecon/docs/REPORT_GUIDE.md) | Operator | Every output file and its schema |

---

## Status

**v0.5.0 — pre-beta.** Closed-beta testing in progress; APIs and report
formats may shift before 1.0. We track open issues in
[`ITERATION_BACKLOG.md`](ITERATION_BACKLOG.md).

What's stable:

- 9-phase pipeline + credential harvest
- 89-tool registry with scope-gated execution
- LLM dispatcher (lite / full / off)
- Audit chain, cost tracking, rate limiter
- Master report + 16 other deliverables

What's still moving:

- Plugin discovery API
- Vault integration (`AGENT_LOOP.md` references a `VaultStore`; today secrets
  live in `.env`)
- Some niche tools are stubs awaiting API access

If you want to help shape the 1.0, see [`BETA_TESTING_GUIDE.md`](BETA_TESTING_GUIDE.md).

---

## Legal

Proprietary software. **Authorized engagements only.** Full terms in
[`DISCLAIMER.md`](DISCLAIMER.md).

Scope enforcement is built into the framework — every tool invocation is
checked against the signed scope before execution, tagged with the scope hash,
and written to a hash-chained audit log. This is a backstop, not a substitute
for operator judgment.

---

<sub>NexusRecon is built and maintained by **d4rk pri0r** ·
[darkpriorlabs](https://github.com/d4rk-pri0r) · for defenders who test like
attackers — with permission.</sub>
