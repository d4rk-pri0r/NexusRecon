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
[![engine](https://img.shields.io/badge/engine-agentic-purple)](#why-agentic-osint)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

You hand it a scope file and a seed domain. ~30–60 minutes later it
hands you back a ranked, prioritized, citation-backed attack-surface
report — every finding traced to the tool that produced it, every tool
invocation validated against the signed scope and written to a
hash-chained audit log.

> ⚠ **Authorized use only.** Every tool invocation is validated against a signed
> scope file. Out-of-scope targets are silently dropped and logged. Use only
> against systems you have explicit written permission to test. See
> [DISCLAIMER.md](DISCLAIMER.md).

---

## Why agentic OSINT?

The hard part of an OSINT engagement isn't running the tools — it's
deciding **which tool to run next, on what target, in response to what
the previous tool just told you**.

A subdomain harvester surfaces `vpn.acme.com` → that means you want to
fingerprint its version with Shodan → that means you want to check
NVD and KEV for known CVEs → that means you want to cross-reference
breach data to see whether a known credential gives you a path in.
A human operator does that swivel-chair manually across a dozen tools
and as many output formats. NexusRecon does it automatically.

Between every two phases of a campaign, an **LLM dispatcher** inspects
the collected state — what's been found, what's still missing — and
queues targeted follow-up tool runs based on what the data warrants:

- Phase 1 surfaces a Play Store Android app → dispatcher queues the
  **APK analyzer** against that package before Phase 2 starts.
- Phase 2 surfaces an M365 federation endpoint → dispatcher queues
  **AWS / GCP enumeration** to see if the org is multi-cloud.
- Phase 4 surfaces an executive's email + a 2023 breach hit →
  dispatcher hands it to the **phishing drafter** to write a targeted
  pretext referencing recent SEC filings.

At the end of the run a **`master_reporter` agent** synthesises everything
into a single cohesive narrative report that an operator can hand
straight to the client's CISO — backed by:

- a **ranked attack-thread list** scored by `CVSS × EPSS × KEV × Metasploit`,
- a **hash-chained audit log** of every tool invocation and scope-gate decision,
- a **citation graph** linking every finding back to its source tool.

**The value vs. running tools by hand**: an OSINT analyst running the
same source set manually against a single seed domain typically loses
6–8 hours, doesn't get cross-tool correlation, doesn't get LLM-driven
follow-up, doesn't produce a ranked threat list, and doesn't produce
an audit trail their client's legal team will accept.

---

## A worked example

Given seed `acme.com`, mode `medium`, dispatcher `lite`, on a single
laptop with default API keys configured — typical 30–60 min run:

| When | What happens |
|------|-------------|
| **Phase 1** · passive footprint | crt.sh + Subfinder + Amass + SecurityTrails surface 47 subdomains. One is `vpn.acme.com`. |
| **Dispatcher fires** | Notices the VPN endpoint and an Android app discovered in the Play Store probe. Queues Shodan against `vpn.acme.com` and the APK analyzer against the Play Store package — both run before Phase 2 starts. |
| **Phase 2** · active surface | httpx + gowitness fingerprint 12 live HTTP services; one is an unauthenticated admin console. |
| **Phase 3** · cloud + identity | Azure/M365 enumerator finds the M365 federation; bucket_enum finds two public S3 buckets. |
| **Phase 4** · correlation | LLM correlator stitches subdomains → IPs → cloud account, scores attribution confidence so we don't claim cloud assets we can't prove. |
| **Dispatcher fires** | Sees the admin console + a GitHub org match. Queues a deeper GitHub scan and a urlscan submission. |
| **Phase 5** · people + pretext | Hunter + HIBP harvest 9 employee emails; 3 have hits in known breach corpora. |
| **Phase 7** · vuln correlation | NVD + KEV + EPSS match 4 CVEs to the fingerprinted tech. The Shodan-detected VPN version maps to a KEV-listed CVE with EPSS 0.87. |
| **Dispatcher fires** | KEV-listed CVE → high-priority threat. Queues additional vuln intel + scopes a follow-up phishing draft against the 3 breached employees. |
| **Phase 8** · attack-surface rank | Scores all findings; top thread is "KEV-listed VPN CVE on `vpn.acme.com` + 3 breached employees in scope for credential reuse". |
| **Phase 9** · reports | `master_reporter` agent writes a cohesive narrative for the CISO; `phishing_drafter` produces 3 targeted templates. |

**Output**: a `campaigns/acme/<engagement>/<id>/reports/` directory with
17 deliverables — master report, ranked top threads, asset inventory,
phishing package, attack-surface matrix, vuln correlation, hash-chained
audit log, Maltego CSV export, the lot.

Doing the same by hand: 6–8 hours of context switching across crt.sh,
Subfinder, Amass, SecurityTrails, Shodan, Censys, urlscan, GitHub,
Hunter, HIBP, NVD, KEV, EPSS, Maltego — with no automatic correlation,
no LLM follow-up loop, no ranked threats, no audit chain.

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
     │ OSINT    │       │ 8 LLM    │         │  Dynamic     │
     │ tool     │       │ phase    │         │  dispatcher  │
     │ registry │       │ agents   │         │  (between    │
     │ (T0–T3)  │       │          │         │   phases)    │
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
   │       N tools registered · 0 campaigns · LLM: anthropic    │
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
- **Browse the live tool catalogue** and see which tools are unlocked by which keys
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

The tool registry spans subdomain enumeration, certificate transparency,
DNS / passive DNS, breach data, email / identity, code-leakage scanners,
cloud posture (AWS / Azure / GCP), threat intel (Shodan / Censys / VT /
GreyNoise / urlscan), vuln intel (NVD / KEV / EPSS / ExploitDB / GH
Advisory), mobile, and HUMINT / pretext sources. New tools land every
release. Run `nexusrecon tools` for the live catalogue, or browse the
**Tools** screen in the TUI.

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
- Extensible tool registry with scope-gated execution
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

## License & legal

Licensed under [Apache 2.0](LICENSE). The license grants you broad
permission to use, modify, and redistribute. We ask one thing in
return — **use it only against systems you have explicit written
permission to test.** Full responsible-use policy:
[`DISCLAIMER.md`](DISCLAIMER.md). Third-party components and the
authorized-use rider: [`NOTICE`](NOTICE).

Scope enforcement is built into the framework — every tool invocation is
checked against the signed scope before execution, tagged with the scope hash,
and written to a hash-chained audit log. This is a backstop, not a substitute
for operator judgment.

---

<sub>NexusRecon is built and maintained by **d4rk pri0r** ·
[darkpriorlabs](https://github.com/d4rk-pri0r) · for defenders who test like
attackers — with permission.</sub>
