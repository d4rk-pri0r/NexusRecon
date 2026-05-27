```
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
           R E C O N   v 0 . 7 . 0
```

# NexusRecon

**Agentic OSINT orchestration framework for authorized red-team reconnaissance.**

[![status](https://img.shields.io/badge/status-beta-yellow)](#status)
[![version](https://img.shields.io/badge/version-0.7.0-blue)](nexusrecon/__init__.py)
[![python](https://img.shields.io/badge/python-3.11--3.13-blue)](pyproject.toml)
[![engine](https://img.shields.io/badge/engine-agentic-purple)](#why-agentic-osint)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![tests](https://github.com/d4rk-pri0r/NexusRecon/actions/workflows/test.yml/badge.svg)](https://github.com/d4rk-pri0r/NexusRecon/actions/workflows/test.yml)
[![live-drift](https://github.com/d4rk-pri0r/NexusRecon/actions/workflows/live-drift.yml/badge.svg)](https://github.com/d4rk-pri0r/NexusRecon/actions/workflows/live-drift.yml)

You hand it a scope file (or a single English sentence) and a seed
domain. ~30-60 minutes later it hands you back a ranked, prioritized,
citation-backed attack-surface report. Every finding traced to the
tool that produced it, every tool invocation validated against the
signed scope and written to a hash-chained audit log, the whole
campaign exportable as a cryptographically signed STIX 2.1 bundle that
downstream vuln scanners, C2 frameworks, and ticketing systems can
consume directly.

> ⚠ **Authorized use only.** Every tool invocation is validated against
> a signed scope file. Out-of-scope targets are silently dropped and
> logged. Use only against systems you have explicit written permission
> to test. See [DISCLAIMER.md](DISCLAIMER.md).

---

## Why agentic OSINT?

Running the tools is the easy part. The hard part is **deciding which
tool to run next, on what target, in response to what the previous
tool just told you**. And proving the resulting findings are still
true six weeks later when legal asks.

NexusRecon is built around five durable capabilities:

1. **Living Intelligence Graph**: every entity (subdomain, IP, email,
   person, cloud asset, vulnerability, hypothesis, lead, open
   question) is a first-class node with provenance, confidence,
   citations, and traversable relationships. Agents reason over the
   graph instead of flat dictionaries.
2. **Strategic Reasoning Engine**: operator-authored or
   planner-generated `Strategy` objects drive phase selection,
   dispatch policy, success / kill criteria, and tool budgets. Cost
   simulation runs before every LLM dispatch; bounded-agency
   primitives let high-tier items queue for human approval instead
   of auto-firing.
3. **Continuous Confidence Engine**: every graph mutation flows
   through an orchestrator that runs corroboration, contradiction
   detection, propagation, and adversarial self-check verifiers.
   Confidence rises when multi-source independent agreement appears
   and falls when contradictions land. Both bounded, both
   audit-logged.
4. **First-class extensibility**: community recon packs (a
   directory + `manifest.yaml`) contribute tools, agents, dispatch
   policies, report templates, and custom entity / relationship
   types. Three scaffolders (`agent new` / `tool new` /
   `policy new`) generate working boilerplate in seconds.
5. **Cryptographically signed handoff**: STIX 2.1 bundle export +
   Ed25519 signed receipts + a standalone single-file Python
   verifier downstream consumers can run without installing
   NexusRecon. Plus bidirectional import from Nessus, Nuclei,
   generic CSV, and STIX bundles produced by partners.

---

## A worked example

Given seed `acme.com`, mode `medium`, dispatcher `lite`, on a single
laptop with default API keys configured, typical 30-60 min run:

| When | What happens |
|------|-------------|
| **Plan** | `nexusrecon plan "find leaked creds at acme.com, passive only"` synthesizes a `scope.yaml` stub + a `Strategy` (lite dispatch, T1 ceiling, breach lookups enabled). Operator reviews + saves. |
| **Phase 1** · passive footprint | crt.sh + Subfinder + Amass + SecurityTrails surface 47 subdomains. One is `vpn.acme.com`. |
| **Dispatcher fires** | Notices the VPN endpoint and an Android app discovered in the Play Store probe. Simulator forecasts the dispatch will add ~12 entities at $0.02 cost; queues Shodan + the APK analyzer. |
| **Phase 2** · active surface | httpx + gowitness fingerprint 12 live HTTP services; one is an unauthenticated admin console. |
| **Phase 3** · cloud + identity | Azure/M365 enumerator finds the M365 federation; bucket_enum finds two public S3 buckets. |
| **Phase 4** · correlation | LLM correlator promotes hypotheses to LeadEntities, draws CITES edges back to supporting evidence, scores attribution confidence. |
| **Corroboration engine** | Same subdomain seen via passive_dns + certificate + active_probe → confidence lifts from 0.5 → 0.745 → 0.871. |
| **Phase 7** · vuln correlation | NVD + KEV + EPSS match 4 CVEs. KEV-listed VPN CVE with EPSS 0.87 lands in the graph. |
| **Adversarial scan** | `nexusrecon adversarial scan` finds 2 subdomains lockstep-fabricated by an upstream wildcard DNS server → confidence halved + queued for review. |
| **Phase 8** · attack-surface rank | Top thread: "KEV-listed VPN CVE on `vpn.acme.com` + 3 breached employees in scope for credential reuse". |
| **Phase 9** · reports | `master_reporter` writes the narrative. STIX 2.1 export + Ed25519 signed receipt produced for downstream consumers. |
| **Watch** | `nexusrecon watch create acme-watch <campaign> --parent-domain acme.com --interval-hours 6` keeps a sensor running. Any new subdomain or KEV-listed CVE triggers a tiered alert + a queued micro-campaign. |

**Output**: a `campaigns/acme/<engagement>/<id>/reports/` directory
with the master report + ranked threads + STIX bundle + signed receipt
+ adversarial findings log + 17 other deliverables.

By hand, you spend 6-8 hours bouncing across crt.sh, Subfinder, Amass,
SecurityTrails, Shodan, Censys, urlscan, GitHub, Hunter, HIBP, NVD,
KEV, EPSS, and Maltego, and you finish without the cross-tool
correlation, LLM follow-up, ranked threats, audit chain, signed STIX
bundle, or the continuous watch the framework gives you for free.

---

## How it works

```
   ┌──────────┐    ┌─────────────┐    ┌──────────────────┐
   │  Scope   ├───►│  Campaign   ├───►│ 12-phase pipeline│
   │  YAML    │    │  Manager    │    │ + LLM dispatcher │
   └──────────┘    └─────────────┘    └────────┬─────────┘
                                               │
       ┌───────────────────────────────────────┘
       │
       ▼
  ┌─────────────────────────────────────────────────────────┐
  │           Living Intelligence Graph                     │
  │  17+ entity types · provenance · confidence ·           │
  │  relationships · hypotheses · leads · open questions    │
  └────────┬──────────────────┬────────────────────┬────────┘
           │                  │                    │
           ▼                  ▼                    ▼
  ┌──────────────┐    ┌──────────────┐     ┌──────────────────┐
  │ OSINT tool   │    │ 11 LLM phase │     │ Strategic engine │
  │ registry +   │    │ agents +     │     │ planner +        │
  │ recon packs  │    │ verifiers    │     │ simulator +      │
  │ (T0-T3)      │    │              │     │ bounded agency   │
  └──────────────┘    └──────────────┘     └──────────────────┘
           │                  │                    │
           └────────────┬─────┴────────────────────┘
                        │
                        ▼
              ┌───────────────────────┐
              │ Continuous Confidence │
              │ + Adversarial defense │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │ Report engine         │
              │ + STIX 2.1 export     │
              │ + Ed25519 signing     │
              │ + downstream emitters │
              │   (Jira / Nuclei / CS)│
              └───────────────────────┘
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the phase pipeline, agent
personas, dispatcher loop, scoring formula, and a detailed walk
through the post-0.5 architecture additions (Living Graph, Strategy
engine, Verification engine, Pack format, Watch mode, signed bundles,
adversarial defense, vision pipeline).

---

## Quick start

### 1. Install

```bash
git clone https://github.com/d4rk-pri0r/NexusRecon.git
cd NexusRecon
./install.sh                  # creates venv, installs Python deps + system binaries
source venv/bin/activate
```

**Python 3.13 is recommended** (3.11-3.13 supported; **not 3.14**,
CrewAI incompatibility). If `python3` points at 3.14:

```bash
PYTHON=python3.13 ./install.sh
```

### 2. Launch the TUI

```bash
nexusrecon
```

Running with no arguments opens an interactive Textual UI:

![NexusRecon TUI walkthrough](docs/demo/nexusrecon.gif)

From the TUI you can:

- Walk a **new-campaign wizard** that builds the scope file for you
- **Browse the live tool catalogue** with category labels, per-tool
  required + optional key status, and a `c`-shortcut that pops a
  masked edit modal right where the missing key lives
- **Configure** application-wide settings (LLM, OPSEC, storage, debug)
  in the Configuration screen. Tool API keys live in the Tools
  surface
- **Resume** or **diff** prior campaigns
- See the **top-impact missing API keys** ranked by how many tools
  each one would unlock, right on the dashboard

### 3. Or use the CLI directly

```bash
# Author a campaign from a natural-language goal
nexusrecon plan "find leaked credentials at acme.com, passive only"

# Validate a scope file
nexusrecon validate examples/scopes/minimal_seed.yaml

# Dry-run (validate scope + show plan, no tools fired)
nexusrecon run --scope examples/scopes/minimal_seed.yaml --dry-run

# Show the planner's proposed Strategy without launching
nexusrecon run --scope my-scope.yaml --plan-only

# Default run (T0+T1, lite dispatcher, ~30-60 min)
nexusrecon run --scope my-scope.yaml --seeds acme.com

# Full agentic dispatch
nexusrecon run --scope my-scope.yaml --seeds acme.com --dispatch-mode full

# Credential harvest + phishing drafts (authorized engagements only)
nexusrecon run --scope my-scope.yaml --seeds acme.com \
  --validate-creds --generate-phishing

# Export a STIX 2.1 bundle + sign it
nexusrecon export <campaign-id> --format stix2
nexusrecon keys generate corp-red-team-2026
nexusrecon sign <campaign-id> --key-id corp-red-team-2026

# Verify a bundle (no NexusRecon install required:
# scripts/nexusrecon-verify.py is a standalone script)
nexusrecon verify stix2-bundle.json stix2-bundle.json.receipt.json corp.pub.pem

# Continuously monitor a campaign for material changes
nexusrecon watch create acme-watch <campaign-id> \
  --parent-domain acme.com --interval-hours 6
nexusrecon watch tick acme-watch        # one pass; cron-friendly

# Pull in third-party tool output
nexusrecon ingest stix   <campaign-id> partner-bundle.json
nexusrecon ingest nessus <campaign-id> scan-report.nessus
nexusrecon ingest nuclei <campaign-id> nuclei-output.jsonl

# Author a new agent / tool / dispatch policy
nexusrecon agent new
nexusrecon tool new
nexusrecon policy new

# Install + browse a community recon pack
nexusrecon packs install gh:operator-x/corp-red-team
nexusrecon packs list

# Run adversarial detectors on a campaign's graph
nexusrecon adversarial scan <campaign-id>

# Resume from a checkpoint
nexusrecon resume nr-20260514-120000-abc12345
```

`nexusrecon --help` lists every command. The full reference is in
[`MANUAL.md`](MANUAL.md#5-cli-reference).

---

## Capabilities

### Reconnaissance pipeline (12 phases)

| Phase | What it does | Sample tools |
|-------|-------------|--------------|
| **1. Passive footprint** | Subdomain harvest, cert transparency, WHOIS, DNS | crt.sh, Subfinder, Amass, SecurityTrails |
| **2. Active surface** | HTTP probing, screenshotting, tech fingerprint | httpx, gowitness, WAF/CMS/TLS detection |
| **2.5. Code & secret leakage** | Repos, leaked secrets, leaked CI configs | gitleaks, trufflehog, gitdorker, postman |
| **3. Cloud & identity** | M365 federation, S3/GCS buckets, AWS account ID | Azure/M365 enumerator, bucket_enum, AWS recon |
| **4. Correlation** | Cross-source asset linking, hypothesis promotion | (LLM agent, no tools) |
| **5. People & pretext** | Org chart inference, breach lookup, HUMINT leads | Hunter, HIBP, EmailRep, news, SEC EDGAR |
| **6. Threat intel** | Shodan, Censys, GreyNoise, VirusTotal, urlscan | (intel category, 12 sources) |
| **7. Vuln correlation** | NVD + KEV + EPSS + ExploitDB + GH Advisory | CVE matcher, KEV lookup, EPSS scorer |
| **7.5. Cred harvest** | Mask + hash creds in exposed `.env` / configs | gitleaks, TruffleHog, infra_probe |
| **7.7. Pretext intelligence** | Per-target spear-phish dossier (sender × topic × timing) | conference_speakers, news, business_partners |
| **8. Attack-surface rank** | `CVSS × EPSS × KEV × Metasploit` scoring | (scoring engine) |
| **9. Reporting** | LLM-synthesized narrative + 17 deliverables + STIX export | (master_reporter agent) |

### Strategic + verification + safety layers

| Capability | Surface | What it does |
|------------|---------|--------------|
| **Living Graph** | `nexusrecon.core.entity_graph` | 17+ entity types, provenance records, confidence, relationships, hypotheses/leads/open-questions as first-class nodes, mutation events. |
| **Strategy + planner** | `nexusrecon.strategy` | Declarative plan (phases / dispatch policy / tool budgets / success+kill criteria); planner agent + `nexusrecon plan` for NL→Strategy. |
| **Dispatch policies** | `LitePolicy` / `FullPolicy` / `OffPolicy` + plugin | Pluggable per-phase caps + eligibility. Community packs ship custom policies. |
| **Simulation** | `simulate_dispatch_plan` | Cheap pre-execution cost + graph-growth + scope-creep forecast for every dispatch; opt-in gating. |
| **Bounded agency** | `route_plan_items` | Deep-pivot per-item policy escalation + human-approval queue for high-tier items. |
| **Strategic audit** | `AuditLog.log_strategy_*` | Every strategic decision (plan, replan, dispatch policy, simulation, deep-pivot, human approval) is hash-chained. |
| **Corroboration engine** | `CorroborationEngine` verifier | Confidence lift when multi-source independence-classes (passive_dns + cert + active_probe + …) agree on an entity. |
| **Contradiction detector** | `ContradictionDetector` verifier | Sticky-field + exclusive-relationship conflicts → bounded downgrade + queued for human review. |
| **Confidence propagation** | `ConfidencePropagator` verifier | Downgrades cascade through `cites` / `belongs_to` / `part_of` edges with depth decay + cycle protection. |
| **Adversarial self-check** | `AdversarialSelfCheck` | Heuristic graph audit: single-source high-confidence claims, citation cycles, disconnected islands, source monocultures. |
| **Adversarial defense** | `nexusrecon adversarial scan` | Four detectors: poisoned data, suspicious tool-call patterns, evidence inconsistency, prompt injection (regex+structural default, LLM mode opt-in). |

### Interop + distribution

| Capability | Surface | What it does |
|------------|---------|--------------|
| **STIX 2.1 export** | `nexusrecon export … --format stix2` | EntityGraph → STIX Bundle. Stdlib-only serializer. Domain / IP / Email / Identity / Vulnerability / Infrastructure / Note SDOs. |
| **Signed bundles** | `nexusrecon sign / verify` + standalone script | Ed25519, passphrase-encrypted PEM keys, single-file verifier (`scripts/nexusrecon-verify.py`) that needs only `cryptography`. |
| **Bidirectional import** | `nexusrecon ingest stix/nessus/nuclei/csv` | Folds partner STIX bundles, Nessus XML, Nuclei JSON-lines, and generic CSV asset inventories into the campaign graph. |
| **Downstream emitters** | `--format jira / nuclei-targets / cobaltstrike-profile` | Jira REST NDJSON, Nuclei `-list` targets, Cobalt Strike Malleable C2 profile stub (with explicit "review before deploying" warning). |
| **Watch mode** | `nexusrecon watch` | Diff-driven (EntitySensor + ScopeSensor) + polling (TimedSensor) sensors. Tiered actions: low→alert, medium→notification, high→queued micro-campaign. |
| **Vision pipeline** | `nexusrecon vision scan` | Screenshots / PDFs / logos / QR codes → entities + narrative hypothesis. Multi-provider via langchain. Strategy-driven cost cap (`tool_budgets["vision_calls"]`). |

### Extensibility (Recon Pack format)

| Capability | Surface | What it does |
|------------|---------|--------------|
| **Pack format** | `~/.nexusrecon/packs/<name>/manifest.yaml` | Tools, agents, dispatch policies, report templates, custom entity/rel types. Manifest hash + unsigned trust model. |
| **Pack distribution** | `nexusrecon packs install gh:owner/repo` | Git URL or local dir install. `update` / `uninstall` / `search` companions. |
| **Agent SDK** | `nexusrecon agent new` | Interactive Rich-prompted scaffolder. Prompt versioning + citation guardrails wired into the template. |
| **Tool SDK** | `nexusrecon tool new` | Interactive capability picker (category × tier × target_types). |
| **Policy SDK** | `nexusrecon policy new` | Phase-eligibility picker. Generated policy selectable via `--dispatch-mode <name>`. |
| **First-party pack** | `packs/burp/` | Bidirectional Burp Suite XML handoff (import site map + export scope). Dogfood example for the pack format. |

The tool registry spans subdomain enumeration, certificate
transparency, DNS / passive DNS, breach data, email / identity,
code-leakage scanners, cloud posture (AWS / Azure / GCP), threat intel
(Shodan / Censys / VT / GreyNoise / urlscan), vuln intel (NVD / KEV /
EPSS / ExploitDB / GH Advisory), mobile, social / SOCMINT, and HUMINT
/ pretext sources. New tools and packs land every release. Run
`nexusrecon tools` for the live catalogue or `nexusrecon packs list`
for installed community packs.

---

## Tier system

| Tier | Name | Contact with target | Examples |
|------|------|---------------------|----------|
| T0 | Pure passive | None, public datasets only | crt.sh, Shodan, GitHub, breach DBs, WHOIS |
| T1 | Semi-passive | DNS resolution, passive DNS | DNS sweep, SecurityTrails, urlscan |
| T2 | Light active | HTTP probes, screenshots | httpx, gowitness, favicon hashing |
| T3 | Active | Brute force, fuzzing | ffuf, gobuster, recursive amass |

**Default ceiling is T1.** T2 and T3 require explicit scope
authorization. Out-of-tier tools are dropped with an audit-log entry,
not executed silently. The Phase 1 simulator forecasts tier
escalations BEFORE execution so an LLM dispatcher proposing a T3 call
against a T1-ceiling scope flags visibly in the audit trail.

---

## Deliverables

Every campaign writes to `./campaigns/<client>/<engagement>/<campaign-id>/reports/`:

**Operator-facing**
- `master_report.md`, single cohesive narrative for the client
- `executive_summary.md`, one-page exec-level brief
- `top_threads.md`, top 10 ranked attack paths
- `attack_surface.md`, likelihood × impact matrix, PRE-ATT&CK mapped
- `findings.json`, every `Finding` with severity, confidence, MITRE,
  evidence
- `spear_phishing_intelligence.md`, per-target dossier (Phase 7.7)

**Client-facing**
- `phishing_package.md`, validated emails, pretext hooks, DMARC gaps
- `cloud_posture.md`, M365 federation, AWS account, public buckets
- `vuln_correlation.md`, CVE/KEV findings matched to fingerprinted
  tech
- `harvested_credentials.md`, masked + hashed exposed creds
- `asset_inventory.md` / `.json` / `.csv`, discovered assets
- `report.pdf`, full report as PDF (requires `weasyprint`)
- `master_report.obsidian.md`, parallel master report with
  `[[wikilinks]]` + Obsidian callouts (with `--obsidian`)

**Interop**
- `stix2-bundle.json` + `stix2-bundle.json.receipt.json` (with
  `nexusrecon export … --format stix2 && nexusrecon sign …`)
- `maltego_export.csv`, Maltego-compatible entity import
- Jira NDJSON, Nuclei target list, Cobalt Strike profile stub (with
  `nexusrecon export … --format jira / nuclei-targets /
  cobaltstrike-profile`)

**Provenance**
- `logs/audit.jsonl`, hash-chained record of every tool call, dispatch
  decision, strategic decision, simulation outcome, deep-pivot grant,
  human-approval queue add
- `adversarial_findings`, `verification_log`, `simulation_log` in
  `state.json`, each detector's verdicts time-ordered

Full index with content schemas:
[`nexusrecon/docs/REPORT_GUIDE.md`](nexusrecon/docs/REPORT_GUIDE.md).

---

## Configuration

NexusRecon reads secrets and toggles from a `.env` file in the project
root.

The fastest path is the TUI: launch `nexusrecon`, press `c`, and the
Configuration screen presents every editable variable in 11
categories (LLM provider, intel APIs, email/identity, vuln intel,
OPSEC, cloud, storage, debug, vault, etc.). Values are masked, saved
atomically, and the file is `chmod 0o600`'d on disk.

Manual edit is also fine:

```bash
cp .env.example .env
$EDITOR .env
```

Required for any meaningful run:

- One LLM provider key, `ANTHROPIC_API_KEY` (recommended) or
  `OPENAI_API_KEY`, or set `NEXUS_LLM_PROVIDER=ollama` for a local
  model.

Recommended:

- `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, `HUNTER_API_KEY`,
  `HAVEIBEENPWNED_API_KEY`, `GITHUB_TOKEN`.

Optional environment variables for the post-0.5 features:

- `NEXUSRECON_PACK_DIR`. Override the recon-pack root (default
  `~/.nexusrecon/packs/`).
- `NEXUSRECON_KEY_DIR`. Override the signing-key root (default
  `~/.nexusrecon/keys/`).
- `NEXUSRECON_WATCH_DIR`. Override the watch state root (default
  `~/.nexusrecon/watch/`).
- `NEXUSRECON_MARKETPLACE_URL`. URL of a marketplace JSON index for
  `nexusrecon packs search`.

Per-key tool-unlock matrix:
[`CONFIGURATION_GUIDE.md`](CONFIGURATION_GUIDE.md).

---

## Documentation

| Doc | Audience | What's in it |
|-----|----------|--------------|
| [`README.md`](README.md) (this) | First-time visitor | What is it, how to start |
| [`MANUAL.md`](MANUAL.md) | Operator | Install, scope, CLI ref, tool inventory, troubleshooting |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Engineer / curious operator | Phase pipeline, agents, dispatcher, scoring, post-0.5 architecture additions (Living Graph, Strategy engine, Verification, Packs, Watch, Crypto, Adversarial, Vision) |
| [`CONFIGURATION_GUIDE.md`](CONFIGURATION_GUIDE.md) | Operator setting up keys | Every env var, which tools each unlocks |
| [`CHANGELOG.md`](CHANGELOG.md) | Anyone tracking releases | Version-by-version feature list |
| [`ROADMAP.md`](ROADMAP.md) | Anyone tracking what's next | Current state + path to 1.0 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor | Dev setup, adding tools / agents / packs |
| [`BETA_TESTING_GUIDE.md`](BETA_TESTING_GUIDE.md) | Beta tester | First campaign walkthrough |
| [`DISCLAIMER.md`](DISCLAIMER.md) | Everyone | Authorized-use policy, legal terms |
| [`nexusrecon/docs/AGENT_LOOP.md`](nexusrecon/docs/AGENT_LOOP.md) | Engineer | Dynamic dispatcher internals |
| [`nexusrecon/docs/REPORT_GUIDE.md`](nexusrecon/docs/REPORT_GUIDE.md) | Operator | Every output file and its schema |

---

## Status

**v0.7.0, beta.** The four core bets of the post-0.5 transformation
(Living Graph foundation, Strategic Reasoning Engine, Continuous
Confidence Engine, Contribution & Pack format) and the intent-driven
entry + STIX export/import + downstream emitters ship in this
release. Four of five moonshot capabilities are in place (Watch
Mode, Signed Bundles, Adversarial Defense, Vision). Fleet-Level
Learning is open for design discussion.

**Test suite: 590/590 passing.**

What's stable:

- 12-phase pipeline + credential harvest + pretext intelligence
- Living Intelligence Graph with provenance, confidence, and
  mutation events
- Strategic engine: planner, dispatch policies, simulation, bounded
  agency
- Continuous verification: corroboration, contradiction, propagation,
  adversarial self-check
- Recon Pack format with SDK scaffolders for agents / tools / policies
- STIX 2.1 export + Ed25519 signed receipts + standalone verifier
- Bidirectional import (STIX, Nessus, Nuclei, CSV) + Burp first-party
  pack
- Watch mode with diff-driven + polling sensors and tiered actions
- Adversarial platform self-defense (poisoned data, tool patterns,
  inconsistency, prompt injection)
- Vision pipeline (screenshots, PDFs, QR codes; strategy-budgeted)

What's still moving:

- Fleet-Level Learning (privacy-preserving cross-campaign patterns)
- TUI surfaces for the new Watch / Intent / Vision flows (the
  underlying capabilities ship; TUI tabs land as community pull
  warrants)
- Auto-dispatch of high-severity micro-campaigns (opt-in flag exists
  in storage; wiring deferred)
- Curated marketplace content (index format + search ship; canonical
  hosted content is operator / community curated)

If you want to help shape the 1.0, see
[`BETA_TESTING_GUIDE.md`](BETA_TESTING_GUIDE.md) or
[`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## License & legal

Licensed under [Apache 2.0](LICENSE). The license grants you broad
permission to use, modify, and redistribute. One ask in return:
**use it only against systems you have explicit written permission
to test.** Full responsible-use policy in
[`DISCLAIMER.md`](DISCLAIMER.md). Third-party components and the
authorized-use rider in [`NOTICE`](NOTICE).

Scope enforcement is built into the framework. Every tool invocation
is checked against the signed scope before execution, tagged with the
scope hash, and written to a hash-chained audit log. This is a
backstop, not a substitute for operator judgment.

---

<sub>NexusRecon is built and maintained by **d4rk pri0r** ·
[darkpriorlabs](https://github.com/d4rk-pri0r) · for defenders who
test like attackers, with permission.</sub>
