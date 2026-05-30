# Sample Campaign — GitLab via HackerOne

This directory contains the published artifacts from a real NexusRecon
campaign against `gitlab.com`. The campaign ran under the authorization
of GitLab's public HackerOne bug bounty program, which includes
safe-harbor language for security research conducted within its
documented scope.

This isn't a synthetic walkthrough or a contrived test target ── it's
what the framework actually produced against a real corporate external
surface, with PII redacted and per-employee findings withheld.

> **Provenance note.** This run predates the Wave F (signal quality +
> failure honesty) and OPSEC-binding work. The three items under "Known
> framework issues this run surfaced" below have since been fixed, so
> read that section as a record of what this run caught at the time, not
> as current behaviour. See [`docs/killer-demo.md`](../../docs/killer-demo.md)
> for the runbook and the publishing checklist, and for what a refreshed
> run would now show.

---

## What's in this directory

| File | What it is |
|---|---|
| `scope.yaml` | The engagement scope of record. Hash-anchored to the HackerOne program URL as the SOW equivalent. Validated by `nexusrecon validate`. |
| `dispatcher_trace.md` | Operational backbone — every tool fire, every result, every error, in chronological order. Reconstructed from the hash-chained audit log. |
| `audit_excerpt.jsonl` | First 60 entries from the tamper-evident audit chain. Each entry's `entry_hash` references the previous entry's hash; flipping a byte anywhere breaks the chain. |
| `reports/asset_inventory.md` | 333 subdomains discovered, full inventory. Subdomains are publicly enumerable via CT logs — no redaction needed. |
| `reports/master_report.redacted.md` | The narrative deliverable. Employee email addresses redacted to `[REDACTED]@gitlab.com`; Azure tenant ID redacted. Structural intelligence intact. |
| `reports/executive_summary.redacted.md` | The 1-page summary version, same redactions. |

---

## What's NOT in this directory (deliberately)

| Withheld | Why |
|---|---|
| Per-employee findings | Hunter + theHarvester surfaced 10 real GitLab employee emails with names + titles. The framework correctly identified them; publishing them as a *demo* artifact would amplify the OSINT signal beyond what GitLab themselves chose to expose. Aggregate-only in the published reports. |
| Azure tenant ID | Discoverable via the public Microsoft `user-realm` endpoint, but publishing it in a demo signals "use this for phishing prep." Replaced with `[REDACTED-TENANT-ID]`. |
| Phishing draft generation | `--generate-phishing` was deliberately not passed. We hold the line on no phishing artifact creation for the demo, even authorized. |
| Specific vulnerabilities / CVEs (if any) | This campaign found no specific exploitable vulnerabilities ── it's an OSINT/recon engagement, not a vuln scan. If it had found something, that would have gone through HackerOne disclosure before publication, not into this demo. |
| Raw `findings.json`, `harvested_credentials.md`, `people_identity_map.md` | These files exist in the full campaign output but mix per-employee data with aggregate signal. Aggregate is captured in the published reports above. |

---

## Reproducing this campaign

Anyone with the framework installed and the relevant API keys can re-run:

```bash
# Required:
#   - ANTHROPIC_API_KEY (for the LLM agents)
# Recommended (more tools fire with more keys):
#   - SHODAN_API_KEY, VIRUSTOTAL_API_KEY, GITHUB_TOKEN, HUNTER_API_KEY,
#     ABUSEIPDB_API_KEY, OPENAI_API_KEY (fallback LLM)
#
# Optional binaries (one-off install):
#   pipx install maigret    # username account checking (~3000 sites)

nexusrecon run \
  --scope examples/sample_run/scope.yaml \
  --seeds gitlab.com \
  --mode medium \
  --use-graph \
  --dispatch-mode full
```

Wall-clock: ~20 minutes on a typical broadband connection. LLM spend:
`$2.32` (Anthropic Claude Opus 4.5, default model). Output landed
under `campaigns/gitlab_inc./NEXUSRECON-DEMO-GITLAB/<run-id>/`.

---

## Tool activity summary

143 tool invocations, 147 successful responses (some tools fire
multiple endpoints), 5 errors. The errors were:

- `crtsh` (cert transparency) ── upstream returned HTTP 502 twice. Caught
  by the post-0.5.0 status-code classifier and reported loudly.
- `theharvester` ── binary not installed on this host. Auto-skipped via
  `is_available()` rather than crashing.
- `asn_bgp` ── DNS resolution failed (network blip). Returned an error
  result, didn't crash the phase.

**Top by raw items surfaced:**

| Tool | Items | What it produced |
|---|---:|---|
| `subfinder` | 332 | Passive subdomain enumeration |
| `shodan` | 88 | Hosts indexed by service |
| `dns` | 57 | A/AAAA/MX/NS/TXT records |
| `holehe` | 31 | Third-party service registrations across 10 emails |
| `dockerhub` | 24 | Container images |
| `aws_recon` | 22 | S3 bucket / Lambda surface (flagged stem-match) |
| `urlscan` | 20 | Recently submitted URL scans |
| `virustotal` | 20 | Domain reputation + passive DNS |
| `ransomwatch` | 15 | Dark-web mention check (negative) |
| `email_format` | 10 | Inferred `flast` pattern with 100% confidence |
| `hunter` | 10 | Harvested email addresses (redacted in published reports) |

Full per-tool tally in `dispatcher_trace.md`.

---

## What the framework actually concluded

51 findings total. Severity breakdown: **0 critical, 3 HIGH, 12 medium**,
the rest low/info. The three HIGH findings:

1. **Authentication Infrastructure Exposed.** Subdomains
   `auth.aws.gitlab.com`, `auth.token.gitlab.com`, `auth.staging.gitlab.com`,
   `auth.gcp.gitlab.com` identified ── identity infrastructure visible
   without authentication. Source: subfinder. Confidence: 90%.
2. **Exposed Staging and Pre-Production Environments.** Multiple
   `*.staging.*` and `*.pre.*` subdomains discovered. Source:
   subfinder. Confidence: 85%.
3. **Exposed Staging and Pre-Production Environments** (correlation
   agent variant ── flagged independently from the cloud_identity
   stream). Confidence: 75%.

Notable mediums include multi-cloud architecture (Azure + GCP confirmed,
AWS flagged `[POSSIBLE]` due to stem-match attribution backstop with
0.2 confidence), OpenSearch/Elasticsearch clusters inside the Cells
architecture, container registry endpoints, and an extensive third-party
service integration map (DocuSign, Drift, Marketo, Salesforce, Workday,
Zendesk, OpenAI, etc.) extracted from public DNS TXT records.

**Things the framework correctly did NOT claim:**

- AWS S3 bucket attribution. `gitlab-images`, `gitlab-prod`,
  `packages-gitlab-com` were detected by `aws_recon` but the attribution
  backstop flagged them `[POSSIBLE]` with 0.2 confidence ── "stem-match
  only, may belong to unrelated organizations using 'gitlab' naming."
  This is the framework refusing to make confident claims about
  ownership it can't actually verify.
- GCP `gitlab` and `gitlab-data` buckets ── same `[POSSIBLE]` treatment.
- The `LabCoat for GitLab` Play Store app ── identified as third-party
  (`Commit 451` publisher) and NOT confused with an official GitLab
  application. Source: `playstore`. Confidence: 90%.

---

## What the LLM cost

| Phase | Agent | Findings | Steps | $ |
|---|---|---:|---:|---:|
| 1 | `passive_recon` | 12 | 1 | $0.430 |
| 2 | `cloud_identity` | 6 | 2 | $0.298 |
| 3 | `passive_recon` | 3 | 3 | $0.115 |
| 4 | `correlation` | 5 | 4 | $0.183 |
| 5 | `active_recon` | 5 | 5 | $0.210 |
| 7 | `vuln_correlator` | 5 | 6 | $0.169 |
| 8 | `risk_analyst` | 10 | 7 | $0.342 |
| 9 | `executive_reporter` | 5 | 8 | $0.405 |
| 9 | `master_reporter` | 0 | 1 | $0.170 |
| **Total** | | **51** | — | **$2.32** |

Phase 6 (T3 nuclei actives) was skipped per the scope's `max_tier: T2`
cap. Phase 7.5 (credential harvest) ran but produced no published
findings under our publishing rules (per-employee credential data
stays in the unpublished campaign dir).

The LLM cost cap was `$10` per `scope.yaml`; actual spend was 23% of
the budget.

---

## Known framework issues this run surfaced

- **`top_threads.md` reported "No ranked threats available"** despite
  Phase 8 producing 10 findings via `risk_analyst`. The report engine
  didn't pull the ranked-threads field from state. Tracked as a
  follow-up issue.
- **CLI completion box showed `Findings: 0`** but `findings.json` and
  `campaign_meta.json` both correctly report 51. Display-only counter
  bug in the CLI summary; the underlying data is correct.
- **OPSEC profile declared but not enforced at the wire.** The scope
  specifies `stealth_profile: high` (1-3s delays per source) but the
  campaign runner doesn't yet bind the rate limiter to the registry
  (documented gap in `OPSEC_STATUS.md`). Outbound traffic was per-tool
  best-effort, not the documented 1-3s cadence.

These are gaps to close, surfaced honestly by running the demo. None
invalidate the findings the framework produced ── the findings come
from tool results + LLM synthesis, both of which functioned correctly.

---

## Authorization & ethics

This campaign was run under GitLab's public HackerOne program scope
(<https://hackerone.com/gitlab>). Per program rules + applicable safe-
harbor language, security research within the documented scope is
authorized. **Anyone re-running this campaign must read and agree to
the program rules before doing so.**

The framework's purpose is authorized security research. It must not
be used against targets without explicit authorization. See
`DISCLAIMER.md` at the repo root.

---

## Reading order

For the impatient, in order of value:

1. `dispatcher_trace.md` ── what the framework actually did, in order.
   This is the killer artifact and the answer to "what's the agentic
   value prop, concretely."
2. `reports/master_report.redacted.md` ── the narrative the framework
   wrote about what it found. ~1500 words, operator voice, evidence
   cited per finding.
3. `reports/asset_inventory.md` ── the raw catalog. 333 subdomains
   across the gitlab.com surface.
4. `reports/executive_summary.redacted.md` ── if you only have one
   page of attention.
5. `audit_excerpt.jsonl` ── proof the chain integrity claim is real.

The full campaign output (unredacted, including the people identity
map and credential harvest report) stays on the operator's machine
and is not committed to this repo.
