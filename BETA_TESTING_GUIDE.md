# NexusRecon: Closed Beta Tester Onboarding

Welcome. You're getting early access to NexusRecon, an agentic OSINT
orchestration platform for authorized red team and threat intelligence work.
This guide gets you from clone to working campaign in roughly an hour.

**Status:** closed beta. Substantial real-target testing has been completed
(see "Validated on" below). Two known polish issues are documented near the
end with workarounds. The platform is solid enough to use on authorized
engagements; we want your feedback on edge cases, target-diversity bugs,
report quality, and the agentic dispatch behavior we can't simulate solo.

**Validated on:** a public scanner-test target plus a real authorized
corporate target. Both produced clean exit, accurate attribution, and
substantive deliverables. Typical cost per medium-mode campaign on a
real target: ~$2 in Anthropic API spend.

---

## 1. What you're testing

The platform takes a single seed domain plus an authorization scope file
and produces:

- A ranked "top threads to pull" deliverable with attack-path reasoning
- An executive summary with severity-categorized findings
- Per-target spearphishing email drafts (when `--generate-phishing` is on
  and emails were harvested)
- Asset inventories, attack-surface matrices, vulnerability correlations,
  cloud posture briefs, vendor/supply-chain reports, Jira-ready CSV
- An interactive entity-graph HTML
- PDF + PPTX executive deliverables

The agentic loop fires a "dispatcher" LLM between phases 1/4/7 that
chooses follow-up tools based on gaps in the campaign state, e.g., if
no subdomains were found after phase 1, it dispatches `subfinder`,
`crtsh`, `theharvester`, and friends without operator intervention.

The platform refuses to scan anything not in the scope YAML's
`in_scope.domains`. Out-of-scope tool invocations are silently dropped
and logged for audit.

---

## 2. Authorization, non-negotiable

Before you run a campaign against anything:

1. You must have **written authorization** to perform OSINT against the
   target. This includes passive techniques. Some passive techniques
   (e.g., breach DB lookups, infostealer log queries) interact with
   third-party services in ways that may carry their own ToS.
2. Your scope YAML must contain `engagement.authorized_by` and
   `engagement.signed_sow_hash` fields. For testing against your own
   assets or invited bug-bounty programs with explicit OSINT scope, the
   `signed_sow_hash` can be a 64-char placeholder; for real client work
   compute it from the signed SOW PDF (`shasum -a 256 signed_sow.pdf`).
3. The CLI displays a Rules of Engagement banner at every `run`. Read it.
4. The audit log under `campaigns/<id>/logs/audit.jsonl` is hash-chained
   and tamper-evident. It includes every tool invocation with the scope
   hash. Keep it.

**Recommended beta targets (decreasing preference):**

- A domain you own (your homelab, personal site, your employer with
  written permission)
- A public scanner-test target like `testphp.vulnweb.com` (deliberately
  vulnerable, explicitly for testing scanners, thin but safe)
- A public bug bounty program where the OSINT scope is explicit in the
  policy (verify their policy yourself, programs vary)

**Do NOT** point this at a random company "just to see what it finds."
The audit log will show you scanned them; that's not a defense.

---

## 3. Prerequisites

| Requirement | Why | Check |
|---|---|---|
| macOS or Debian/Ubuntu/Kali Linux | Tested platforms | `uname -s` |
| Python 3.11, 3.12, or 3.13 (NOT 3.14) | CrewAI compatibility window | `python3.13 --version` |
| Anthropic API key | LLM provider (required for agent synthesis) | https://console.anthropic.com/ |
| ~$10 budget for initial testing | Real-target campaigns are ~$2 each | n/a |
| 12 external binaries | Tool integrations (installed by `install.sh`) | see step 4.2 |

**Optional but high-leverage keys (configure if you have them):**

- `GITHUB_TOKEN`, unlocks 5 code/secret discovery tools
- `HUNTER_API_KEY`, email pattern + harvesting (free tier: 50/month)
- `VIRUSTOTAL_API_KEY`, domain reputation + passive DNS (free: 500/day)
- `SHODAN_API_KEY`, host/service fingerprinting (free tier or ~$5 one-time)
- `URLSCAN_API_KEY`, `ABUSEIPDB_API_KEY`, `IPINFO_API_KEY`, all free

See `CONFIGURATION_GUIDE.md` for the full key inventory with signup
URLs and what each one unlocks.

---

## 4. Install

### 4.1 Clone and run the installer

```bash
git clone <repo_url> agentic-osint
cd agentic-osint

# If your default python3 is 3.14, override:
PYTHON=python3.13 ./install.sh

# Otherwise:
./install.sh
```

The installer creates `./venv`, installs Python dependencies, installs
Go-based binaries (subfinder, httpx, nuclei, katana, etc.), and runs a
post-install verification step. Expected output near the end:

```
[+] nexusrecon package imports OK
[+] nexusrecon CLI on PATH: .../agentic-osint/venv/bin/nexusrecon
[+] Tool registry OK: <N> tools registered
[*] External binary presence check:
  [+] subfinder
  [+] amass
  [+] httpx
  ...
[+] Installation complete!
```

### 4.2 Activate the venv

**Every new terminal session needs:**

```bash
source venv/bin/activate
which nexusrecon   # should resolve to .../venv/bin/nexusrecon
```

### 4.3 Configure API keys

```bash
cp .env.example .env
$EDITOR .env
```

Minimum to be useful:

```
ANTHROPIC_API_KEY=sk-ant-...
NEXUS_LLM_PROVIDER=anthropic
NEXUS_LLM_MODEL=claude-sonnet-4-6
```

Add as many of the optional keys as you have. The platform degrades
gracefully, missing keys mean specific tools are skipped, but the
campaign still completes.

### 4.4 Verify install

```bash
nexusrecon --help                # should list every command
nexusrecon tools | head          # first page of the live tool registry
```

If `nexusrecon --help` exits cleanly and `nexusrecon tools` shows the
tool table, you're in.

**If install fails:** see `MANUAL.md` §12 Troubleshooting for the most
common issues (PEP 668, Python 3.14, venv activation, missing binaries).

---

## 5. Your first campaign

### 5.1 Pick a target and build a scope

```bash
cp examples/scopes/minimal_seed.yaml my_scope.yaml
$EDITOR my_scope.yaml
```

Required edits:

- `engagement.client`, short org name
- `engagement.engagement_id`, your tracker ID, free text
- `engagement.authorized_by`, your name + the authorizing party
- `engagement.authorization_date`, today's date in `YYYY-MM-DD`
- `scope.in_scope.domains: ["YOUR-TARGET-DOMAIN"]`, just one seed; the
  platform expands from there

Optional:

- `constraints.max_llm_cost_usd: 5.0`, hard budget cap. Campaign aborts
  if this is hit mid-flight.

### 5.2 Validate the scope

```bash
nexusrecon validate my_scope.yaml
```

Should print "Scope file is valid!" plus a summary with the scope hash.
The hash is what every tool invocation will be tagged with for audit.

### 5.3 Dry run

```bash
nexusrecon run --scope my_scope.yaml --dry-run
```

Confirms the campaign would initialize without actually running tools or
making LLM calls. Should print "Dry run, scope is valid, campaign ready."

### 5.4 First real campaign (light mode, no agentic dispatch)

```bash
nexusrecon run \
  --scope my_scope.yaml \
  --mode light \
  --dispatch-mode off
```

This is the cheapest, fastest path to a working campaign. Light mode
runs phases 1-5 + 7-9 with no agentic dispatcher. Expected:

- 5-10 min runtime
- ~$1-$2 in Anthropic API spend on a real target (a few cents on a thin
  target like `testphp.vulnweb.com`)
- 30-50 findings depending on target richness

### 5.5 Full campaign with all features

After the light-mode run produces a clean campaign:

```bash
nexusrecon run \
  --scope my_scope.yaml \
  --mode medium \
  --dispatch-mode lite \
  --validate-creds \
  --generate-phishing
```

`--dispatch-mode lite` fires the agentic dispatcher after phases 1, 4, 7.
`--validate-creds` runs phase 7.5 (credential harvest from exposed
config files; opt-in because validation calls touch cloud-provider APIs).
`--generate-phishing` produces per-target email drafts when emails are
harvested.

Expected: ~10-15 min runtime, ~$2-$3 spend on a real target.

### 5.6 Where the reports live

```bash
ls campaigns/<client_slug>/<engagement_id>/<campaign_id>/reports/
```

Open these in order:

1. **`top_threads.md`**: operator's starting point; ranked attack paths
2. **`executive_summary.md`**: client-deliverable summary
3. **`phishing_drafts.md`**: index of per-target drafts (one `.md` per email)
4. **`harvested_credentials.md`**: exposed credentials with redaction
5. **`full_report.md`**: comprehensive findings detail
6. **`entity_graph.html`**: interactive entity graph (open in browser)
7. **`jira_tracker.csv`**: Jira-importable findings list

See `nexusrecon/docs/REPORT_GUIDE.md` for the per-file rationale.

---

## 6. Known issues and workarounds

These are open bugs we know about. If you hit one of these, it's not new
,  just confirming the workaround works for you is useful feedback.

### Empty shell env var defeats `.env` value

If your shell has `ANTHROPIC_API_KEY=""` set (empty), pydantic-settings'
precedence rules make that empty value beat the real one in `.env`.
Campaigns fall back to MockLLM (cost $0, no real analysis).

**Symptom:** `state.llm_cost_usd: 0.0` after a campaign that should have
cost something. The startup also prints a yellow `[WARN]` about empty env
keys, easy to miss in the registration noise.

**Workaround:**

```bash
unset ANTHROPIC_API_KEY  # or whichever key
nexusrecon run ...
```

Or wrap the invocation:

```bash
env -u ANTHROPIC_API_KEY nexusrecon run ...
```

(Filed as B33; fix is queued for the next maintenance round.)

### Duplicate findings in top threads

The platform's per-phase agents (passive_recon, cloud_identity, correlation,
risk_analyst, executive_reporter) sometimes independently emit findings
about the same underlying observation. On a real target, you'll see
4-5 entries about "M365 Password Spray Viable" with slightly different
wording.

**Why it happens:** each phase has its own LLM call against shared
campaign state. No cross-phase deduplication exists yet.

**Impact:** redundancy in `top_threads.md` and `executive_summary.md`. The
underlying intel is correct; the deliverable just lists it more than once.

**Workaround:** when reading top threads, treat the top N entries as
multiple-phase corroboration of the same finding, not N independent leads.

(Filed as B36. Specified fix is programmatic dedup with
`corroborating_phases` provenance; queued for the next round.)

### Tools that may legitimately fail in your environment

Several tools require specific configurations and will fail cleanly when
they can't:

- `crtsh`, fails on transient crt.sh service outages (502 responses).
  Retry the campaign.
- `theHarvester`, requires the binary (case-sensitive, `theHarvester`).
  If missing: `pipx install theHarvester`.
- `asn_bgp`, requires DNS resolution; fails gracefully on hosts that
  can't resolve (e.g., synthetic test domains).
- `sslyze`, requires the target to actually have HTTPS on port 443.

These failures are visible in `logs/audit.jsonl` with `tool_error` event
type and a clear message in the `error` field.

---

## 7. Reporting bugs and feedback

When something breaks or surprises you, capture this **before moving on**
(state and logs get overwritten quickly):

```bash
# Latest campaign artifacts (compressed)
CAMP_DIR=$(ls -td campaigns/*/*/*/ | head -1)
tar czf nexusrecon-bug-report.tgz \
  "$CAMP_DIR/state.json" \
  "$CAMP_DIR/logs/" \
  "$CAMP_DIR/scope_metadata.json"
```

Then file the bug with this template:

```
TITLE: [one-line summary]

SEVERITY:
  [ ] BLOCKER, couldn't get past install / dry-run
  [ ] CRITICAL, campaign crashes mid-run
  [ ] HIGH, campaign completes but core feature broken
  [ ] MEDIUM, feature works but output is wrong or confusing
  [ ] LOW, cosmetic, polish, doc gap

ENVIRONMENT:
  OS: [macOS X.Y / Ubuntu X.Y / Kali]
  Python: [3.11.X / 3.12.X / 3.13.X]
  Install method: [./install.sh / manual]
  LLM provider: [anthropic / openai / ollama]
  Keys configured: [list names, NOT values]
  Binaries present: [output of: nexusrecon tools | wc -l]

WHAT YOU RAN:
  Exact CLI command:
  Scope target (domain only, redact if sensitive):
  Mode + flags:

EXPECTED vs ACTUAL:
  Expected:
  Actual:

ARTIFACTS:
  Attached: nexusrecon-bug-report.tgz
  Stderr output: [paste relevant portion]

REPRODUCIBILITY:
  [ ] One-shot, happened once
  [ ] Intermittent, N of M runs
  [ ] Reliable, every run

CONTEXT:
  Anything else worth knowing, target characteristics, scale, what
  you expected the platform to do.
```

**Send bug reports to:** [TBD, operator to fill in: GitHub issues URL,
email, Discord channel, whatever you set up for the beta cohort].

---

## 8. What we want feedback on

Not all feedback is equally useful at this stage. In rough priority order:

1. **Crashes on real targets**: your target's data shape may trigger
   bugs that solo testing didn't.
2. **Wrong findings**: false attribution, hallucinated tenant IDs,
   confident claims about infrastructure the target doesn't actually own.
   We have an attribution gate (B26/B29) that's been heavily tested,
   but new edge cases will surface.
3. **Phishing draft quality**: are the per-target drafts realistic
   enough for actual use? Tone, technique, OSINT citations, sender
   strategy. Real operator judgment matters here.
4. **Cost surprises**: campaigns going over the `max_llm_cost_usd` cap
   without warning, or wildly different costs than what we documented.
5. **Report ergonomics**: is the report set you get actually what
   you'd use in your workflow? What's missing? What's noise?
6. **Tool gaps**: what OSINT source do you reach for that we don't
   integrate?

Less useful at this stage:

- Cosmetic polish (we know about most of it)
- "It would be cool if it could..." feature requests, file these
  separately; they don't belong in the bug stream
- Issues you didn't reproduce, we need state to debug

---

## 9. Operating responsibly

Some things to remember:

- **You're an operator, not the platform.** Findings are starting points
  for your judgment, not conclusions. The platform produces an
  Identity Intelligence Gap finding if it can't harvest emails, that's
  signal, not an attack vector.
- **Phishing drafts are drafts.** They require operator review before any
  send. The drafts include explicit `⚠ AUTHORIZATION REQUIRED ⚠`
  banners; do not strip them when sharing with teammates.
- **Credentials in `harvested_credentials.md` are real.** Rotate
  immediately if they belong to assets you're authorized to remediate;
  for client engagements, deliver via secure channels (encrypted ZIP,
  vault drop, secure portal).
- **The audit log is hash-chained.** If you need to demonstrate provenance
  to a client or in court, the chain at `logs/audit.jsonl` is the
  authoritative record.

---

## 10. Quick reference

### CLI commands

```bash
nexusrecon --help                                 # list commands
nexusrecon run --help                             # run options
nexusrecon validate <scope.yaml>                  # check scope
nexusrecon run --scope <scope.yaml> --dry-run     # dry run
nexusrecon run --scope <scope.yaml>               # default campaign
nexusrecon tools                                  # list available tools
nexusrecon campaign-list                          # show all campaigns
nexusrecon resume <campaign_id>                   # resume from checkpoint
nexusrecon diff <campaign_id_old> <campaign_id_new>  # diff two campaigns
nexusrecon export <campaign_id> --format csv      # export findings
```

### Useful flags

| Flag | Effect |
|------|--------|
| `--mode light` | Runs phases 1-5+7-9, no T2/T3 active scanning |
| `--mode medium` | Adds T1/T2 active fingerprinting + scanning |
| `--mode deep` | Adds T3 intrusive ops (only if scope authorizes) |
| `--dispatch-mode off` | Disables agentic dispatcher; cheapest, most predictable |
| `--dispatch-mode lite` | Dispatcher fires after phases 1, 4, 7 (default) |
| `--dispatch-mode full` | Dispatcher fires after every phase (most LLM cost) |
| `--validate-creds` | Runs phase 7.5 credential harvest from exposed configs |
| `--generate-phishing` | Generates per-target phishing email drafts |
| `--use-graph` | Use LangGraph workflow engine (alternative to direct loop) |
| `--dry-run` | Validate scope + plan without running tools |

### Recommended first-week test sequence

1. **Day 1:** install, configure 1 API key (Anthropic), run light mode on
   `testphp.vulnweb.com`. ~30 min, ~$0.10.
2. **Day 2:** add 3-5 more API keys, run light mode on a domain you own
   or have explicit recon authorization for. ~1 hr, ~$2.
3. **Day 3:** medium mode + lite dispatch on the same target. Compare
   findings. ~1 hr, ~$3.
4. **Day 4-5:** full flag combination on the same target. Inspect every
   report. File anything that surprises you. ~2 hr, ~$5.
5. **Day 6-7:** point at a more interesting authorized target (your
   employer's external surface with permission, or a bug bounty program
   with explicit OSINT scope). Focus on report quality + accuracy.

By end of week one, you should have a clear opinion on:

- Does this save you time compared to your existing workflow?
- Is the output trustworthy enough to incorporate into deliverables?
- What's the killer feature for you?
- What's the deal-breaker, if any?

---

## 11. References

- **`MANUAL.md`**: comprehensive operator manual (1100+ lines). Use as
  reference once you hit specific questions.
- **`README.md`**: quick-start at the project root.
- **`CONFIGURATION_GUIDE.md`**: wiki-grade reference for every env var
  and what each API key unlocks.
- **`TESTING_RUNBOOK.md`**: detailed end-to-end test procedure. Useful
  when something breaks and you need to isolate where.
- **`ITERATION_BACKLOG.md`**: open and resolved bugs. Check here before
  filing a new bug to avoid duplicates.
- **`nexusrecon/docs/AGENT_LOOP.md`**: dispatcher deep-dive (how the
  agentic loop works and when it fires).
- **`nexusrecon/docs/REPORT_GUIDE.md`**: which report file is for which
  audience.

---

Thanks for joining the beta. Your real-world testing is going to surface
things solo testing couldn't. Be thorough, be honest, be specific.
