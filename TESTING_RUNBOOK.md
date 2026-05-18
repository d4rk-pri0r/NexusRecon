# NexusRecon Testing Runbook

> **Read top-to-bottom in order.** Each phase is gated by the success of the
> previous one. If something fails, capture the artifacts listed in the
> "Report Back" template at the bottom and stop, don't try to push past
> failures, they compound.

**Working directory throughout:** `/Users/waifumachine/agentic-osint`

> **Authorization reminder:** every campaign requires a signed scope YAML.
> The CLI shows a banner and refuses to run without one. Do not test against
> third-party infrastructure without written authorization. The recommended
> test target is a domain you control (your own homelab, a personal site,
> a deliberate practice target like `testphp.vulnweb.com`, or a bug bounty
> program with explicit recon authorization).

---

## Phase 0: Pre-flight checks (5 min)

```bash
cd /Users/waifumachine/agentic-osint

# 0.1, Python version: must be 3.11, 3.12, or 3.13 (NOT 3.14)
#       CrewAI does not yet support Python 3.14.
python3 --version

# 0.2, Confirm an in-range Python is available somewhere
#       If `python3 --version` shows 3.14, you need a 3.13 install too.
python3.13 --version 2>/dev/null || echo "Python 3.13 not found, see remediation below"

# 0.3, Confirm you're in the repo root
ls pyproject.toml README.md install.sh nexusrecon/ examples/scopes/
```

**Pass condition:**
- Some Python in range 3.11-3.13 is available (`python3` or `python3.13`)
- All files listed exist

**If `python3 --version` reports 3.14 or higher (macOS Homebrew default since late 2025):**

```bash
brew install python@3.13
# Then below, when running install.sh, prefix with: PYTHON=python3.13 ./install.sh
```

**On Debian/Ubuntu:**
```bash
sudo apt-get install python3.13 python3.13-venv
```

**If `python3 --version` reports < 3.11:** upgrade Python, the install script will refuse to proceed otherwise.

---

## Phase 1: Environment Setup (15-30 min)

### 1.1 Run the install script (recommended path)

The bundled installer handles everything: Python version gate, venv
creation, system binaries (via Homebrew on macOS / apt on Debian/Kali),
Go-installed binaries, Python dependencies, and a post-install
verification step.

```bash
# See what flags are available
chmod +x install.sh && ./install.sh --help

# Full install (default Python interpreter)
./install.sh

# If your default python3 is 3.14, override:
PYTHON=python3.13 ./install.sh
```

**Then activate the venv in your current shell:**

```bash
source venv/bin/activate
```

You'll see `(venv)` prepended to your prompt. **Every new terminal session
needs `source venv/bin/activate` before running `nexusrecon`.**

**Pass condition**, at the end of `./install.sh` you should see something like:

```
[+] nexusrecon package imports OK
[+] nexusrecon CLI on PATH: /Users/.../agentic-osint/venv/bin/nexusrecon
[+] Tool registry OK: <N> tools registered
[*] External binary presence check:
  [+] subfinder
  [+] amass
  ...
[+] Installation complete!
```

**If the install fails:** capture all stderr from `./install.sh` → see "Report Back" template. Common causes are covered by `MANUAL.md` §12 Troubleshooting (PEP 668, Python 3.14, missing venv).

### 1.2 Alternative, phased install

If you already have most binaries (e.g., from a prior session), skip the slow steps:

```bash
./install.sh --skip-system        # Python venv + pip only
./install.sh --skip-python        # binaries only
./install.sh --skip-system --skip-python   # verification-only smoke check
```

### 1.3 Manual install (if you prefer to manage your own venv)

```bash
python3.13 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
./install.sh --skip-python    # binaries only, since deps are already done
```

### 1.4 Confirm CLI is wired correctly

```bash
# Must show the venv's nexusrecon: NOT a system-level one
which nexusrecon
# Expected: .../agentic-osint/venv/bin/nexusrecon
# Wrong:    /Library/Frameworks/Python.framework/Versions/X.Y/bin/nexusrecon
#           or any path not inside this project's venv

# Basic help screen
nexusrecon --help

# Tool inventory, should print the full registry (rows scale with
# release: new tools are added and old ones retired each version).
nexusrecon tools | wc -l
```

**Pass condition:**
- `which nexusrecon` points inside `./venv/`
- `nexusrecon --help` lists the `run` command
- `nexusrecon tools` lists 80+ tools

**If `which nexusrecon` shows a system Python path**, your venv isn't activated. Run `source venv/bin/activate` and re-check. If still wrong, run `hash -r` to clear the shell's command cache.

### 1.5 Binary inventory (informational)

The install script already printed this at the end, but to re-check later:

```bash
for b in amass arjun dnsx gau gitleaks gowitness httpx katana maigret nuclei subfinder trufflehog waybackurls; do
  if command -v "$b" >/dev/null 2>&1; then echo "OK      $b"; else echo "MISSING $b"; fi
done
```

**Partial-pass acceptable:** missing binaries → those tools will be marked
`missing` in `nexusrecon tools` but won't block testing. The minimum
useful set for early phases is `subfinder`, `dnsx`, `httpx`, `nuclei`,
`katana`.

### 1.6 API keys (.env)

Copy the template and populate:

```bash
cp .env.example .env
```

**Open `.env` in an editor.** For the FIRST run, you only need:

```bash
# Required: at least one LLM provider
ANTHROPIC_API_KEY=sk-ant-...
# (or OPENAI_API_KEY, or set NEXUS_LLM_PROVIDER=ollama if you have a local model)

NEXUS_LLM_PROVIDER=anthropic
NEXUS_LLM_MODEL=claude-sonnet-4-6
NEXUS_LLM_TEMPERATURE=0.1
```

**Nice-to-have for early tests** (skip if you don't have them; tools degrade
gracefully):

```bash
GITHUB_TOKEN=ghp_...   # massively expands code-recon coverage
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
HUNTER_API_KEY=
```

**Skip all other keys for now.** You can add them later, each missing key
just means one tool stays gated.

### 1.7 Output directory

```bash
mkdir -p campaigns reports
```

---

## Phase 2: Sanity Checks (5 min)

```bash
# 2.1, Everything compiles
python3 -m py_compile $(find nexusrecon -name '*.py')
echo "exit_code=$?"

# 2.2, Tool registry counts
python3 -c "
import nexusrecon.tools.domain, nexusrecon.tools.pretext, nexusrecon.tools.cloud
import nexusrecon.tools.intel, nexusrecon.tools.web, nexusrecon.tools.vuln
import nexusrecon.tools.identity, nexusrecon.tools.mobile
from nexusrecon.tools.registry import get_registry
r = get_registry()
print(f'Registered total: {len(list(r._tools.values()))}')
print(f'Available with current keys/binaries: {len(r.available_tools())}')
"

# 2.3, CLI surface
nexusrecon --help
nexusrecon run --help
```

**Pass condition:**
- `exit_code=0`
- Registered total matches what the previous run produced (drift only
  on intentional add / retire, flag any silent change)
- Available count is at least 40 (more if you populated more keys / binaries)
- `run --help` lists `--scope`, `--seeds`, `--mode`, `--dispatch-mode`,
  `--validate-creds`, `--generate-phishing`, `--dry-run`, `--use-graph`

**If fail:** capture the full output → see "Report Back" template.

---

## Phase 3: Build a Test Scope (5 min)

The CLI requires a scope YAML. **Choose a target you own.**

Start from the minimal template (fewest fields, easiest to fill in):

```bash
cp examples/scopes/minimal_seed.yaml test_scope.yaml
```

Then edit `test_scope.yaml`, only three things to change:
1. Set `engagement.client`, `engagement_id`, `authorized_by`, and `authorization_date`
2. Replace `acme.com` in `scope.in_scope.domains` with your test domain
3. Adjust `end_date` if needed

The resulting file will look like:

```yaml
engagement:
  client: "Internal Testing"
  engagement_id: "TEST-001"
  authorized_by: "Self-test"
  authorization_date: "2026-05-12"
  signed_sow_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  start_date: "2026-05-12"
  end_date: "2026-12-31"

scope:
  in_scope:
    domains:
      - "YOUR-DOMAIN-HERE.example"   # <-- REPLACE with your test target

constraints:
  max_tier: "T1"
  stealth_profile: "high"
  max_llm_cost_usd: 5.0    # cap early-test cost
```

**Edit `YOUR-DOMAIN-HERE.example`** to whatever you're testing. Suggestions
in decreasing order of preference:

1. A domain you own (personal site, homelab)
2. `testphp.vulnweb.com` (Acunetix's public test target, intentionally vulnerable)
3. A bug bounty program with explicit OSINT authorization in their policy

**Do NOT use a real company's domain you don't own.**

---

## Phase 4: Dry Run (1 min)

Validate the scope and the planner without running any tools:

```bash
nexusrecon run --scope test_scope.yaml --dry-run
```

**Pass condition:** prints a `Dry run, scope is valid, campaign ready.`
message plus a campaign ID. No errors, no tracebacks.

**If fail:** save the full output → report back. Common causes:
- Scope YAML syntax error
- Missing required field
- Authorization warning treated as error

---

## Phase 5: Minimal Live Campaign (10 min)

Run a real campaign at the lowest tier with dispatch disabled. This
exercises the core pipeline without surfacing dispatcher or LLM-cost issues.

```bash
nexusrecon run \
  --scope test_scope.yaml \
  --mode light \
  --dispatch-mode off
```

**Expected behavior:**
- ROE banner prints
- Progress bar shows phases 1-9
- Final output: "Reports saved to: campaigns/{id}/reports/"
- No unhandled tracebacks

**Pass condition:** campaign completes, reports directory has ≥ 10 files.

**Inspect:**

```bash
# Latest campaign directory
CAMP=$(ls -td campaigns/*/ | head -1)
echo "Campaign: $CAMP"
ls "${CAMP}reports/"
cat "${CAMP}reports/campaign_meta.json" | python3 -m json.tool
```

**Look for in `campaign_meta.json`:**
- `total_findings` is a number (even 0 is fine)
- `phases_completed` lists at least phase1-phase4
- `report_paths` is populated

**Look for in `reports/`:**
- `executive_summary.md`
- `top_threads.md`
- `full_report.md`
- `asset_inventory.md`
- `harvested_credentials.md` (will be near-empty for a domain with no exposed creds, that's fine)

**If fail:** report back with:
- Campaign ID
- Full stderr output
- Contents of `${CAMP}reports/campaign_meta.json` if it exists
- Contents of `${CAMP}audit_log.jsonl` if it exists

---

## Phase 6: Light Campaign with LLM Synthesis (15 min)

Same target, but lite dispatch + LLM analysis enabled (default behavior):

```bash
nexusrecon run \
  --scope test_scope.yaml \
  --mode medium \
  --dispatch-mode lite
```

**Difference from Phase 5:**
- Agent synthesis runs at the end of each phase (uses your LLM key)
- Dynamic dispatcher fires after phases 1, 4, 7
- Cost-tracked in `state.llm_cost_usd` (visible in `campaign_meta.json`)

**Pass condition:** completes, `llm_cost_usd` > 0 in meta, top_threads.md
has at least one "Thread" section if anything was found.

**Watch for:**
- `agent_messages` populated in campaign_meta with non-empty `analysis`
  fields, confirms LLM is being called
- `dynamic_dispatch_log` populated, confirms dispatcher fired

**Cost expectation:** $0.05, $0.50 for a small target. If it exceeds
`max_llm_cost_usd` (5.0 in the scope), the campaign aborts mid-flight.
that's correct behavior.

---

## Phase 7: Feature Flag Probes (15 min each)

These exercise the v2 features. Run each separately and inspect the
specific report.

### 7.1 Credential validation

```bash
nexusrecon run \
  --scope test_scope.yaml \
  --mode medium \
  --validate-creds
```

**What to inspect:** `${CAMP}reports/harvested_credentials.md`

**Pass condition:**
- File exists
- Authorization banner at the top
- If credentials were discovered: each one shows `validated: true|false` and
  a `value_redacted` like `AKIA****FAKE`
- If no credentials: file says "No credentials harvested", also fine

**Capture this:** if any `validated: true` entries appear, note them
(redacted) so you can verify the validation actually called the right API.

### 7.2 Phishing draft generator

```bash
nexusrecon run \
  --scope test_scope.yaml \
  --mode medium \
  --generate-phishing
```

**What to inspect:** `${CAMP}reports/phishing_drafts.md` and any per-target
files in `${CAMP}reports/phishing_drafts/`

**Pass condition:**
- Master index file exists
- If any emails were harvested: per-target draft files exist, each starting
  with `⚠ AUTHORIZATION REQUIRED ⚠`
- `phishing_campaign.json` exists with `templates`, `targets`, `landing_pages`
  fields
- Templates field contains HTML, not raw markdown (look for `<strong>` /
  `<p>` tags)

### 7.3 Full dispatch mode

```bash
nexusrecon run \
  --scope test_scope.yaml \
  --mode medium \
  --dispatch-mode full
```

**Difference:** dispatcher fires after EVERY phase, not just 1/4/7.

**Pass condition:** completes, `dynamic_dispatch_log` length > Phase 6's
length. Cost will be higher.

---

## Phase 8: T2 Active Scanning (20 min, optional)

This exercises the active scanners (nuclei, katana, arjun, bucket_enum).
**Only run if you own the target.**

```bash
# Edit test_scope.yaml first: max_tier: "T2" (already set) is fine
nexusrecon run \
  --scope test_scope.yaml \
  --mode deep \
  --dispatch-mode lite
```

**Watch for:**
- Phase 5 and Phase 6 actually do something (HTTP probing, screenshots)
- `vuln_intel.nuclei_scan` populated in campaign_meta if nuclei found anything
- No crashes from missing binaries, if `nuclei` binary is missing, the
  campaign should still complete, just without nuclei findings

---

## Phase 9: Report Inspection (15 min)

Open the full report suite in order. This is where you find issues that
didn't surface as crashes:

```bash
CAMP=$(ls -td campaigns/*/ | head -1)
open "${CAMP}reports/top_threads.md"           # macOS, use xdg-open on Linux
open "${CAMP}reports/executive_summary.md"
open "${CAMP}reports/phishing_drafts.md"        # if you ran 7.2
open "${CAMP}reports/harvested_credentials.md"
open "${CAMP}reports/entity_graph.html"         # interactive, opens in browser
```

**Checklist, every report should:**
- [ ] Open without rendering errors
- [ ] Have a generation timestamp
- [ ] List the campaign ID
- [ ] Be empty-but-formatted if there's no data, NOT crash or show
      `KeyError` strings

**Common issues to flag:**
- Markdown tables with `None` cells where data should be (means a state key
  wasn't populated)
- Empty bullet lists when the data is present in `findings.json` (means a
  report template isn't reading the right key)
- Mojibake / encoding issues (UTF-8 should be clean everywhere)
- Authorization banner missing from any phishing draft

---

## Phase 10: Smoke at Specific Tools (optional, 10 min)

If something looked off in Phase 5/6, you can invoke specific tools
directly via the registry to isolate:

```bash
python3 -c "
import asyncio
import nexusrecon.tools.domain, nexusrecon.tools.intel, nexusrecon.tools.web
from nexusrecon.tools.registry import get_registry

async def main():
    r = get_registry()
    # Pick the tool you want to probe
    result = await r.execute('crtsh', 'YOUR-DOMAIN-HERE.example', 'domain')
    print('success:', result.success)
    print('error:', result.error)
    print('result_count:', result.result_count)
    print('first 3 entries:', list((result.data or {}).get('subdomains', []))[:3])

asyncio.run(main())
"
```

Repeat with any tool name from `nexusrecon tools` output. Useful for
diagnosing whether a tool is broken vs. just gated.

---

## Report-Back Template

When something fails, send back:

### A. Environment

```
OS: [macOS 14.x / Ubuntu 22.04 / Kali 2024.x / etc.]
Python: [3.11.x / 3.12.x]
LLM provider: [anthropic / openai / ollama]
LLM model: [from .env]
Binaries present: [run the verify loop from Phase 1.5 and paste output]
Keys present (do NOT paste values, just names):
  [e.g., ANTHROPIC_API_KEY, GITHUB_TOKEN, VIRUSTOTAL_API_KEY]
```

### B. What you ran

```
Command: [exact CLI invocation, including scope file path]
Phase reached: [e.g., "Phase 5, Minimal Live Campaign"]
Test target: [your test domain]
```

### C. What happened

```
Expected: [what the runbook said should happen]
Actual:   [what actually happened, in one sentence]
```

### D. Artifacts (attach or paste)

For crashes / tracebacks:
- Full stderr output (everything after the campaign launch banner)
- The traceback if any

For wrong-output bugs (report renders wrong, etc.):
- Path to the offending file: `campaigns/{id}/reports/{file}`
- Paste the offending section (5-20 lines around the bug)
- Paste the corresponding section of `campaigns/{id}/reports/campaign_meta.json`
  so we can see what state Sonnet was working from

For "feature didn't run":
- `campaigns/{id}/audit_log.jsonl` (last 50 lines)
- The flag value as reported by `campaign_meta.json` (confirms the CLI
  actually wired it through to state)

For cost overruns / runaway loops:
- `campaign_meta.json` (full file)
- The `dynamic_dispatch_log` section in particular
- Estimated wall-clock time the campaign ran for

### E. Severity tag (your judgment)

- **BLOCKER**: can't get past Phase 4 (dry run fails)
- **CRITICAL**: campaign crashes mid-phase
- **HIGH**: campaign completes but reports are broken / missing
- **MEDIUM**: feature works but output is wrong/confusing
- **LOW**: cosmetic, polish, doc gap

### F. Reproducibility

- One-shot: [happened once, can't reproduce]
- Sometimes: [3 of N runs]
- Always: [every run]

---

## Suggested Test Pass Order

For your first end-to-end shakedown, run in this order with brief
inspection between each:

1. **Phase 0 → 4**: environment + dry run (~30 min total)
2. **Phase 5**: minimal live campaign, no LLM cost (~10 min)
3. **Phase 9**: inspect reports from Phase 5 (~10 min)
4. **Phase 6**: same target with LLM enabled (~15 min)
5. **Phase 9**: inspect again, compare deltas (~10 min)
6. **Phase 7.1** + 7.2 + 7.3, feature flags one at a time (~45 min total)
7. **Phase 9**: final inspection of each flag's output

If you get to the end of step 7 without BLOCKER or CRITICAL issues, the
platform is shippable for personal use. Iterate on MEDIUM/LOW issues in
subsequent Sonnet sessions using the iteration template below.

---

## Iteration Template (for the next Sonnet prompt)

Once you've completed a testing pass and have a list of issues, hand
back to Sonnet with this template:

```
You are iterating on NexusRecon based on real-world testing feedback.
The full spec is in EXECUTION_PLAN_V2_GOLD_STANDARD.md at
/Users/waifumachine/agentic-osint/. Section 0 conventions are binding.

The operator ran the TESTING_RUNBOOK.md end-to-end and reports the
following issues, in priority order:

[paste the list of issues from the Report-Back Template, one per heading,
with all artifacts attached or inline]

For each issue:
1. Locate the responsible file(s) and line(s)
2. Diagnose the root cause
3. Implement the fix surgically (no broad refactors)
4. Note the fix in your end-of-turn report

Working rules from prior sessions still apply:
- No git commits, operator commits manually after review
- No system binary installs (PyPI fine)
- Stop and ask on architectural ambiguity
- Parallel tool calls for independent edits
- End-of-turn report under 15 lines

Begin by reading the issue list in full, then state your fix order
(typically: BLOCKER → CRITICAL → HIGH → MEDIUM → LOW), then proceed.
```

---

## Appendix: Useful Diagnostics

```bash
# Show all registered tools with availability status
nexusrecon tools

# Show only tools with available status
nexusrecon tools | grep -v missing

# Tail an in-flight campaign's audit log
tail -f campaigns/$(ls -t campaigns/ | head -1)/audit_log.jsonl

# Compute total LLM cost across all campaigns this session
find campaigns -name campaign_meta.json -exec jq '.total_llm_cost_usd' {} \; | \
  awk '{s+=$1} END {printf "Total: $%.2f\n", s}'

# Re-run a failed campaign by ID (resumes from last checkpoint)
nexusrecon run --scope test_scope.yaml --resume CAMPAIGN_ID
```
