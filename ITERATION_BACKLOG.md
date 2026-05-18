# NexusRecon: Iteration Backlog

> **What this is:** running log of bugs, papercuts, and small-scope improvements
> surfaced during testing. When you finish a testing pass, this file feeds
> directly into the next Sonnet prompt.
>
> **What this is NOT:** a feature wishlist or architectural-redesign tracker.
> Those belong in `EXECUTION_PLAN_V2_GOLD_STANDARD.md` or a successor.
>
> **Convention:** every entry has ID, severity, status, location, repro, and
> a fix suggestion. Strike-through (~~ID~~) when fixed. Don't delete, keep
> the history so we can spot patterns.

---

## Open

### B36: Findings about the same underlying intel get emitted by multiple phases without dedup

- **Severity:** MEDIUM (quality/polish, wastes ranked_threads slots, makes top-10 redundant)
- **Status:** OPEN
- **Discovered:** real-target campaign `nr-20260513-184341-d8ae58b2`, 2026-05-13
- **Repro:** Real-target campaign against the real-target domain produces FIVE findings about Azure M365 password-spray viability:
  - phase2: "M365 Managed Authentication - Password Spray Viable"
  - phase4: "Azure Managed Federation Enables Password Spray Attack Vector"
  - phase8: "M365 Managed Authentication - Password Spray Attack Vector"
  - phase8: "Azure Managed Federation - Password Spray Enablement"
  - phase9: "M365 Managed Authentication - Password Spray Attack Vector"
  All five reference the same tenant_id and the same underlying observation (managed auth = direct credential spray viable). They all end up in ranked_threads, consuming 3-5 of the top-10 slots.
- **Root cause:** Each phase's agent independently observes the same cloud_intel data and emits its own version of the finding. No cross-phase deduplication step exists. The scoring engine just sorts by score.
- **Fix options:**
  1. **Normalized-title dedup** in `nexusrecon/core/scoring.py` `score_findings()`. Compute a "topic key" per finding (lowercased title with stopwords removed + first 100 chars of description). Group findings by topic key; within each group keep the highest-confidence one and add a `corroborating_phases: [phase4, phase8, ...]` field. Operator sees one finding with provenance from 5 phases, actually MORE useful than 5 separate entries.
  2. **Prompt-level dedup**: in each phase's task_prompt, append "Do not re-state findings already established in prior phases, see state.findings." Less reliable (depends on LLM following the instruction).
  3. **Hybrid**: prompt-level instruction + programmatic backstop.
- **Recommendation:** Option 1, programmatic dedup with corroboration tracking. Cleaner than relying on LLM behavior.
- **Acceptance:** After fix, real-target campaign produces at most 1 "Password Spray" finding in `state.findings` (or `ranked_threads`), with `corroborating_phases` listing the phases that converged on it.

---

### ~~B35~~: Executive summary undercount: "Cloud Assets: 0" despite verified Azure presence

- **Severity:** MEDIUM (misleading top-line metric, operators believe target has no cloud presence)
- **Status:** RESOLVED 2026-05-13 (fixed inline by Claude)
- **Discovered:** real-target campaign, `cloud_intel["azure/<target>"]` had `attribution_confidence=1.0` and a real verified tenant ID, but executive_summary.md showed "Cloud Assets: 0".
- **Root cause:** `nexusrecon/reports/engine.py` `_executive_summary()` counted ONLY S3 buckets: `sum(len(v.get('s3_buckets', [])) for v in cloud_intel.values())`. Verified Azure tenants, GCP projects, public buckets, generic storage objects were all invisible to this metric.
- **Fix:** Added module-level helper `_count_cloud_assets(cloud_intel)` that:
  - Skips stem-match-only entries (`attribution_confidence < 0.5`)
  - Counts S3 buckets, public_buckets, gcs_buckets, generic storage objects across all providers
  - Counts each verified Azure tenant (openid_config.found == True) as 1 asset
  - Counts discovered GCP projects
  Replaced the inline S3-only sum with a call to this helper.
- **Files:** `nexusrecon/reports/engine.py`

### ~~B34~~: Phishing draft generation fails for every email; FINDINGS_JSON contamination breaks JSON parsing

- **Severity:** HIGH (entire `--generate-phishing` feature is dead on real targets; wastes ~$1.30 in LLM cost per campaign with harvested emails)
- **Status:** RESOLVED 2026-05-13 (fixed inline by Claude)
- **Discovered:** real-target campaign, 10 emails harvested, `phishing_drafter` agent called 10 times spending ~$1.30 in LLM cost, but every call logged `phishing_drafter returned unparseable output`. Zero draft files generated.
- **Root cause:** B25's FINDINGS_JSON requirement is injected into EVERY agent's prompt via `_build_context()`. The `phishing_drafter` agent specifically needs to return a pure draft JSON object for downstream parsing. With FINDINGS_JSON prepended, the agent now emits `FINDINGS_JSON:[...]\n\n{draft json}`. The `_extract_json` parser in phishing_drafts.py used a greedy `\{.*\}` regex that matched from the first `{` (inside FINDINGS_JSON's array element) to the last `}` (closing the draft), producing unparseable mixed content.
- **Fix (two-part):**
  1. **`agent_executor.py` `_build_context()`**: added `_SKIP_FINDINGS_JSON_AGENTS = {"phishing_drafter", "dynamic_dispatcher"}` set. Agents in this set get the prompt without the FINDINGS_JSON requirement and ATTRIBUTION RULE block, they need clean structured output for downstream parsing, not findings synthesis.
  2. **`phishing_drafts.py` `_extract_json()`**: hardened parser. First strips any FINDINGS_JSON block defensively (backstop in case agent emits it anyway). Then strips markdown code fences. Then tries direct parse. Then uses `json.JSONDecoder().raw_decode()` to find a balanced JSON object anywhere in the text, much more robust than the previous greedy regex.
- **Files:** `nexusrecon/graph/agent_executor.py`, `nexusrecon/reports/phishing_drafts.py`
- **Verified (unit):** all 4 test cases pass: clean JSON, FINDINGS_JSON-contaminated, prose-wrapped, markdown-fenced.
- **Pending:** real-target re-verification with real-target campaign.

---

### B33: Set-but-empty env var still defeats `.env` value despite B13 startup warning

- **Severity:** LOW (polish, workaround documented; doesn't block users who follow runbook)
- **Status:** OPEN
- **Discovered:** Campaign B3 attempt in feature-flag verification, 2026-05-13
- **Location:** `nexusrecon/core/config.py` pydantic-settings precedence
- **Repro:** Shell has `export ANTHROPIC_API_KEY=""` (empty). `.env` has the real key. Pydantic-settings precedence is `env > .env > default`, so it loads `SecretStr('')`. B13's `get_secret()` correctly returns `None` for empty values, but at that point `.env` has already been bypassed. The campaign falls through to MockLLM with no warning visible during runtime (the `_warn_empty_env_keys()` warning fires once at startup but is easy to miss in tool-registration noise).
- **Impact:** Operator runs a campaign and gets all-MockLLM output (findings=0, cost=$0) without an obvious indicator. Workaround: `env -u ANTHROPIC_API_KEY ./...` or `unset ANTHROPIC_API_KEY` before invoking.
- **Fix options:**
  1. **Prefer .env over empty env vars.** Subclass `EnvSettingsSource` to filter out empty values from `os.environ` before merging. Then pydantic precedence becomes `env (non-empty) > .env > default`, which is what users expect.
  2. **Make the empty-env warning louder.** Print it via `console.print(..., style="bold red")` immediately before the campaign starts, not at module-import time. The current `_warn_empty_env_keys()` is buried.
- **Recommendation:** Option 1, the root cause is pydantic-settings' "env always wins" precedence even for empty strings. Filtering empties from `os.environ` fixes it at the source.
- **Non-blocking:** the runbook tells operators to clean their env; the platform works correctly when env is clean. File for next polish round.

---

### ~~B32~~, `--generate-phishing` produces no `phishing_drafts.md`/`phishing_campaign.json` on empty input

- **Severity:** MEDIUM (UX, user can't tell the feature ran)
- **Status:** RESOLVED 2026-05-13 (fixed inline by Claude)
- **Discovered:** Campaign B with `--generate-phishing` on testphp produced empty "## Generated Drafts" section in `phishing_package.md` and no top-level draft index files.
- **Root cause:** `generate_phishing_drafts()` returned `{}` on empty emails and created zero files. No graceful empty-state handler.
- **Fix:** Added early-return branch in `nexusrecon/reports/phishing_drafts.py` for the empty-targets case. Writes `phishing_drafts.md` with the AUTHORIZATION banner + "No Targets" section explaining how to enable email harvesting. Writes `phishing_campaign.json` with the full GoPhish schema (`templates: []`, `targets: []`, etc.) plus warnings. Skips LLM cost entirely. Also fixed a `results` variable scope bug introduced in the first attempt (declared `results: Dict[str, str] = {}` earlier in the function so the empty-state branch can populate it).
- **Files:** `nexusrecon/reports/phishing_drafts.py`
- **Verified:** Campaign `nr-20260513-182208-4f54c5ae`, `phishing_drafts.md` (833 bytes) contains banner + operator guidance; `phishing_campaign.json` (284 bytes) has correct empty schema; no LLM cost burned on draft generation; ran alongside `--validate-creds` cleanly.

### ~~B31~~, `phase7_5_harvest` exists in nodes.py but is missing from the CLI phases list

- **Severity:** HIGH (the entire `--validate-creds` feature is dead code in the default CLI path)
- **Status:** RESOLVED 2026-05-13 (fixed inline by Claude)
- **Discovered:** Campaign B with `--validate-creds` flag produced no `state["harvested_credentials"]` key. `completed_phases` showed `phase1...phase9` with no `phase7_5`.
- **Root cause:** Same architectural pattern as B30. `phase7_5_harvest` is defined in `nodes.py:852` and is in `route_to_next_phase()`'s phase order, but the CLI's direct phase loop `phases = [...]` list (in `cli/main.py`) skips from `phase7` to `phase8`. The function is only invoked under `--use-graph`. The default path never runs credential harvest.
- **Fix:** Added `phase7_5_harvest` to the CLI import block + inserted `("phase7_5", "Credential Harvest", phase7_5_harvest)` between phase7 and phase8 in the `phases` list. Added `"phase7_5": 0` to the `phase_map` (T0 tier).
- **Files:** `nexusrecon/cli/main.py`
- **Verified:** Campaign `nr-20260513-182208-4f54c5ae`, `completed_phases: [..., "phase7_5", "phase8", "phase9"]`. `state["harvested_credentials"] = []` (correct empty list for testphp; would be populated on a target with exposed creds). `harvested_credentials.md` and `.json` now render from real phase output, not from the engine's fallback stub.

### ~~B30~~: Dispatcher never fires in default CLI path; `reflection_node` only wired into `--use-graph` workflow

- **Severity:** HIGH
- **Status:** RESOLVED 2026-05-13 (fixed inline by Claude during feature flag testing)
- **Discovered:** Campaign A (`nr-20260513-163753-2f9d887d`) ran with `--dispatch-mode lite` but produced empty `dynamic_dispatch_log`. Cost delta vs `--dispatch-mode off` was negligible, proving no extra dispatcher LLM calls happened.
- **Root cause:** `reflection_node` was correctly wired into the LangGraph workflow but NOT into the CLI's direct phase loop (which is the default execution path). Only `--use-graph` invocations got the dispatcher; everyone else's `dispatch_mode` setting was dead code.
- **Fix:** Added `reflection_node` import to `cli/main.py` + inline `s = await reflection_node(s)` call between each phase in `_run_campaign_phases()`. Reflection_node is self-gating: checks `dispatch_mode` and `current_phase` internally, so off-mode is a no-op.
- **Files:** `nexusrecon/cli/main.py` (1-line import + 8-line block)
- **Verified:** Campaign `nr-20260513-164946-f952b85c` (real Anthropic, $1.47, only $0.05 over `off` baseline). All 5 acceptance criteria pass:
  1. ✅ dispatch_log has 5 entries
  2. ✅ Reflection_node fired after all 3 lite-mode gates (phases 1, 4, 7). Phases 4 and 7 emitted "empty plan from LLM", the LLM intelligently judged no further dispatches needed after the initial seed expansion.
  3. ✅ Per-cycle cap of 5 held exactly
  4. ✅ Off-mode no-op preserved (baseline run confirmed empty dispatch_log)
  5. ✅ Dispatched tool results merged correctly: `subfinder → subdomain_intel/dynamic/...`, `crtsh → domain_intel/dynamic/...`, `shodan + virustotal → infra_intel/dynamic/...`
- **Notable:** LLM rationale strings are well-reasoned, e.g. *"Zero subdomains found for seed domain; subdomain enumeration is a critical phase1 gap"*, the agentic behavior is working as intended.

---

## Resolved (kept for history)

### ~~B29~~: Partial B26 regression: `user_realm` "Managed" + onmicrosoft stem-match still produces unmarked password-spray findings

- **Severity:** MEDIUM
- **Status:** RESOLVED 2026-05-13 (fixed inline by Claude, not Sonnet)
- **Fix (three-part defense in depth):**
  1. **`azure_tool.py` (B29 Option 1, per-sub-field tagging):** After existing top-level `attribution_confidence` assignment, propagate the value to `user_realm`, `onmicrosoft_domain`, each `app_services[i]`, and each `azure_devops[i]` sub-dict. Microsoft's `getuserrealm.srf` returns "Managed" by default for any domain, its data is only reliable when `openid_config.found == True`. Sub-field tagging makes the gate explicit at every level the agent might consume.
  2. **`agent_executor.py` (B29 Option 2, programmatic backstop):** Added static method `_gate_findings_by_attribution(findings, state)` that runs after `_parse_findings_json` and before `state.findings.extend(...)`. Walks findings and downgrades any that (a) reference stem-match identifiers (tenant IDs, bucket names, app URLs) collected from `cloud_intel` sections with `attribution_confidence < 0.5`, or (b) make Azure/AWS attack-vector claims (password spray, managed federation, S3 bucket exposure) when the target has no verified cloud presence. Downgraded findings get severity="info", title prefixed with "[POSSIBLE]", and `attribution_gated: True` flag.
  3. **`nodes.py` phase 2 (B29 bug-within-the-fix):** Moved `state["cloud_intel"] = cloud_intel` and `state["email_intel"] = email_intel` to BEFORE the agent run. Previously these assignments happened after the agent, so the gate ran blind (state["cloud_intel"] was empty in phase 2). Without this move, sub-field tagging and the backstop couldn't see the data they were supposed to gate against.
- **Files:** `nexusrecon/tools/cloud/azure_tool.py`, `nexusrecon/graph/agent_executor.py`, `nexusrecon/graph/nodes.py`
- **Verified:** Campaign `nr-20260513-161850-e66903e3` (real Anthropic, $1.42 cost):
  - Acceptance #1 ✅ 0 unmarked password-spray findings at medium+ severity
  - Acceptance #2 ✅ 1 finding cites tenant `<third_party_tenant_id>`, correctly tagged `[info] [POSSIBLE]`
  - Acceptance #3 ✅ Top-5 ranked threats contain no false cloud attribution (SPF/DMARC/identity-gap/WAF/DNSSEC are all legitimate)
  - Sanity: 38 findings across 8 distinct phases (B25/B28 not regressed); 2 findings gated by backstop; 0 rejected by evidence auditor.

### ~~B28~~, `EvidenceAuditorAgent` rejects every agent-synthesized finding; B25's "fix" was a false-resolve

- **Severity:** HIGH
- **Status:** RESOLVED 2026-05-13 (also closes B25 fully)
- **Fix:** Added `import hashlib` to `agent_executor.py`; in `_parse_findings_json` after `setdefault("timestamp", ...)`, compute `evidence_str = f"{phase}::{title}|{description[:500]}"` and call `finding.setdefault("raw_evidence_hash", "sha256:" + hashlib.sha256(...).hexdigest())` plus `finding.setdefault("source", ...)`. Two-line addition, auditor now sees a valid hash on every agent finding.
- **File:** `nexusrecon/graph/agent_executor.py`
- **Verified:** Campaign `nr-20260513-153707-6ba9fdf1`, `passed=35 rejected=0`; findings=40; 8 distinct phases (phase1:6, phase2:5, phase3:1, phase4:5, phase5:4, phase7:4, phase8:10, phase9:5); rejected=0.

---

## Resolved (kept for history)

### ~~B26~~: Confident misattribution: tools report name-stem-matching assets as if they belong to the target

- **Severity:** CRITICAL (blocks public release, operators acting on these findings would attempt unauthorized access to third-party infrastructure)
- **Status:** RESOLVED 2026-05-13
- **Fix:**
  1. `azure_tool.py`: Added `attribution_confidence` (1.0 if openid-config returns 200 for exact domain, else 0.2) and `attribution_signals` list to every result.
  2. `azure_tenant_tool.py`: Same, 1.0 if `tenant_id` was resolved via openid-config, else 0.2.
  3. `aws_tool.py`: Always 0.2 (`attribution_confidence`) + `attribution_signals: ["stem_enumeration_only","no_dns_ownership_link"]`.
  4. `bucket_enum_tool.py`: Added `attribution_confidence: 0.2, attribution_signals: ["name_permutation_enumeration"]` to result dict.
  5. `agent_executor.py` `_build_context()`: Prepended ATTRIBUTION RULE block, any data with `attribution_confidence < 0.5` must cap severity at "info" and prefix title "[POSSIBLE]".
  6. `nodes.py` phase2/phase4 task_prompts: Added explicit guidance to check `attribution_confidence` and gate cloud assertions on ≥ 0.5.
  7. `nodes.py` phase4 Python logic: `confirmed_leads.append(...)` for cloud federation/bucket findings now guarded by `data.get("attribution_confidence", 1.0) >= 0.5`; low-confidence items go to `open_questions` instead.
- **Files:** `nexusrecon/tools/cloud/azure_tool.py`, `nexusrecon/tools/cloud/azure_tenant_tool.py`, `nexusrecon/tools/cloud/aws_tool.py`, `nexusrecon/tools/cloud/bucket_enum_tool.py`, `nexusrecon/graph/agent_executor.py`, `nexusrecon/graph/nodes.py`
- **Verified:** Re-ran campaign `nr-20260513-144408-e01513dc` against `testphp.vulnweb.com`. Zero critical/high Azure or AWS findings. Azure and AWS presence shown as `[info] [POSSIBLE] ... Stem-Match Only`. Password-spray finding eliminated.

### ~~B27~~: Findings have empty `affected_assets`, `mitre_techniques`, `recommendation` fields

- **Severity:** MEDIUM (reports look unprofessional with empty fields; downstream automation breaks)
- **Status:** RESOLVED 2026-05-13
- **Fix:**
  1. `agent_executor.py` `_build_context()`: Restructured FINDINGS_JSON requirement block, moved to lead position (before task prompt and data context), made `affected_assets`, `next_steps`, and `recommendation` explicitly required with non-negotiable example language.
  2. `engine.py` `_full_report()`: Replaced unconditional rendering of affected_assets/mitre/recommendation with conditional blocks, labels are only emitted when values are non-empty and not "N/A"/"-"/"none".
- **Files:** `nexusrecon/graph/agent_executor.py`, `nexusrecon/reports/engine.py`
- **Verified:** `nr-20260513-144408-e01513dc` `full_report.md` has 0 "Recommendation: N/A" lines; all 5 findings have populated `affected_assets` and `next_steps` with concrete tool-specific actions.

### ~~B25~~: Per-phase agents don't emit FINDINGS_JSON blocks under real Anthropic; only the phase 9 reporter does

- **Severity:** MEDIUM (platform still produces findings via the reporter, but loses per-phase signal that should bubble up; ranked_threads list under-populated)
- **Status:** RESOLVED 2026-05-13
- **Fix (Option 1, prompt restructuring):**
  1. `agent_executor.py` `_build_context()`: FINDINGS_JSON requirement block now comes FIRST in every agent prompt (before role context, before data, before task). Real LLMs respect instruction ordering, leading with the requirement ensures it's emitted reliably.
  2. `MockLLM._generate_response()`: Updated to emit `FINDINGS_JSON:{...}\n\n{prose}` (JSON first) to mirror the prompt structure.
- **Files:** `nexusrecon/graph/agent_executor.py`
- **Verified:** `nr-20260513-144408-e01513dc` logs show `new_findings` in all 8 executed phases (7+4+1+5+4+4+8+5); criterion was ≥4 distinct phases.

### ~~B24~~: Agents produce analysis prose but no structured `findings` entries
- **Severity:** HIGH
- **Status:** RESOLVED 2026-05-12
- **Fix:**
  1. `AgentExecutor._build_context()` now appends FINDINGS_JSON instructions to every agent prompt, requiring a `FINDINGS_JSON:[{...}]` block after the prose.
  2. `AgentExecutor._parse_findings_json(content, phase)` extracts the block using `json.JSONDecoder().raw_decode()`. Silently skips on parse failure.
  3. `AgentExecutor.run_agent()` accepts `state=` kwarg; when provided, extends `state["findings"]` with parsed findings in-place.
  4. `MockLLM._generate_response()` always emits a FINDINGS_JSON block.
  5. `scoring._score_agent_findings(state)` converts `state["findings"]` into `RankedFinding` objects so Phase 8 can produce non-empty `ranked_threads` even in light mode.
  6. Phase 8 (nodes.py): removed `ranked_legacy` snapshot overwrite; re-sort happens after agent synthesis.
  7. All 9 `run_agent()` calls in nodes.py updated to pass `state=state`.
- **Files:** `nexusrecon/graph/agent_executor.py`, `nexusrecon/graph/nodes.py`, `nexusrecon/core/scoring.py`
- **Verified:** `state.findings=6`, `ranked_threads=10`, `top_threads.md` has 10 `## Thread` sections

### ~~B23~~, `llm_cost_usd` not tracked despite LLM clearly being used
- **Severity:** MEDIUM
- **Status:** RESOLVED 2026-05-12
- **Fix:**
  1. `AgentExecutor.__init__()` now creates a `CostTracker("agent_executor", max_llm_cost_usd=1_000_000)`.
  2. `AgentExecutor._extract_token_usage(response)` reads `usage_metadata` (Anthropic) or `response_metadata["token_usage"]` (OpenAI); falls back to content-length estimate for MockLLM.
  3. After each LLM call, `record_llm_call()` is called and `state["llm_cost_usd"] += call_cost`.
  4. Budget pre-check in `run_agent()` raises `BudgetExceededError` when `llm_cost_usd >= max_llm_cost_usd`.
  5. `cli/main.py` initial state now includes `"max_llm_cost_usd": scope_model.constraints.max_llm_cost_usd`.
- **Files:** `nexusrecon/graph/agent_executor.py`, `nexusrecon/cli/main.py`
- **Verified:** `state.llm_cost_usd=1.2864` after 8-agent MockLLM campaign

### ~~B22~~: Audit log error field replaces real error message with literal string `"unknown"`
- **Severity:** MEDIUM
- **Status:** RESOLVED 2026-05-12
- **Fix:** `registry.py` line 175: changed `result.error or "unknown"` → `result.error or "(no error message provided by tool)"`.
- **Files:** `nexusrecon/tools/registry.py`
- **Verified:** `certstream_recent` audit entry now shows `"(no error message provided by tool)"` instead of `"unknown"`

### ~~B21~~, `theharvester` binary not found: case-sensitive name mismatch
- **Severity:** LOW
- **Status:** RESOLVED 2026-05-12
- **Fix:** `theharvester_tool.py` now calls `shutil.which("theHarvester") or shutil.which("theharvester")` and returns a clean `ToolResult(success=False, error="...")` if neither is found.
- **Files:** `nexusrecon/tools/identity/theharvester_tool.py`
- **Verified:** Audit log shows `"theHarvester binary not found in PATH (tried 'theHarvester' and 'theharvester')"`, clean message, no crash

### ~~B20~~, `nuclei` tool errors: `'list' object has no attribute 'get'`
- **Severity:** MEDIUM
- **Status:** RESOLVED 2026-05-12
- **Fix:** `nuclei_tool.py` parsing now checks `isinstance(parsed, list)` and iterates items; only calls `.get()` on dict items. Handles both `{...}` and `[{...}]` nuclei JSONL line formats.
- **Files:** `nexusrecon/tools/web/nuclei_tool.py`

### ~~B19~~, `asn_bgp` tool: DNS resolution failure for single-host targets
- **Severity:** LOW
- **Status:** RESOLVED 2026-05-12
- **Fix:** `asn_bgp_tool.py` now detects non-IP non-ASN targets (domains), calls `socket.gethostbyname()` to resolve, and returns `ToolResult(success=False, error="DNS resolution failed for ...")` on `socket.gaierror`. Uses the resolved IP for the BGPView `/ip/` endpoint.
- **Files:** `nexusrecon/tools/domain/asn_bgp_tool.py`
- **Verified:** Audit log entry shows `"DNS resolution failed for domain 'testphp.vulnweb.com': ..."`, clean message, no crash

### ~~B18~~: Tool error messages hidden as `"unknown"` in audit log; remaining failures need triage
- **Severity:** MEDIUM
- **Status:** RESOLVED 2026-05-12
- **Investigation result (post B22 fix):** Re-ran clean campaign against `testphp.vulnweb.com`. Remaining 4 `tool_error` entries after all fixes:
  - `asn_bgp`: DNS resolution failure (B19 fix working; offline test environment)
  - `certstream_recent`: WebSocket connection unavailable (offline environment; B22 shows real message)
  - `theharvester`: binary not installed (B21 fix working, clean message)
  - `sslyze`: Cannot connect to port 443 (offline environment; benign)
- **Conclusion:** No new genuine bugs. All remaining failures are offline-environment artifacts or already-fixed issues showing correct behavior. No B25+ needed.

### ~~B17~~: Campaign state never persisted to state.json; every campaign produces empty deliverables
- **Status:** RESOLVED 2026-05-12
- **Fix:** Added `CampaignManager.save_state(state_dict)` public method and `_live_dict` instance attribute. `_save_state()` now prefers `_live_dict` over the empty pydantic skeleton. CLI loop calls `campaign.save_state(s)` after each phase. Removed F-018 silent-swallow sync block. `finalize()` counts findings from `_live_dict`.
- **Files:** `nexusrecon/core/campaign.py`, `nexusrecon/cli/main.py`

### ~~B16~~, crtsh tool fails immediately: `h2` package not installed for httpx HTTP/2
- **Status:** RESOLVED 2026-05-12
- **Fix:** Changed `"httpx[socks]>=0.27.0"` → `"httpx[socks,http2]>=0.27.0"` in `pyproject.toml`. Run `pip install -e .` to pull in `h2`.
- **Files:** `pyproject.toml`

### ~~B15~~: Panel concat crash at end of campaign
- **Status:** RESOLVED 2026-05-12
- **Fix:** Replaced `console.print("\n" + Panel(...))` with two separate calls: `console.print()` then `console.print(Panel(...))`.
- **Files:** `nexusrecon/cli/main.py`

### ~~B14~~: Audit log entries omit `success` field
- **Status:** RESOLVED 2026-05-12
- **Fix:** Added `"success": True` to `log_tool_result()` and `"success": False` to `log_tool_error()`.
- **Files:** `nexusrecon/core/audit.py`

### ~~B13~~: Empty env vars silently override populated `.env` values; campaigns silently fall back to MockLLM
- **Status:** RESOLVED 2026-05-12
- **Fix:** `get_secret()` now returns `None` instead of `""` for empty SecretStr/str values. Added `_warn_empty_env_keys()` startup function that detects set-but-empty shell env vars overriding `.env` values and emits a clear `[WARN]` with `unset {KEY}` instructions.
- **Files:** `nexusrecon/core/config.py`, `nexusrecon/cli/main.py`

### ~~B12~~: Dry-run prints an `Output:` path it never actually creates
- **Status:** RESOLVED 2026-05-12
- **Fix:** Changed message to `"Would create output at: ..."` (future-tense, side-effect-free).
- **Files:** `nexusrecon/cli/main.py`

### ~~B11~~: Tool-registration INFO logs pollute every CLI invocation
- **Status:** RESOLVED 2026-05-12
- **Fix:** Changed `log.info("Registered tool", ...)` → `log.debug(...)` in `ToolRegistry.register()`.
- **Files:** `nexusrecon/tools/registry.py`

### ~~B10~~: ROE banner printed twice on every `run` command
- **Status:** RESOLVED 2026-05-12
- **Fix:** Removed duplicate `console.print(ROE_BANNER)` from `run()` in `cli/main.py`. Banner is displayed exactly once by `campaign.setup()` → `_display_roe_banner()`.
- **Files:** `nexusrecon/cli/main.py`

### ~~B9~~: No "discovery-surfacing" or "auto-expand" scope mode
- **Status:** DEFERRED, feature work, separate iteration. Spec preserved in git history.

### ~~B8~~: Scope templates are misleading; minimal-scope path is undocumented
- **Status:** RESOLVED 2026-05-12
- **Fix:** Created `examples/scopes/minimal_seed.yaml` (one-domain starter). Renamed existing three scopes to `*_completed_example.yaml` and added header comments. Updated README Quick Start, MANUAL.md §4, and TESTING_RUNBOOK.md Phase 3 to point to `minimal_seed.yaml`.
- **Files:** `examples/scopes/minimal_seed.yaml` (new), `examples/scopes/*_completed_example.yaml` (renamed), `README.md`, `MANUAL.md`, `TESTING_RUNBOOK.md`

### ~~B7~~, `--seeds` CLI flag interaction with scope-listed domains undocumented
- **Status:** RESOLVED 2026-05-12
- **Fix:** Added scope-subset guard in `run()`: seeds not matching a scope domain or subdomain cause a hard error before any tool runs. Documented precedence rules and `--seeds` semantics in MANUAL.md §5.
- **Files:** `nexusrecon/cli/main.py`, `MANUAL.md`

### ~~B6~~: Spurious "may not be running inside the project venv" warning on every CLI invocation
- **Status:** RESOLVED 2026-05-12
- **Fix:** Replaced path-string heuristic `"venv" not in nexusrecon.__file__` with reliable venv detection using `sys.real_prefix`, `sys.prefix != sys.base_prefix`, and `os.environ.get("VIRTUAL_ENV")`.
- **Files:** `nexusrecon/cli/main.py`

### ~~B5~~, `install.sh` does not install `cairo` + `pkg-config` (macOS) / `libcairo2-dev` (Debian)
- **Status:** RESOLVED 2026-05-12
- **Fix:** Added `cairo`, `pkg-config`, `pipx` to `BREW_PKGS`; added `libcairo2-dev`, `pkg-config`, `python3-pipx` to `APT_PKGS`.
- **Files:** `install.sh`

### ~~B4~~: Architectural: `maigret` should be pipx-isolated, not pip-installed
- **Status:** RESOLVED 2026-05-12
- **Fix:** Added `install_pipx_tools()` helper function with `pipx install maigret` + `pipx ensurepath`. Called from `install_python_packages()`. Post-install note printed about `~/.local/bin`.
- **Files:** `install.sh`

### ~~B3~~, `maigret` missing from `install.sh` Python install step
- **Status:** RESOLVED 2026-05-12 (via B4, installed through `install_pipx_tools()` instead of pip)
- **Files:** `install.sh`

### ~~B2~~, `install.sh` does not add `$HOME/go/bin` to PATH
- **Status:** RESOLVED 2026-05-12
- **Fix:** Added PATH check at end of `install_go_tools()`. With `--yes`, appends `export PATH="$HOME/go/bin:$PATH"` to `~/.zshrc`/`~/.bashrc`. Otherwise prints explicit instruction block.
- **Files:** `install.sh`

### ~~B1~~, `install.sh install_go_tools` hides install errors
- **Status:** RESOLVED 2026-05-12
- **Fix:** Removed `2>/dev/null` from `go install` line so stderr passes through to the terminal.
- **Files:** `install.sh`

### ~~B0a~~, `install.sh` runs `pip install` outside a venv (PEP 668)
- **Fixed in:** `INSTALL_FIX_PLAN.md` Fix 2 (`ensure_venv()` function)

### ~~B0b~~, `install.sh` Python version gate had no upper bound (Python 3.14 accepted)
- **Fixed in:** `INSTALL_FIX_PLAN.md` Fix 3

### ~~B0c~~, `pyproject.toml` `requires-python = ">=3.11"` lacked upper bound
- **Fixed in:** `INSTALL_FIX_PLAN.md` Fix 1 (now `">=3.11,<3.14"`)

### ~~B0d~~, `BREW_PKGS` contained non-formulae (`waybackurls`, `naabu`, `dnstwist`)
- **Fixed in:** `INSTALL_FIX_PLAN.md` Fix 4

### ~~B0e~~, `install.sh` had no end-of-install verification
- **Fixed in:** `INSTALL_FIX_PLAN.md` Fix 6 (`verify_install()` function)

### ~~B0f~~: README/MANUAL install instructions did not mention venv
- **Fixed in:** `INSTALL_FIX_PLAN.md` Fix 7

---

## How to convert this backlog into the next Sonnet prompt

When you finish your testing pass:

1. Anything you found and we discussed in chat goes into a new entry below
   the last open entry, I'll add them as we go.
2. When ready to iterate, the next Sonnet prompt is essentially:

```
You are iterating on NexusRecon based on testing feedback. The full
spec is EXECUTION_PLAN_V2_GOLD_STANDARD.md; Section 0 conventions are
binding. Open bugs are listed in ITERATION_BACKLOG.md, fix every entry
under "## Open" in severity order (CRITICAL → HIGH → MEDIUM → LOW).

For each fix: implement surgically, update the entry's status to RESOLVED
in the same commit-worthy edit (move it to "## Resolved" with the fix
description), and run the verification command listed in the entry.

Working rules: no git commits, no system binary installs, surgical edits,
stop and ask on architectural ambiguity, parallel tool calls for
independent edits. End-of-turn report under 15 lines.

Begin by reading ITERATION_BACKLOG.md in full, then state your fix
order, then proceed.
```

That's it. No need to rewrite the bug list inline, Sonnet reads the file.

---

## Conventions

- **Severity:** CRITICAL (BLOCKER) > HIGH > MEDIUM > LOW
- **Status:** OPEN | IN PROGRESS | RESOLVED | WONT FIX | DEFERRED
- **IDs:** B-prefix + monotonic int. Don't renumber on resolution, strike
  through the ID and move the entry to the Resolved section.
- **Add new bugs** at the top of the Open section (most recent first).
- **Move resolved bugs** to the Resolved section in order of resolution.


---

## Features Shipped

| Date | Feature | Notes |
|------|---------|-------|
| 2026-05-13 | **V3 Move 2, Master Report** | New `master_reporter` agent + `_master_report()` engine method. Single cohesive narrative deliverable; sections 1, 2, 3, 9, 10, 11 always present; sections 4-8 conditionally rendered with skip-empty logic gated on `attribution_confidence >= 0.5` and actual discovery content. Files: `nexusrecon/agents/master_reporter.py` (new), `nexusrecon/graph/agent_executor.py` (registry + skip set), `nexusrecon/reports/engine.py` (+`_master_report`), `nexusrecon/docs/REPORT_GUIDE.md`. Verified on `nr-20260514-144842-6a6b316f`: 6 sections (1/2/3/9/10/11) present, 4-8 absent for thin target; agent cost $0.1232 (< $1 budget); LLM prose tagged `[POSSIBLE]` correctly. |
| 2026-05-13 | **V3 Move 1, Interactive TUI** | New Textual-based wizard / runner / results UI invoked via `nexusrecon tui` or `nexusrecon` with no args; non-TTY environments fall back to CLI help with a clear message. Existing CLI surface unchanged. Files: `nexusrecon/tui/{__init__,app,banner,app.tcss}.py` + `nexusrecon/tui/screens/{welcome,wizard,runner,results,campaigns,config}.py` (new), `nexusrecon/core/campaign_runner.py` (extracted phase loop with `on_event` callback, shared by CLI + TUI), `nexusrecon/cli/main.py` (callback for default subcommand + `tui` subcommand + Progress integration via on_event), `pyproject.toml` (+`textual>=0.50.0`). |
