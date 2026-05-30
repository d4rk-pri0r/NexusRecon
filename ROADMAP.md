# NexusRecon Roadmap

Current state, what's left before 1.0, what comes after. Pull requests
welcome; prioritisation is set by the maintainer.

---

## Current state: `0.7.0` (beta)

The four core bets of the post-0.5 transformation (Living Graph
foundation, Strategic Reasoning Engine, Continuous Confidence
Engine, Contribution & Pack format) plus four of five moonshot
capabilities ship in this release.
**Test suite: 590/590 passing.**

What works today:

- **12-phase reconnaissance pipeline** + credential harvest
  (phase 7.5) + pretext intelligence (phase 7.7).
- **Living Intelligence Graph**: 17+ entity types, per-source
  provenance, confidence, traversable relationships, first-class
  hypotheses / leads / open questions, mutation events.
- **Strategic Reasoning Engine**: Strategy dataclass, pluggable
  DispatchPolicy (lite / full / off + community-extensible),
  simulation, bounded agency (deep-pivot + human-approval queue).
- **Continuous Confidence Engine**: corroboration (lifts on
  multi-class agreement), contradiction (downgrades on conflicts),
  propagation (cascades downgrades), adversarial self-check (graph
  audit).
- **Recon Pack format**: community-authored bundles contribute
  tools / agents / dispatch policies / report templates / custom
  entity-and-rel types. Git URL install, marketplace search.
- **Contribution SDK**: `nexusrecon agent new` / `tool new` /
  `policy new` scaffolders with prompt versioning + citation
  guardrails wired in.
- **Intent-driven entry**: `nexusrecon plan "<sentence>"`
  synthesizes scope.yaml + Strategy from natural language.
- **STIX 2.1 export + bidirectional import**: STIX bundles,
  Nessus XML, Nuclei JSON-lines, generic CSV.
- **Downstream emitters**: Jira NDJSON, Nuclei target lists,
  Cobalt Strike Malleable C2 profile stubs.
- **Watch Mode**: continuous monitoring with three sensor types
  and tiered actions (alert / notification / queued micro-campaign).
- **Provenance cryptography**: Ed25519 signed STIX bundles +
  standalone single-file verifier auditors can run without
  NexusRecon installed.
- **Adversarial platform self-defense**: four detectors (poisoned
  data, tool patterns, evidence inconsistency, prompt injection).
- **Multi-modal vision pipeline**: screenshots, PDFs, QR codes;
  multi-provider via langchain; strategy-budgeted.
- Tool registry with scope-gated execution; LLM-driven dynamic
  dispatcher; hash-chained audit log; cost tracker; rate limiter.
- 17+ deliverable report types (master narrative, top threads,
  asset inventory, phishing package, attack-surface matrix, vuln
  correlation, harvested credentials, STIX bundles, spear-phishing
  intelligence, etc.).
- TUI front door (welcome screen, new-campaign wizard, runner with
  live structlog stream, results browser, masked .env editor).

What's still beta-status about it:

- TUI surfaces for the new Watch / Intent / Vision flows not yet
  built. Capabilities are CLI-first; TUI tabs land as community
  pull warrants.
- Auto-dispatch of high-severity Watch Mode micro-campaigns is
  deferred behind an opt-in flag
  (`auto_dispatch_micro_campaigns` in the watch config) but not
  yet wired through to the campaign runner.
- Curated marketplace content. Index format + search ship;
  canonical hosted content is operator / community curated.
- Some niche tools still flagged `[STUB]` in their descriptions
  (gowitness; awaiting subprocess wrapper).
- Fresh-VM install across all platforms (M-series macOS,
  Linux x86_64, Linux arm64) needs documented coverage matrix.

---

## Next wave (Wave F): trustworthy signal + failure honesty

This wave is the current top priority. It does not add tools or
phases; it makes the existing pipeline tell the truth about what it
did and surface only what is worth a pentester's attention.

**Scope note:** Wave F is correctness baseline work, the bar for the
tool not being broken, not a GA gate. Finishing it does not mean
`1.0` / GA. The "Path to `1.0.0`" section below is still the GA
checklist and sits on top of this wave, not in place of it.

**Evidence base: the 2026-05-27 `ginandjuice.shop` run**
(`nr-20260527-194140-04f5cc30`). On paper: 9 phases completed, 36
findings, 8 medium, a confident multi-section executive summary.
Reading the audit log against the reports tells a different story:

- 12 `tool_error` events; ~23 tools returned `success=True` with
  `result_count=0`; `entities_count=0` for every phase; `$0.00`
  LLM cost reported throughout.
- Several zero-result "successes" are silent failures, not real
  negatives: `nuclei` ran 140s and found nothing on a deliberately
  vulnerable shop; `sslyze` returned 0 against a live HTTPS host;
  `wafw00f` reported no WAF on a CDN-fronted site; `whois` returned
  0 for a registered domain and became a "WHOIS Privacy / Anomaly"
  finding.
- `shodan` and `dehashed` were dispatched and errored even though
  the scope set `allow_paid_apis: false` and
  `allow_breach_db_lookup: false`. `theHarvester` errored twice
  (binary not installed) with no preflight warning.
- Of the 36 findings, roughly 4 are genuinely actionable. The rest
  are absence-of-data notes, conf-0.2 speculation, and the same few
  facts counted two or three times.

The throughline: today the framework cannot distinguish "looked and
found nothing" from "the tool failed to do its job," and it renders
both, plus low-confidence guesses and duplicate facts, as ranked
findings. This wave closes that gap. It also finally lands the
unchecked "Report quality smoke" beta blocker below, which this run
proves is not optional.

### F-A: failure detection and run honesty

- [x] **F-A1 Result-plausibility floor per tool.** Added an
      `assess_result()` hook to `nexusrecon/tools/base.py::OSINTTool`
      plus `degraded` / `degraded_reason` on `ToolResult`. The
      registry calls it after every successful, non-cached run and
      records the verdict in the audit log's `tool_result` event. A
      zero-result run that should not be zero is now flagged
      `degraded` instead of passing as a clean `success`. Seed
      checks shipped: `sslyze` (no protocols and no cert = handshake
      failure, keyed on data not the vuln count), `whois` (no fields
      at all for a resolving domain), `wafw00f` (now records a
      `reachable` signal; an unreachable probe is degraded, a real
      "no WAF" is not), `nuclei` (now captures the previously
      discarded subprocess exit code: non-zero with no findings is a
      hard failure, and stderr failure markers flag degraded; a clean
      empty scan is left as a valid negative). Tests in
      `tests/unit/test_wave_f_failure_detection.py`.
- [x] **F-A2 Gate dispatch on engagement constraints, not just
      keys/binaries.** Added `ScopeGuard.check_constraints()` in
      `nexusrecon/core/scope.py` and a gate in the tool registry's
      `execute()` chokepoint (`nexusrecon/tools/registry.py`), which
      every phase already routes through. Breach-category tools are
      skipped when `allow_breach_db_lookup: false`; tools flagged
      `paid_api` are skipped when `allow_paid_apis: false`. Skips are
      audited as `policy_skipped` (new event) before invocation, so
      `shodan` (now `paid_api = True`) and `dehashed` (breach
      category) no longer fire and 403/404 in a constraints-off
      engagement. `max_tier` was already enforced via `check_tier`.
      The paid-tool flag is deliberately conservative (only tools
      with no usable free tier) so a paid-off engagement never
      silently loses free recon; widening the `paid_api` marking
      across the other metered APIs is a follow-up. Tests in
      `tests/unit/test_wave_f_failure_detection.py`.
- [x] **F-A3 Preflight availability report.** `ToolRegistry`
      `availability_report()` buckets every tool into active /
      missing_binary / missing_key / policy / over_tier / stubbed
      (each with a reason). `run_campaign()` emits it as a `preflight`
      event, audit-logs it (`preflight_summary`), and stashes it in
      `state["preflight"]` before the first phase, so the operator
      sees `theHarvester` is uninstalled and `shodan` is policy-off up
      front. The CLI prints a one-line preflight summary and the TUI
      runner logs it (`format_preflight_console`). Tests in
      `tests/unit/test_wave_f_failure_detection.py`.
- [x] **F-A4 Retry + distinguish transient upstream failures.**
      Added `http_get_with_retry()` in `nexusrecon/tools/base.py`:
      bounded exponential backoff on 5xx (502/503/504) and on
      timeout/transport errors, returning the last response on
      exhaustion so the failure is still classified and reported (the
      retry never hides it). 429 and 4xx are deliberately not retried.
      Adopted in `crtsh` and `certstream_recent`, the load-bearing
      passive sources that 502'd in the run. The registry now logs a
      concrete message when a tool returns failure with no error
      string, so nothing reaches the trail as a silent blank. When a
      load-bearing source still fails, F-A5 flags its capability as
      degraded (the ginandjuice replay shows `certificate` degraded
      from the crt.sh 502s). Tests in
      `tests/unit/test_wave_f_failure_detection.py`.
- [x] **F-A5 Run-level health summary.** `nexusrecon/core/run_health.py`
      reads the audit log back into a `RunHealth`: productive vs.
      empty-ok vs. degraded vs. errored vs. policy-skipped counts,
      plus `degraded_capabilities` (a category attempted but with no
      usable data, distinguishing real failure from a clean empty)
      and a `zero_entities` flag. `_build_caveats` emits blunt
      warnings: active-scanning-unverified, zero-entities-despite-
      successes, error/degraded/policy counts. `run_campaign()` writes
      `run_health.md`, stashes `state["run_health"]`, and folds it
      into the `campaign_complete` event. Validated against the real
      ginandjuice.shop log (6 productive / 23 empty / 12 errors / zero
      entities / breach+certificate degraded). The master report now
      carries a "1a. Run Health" banner (caveats + tool-outcome tally +
      degraded capabilities + analysis-engine provenance) since
      `generate_all` runs after `run_campaign` populates
      `state["run_health"]`. Tests in
      `tests/unit/test_wave_f_failure_detection.py` +
      `test_wave_f_reporting_value.py`.
- [x] **F-A6 Make cost/telemetry trustworthy.** Root cause of the
      `$0.00`: `AgentExecutor` recorded spend into a private
      `CostTracker` while `campaign.end_phase` / `finalize` read the
      campaign's, so the real numbers died in the wrong instance.
      `AgentExecutor.bind_cost_tracker()` + `nodes.set_executor_cost_tracker()`
      now bind the campaign tracker at `run_campaign` start, so phase_end
      and the finalize summary reflect real per-agent token spend. Added
      `mock_llm` (and the current claude-4.x models) to `MODEL_PRICING`;
      `mock_llm` is priced at zero so "cost == 0 and model == mock_llm"
      is an unambiguous fallback signal. The executor records per-model
      call counts into `state["llm_calls_by_model"]`;
      `run_health.llm_provenance_from_state()` derives a
      live/mock/mixed/none verdict, surfaced in `run_health.md` (Analysis
      engine section) with a blunt caveat when findings came from the
      deterministic fallback. Budget now enforces against the real shared
      tracker. Tests in `tests/unit/test_wave_f_cost_telemetry.py`.
- [x] **F-A7 Reconcile the pre-flight simulation with reality.** The
      simulator already never gates on `expected_new_nodes` (its
      recommendation looks only at tier/cost/pivot flags), but it
      never checked the forecast against actual yield, so the ~98-vs-0
      miss went unnoticed. `run_health` now sums the `simulation`
      events' `expected_new_nodes` from the audit log, compares them
      to `entities_total`, and sets `node_estimate_note` plus a caveat
      when the forecast was a gross over-estimate (forecast >= 10 and
      0 produced, or >= 5x the actual). It is labelled honestly as an
      uncalibrated category heuristic, not a forecast. Validated on
      the real ginandjuice.shop log (forecast 98, produced 0,
      flagged). True calibration against historical yield is deferred
      to the Fleet-Level Learning moonshot. Tests in
      `tests/unit/test_wave_f_failure_detection.py`.

### F-B: reporting value and noise reduction

- [x] **F-B1 Findings vs. non-findings split.** `score_findings_with_coverage()`
      in `core/scoring.py` partitions into ranked attack surface vs.
      a coverage list (absence-of-evidence notes like "No MX Records",
      "Clean Reputation", "Limited Email Intelligence", restricted to
      info severity so a real weakness like "DNSSEC Not Configured" is
      never swept in). Phase 8 stashes `state["coverage_items"]`; the
      engine renders a "Coverage / What We Checked" appendix in
      `top_threads.md` (shown even when there are zero ranked threads,
      the ginandjuice case). The appendix also lists DEGRADED tools
      from the run-health summary as "not assessed" when available.
      Tests in `tests/unit/test_wave_f_reporting_value.py`.
- [x] **F-B2 Cross-phase finding dedup/merge.** `_dedup_ranked()` in
      `core/scoring.py` collapses findings by canonical key
      (normalised title stem + category + primary asset), keeping the
      highest-confidence representative and unioning sources /
      next-steps / assets. The title stem drops `[POSSIBLE]` and a
      trailing ` - <qualifier>` so the three reworded SPF/DMARC
      findings merge, while the primary asset in the key keeps
      distinct subdomains apart. Fixed a latent bug where
      `_score_agent_findings` dropped `affected_assets` entirely.
- [x] **F-B3 Confidence floor for findings; speculation is not
      attack surface.** Items below `COVERAGE_CONFIDENCE_FLOOR` (0.30)
      or prefixed `[POSSIBLE]` are routed to coverage, not ranked
      threads, so the conf-0.2 cloud guesses minted from zero-result
      probes stop competing with the real signal.
- [x] **F-B4 Reports must derive presence from results, not from the
      fact a tool ran.** `engine.py` gained `_provider_has_evidence()`
      / `_code_source_has_evidence()`: `vendor_supply_chain` lists a
      cloud provider or code source only when its entry carries a
      positive signal (not just that the tool ran), and
      `cloud_posture` builds each subsection from positive fields and
      omits the header entirely when empty (no more "Tenant ID:
      unknown" or "S3 Buckets Found: 0").
- [x] **F-B5 Input hygiene on discovered identities.** New
      `core/identity_hygiene.py::is_probable_test_identity()` flags
      synthetic/test/role addresses (`abcfoo@`, `noreply@`, junk-token
      locals) while leaving real names safe (`barbara`, `testa`,
      `foster` all pass via end-to-end junk-token decomposition).
      Applied in `email_format` (before pattern inference) and the
      phishing-package pretext bundles.
- [x] **F-B6 Strip machine scaffolding from human reports + compute
      scores once.** `engine.py::strip_agent_scaffolding()` removes any
      `FINDINGS_JSON:[...]` block from agent prose before it is
      rendered (executive summary, full-report analyst notes), so the
      protocol marker never leaks into a deliverable. Likelihood and
      Impact are now computed once in
      `core/scoring.py::likelihood_impact()` (impact from severity,
      likelihood from confidence + weaponisation signals) and surfaced
      via `RankedFinding.to_dict()`; `attack_surface.md` renders the
      real numbers instead of the old blank `- | -` that let the LLM
      exec-summary invent its own inconsistent integers.
- [x] **F-B7 Recommendations must respect what the run already tried
      and what is available.** `unavailable_tools_from_preflight()` +
      `unproductive_tools_from_audit()` + `annotate_next_steps()` in
      `core/scoring.py` flag any next-step that recommends a tool the
      preflight marked uninstalled / key-less / policy-disabled
      (theHarvester, DeHashed, Shodan) OR that already ran this campaign
      with no result / a degraded result / an error (amass 60s->0,
      nuclei 140s->0), read from the audit log. Wired into phase 8.
- [x] **F-B8 Suppress or soften empty deliverables.**
      `harvested_credentials.md` no longer opens with the "contains
      real credentials" banner when empty; it states "No credentials
      were harvested. File retained for completeness." instead.

### F-C: lock it in

- [x] **F-C1 Adopt ginandjuice.shop as a signal-quality regression
      fixture.** `tests/integration/test_wave_f_signal_quality_regression.py`
      encodes the run's failure modes as a CI-safe fixture (the
      campaign output dir is gitignored, so a live re-scan is not
      suitable for CI) and asserts the combined F-A + F-B invariants:
      a degraded tool is never counted as a clean negative, findings
      dedup (the SPF/DMARC and test-subdomain dupes collapse), no
      `FINDINGS_JSON` substring in any rendered `.md`, no AWS/GCP
      presence claim from zero-result probes, empty deliverables carry
      no false-alarm header, the junk identity gets no pretext bundle,
      and the run-health summary names the degraded capabilities and
      flags the 98-vs-0 node forecast. This is the concrete version of
      the "Report quality smoke" beta blocker.

---

## Path to `1.0.0`: GA launch

The remaining work between today and `1.0.0` is mostly polish +
documentation + the one outstanding Phase 5 moonshot. None of it
gates correctness; all of it gates the "I'd recommend this to my
peer" bar.

### Outstanding from the Phase 5 moonshots

- [ ] **Fleet-Level Learning (privacy-preserving)**: the last of
      the five Phase 5+ moonshots. Cross-campaign pattern
      extraction to improve default strategies without leaking
      per-campaign data. Needs a privacy model decision
      (differential privacy vs. Federated aggregates vs.
      operator-controlled opt-in) before scoping.

### TUI co-evolution

- [ ] **Intent Planner tab**: same `plan_from_intent`
      orchestrator backing CLI, but with a live-preview pane
      that updates as the operator types.
- [ ] **Watch dashboard**: list of active watches, per-sensor
      fingerprint history, alert + notification + micro-campaign
      tabs.
- [ ] **Adversarial findings tab**: surface
      `state["adversarial_findings"]` with severity filters +
      resolve actions.
- [ ] **Pack browser**: `nexusrecon packs list` rendered in the
      TUI with install / update / uninstall actions.

### Watch Mode follow-ups

- [ ] **Auto-dispatch of high-severity micro-campaigns**: wire
      the existing `auto_dispatch_micro_campaigns` config flag
      through to the campaign runner.
- [ ] **Live notification channels**: Slack / webhook / email
      sinks subscribed to `notifications.jsonl`.

### Vision pipeline follow-ups

- [ ] **PDF rasterization fallback** for image-only pages.
      Requires the `pdf2image` / `poppler` dep; operators
      pre-export images for now.

### Distribution

- [ ] **Fresh-VM install verification.** Harness shipped:
      `scripts/verify_install.sh` is a standalone, CI-safe post-install
      check (package import + version, CLI on PATH, the F-A3
      `availability_report` tool bucketing, optional-extra presence, and
      a binary inventory) that prints one matrix-ready `RESULT:` line.
      [`docs/install-verification.md`](docs/install-verification.md)
      carries the platform coverage matrix. The M-series macOS row is
      verified (PASS, 80/97 tools active, 11/13 binaries present). The
      Linux x86_64 and Linux arm64 rows still need a run on that hardware
      (or a VM), plus `pipx install nexusrecon` confirmed once the
      package is published, to close this out.

---

## Historical: beta-launch checklist (substantially shipped in 0.6.x / 0.7.0)

These were the items called out before the v0.7.0 release. Most are
done; the unchecked ones moved into the GA-launch section above or
are documented as deferred.

### Beta blockers (must ship before public beta)

- [x] **Killer demo committed.** A real, redacted campaign against
      `gitlab.com` (under GitLab's public HackerOne program) is checked
      in under [`examples/sample_run/`](examples/sample_run/): the
      scope of record, a `dispatcher_trace.md` of every tool fire /
      result / error, the first ~60 hash-chained `audit_excerpt.jsonl`
      entries, and the redacted narrative + asset-inventory reports.
      The README documents provenance, the redaction posture
      (aggregate-only, no per-employee data, no credentials, no phishing
      drafts, tenant ID redacted), the per-tool tally, the findings, and
      the LLM cost. [`docs/killer-demo.md`](docs/killer-demo.md) adds the
      reproduce runbook and a reusable publishing checklist. The
      committed run predates Wave F + the OPSEC binding (a provenance
      note flags this), so refreshing it against the current codebase to
      capture the run-health banner, the provenance-checked findings, and
      the enforced stealth cadence is an optional follow-up, not a gate.
- [x] **OPSEC wire verification.** Two parts, both landed:
      - *Verification* (`tests/integration/test_opsec_wire.py`, 24
        tests via `respx` + a localhost capture stand-in for
        mitmproxy): `execute()` applies stealth jitter in the
        profile's declared range, awaits the per-source rate limiter,
        injects the proxy into the tool's `httpx.AsyncClient`, rotates
        the User-Agent across calls, and unwinds the proxy ContextVar
        between calls. A structural test pins that every
        `BaseHTTPTool` calls `_proxy_kwargs()` and sets a UA.
      - *Production binding* (the real gap the tests hid): the CLI and
        TUI bound only scope_guard/cache/audit, so the stealth profile
        and `NEXUS_PROXY_URL` were never applied to a real campaign's
        traffic. `nexusrecon/opsec/setup.py::build_opsec()` now
        constructs the stealth profile (from the engagement
        `stealth_profile`), a rate limiter from it, and a proxy manager
        from `NEXUS_PROXY_URL` / `NEXUS_TOR_PROXY`, and both entrypoints
        bind them via `set_campaign_context`. `require_proxy` now
        fails loud (`ProxyRequiredError`) when no proxy is configured.
- [x] **JA3 / TLS-fingerprint client.** Outbound TLS otherwise looks
      like one Python `httpx` version to every provider. Shipped as an
      opt-in capability: `nexusrecon/tools/base.py::make_http_client()`
      returns a plain `httpx.AsyncClient` by default (byte-for-byte
      today's path) and, only when a `tls_impersonate` target is active
      AND the optional `nexusrecon[tls]` extra (`curl_cffi`) is
      installed, returns an httpx-compatible adapter over
      `curl_cffi.requests.AsyncSession(impersonate=...)` so the JA3 / TLS
      ClientHello matches a real browser. The target is gated two ways,
      mirroring the proxy precedent: a `StealthProfile.tls_impersonate`
      field (per-engagement, default None on every shipped profile) and a
      `NEXUS_TLS_IMPERSONATE` config override (wins when set). It rides a
      `_current_tls_impersonate` ContextVar entered alongside
      `proxy_context` in `registry.execute()`, so it unwinds per call and
      never leaks across campaigns. The adapter preserves the campaign
      proxy, the rotating User-Agent, base_url, params, and timeout, and
      re-raises curl_cffi transport/timeout errors as their httpx
      equivalents so `http_get_with_retry` is unchanged. When the extra
      is absent (the default install) or the flag is off, behaviour is
      exactly httpx, with a one-time warning if impersonation was
      requested but `curl_cffi` is missing. Reference tools `shodan` and
      `virustotal` route through the factory. `curl_cffi` stays out of the
      core dependency list. Tests in `tests/unit/test_ja3_tls_client.py`
      (fallback matrix, adapter mapping, exception translation, wire
      preservation through the registry, gate defaults, and a
      dependency-hygiene guard).
- [ ] **JA3 client adoption (follow-up).** The factory exists; only the
      two reference tools (`shodan`, `virustotal`) route through it so
      far. The other HTTP tools adopt `make_http_client` incrementally:
      the roughly 60 sites that do not yet inject the campaign proxy
      still emit a plain-httpx JA3 even with the flag on (the same as
      today, so a known incremental gap, not a silent regression).
      Migrate the remaining OPSEC-relevant sites, and make the
      User-Agent pool consistent with the active impersonate target so a
      `chrome120` TLS fingerprint does not ship with a Firefox UA string
      (that mismatch is itself a fingerprint).
- [x] **Report quality smoke.** `tests/unit/test_report_quality_smoke.py`
      runs the real `ReportEngine` against 9 synthetic target-shape
      fixtures (small business, M365 enterprise, AWS-native startup,
      mixed-cloud + breaches, empty, GCP-native, degraded/partial-failure,
      Phase D/E heavy, gov/.gov) with the LLM executor stubbed (a live
      10-campaign run is not CI-viable: real spend plus hours of
      wall-clock, and the campaign output dir is gitignored). All four
      failure modes are pinned as smoke tests:
      - No "As a large language model" / "I'd be happy to help" (or eight
        other disclaimer phrases) in any generated `.md`.
      - Findings deduplicated across overlapping tools (cross-source
        class: same CVE in `enriched_cves` AND KEV collapses to one
        ranked finding; same email from two breach DBs collapses to one),
        on top of the Wave F-B2 dedup regression.
      - Every CVE citation resolves to a real CVE record. The original
        check was format-only (`CVE-YYYY-NNNN` shape), so a correctly
        formatted but fabricated `CVE-2099-99999` shipped clean. Closed
        with a provenance guard: `engine.collect_state_cves()` builds the
        allow-list of CVEs the run actually collected (scanning the
        evidence slots, excluding LLM-prose slots so a hallucination
        cannot self-authorise), and `scrub_unsourced_cves()` redacts any
        CVE token absent from that set at the three LLM-prose embed sites
        (master report brief, executive-summary analyst assessment,
        people-map analyst notes); the Obsidian export inherits the scrub
        because it re-reads the scrubbed `master_report.md`. A parametrised
        subset invariant asserts rendered CVEs are a subset of collected
        CVEs for every fixture, and two adversarial-stub tests confirm a
        fabricated CVE injected into agent prose is redacted while a
        genuinely sourced CVE survives (verified load-bearing: both fail
        with the guard neutered).
      - Scope hash + tool versions in every report footer (scope_hash
        plus `Tooling: NexusRecon vX.Y.Z` in the executive summary and
        full report, and `nexusrecon_version` next to `scope_hash` in the
        JSON deliverables). Broadening the footer to the remaining
        deliverables (credential exposure paths, spear-phishing intel,
        `run_health.md`, and the PDF's hardcoded version string) is
        tracked separately as metadata hygiene, not part of this blocker.
- [x] **`BaseHTTPTool` helper.** Extract the
      "401/403 = auth fail, 429 = rate limit, other non-200 = error"
      pattern from the 9 individual fix commits into a single base
      class so future tools inherit the right behaviour by default.
      Eliminates the silent-swallow bug class structurally. Shipped
      as `nexusrecon/tools/base.py::BaseHTTPTool`; every Phase D + E
      HTTP tool subclasses it.
- [x] **Live-drift CI schedule.** Weekly scheduled workflow
      (`.github/workflows/live-drift.yml`) runs `tests/live/` every
      Monday 06:00 UTC. Each test is gated by
      `@pytest.mark.live("<provider>")`; the `tests/live/conftest.py`
      auto-skips when the relevant env vars aren't set, so the
      workflow runs whatever subset of the live suite has secrets
      configured. Adding a new repo secret widens coverage with
      no workflow edit. Failures on the scheduled run automatically
      open (or update) a `live-drift`-labelled issue with the
      failing tests + a triage runbook so upstream schema drift
      lands in the standard triage flow instead of dying silently
      in the Actions tab. Job summary surfaces the
      passed/failed/errored/skipped counts at the top of every run.
- [x] **Stubbed-tool policy.** `OSINTTool.stubbed: bool` class
      attribute (default False). When True, `is_available()` returns
      False so the registry keeps the tool out of
      `available_tools()` and the LLM dispatcher cannot select it;
      `list_tools()` prepends `[STUB] ` to the description so the
      catalog surfaces the status. `tests/unit/test_stubbed_tools.py`
      pins the inventory ── adding or removing a stub becomes a
      conscious decision. Current inventory: `gowitness` (sole
      remaining stub, awaiting real subprocess wrapper). `gau` was
      mislabelled (real subprocess implementation existed). Fixed.
      `gcp_recon` partial stubs (Firebase / Cloud Run) are flagged
      inline in the per-feature output.
- [ ] **Fresh-VM install verification.** Tracked in the GA "Path to
      `1.0.0`" Distribution section above: `scripts/verify_install.sh`
      plus the coverage matrix in
      [`docs/install-verification.md`](docs/install-verification.md);
      macOS row verified, the two Linux rows pending a run on that
      hardware.
- [ ] **First-run UX polish.**
      - [x] TUI tells the operator on launch how many tools are active
        vs. skipped, and *why*. The dashboard Tool health card now
        sources its counts from the F-A3 `availability_report`, so a tool
        skipped for a missing CLI binary ("need install") is reported
        distinctly from one skipped for a missing API key ("need keys")
        instead of lumping both under "missing keys" (which sent a
        fresh-install operator hunting for a key when the fix for
        `maigret` / `amass` was a package install). A `Needs install:`
        hint names the tools whose binary is absent. The legacy welcome
        shim shares the same honest breakdown. Tests in
        `tests/unit/test_tui_first_run_ux.py`.
      - [ ] Record the 90-second wizard-to-results gif. The reproducible
        recording setup is committed (`docs/demo/nexusrecon.tape`,
        `docs/demo/RECORDING.md`, `make demo`) and the README embed is
        pre-wired at `docs/demo/nexusrecon.gif`. The binary itself is a
        one-command maintainer step (`make demo`, which needs vhs + ttyd
        + ffmpeg + a local monospace font) that cannot run in CI, so it
        stays open until recorded on a workstation.
- [ ] **Report footer hygiene (follow-up).** Split out of "Report
      quality smoke", which pinned the scope_hash + version footer on
      the canonical narrative deliverables (executive summary, full
      report) and the JSON deliverables. Extend the same pair to the
      remaining `.md` deliverables that carry neither field
      (`credential_exposure_paths.md`, `spear_phishing_intelligence.md`,
      `run_health.md`) and fix the PDF footer, which hardcodes
      `NexusRecon v1.0.0` instead of `self.nexusrecon_version`. Metadata
      hygiene, not a correctness gate. A related item: the report
      builders render em-dashes and box-drawing glyphs into operator
      prose, which reads as an AI tell in delivered documents; sweep
      those out of the generated deliverables (separate from the repo
      docs scrub).

### Done (already in 0.5.x)

- [x] `LICENSE` (Apache 2.0) + `NOTICE`.
- [x] `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`.
- [x] `.github/ISSUE_TEMPLATE/` and `.github/workflows/test.yml`.
- [x] Centralised User-Agent pool (47 tools using it).
- [x] `await asyncio.sleep` replacing blocking `time.sleep`.
- [x] Pinned "Path to 1.0" GitHub issue.
- [x] Tagged release for `v0.5.0`.

---

## Additional 1.0.0 work-streams (post-beta cycles)

Once the beta has run for a meaningful number of cycles:

### Toolchain integration

- [x] **Burp Suite bidirectional XML.** Shipped in 0.7.0 as the
      first-party `packs/burp/` reference pack. Site map XML
      import + Burp-compatible scope XML export.
      [`ARCHITECTURE.md §17`](ARCHITECTURE.md#17-recon-pack-format--contribution-sdk-phase-3).
- [ ] **BloodHound CE JSON.** Azure / M365 federation findings →
      BloodHound graph ingest. Natural follow-up pack.
- [x] **Obsidian-friendly master report.** `--obsidian` emits
      `master_report.obsidian.md` alongside the standard report:
      YAML frontmatter (campaign_id / target / scope_hash / version
      / tags), `[[wikilinks]]` between deliverables for Graph
      View, and Obsidian's built-in callouts (`> [!danger]
      CRITICAL`) replacing bare severity blockquotes. Pure-function
      transforms (`nexusrecon/reports/obsidian_export.py`); the
      standard `master_report.md` is unchanged so GitHub rendering
      and external markdown viewers keep working. See
      [`docs/obsidian.md`](docs/obsidian.md).

### Performance + scale

- [ ] **Parallel multi-target campaigns.** Run several scope files
      concurrently from one TUI session, share the LLM budget.
- [ ] **Memory profile for large scopes.** 1000+ subdomain
      campaigns shouldn't OOM the runner.
- [ ] **Resume integrity test.** Pause / kill / restart a campaign
      partway through phases 5-7 and verify the audit chain
      survives, no findings are duplicated, partial reports are
      sensible.

### Plugin SDK

- [x] **Out-of-tree contributions.** Shipped in 0.7.0 as the
      Recon Pack format
      ([`ARCHITECTURE.md §17`](ARCHITECTURE.md#17-recon-pack-format--contribution-sdk-phase-3)).
      Contributors ship a directory + `manifest.yaml` that
      contributes tools, agents, dispatch policies, report
      templates, and custom entity / relationship types.
      `nexusrecon packs install gh:owner/repo` for git
      distribution. Three SDK scaffolders
      (`agent new` / `tool new` / `policy new`) generate working
      boilerplate.
- [x] **Pack trust model.** Manifest_hash (computed + warned on
      mismatch by the loader). Operators inspect before activating.
      A future PR may layer Ed25519 signing on top using the same
      keypair infrastructure as Phase 5 PR B's signed STIX bundles.

### Operator experience

- [ ] **Scope file linter.** `nexusrecon scope-lint` that catches
      common mistakes (overlapping CIDRs, missing SOW hash, date
      ordering, etc.) before campaign launch.
- [ ] **Cost preview.** `nexusrecon run --dry-run --cost-estimate`
      prints expected LLM spend based on scope size + chosen mode.
- [ ] **Live-cost circuit breaker.** When cost approaches budget,
      surface a clear "continue / abort / downgrade to no-LLM"
      prompt rather than silently aborting.

---

## Identity attribution expansion (Phase D + Phase E, in progress)

A two-phase architectural addition that takes the framework from
"confirm corporate identity" to "attacker-mindset OSINT": pivoting
from corporate identity to personal identity, surfacing credential-
exposure paths from breach data, and mining the relationship graph
that makes spear phishing actually plausible. Builds on the existing
attribution scoring (Phase A/B/C) which already lives in
`nexusrecon/core/attribution.py`.

**Architectural decisions locked in (do not relitigate without explicit
go-ahead):**

- **Surface, never execute.** The framework produces (a) credential-
  spray punch lists and (b) spear-phishing pretext intelligence + (when
  `--generate-phishing` is set) actual drafts. It does NOT execute
  credential tests against any target endpoint, and does NOT send
  emails. Always.
- **LinkedIn approach: aggressive.** Use an unofficial scraper / API
  wrapper despite the gray legal / ToS territory. The signal is too
  valuable to leave on the table. Posture revisits if LinkedIn legal
  action lands; the codebase is structured so the LinkedIn integration
  is one module that can be swapped out cleanly.
- **Paid breach DBs (DeHashed, IntelX, LeakCheck) integrate behind
  keys.** Tools fail-fast when the key isn't present (post-Day-4
  status-code classifier behaviour). Operators choose which DBs to
  enable per engagement.
- **Sequencing: Phase D fully, then Phase E.** E's relationship graph
  attaches edges to the `Identity` objects D1 introduces, so doing D
  first means E doesn't have to mock or rebuild the data model.

### Phase D: Identity pivot + credential exposure

Pivot from corporate identity (`jane.doe@gitlab.com`, VP Engineering,
GitLab) to personal identity (`jane.doe.82@gmail.com`, lives in SF,
runs marathons), and surface credential-exposure paths via breach data.

- [x] **D1** `nexusrecon/core/identity_graph.py`. First-class
      ``Identity`` model with ``corp_identifiers``,
      ``personal_identifiers``, ``linked_accounts``,
      ``credential_exposures``, ``confidence_per_link`` sub-fields.
      Replaces the current dict-of-dicts ``email_intel.emails[em]``
      pattern.
- [x] **D2** `nexusrecon/core/personal_handle_derivation.py`:
      generates personal handle candidates from
      ``(name, optional_age_range, optional_location,
        optional_interests)``. Patterns include name + year, name +
      hobby, nickname variants, common personal-email forms
      (``first.last@gmail``, ``firstinitial.last+year@gmail``, etc.).
      LLM-assisted hobby/interest expansion via the dispatcher.
- [x] **D3** `nexusrecon/tools/identity/personal_pivot_tool.py`:
      orchestrator. Takes a confirmed corp identity, runs personal
      handle derivation, fires maigret against personal-service tiers
      (Reddit, Discord, gaming, dating, hobby forums), runs HIBP /
      IntelX / DeHashed against personal email candidates, extends
      the identity graph.
- [x] **D4** `nexusrecon/core/credential_correlation.py`. Takes the
      identity graph + breach hits and produces ranked credential-
      spray candidates. Output is the "hail mary punch list" with
      explicit risk warnings (account lockout risk, IDS noise,
      engagement-scope flags). 46 unit tests. MITRE T1110.003/T1110.002/
      T1550.002/T1078/T1589.002 mapping. Never auto-executes.
- [x] **D5** `nexusrecon/tools/intel/dehashed_tool.py`. Real
      DeHashed integration (paid API key). Returns password-bearing
      breach hits with cleartext/hashed credentials. HTTP Basic Auth
      with DEHASHED_USERNAME:DEHASHED_API_KEY. 10 integration tests.
- [x] **D6** Enhanced `nexusrecon/tools/identity/hudsonrock_tool.py`
     . Today reports only "compromised yes/no". Surface real
      Cavalier data: captured URLs (which services the infostealer
      logged into), passwords, cookies, system fingerprint.
      Optional HUDSONROCK_API_KEY unlocks full credential detail.
      Backward-compatible (community tier unchanged). 9 integration tests.
- [x] **D7** New Phase 2.5 wiring in `nexusrecon/graph/nodes.py` +
      new deliverable `credential_exposure_paths.md`. Phase 2.5 runs
      AFTER corp identity confirmed (Phase 2), BEFORE code-leakage /
      vuln correlation (Phase 3+) so the credential exposure paths
      are available to the risk_analyst in Phase 8. Generates both
      `credential_exposure_paths.md` (operator punch list) and
      `credential_punch_list.json` (machine-readable).

### Phase E: Relationship graph + pretext scoring

Mine the public relationship graph that makes spear phishing actually
work: WHO each target receives email from, WHAT topics are plausible
given their public activity, WHEN pretexts are time-sensitive.

- [x] **E1** `nexusrecon/core/relationship_graph.py`. Human-to-human
      edges as first-class data. Edge fields: ``(source_identity,
      target_identity, interaction_type, strength, last_observed,
      sources)``. Weighted by interaction depth (co-author > follower)
      and recency-decayed. 76 unit tests. Pure Python.
- [x] **E2** `nexusrecon/tools/identity/github_social_tool.py`:
      commit co-authors, repo collaborators, issue/PR discussion
      participants, follow graph. Free via GitHub API. 33 unit tests.
- [x] **E3** `nexusrecon/tools/identity/mastodon_social_tool.py`:
      follows / boosts / mentions / replies. Anonymous reads against a
      hardcoded default-instance list (mastodon.social, hachyderm.io,
      infosec.exchange, fosstodon.org, mas.to, tech.lgbt). 35 unit tests.
- [x] **E4** `nexusrecon/tools/identity/bluesky_social_tool.py`:
      follow + interaction graph via the AT Protocol xrpc API. Raw
      HTTP (no SDK dep). 32 unit tests.
- [x] **E5** `nexusrecon/tools/identity/linkedin_social_tool.py`:
      isolated `linkedin-api` wrapper. Cookie auth (LINKEDIN_LI_AT +
      LINKEDIN_JSESSIONID) preferred, user/pass fallback. Returns
      title history, current title, recent posts, post reactors /
      commenters, skill endorsements, mentioned colleagues. 45 unit
      tests.
- [x] **E6** `nexusrecon/tools/intel/business_partner_tool.py`:
      aggregator that calls the existing `crunchbase` tool via the
      registry + BuiltWith API + DNS TXT vendor inference (SPF + MX)
      + press-page scraping. Emits org-to-org edges. 21 unit tests.
- [x] **E7** `nexusrecon/tools/pretext/conference_speaker_tool.py`:
      hardcoded site list (DEFCON, BSides, RSA, KubeCon, FOSDEM,
      BlackHat, Strange Loop, USENIX). Per-site parser interface
      (FOSDEM has a working parser; others ship as stubs). Co-speaker
      edges feed the relationship graph. 29 unit tests.
- [x] **E8** `nexusrecon/tools/pretext/news_tool.py` (extended
      in-place). Time-windowed `RecentActivity` records alongside
      the existing `articles` list. 90-day default half-life,
      configurable via `time_window_days` kwarg. `RecentActivity`
      dataclass lives in `nexusrecon/core/recent_activity.py`. 18
      unit tests + 27 for the core module.
- [x] **E9** `nexusrecon/core/pretext_scoring.py`. Score
      ``(sender × topic × timing)`` tuples via geometric mean of three
      recency-decayed axes. Every candidate carries a `sources` audit
      trail. `target_ids: list[str] | None = None` parameter narrows
      scope (defaults to all identities). 34 unit tests. Pure Python.
- [x] **E10** Enhanced `nexusrecon/agents/phishing_drafter.py`:
      expanded backstory + JSON schema (subject /
      sender_display_name / sender_address / body_markdown /
      rationale / sources). Documents the do-not-fabricate rule,
      DMARC-driven sender-domain decision, no-draft fallback for
      low-signal targets. Still gated on ``--generate-phishing``.
- [x] **E11** Phase 7.7 (`phase7_7_pretext_intelligence`) wires the
      E2-E9 modules into the workflow between Phase 7.5 and Phase 8.
      Emits `spear_phishing_intelligence.md` (per-target dossier)
      + `pretext_candidates.json` (machine-readable). New CLI flag
      `--pretext-targets` narrows scoring. State slots:
      `relationship_graph`, `pretext_scores`,
      `spear_phishing_intelligence`. 16 unit tests pin the phase
      ordering, state shape, narrowing, drafter gating, and report
      output.

### Phase D + E publishing posture

The deliverables produced by D and E contain meaningfully sensitive
data (real credentials from breach data, personal identity linkage,
plausible-pretext drafts). The publishing rules established for the
`examples/sample_run/` demo apply doubly here:

- Per-employee findings stay in the unpublished campaign directory
  by default.
- Aggregate-only statistics in any published artifact.
- Real credentials never published anywhere ── even redacted samples
  are too risky.
- Plausible pretext drafts never published with real target names; if
  used as demo material, sanitised to fictional examples.

---

## Post-`1.0`: ecosystem

- [ ] **Public LLM-prompt evaluation set.** Once enough campaigns
      have run, publish prompt + expected-output pairs for the 11
      agent personas so contributors can improve them
      reproducibly.
- [ ] **Cohort report comparison.** Diff campaigns across time for
      the same scope ("what changed about Acme's attack surface
      between Q2 and Q3?"). The `nexusrecon diff` command exists
      but is bare-bones today.
- [ ] **Local-only mode certification.** Document and test the
      configuration that runs zero external LLM calls (Ollama
      local model + no telemetry) for engagements where data must
      not leave the operator's machine.

---

## Out of scope

Things people sometimes ask for that we won't build:

- **Automated exploitation.** This is recon tooling. Pivot to
  Metasploit / Sliver / Mythic for exploit phases.
- **Stealth-claim-of-attribution evasion.** We don't help operators
  hide that they're running NexusRecon, the tool's purpose is
  authorised testing, and authorised tests don't need to
  obfuscate the tooling.
- **Anything that bypasses the scope guard.** Hard rule. See
  `DISCLAIMER.md`.
- **Telemetry / phone-home.** Air-gapped operation is a hard
  requirement.
