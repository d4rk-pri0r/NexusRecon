# NexusRecon Roadmap

Current state, what's left before 1.0, what comes after. Pull requests
welcome; prioritisation is set by the maintainer.

---

## Current state: `0.7.0` (beta)

The four core bets of the
[METASPLOIT_OSINT implementation plan](docs/IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md)
plus four of five Phase 5 moonshots ship in this release.
**Test suite: 590/590 passing.**

What works today:

- **12-phase reconnaissance pipeline** + credential harvest
  (phase 7.5) + pretext intelligence (phase 7.7).
- **Living Intelligence Graph** — 17+ entity types, per-source
  provenance, confidence, traversable relationships, first-class
  hypotheses / leads / open questions, mutation events.
- **Strategic Reasoning Engine** — Strategy dataclass, pluggable
  DispatchPolicy (lite / full / off + community-extensible),
  simulation, bounded agency (deep-pivot + human-approval queue).
- **Continuous Confidence Engine** — corroboration (lifts on
  multi-class agreement), contradiction (downgrades on conflicts),
  propagation (cascades downgrades), adversarial self-check (graph
  audit).
- **Recon Pack format** — community-authored bundles contribute
  tools / agents / dispatch policies / report templates / custom
  entity-and-rel types. Git URL install, marketplace search.
- **Contribution SDK** — `nexusrecon agent new` / `tool new` /
  `policy new` scaffolders with prompt versioning + citation
  guardrails wired in.
- **Intent-driven entry** — `nexusrecon plan "<sentence>"`
  synthesizes scope.yaml + Strategy from natural language.
- **STIX 2.1 export + bidirectional import** — STIX bundles,
  Nessus XML, Nuclei JSON-lines, generic CSV.
- **Downstream emitters** — Jira NDJSON, Nuclei target lists,
  Cobalt Strike Malleable C2 profile stubs.
- **Watch Mode** — continuous monitoring with three sensor types
  and tiered actions (alert / notification / queued micro-campaign).
- **Provenance cryptography** — Ed25519 signed STIX bundles +
  standalone single-file verifier auditors can run without
  NexusRecon installed.
- **Adversarial platform self-defense** — four detectors (poisoned
  data, tool patterns, evidence inconsistency, prompt injection).
- **Multi-modal vision pipeline** — screenshots, PDFs, QR codes;
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
- Curated marketplace content — index format + search ship;
  canonical hosted content is operator / community curated.
- Some niche tools still flagged `[STUB]` in their descriptions
  (gowitness; awaiting subprocess wrapper).
- Fresh-VM install across all platforms (M-series macOS,
  Linux x86_64, Linux arm64) needs documented coverage matrix.

---

## Path to `1.0.0`: GA launch

The remaining work between today and `1.0.0` is mostly polish +
documentation + the one outstanding Phase 5 moonshot. None of it
gates correctness; all of it gates the "I'd recommend this to my
peer" bar.

### Outstanding from the Phase 5 moonshots

- [ ] **Fleet-Level Learning (privacy-preserving)** — the last of
      the five Phase 5+ moonshots. Cross-campaign pattern
      extraction to improve default strategies without leaking
      per-campaign data. Needs a privacy model decision
      (differential privacy vs. federated aggregates vs.
      operator-controlled opt-in) before scoping.

### TUI co-evolution

- [ ] **Intent Planner tab** — same `plan_from_intent`
      orchestrator backing CLI, but with a live-preview pane
      that updates as the operator types.
- [ ] **Watch dashboard** — list of active watches, per-sensor
      fingerprint history, alert + notification + micro-campaign
      tabs.
- [ ] **Adversarial findings tab** — surface
      `state["adversarial_findings"]` with severity filters +
      resolve actions.
- [ ] **Pack browser** — `nexusrecon packs list` rendered in the
      TUI with install / update / uninstall actions.

### Watch Mode follow-ups

- [ ] **Auto-dispatch of high-severity micro-campaigns** — wire
      the existing `auto_dispatch_micro_campaigns` config flag
      through to the campaign runner.
- [ ] **Live notification channels** — Slack / webhook / email
      sinks subscribed to `notifications.jsonl`.

### Vision pipeline follow-ups

- [ ] **PDF rasterization fallback** for image-only pages.
      Requires the `pdf2image` / `poppler` dep; operators
      pre-export images for now.

### Distribution

- [ ] **Fresh-VM install verification.** Test `./install.sh` on
      M-series macOS, Linux x86_64, Linux arm64. Document any
      platform-specific failures. Confirm `pipx install nexusrecon`

---

## Historical: beta-launch checklist (substantially shipped in 0.6.x / 0.7.0)

These were the items called out before the v0.7.0 release. Most are
done; the unchecked ones moved into the GA-launch section above or
are documented as deferred.

### Beta blockers (must ship before public beta)

- [ ] **Killer demo committed.** Real campaign against a known-
      vulnerable public target (`juice-shop.herokuapp.com` or
      similar) with full report directory + dispatcher-log excerpt
      checked in under `examples/sample_run/`. The agentic value
      proposition needs evidence, not marketing copy.
- [ ] **OPSEC wire verification.** Integration tests that run the
      tool through `mitmproxy` / a capturing proxy and assert:
      - `paranoid` profile produces 1-thread sequential requests
        with 3-10s jitter.
      - `NEXUS_PROXY_URL` routes every outbound request.
      - User-Agent values actually rotate per request (or per
        session) as documented.
      - TLS fingerprints don't always look like one Python `httpx`
        version (consider `curl_cffi` or similar JA3-friendly clients
        for any tool aimed at production red-team use).
- [ ] **Report quality smoke.** Run 10 campaigns across varied
      target shapes (small biz, M365 enterprise, AWS-native startup,
      etc.). Pin failure modes as smoke tests:
      - No "As a large language model" / "I'd be happy to help"
        artifacts in any generated prose.
      - Findings deduplicated across overlapping tools.
      - Every CVE citation resolves to a real CVE record.
      - Scope hash + tool versions in every report footer.
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
      configured — adding a new repo secret widens coverage with
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
      mislabelled (real subprocess implementation existed) — fixed.
      `gcp_recon` partial stubs (Firebase / Cloud Run) are flagged
      inline in the per-feature output.
- [ ] **Fresh-VM install verification.** Test `./install.sh` on
      M-series macOS, Linux x86_64, Linux arm64. Document any
      platform-specific failures. Confirm `pipx install nexusrecon`
      works once we publish the package.
- [ ] **First-run UX polish.** TUI tells the operator on launch
      how many tools are active vs. skipped-for-missing-keys.
      Record a 90-second gif of `nexusrecon` → wizard → results
      and embed it in the README.

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
      first-party `packs/burp/` reference pack — site map XML
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
      [`docs/obsidian.md`](docs/obsidian.md). Phase 1 of
      [`TOOLCHAIN_AND_PLUGIN_SDK_PLAN.md`](TOOLCHAIN_AND_PLUGIN_SDK_PLAN.md).

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

### Phase D — Identity pivot + credential exposure

Pivot from corporate identity (`jane.doe@gitlab.com`, VP Engineering,
GitLab) to personal identity (`jane.doe.82@gmail.com`, lives in SF,
runs marathons), and surface credential-exposure paths via breach data.

- [x] **D1** `nexusrecon/core/identity_graph.py` — first-class
      ``Identity`` model with ``corp_identifiers``,
      ``personal_identifiers``, ``linked_accounts``,
      ``credential_exposures``, ``confidence_per_link`` sub-fields.
      Replaces the current dict-of-dicts ``email_intel.emails[em]``
      pattern.
- [x] **D2** `nexusrecon/core/personal_handle_derivation.py` —
      generates personal handle candidates from
      ``(name, optional_age_range, optional_location,
        optional_interests)``. Patterns include name + year, name +
      hobby, nickname variants, common personal-email forms
      (``first.last@gmail``, ``firstinitial.last+year@gmail``, etc.).
      LLM-assisted hobby/interest expansion via the dispatcher.
- [x] **D3** `nexusrecon/tools/identity/personal_pivot_tool.py` —
      orchestrator. Takes a confirmed corp identity, runs personal
      handle derivation, fires maigret against personal-service tiers
      (Reddit, Discord, gaming, dating, hobby forums), runs HIBP /
      IntelX / DeHashed against personal email candidates, extends
      the identity graph.
- [x] **D4** `nexusrecon/core/credential_correlation.py` — takes the
      identity graph + breach hits and produces ranked credential-
      spray candidates. Output is the "hail mary punch list" with
      explicit risk warnings (account lockout risk, IDS noise,
      engagement-scope flags). 46 unit tests. MITRE T1110.003/T1110.002/
      T1550.002/T1078/T1589.002 mapping. Never auto-executes.
- [x] **D5** `nexusrecon/tools/intel/dehashed_tool.py` — real
      DeHashed integration (paid API key). Returns password-bearing
      breach hits with cleartext/hashed credentials. HTTP Basic Auth
      with DEHASHED_USERNAME:DEHASHED_API_KEY. 10 integration tests.
- [x] **D6** Enhanced `nexusrecon/tools/identity/hudsonrock_tool.py`
      — today reports only "compromised yes/no". Surface real
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

### Phase E — Relationship graph + pretext scoring

Mine the public relationship graph that makes spear phishing actually
work: WHO each target receives email from, WHAT topics are plausible
given their public activity, WHEN pretexts are time-sensitive.

- [x] **E1** `nexusrecon/core/relationship_graph.py` — human-to-human
      edges as first-class data. Edge fields: ``(source_identity,
      target_identity, interaction_type, strength, last_observed,
      sources)``. Weighted by interaction depth (co-author > follower)
      and recency-decayed. 76 unit tests. Pure Python.
- [x] **E2** `nexusrecon/tools/identity/github_social_tool.py` —
      commit co-authors, repo collaborators, issue/PR discussion
      participants, follow graph. Free via GitHub API. 33 unit tests.
- [x] **E3** `nexusrecon/tools/identity/mastodon_social_tool.py` —
      follows / boosts / mentions / replies. Anonymous reads against a
      hardcoded default-instance list (mastodon.social, hachyderm.io,
      infosec.exchange, fosstodon.org, mas.to, tech.lgbt). 35 unit tests.
- [x] **E4** `nexusrecon/tools/identity/bluesky_social_tool.py` —
      follow + interaction graph via the AT Protocol xrpc API. Raw
      HTTP (no SDK dep). 32 unit tests.
- [x] **E5** `nexusrecon/tools/identity/linkedin_social_tool.py` —
      isolated `linkedin-api` wrapper. Cookie auth (LINKEDIN_LI_AT +
      LINKEDIN_JSESSIONID) preferred, user/pass fallback. Returns
      title history, current title, recent posts, post reactors /
      commenters, skill endorsements, mentioned colleagues. 45 unit
      tests.
- [x] **E6** `nexusrecon/tools/intel/business_partner_tool.py` —
      aggregator that calls the existing `crunchbase` tool via the
      registry + BuiltWith API + DNS TXT vendor inference (SPF + MX)
      + press-page scraping. Emits org-to-org edges. 21 unit tests.
- [x] **E7** `nexusrecon/tools/pretext/conference_speaker_tool.py` —
      hardcoded site list (DEFCON, BSides, RSA, KubeCon, FOSDEM,
      BlackHat, Strange Loop, USENIX). Per-site parser interface
      (FOSDEM has a working parser; others ship as stubs). Co-speaker
      edges feed the relationship graph. 29 unit tests.
- [x] **E8** `nexusrecon/tools/pretext/news_tool.py` (extended
      in-place) — time-windowed `RecentActivity` records alongside
      the existing `articles` list. 90-day default half-life,
      configurable via `time_window_days` kwarg. `RecentActivity`
      dataclass lives in `nexusrecon/core/recent_activity.py`. 18
      unit tests + 27 for the core module.
- [x] **E9** `nexusrecon/core/pretext_scoring.py` — score
      ``(sender × topic × timing)`` tuples via geometric mean of three
      recency-decayed axes. Every candidate carries a `sources` audit
      trail. `target_ids: list[str] | None = None` parameter narrows
      scope (defaults to all identities). 34 unit tests. Pure Python.
- [x] **E10** Enhanced `nexusrecon/agents/phishing_drafter.py` —
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
