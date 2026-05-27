# Changelog

All notable changes to NexusRecon land here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [SemVer](https://semver.org/) with the pre-1.0 caveat that
minor bumps (0.x → 0.x+1) may break APIs.

## [0.7.0]: 2026-05-27

**Test suite: 590/590 passing.** This release executes the four core
bets of the
[METASPLOIT_OSINT implementation plan](docs/IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md)
plus four of five Phase 5 moonshots. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) sections 13-22 for design
deep-dives.

### Phase 0: Living Intelligence Graph

- **Step 0.0**: `EntityGraph.from_state(state)` reconstructor +
  agent integration. The phase4 correlation + phase8 attack-surface
  agents now receive a `GraphContext` instead of a truncated
  500-entry name-list dict. `state["entity_graph"]` carries the full
  serialised graph through `to_dict()` / `from_dict()` round-trips.
- **Step 0.1 PR A**: provenance schema. `ProvenanceRecord{source,
  timestamp, evidence_hash, tool_name}` lifted to a first-class
  field on every entity. Path-finding queries (`find_paths`,
  `get_neighbors_filtered`, `get_attack_surface_nodes`). Phase-aware
  `GraphContext` (`PHASE_FOCUS_TYPES` + `most_cited_entities` +
  `for_phase()`).
- **Step 0.1 PR B**: three-graph unification. Phase D
  `IdentityGraph` + Phase E `RelationshipGraph` collapse into
  `EntityGraph` via `merge_identity_graph` /
  `merge_relationship_graph`. New rel types: `CITES`, `BLOCKS`,
  `KNOWS`, `COLLABORATES_WITH`, `FOLLOWS`, `FEDERATED_WITH`. New
  entity types: `HYPOTHESIS`, `LEAD`, `OPEN_QUESTION`.
- **Step 0 closeout**: `LivingGraph` alias documents the
  architectural intent. `GRAPH_SCHEMA_VERSION` constant pinned.
  `scripts/migrate_state_to_living_graph.py` eagerly upgrades old
  `state.json` files (dry-run by default).

### Phase 1: Strategic Reasoning Engine

- **PR A**: `nexusrecon/strategy/` scaffold. `Strategy` dataclass
  (phases, dispatch_policy_name, tool_budgets, success_criteria,
  kill_criteria, metadata). `DispatchPolicy` ABC + bundled
  `LitePolicy` / `FullPolicy` / `OffPolicy`. `get_policy(name)`
  resolver + `register_policy()` plugin hook. Dispatcher reads caps
  + per-phase eligibility from the active policy instead of
  module-level constants.
- **PR B**: `CampaignPlannerAgent` operationalised.
  `plan_campaign(scope_summary, seeds, mode, …)` orchestrator runs
  the planner with a strict-JSON prompt; falls back to
  `Strategy.default()` on any failure with
  `metadata.planner_response_kind="fallback"`. New CLI flag
  `--plan-only` + `--no-llm` (regex fallback).
  `state["strategy_history"]` audit hook on every plan / replan.
- **PR C**: Simulation & What-If. `simulate_dispatch_plan(plan,
  state)` runs between validate + execute on every dispatcher call.
  Forecasts cost, expected graph growth (per-category heuristic),
  scope-creep flags (tier_exceeds_scope, pivot_to_new_target).
  Recommendation `proceed` / `warn` / `abort`. Always logged to
  `state["simulation_log"]`; gating opt-in via
  `state["simulation_gating"]`.
- **PR D**: Strategic audit + bounded agency. Seven new audit-log
  event types (`strategy_generated`, `strategy_replan`,
  `dispatch_policy_resolved`, `simulation`, `deep_pivot_grant`,
  `human_approval_queued`, `human_approval_decision`). `nexusrecon/
  strategy/bounded_agency.py` ships `route_plan_items`,
  `queue_for_approval`, `resolve_approval`, `resolve_pivot_policy`
  (per-item policy escalation that refuses to NARROW agency).

### Phase 2: Continuous Confidence Engine

- **PR A**: `nexusrecon/verification/`. `VerificationOrchestrator`
  subscribes to graph mutation events
  (`register_mutation_listener`). `CorroborationEngine` lifts
  confidence when multi-source independence classes (`passive_dns`,
  `certificate`, `active_probe`, `breach_corpus`, …) vouch for the
  same entity. Formula: `new = old + (CAP - old) × (1 - DECAY^(n-1))`
  with CAP 0.99, DECAY 0.5.
- **PR B**: `ContradictionDetector`. Fires on
  `sticky_field_conflict` + `exclusive_rel_conflict` events
  (emitted by `EntityGraph.add_entity` / `add_relationship`).
  Severity-graded bounded downgrade (factor 0.6, floor 0.05).
  Medium+ findings queued in `state["contradictions"]`;
  `resolve_contradiction()` for operator resolution.
- **PR C**: `ConfidencePropagator`. New
  `EntityGraph.set_confidence(entity_id, value, *, reason, source)`
  setter emits `confidence_changed` events. Propagator cascades
  downgrades through reliance-semantics edges (`cites`,
  `belongs_to`, `part_of`, `hosted_on`, `registered_by`, `blocks`)
  with depth decay + visited-set cycle protection + one-way ratchet
  (upgrades don't propagate).
- **PR D**: `AdversarialSelfCheck` + strategic feedback.
  Heuristic graph audit emits four `WeakLink` kinds. Planner reads
  `state["verification_health"]` and biases toward verification
  tools when corroboration coverage is low.

### Phase 3: Recon Pack format + Contribution SDK

- **PR A**: `nexusrecon/packs/`. Pack format v1: directory under
  `~/.nexusrecon/packs/<name>/` (overridable via
  `NEXUSRECON_PACK_DIR`) with `manifest.yaml` declaring tools,
  agents, dispatch policies, report templates, custom entity / rel
  types. Unsigned + manifest_hash trust model. `load_packs()`
  invoked before scope load in `nexusrecon run`. Per-pack +
  per-contribution failure isolation.
- **PR B**: `nexusrecon/sdk/`. `register_prompt(name, version,
  body)` with hot-edit detection. `validate_citations(text, graph)`
  with three severity grades. `nexusrecon agent new`:
  Rich-prompted scaffolder that generates an agent module with
  prompt versioning + citation guardrails wired in.
- **PR C1**: Git distribution. `nexusrecon packs install
  gh:owner/repo[@ref]` (shallow clone). `packs update`,
  `packs uninstall`, `packs search` against a configurable
  marketplace JSON index (`NEXUSRECON_MARKETPLACE_URL`).
- **PR C2**: Tool + policy scaffolders. `nexusrecon tool new` +
  `nexusrecon policy new` with interactive capability pickers
  (tool: category × tier × target_types; policy: eligible phases +
  caps).
- **PR C3**: First-party Burp Suite pack at `packs/burp/`.
  Bidirectional XML handoff: `BurpXmlImporter` (site map XML →
  entities, dedup by (host, port, path)) +
  `render_scope_to_burp_xml()` / `export_campaign_scope_to_burp()`
  helpers. Dogfood example for the pack format.

### Phase 4: Intent-driven entry + Kill-chain handoff

- **PR A**: `nexusrecon/intent/`. NL → Strategy translation.
  `nexusrecon plan "<sentence>"` (one-shot) +
  `nexusrecon plan` (interactive). Two-path extractor: LLM-driven
  + regex fallback. Operator confirmation required before disk
  writes (Auditability First).
- **PR B**: STIX 2.1 export. `nexusrecon export <id> --format
  stix2` emits a Bundle with Identity / Domain / IP / Email / URL
  / Vulnerability / Infrastructure / Note SDOs. Stdlib-only
  serializer (no `stix2` library dep). UUIDv5 deterministic IDs.
  Custom `x_nexusrecon_*` properties preserve provenance.
- **PR C**: Bidirectional import. `nexusrecon ingest stix /
  nessus / nuclei / csv`. STIX importer round-trips PR B's
  output; Nessus XML emits host + CVE entities with `has_cve`
  edges; Nuclei JSON-lines emits URL + host + CVE; CSV importer
  takes a declarative `entity_type` + `value_column` mapping.
  All imported entities tagged `imported_from:<importer>`.
- **PR D**: Downstream consumer integrations. New export
  formats: `jira` (Jira REST API NDJSON), `nuclei-targets`
  (plain text for `nuclei -list`), `cobaltstrike-profile`
  (Malleable C2 profile stub with explicit "review before
  deploying" warnings).

### Phase 5: Moonshots

- **PR A. Watch Mode** (`nexusrecon/watch/`). Three sensor
  types (Entity / Scope / Timed). Severity classifier with rules
  cascade. Tiered actions: low → alert; medium → notification;
  high → queued micro-campaign. Persistence under
  `~/.nexusrecon/watch/<watch-id>/`. `nexusrecon watch create /
  list / tick / alerts / remove`. `tick` is synchronous + one-shot
  for cron-friendly deployment.
- **PR B. Provenance cryptography** (`nexusrecon/crypto/`).
  Ed25519 keypairs (PKCS8 + passphrase-encrypted PEM under
  `~/.nexusrecon/keys/<key-id>/`). Receipt v1.0 schema. Signed
  message includes the algorithm tag
  (`"ed25519|<bundle_hash>"`) to defeat algorithm-substitution
  attacks. `nexusrecon keys generate / list / export-public`,
  `nexusrecon sign`, `nexusrecon verify`.
  `scripts/nexusrecon-verify.py`. ~250-line standalone single-file
  verifier that depends only on `cryptography`. Auditors don't
  need a NexusRecon install.
- **PR C. Adversarial self-defense**
  (`nexusrecon/adversarial/`). Four detectors:
  `PoisonedDataDetector` (sinkhole IPs, wildcard DNS, uniform
  fabrication), `ToolPatternAnalyzer` (rapid pivots, low-yield
  bursts, repeat hits, tier escalation),
  `EvidenceInconsistencyDetector` (timing impossibility, platform
  / provider mismatch, email/org disagreement),
  `PromptInjectionScanner` (regex+structural by default; LLM
  classifier opt-in via `state["adversarial_use_llm"]`). Tiered
  bounded downgrade (medium ×0.7, high ×0.5, floor 0.05) that
  routes through `set_confidence` so the propagator cascades it
  naturally. `nexusrecon adversarial scan / show / scan-text`.
- **PR D. Vision pipeline** (`nexusrecon/vision/`).
  `VisionBackend` protocol + `LangChainVisionBackend` default
  (picks up operator's configured chat model). Preprocessing:
  pypdf for PDF text, pyzbar for QR codes (both optional with
  graceful skip). Strict-JSON prompt extracts URLs, emails,
  persons, organizations, brands, technologies, domains.
  Structured entities + narrative HypothesisEntity citing them.
  Strategy-driven cost control via
  `tool_budgets["vision_calls"]` (default 0. Opt-in only).
  `nexusrecon vision scan / scan-dir`.

### Documentation

- README rewritten for v0.7.0. Capabilities tables for the
  strategic / verification / interop / extensibility layers,
  expanded CLI section with every new command, status block
  pointing at the IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md
  acceptance criteria.
- ARCHITECTURE.md gained sections 13-22 (post-0.5 architecture
  deep-dives) and a glossary addendum.
- Top-level CLI doc entries for the new Strategy / Plan / Pack /
  Agent SDK / Watch / Sign / Verify / Vision / Adversarial /
  Ingest / Export surfaces.

### Dependencies

- Pinned `cryptography>=42.0.0` explicitly in `requirements.txt`
  (was a transitive dep). Used by Ed25519 signing.
- Optional: `pypdf` (PDF text extraction in the vision pipeline),
  `pyzbar` + `Pillow` (QR decoding). Both gracefully skip if
  absent.

### Breaking changes

- None to existing CLI commands or state shapes. Every layer
  preserves backward compatibility (Strategy defaults match
  pre-0.6 behavior; new event types ride existing audit-log
  paths; old `state.json` files load via `from_state` tolerance).
- `FullPolicy.max_total = 50` (was 30 universally). Operators
  who pinned the legacy 30-cap cross both modes should set
  `dispatch_policy_name="lite"` explicitly to preserve the
  conservative cap.

---

## [Unreleased]

### Added

- **Phase E: Relationship graph + pretext scoring**: full
  identity-attribution expansion from human-to-human edges to
  spear-phish intelligence. Six PRs:
  - **E1** `nexusrecon/core/relationship_graph.py`:
    `RelationshipGraph` with dual storage (per-identity
    `related_to` mirror + top-level `by_source`/`by_target`
    indexes), exponential recency decay (180-day default
    half-life, configurable), cross-source corroboration via
    `1 − ∏(1 − sᵢ)`. Pure Python, no network. 76 unit tests.
  - **E2-E5** Social-graph crawlers. `github_social`,
    `mastodon_social`, `bluesky_social`, `linkedin_social`. Each
    inherits from `BaseHTTPTool`, ships with empty
    `dynamic_trigger_hints` (no auto-fire from the LLM
    dispatcher), and exposes an `extract_edges_from_*` adapter
    that turns raw API data into `RelationshipEdge` tuples.
    LinkedIn isolated per the locked-in posture decision; uses
    `linkedin-api` (pinned `>=2.3,<3`) with cookie auth
    preferred. 145 new unit tests across the four tools.
  - **E6** `nexusrecon/tools/intel/business_partner_tool.py`:
    org-to-org aggregator combining Crunchbase (via the existing
    `crunchbase` tool through the registry), BuiltWith API
    (fail-fast on `BUILTWITH_API_KEY` when enabled), DNS TXT
    vendor inference (SPF + MX), and best-effort press-page
    scraping. 21 unit tests.
  - **E7** `nexusrecon/tools/pretext/conference_speaker_tool.py`:
    hardcoded default conference list (DEFCON, BSides, RSA,
    KubeCon, FOSDEM, BlackHat, Strange Loop, USENIX) with a
    per-site parser interface. FOSDEM has a working parser;
    others ship as stubs ready to wire. Co-speaker edges (weight
    0.95). 29 unit tests.
  - **E8** `nexusrecon/tools/pretext/news_tool.py` extended
    in-place with `time_window_days` kwarg +
    `recent_activity_records` field (additive. Existing shape
    preserved). New shared dataclass
    `nexusrecon/core/recent_activity.py::RecentActivity` with
    timeline helpers consumed by E9. 18 new unit tests + 27 for
    the core module; existing news_tool integration tests
    untouched.
  - **E9** `nexusrecon/core/pretext_scoring.py`:
    `PretextCandidate` + `score_pretext_candidates`. Three-axis
    score (sender × topic × timing) combined as the geometric
    mean. Any zero axis zeroes the result, modelling
    "no recent activity = no anchor." Every candidate carries a
    `sources: list[str]` audit trail. Pure Python, deterministic
    with `now=` override. 34 unit tests.
  - **E10** Enhanced `nexusrecon/agents/phishing_drafter.py`:
    expanded backstory + JSON output schema. Documents
    do-not-fabricate rule, DMARC-driven sender-domain decision
    (reject → lookalike; none/absent → real corp address),
    no-draft fallback for low-signal targets. Still gated on
    `--generate-phishing`.
  - **E11** Phase 7.7 (`phase7_7_pretext_intelligence`) wires the
    above into the workflow between Phase 7.5 and Phase 8. New
    state slots `pretext_scores`, `spear_phishing_intelligence`,
    `pretext_targets`. New deliverables
    `spear_phishing_intelligence.md` (per-target dossier with
    top 3 senders + top 3 pretexts + recent-activity timeline +
    recommended draft framing) + `pretext_candidates.json`. New
    CLI flag `--pretext-targets` narrows scoring scope. 16 unit
    tests cover phase ordering, state shape, the
    `generate_phishing_drafts` gate, and report builder output.
  - **Live-test safety:** every Phase E tool registers with empty
    `dynamic_trigger_hints`. The LLM dispatcher cannot fire them
    mid-campaign; they only execute when Phase 7.7 explicitly
    invokes them through the registry.
- Apache 2.0 LICENSE + NOTICE (replaces the earlier proprietary
  declaration in `pyproject.toml`).
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `ROADMAP.md`.
- `.github/ISSUE_TEMPLATE/` (bug + feature templates) and
  `.github/workflows/test.yml` running `pytest tests/unit
  tests/integration tests/smoke` on every PR.
- Centralised User-Agent pool at `nexusrecon/opsec/useragent.py`
  with a `random_ua()` helper. 47 tools now rotate UAs from the
  ~30-entry pool instead of all hardcoding the same Firefox-128
  string. Closes the "everyone running NexusRecon has an identical
  TLS+UA fingerprint" issue.
- **`BaseHTTPTool`** (`nexusrecon/tools/base.py`): subclass of
  `OSINTTool` for tools that hit JSON HTTP APIs. Provides a
  `classify_response(resp, endpoint="")` helper that converts the
  common provider error codes (401/403/429/5xx) into uniform
  `ToolResult(success=False)` failures. Tools subclass it and
  customise via `provider_label` and `soft_failure_codes` class
  attributes. Eliminates the per-tool restated if-tree that was the
  root cause of the 0.5.0 silent-failure bug cluster. 11 new unit
  tests in `tests/unit/test_tool_base.py` pin the contract.
- **`.github/workflows/live-drift.yml`**: weekly tripwire that runs
  `tests/live/` against real provider APIs and surfaces upstream
  schema drift as workflow failures. Scheduled Mondays 06:00 UTC
  plus `workflow_dispatch` for manual runs. Each test is gated by
  its `@pytest.mark.live("<provider>")` marker; missing secrets
  auto-skip rather than fail.
- **OPSEC wire-level enforcement**: `ToolRegistry.set_campaign_context`
  now accepts `stealth_profile`, `rate_limiter`, and `proxy_manager`
  kwargs. `registry.execute()` awaits `rate_limiter.wait(tool.name)`
  before invoking `tool.run()`, and propagates the resolved proxy URL
  via a new `nexusrecon.opsec.context.proxy_context` ContextVar.
  `BaseHTTPTool._proxy_kwargs()` reads the ContextVar and returns
  httpx-compatible proxy kwargs for tools to spread into their
  `httpx.AsyncClient(...)` call. Closes the "OPSEC declared in config
  but not verified at the wire level" ROADMAP gap, for the 5 reference
  HTTP tools (shodan/virustotal/censys/fullhunt/greynoise). 37 unit
  tests + 9 wire-verification integration tests cover the new path.
- **`OPSEC_STATUS.md`**: honest accounting of what the OPSEC layer
  actually enforces at the wire level versus what's still
  declared-only. Lists the remaining 65 HTTP tools that still need
  migration to `BaseHTTPTool` to gain proxy support, and the
  campaign-runner gap (`set_campaign_context` accepts the OPSEC
  primitives but the campaign runner doesn't yet pass them).
- **Report-quality automated assertions** (`tests/unit/test_report_quality.py`):
  13 tests covering the four ROADMAP Day-7 properties without
  requiring real LLM calls: AI-tell phrase scanner across agent
  prompts + report templates + report engine prose (LLM-disclaimer
  artifacts, marketing fluff, high-signal AI vocabulary); scope-hash
  presence in `ReportEngine` and templates; CVE citation regex
  validator (rejects malformed `CVE-XX-...` references in static
  prose); findings deduplication for CVEs and breached emails.
- **`tests/manual/REPORT_QUALITY_CHECKLIST.md`**: per-campaign manual
  checklist for the 10 target shapes the ROADMAP wanted Day 7 to
  cover. Operator runs this once before tagging a beta release;
  things only a human can judge (narrative coherence, tone,
  whether a phishing draft sounds plausible) live here, while
  static-checkable properties land in the automated tests above.
- **Maigret tool** (`nexusrecon/tools/identity/maigret_tool.py`):
  full implementation replacing the previous stub. Subprocess wrapper
  around the `maigret` CLI (install via `pipx install maigret` ── the
  PyPI package pins `networkx<3` which conflicts with NexusRecon's
  `networkx>=3.3`, so library-import is not viable). Checks a
  username against ~500 top sites by default (`top_sites` kwarg
  configurable, up to ~3000); accepts either an explicit username
  target or an email which triggers username derivation. Parses
  maigret's `--json simple` output and dedupes hits by
  `(username, service)`. 13 integration tests cover the parsing,
  binary-missing path, email-derivation flow, role-account
  short-circuit, subprocess timeout, and cross-candidate dedup.
- **Username derivation utility**
  (`nexusrecon/core/username_derivation.py`): pure-Python heuristics
  that turn an email + optional harvested names into a ranked list of
  likely usernames. Handles dotted/underscored/dashed corporate
  emails, initial-prefix patterns (jdoe), numeric suffixes that
  persist across services (jane.doe2 → janedoe2 etc.), and
  last-first name forms (DOE, Jane → jane.doe). Role accounts
  (admin@, info@) short-circuit to empty. 26 unit tests pin the
  derivation contract.
- **Phase 2 maigret integration** (`nexusrecon/graph/nodes.py`):
  after holehe runs on the top 20 emails, maigret runs on the top 5
  emails with 2 derived username candidates each (10 maigret
  invocations max, semaphore=2 for concurrency). Results land under
  `email_intel.emails[em].maigret_accounts` and
  `email_intel.emails[em].derived_usernames`. Aggregate
  account-association summary fed to the `cloud_identity` agent so
  the dispatcher trace can include "this employee has accounts at
  N services across holehe+maigret" reasoning.
- **`cloud_identity` agent prompt extended**: now receives
  per-email account counts and high-confidence handles (3+
  service-hits with same username), with directive to surface
  account-association correlations and recommend follow-up
  breach-database lookups against confirmed handles.
- **Attribution confidence scoring**
  (`nexusrecon/core/attribution.py`): multi-axis scorer that
  defends the framework against the "John Smith" false-positive
  trap. Replaces the previous "≥3 service hits = high confidence"
  heuristic (which guaranteed false positives on common names)
  with a weighted combination of four signals:
  - **Derivation rank**: how directly the handle ties to the
    verified email. Exact local-part match = 1.0; stripped-suffix
    variant = 0.8; separator variant = 0.6; initial-prefix
    pattern = 0.4; lone-component = 0.2.
  - **Handle uniqueness**: membership in a bundled common-handles
    list (~400 entries: top US given/family names from Census,
    generic role handles, common breach-data patterns). Common
    handles get a length-weighted penalty.
  - **Service trust tier**: hand-curated tier mapping covering
    ~80 services. Tier 1 (LinkedIn/GitHub/StackOverflow) = 1.0;
    Tier 2 (Reddit/Twitter/Discord) = 0.7; Tier 3
    (gaming/image-hosts) = 0.4; Tier 4 (dating/anonymous) = 0.2.
  - **Profile coherence**: bio mentions email domain stem? Profile
    name matches harvested name? Mostly 0.0 today because maigret
    rarely exposes bio text; lays the foundation for Phase B
    (profile-page fetching).
  Weights: derivation 0.35, uniqueness 0.20, service-tier 0.20,
  profile 0.25. Actionable threshold 0.6. 41 unit tests pin every
  signal individually plus the John-Smith-collision-filtered and
  obvious-attribution-clears-threshold end-to-end scenarios.
- **Maigret tool computes attribution per hit**: every entry in
  `registered_services` now carries `confidence` (float),
  `confidence_band` (high/medium/noise), `confidence_signals`
  (per-axis breakdown), and `confidence_rationale` (human-readable
  citation string). Hits are sorted by confidence descending. New
  `actionable_count` and `confidence_breakdown` fields summarise
  the scoring distribution. 3 new integration tests verify the
  scoring is wired and hits sort correctly.
- **Phase 2 filters maigret noise before reaching the agent**: the
  `account_associations` payload now contains only hits at the
  actionable threshold (≥ 0.6) and reports the noise count
  separately. The `cloud_identity` agent prompt directs the LLM
  to cite the rationale per actionable hit and explicitly NOT
  speculate about the filtered noise (John Smiths on Reddit, admin
  on random forums, etc.). The dispatcher trace becomes
  defensible: "this handle scored 0.78 because exact-derivation +
  Tier 1 service + bio mentions employer" instead of "this
  handle hit on 24 services."
- **Phase B attribution improvements**:
  - **Census/SSA name frequency** (`nexusrecon/core/name_frequency.py`):
    tiered bundled data from US Census Bureau decennial surname
    frequencies + SSA top-1000 baby names. Tier A (top 50 per
    category) commonness 0.95; Tier B (51-200) commonness 0.70;
    Tier C (201-1000, surnames) commonness 0.20. `handle_commonness`
    tokenises a handle and returns the max-component commonness ──
    catches handles like `mjohnson` (Johnson is Tier A) that the
    Phase A curated-list lookup missed. Attribution's uniqueness
    signal now combines the curated list with the name-frequency
    lookup via `max(curated_commonness, name_freq_commonness)` so
    a handle is only "unique" when both signals agree. 23 unit tests.
  - **Profile fetching** (`nexusrecon/core/profile_fetcher.py`):
    fetches real bio/location/company/blog data from GitHub
    (`api.github.com/users/{login}`), GitLab (`gitlab.com/api/v4`),
    Reddit (`/user/{name}/about.json`), and Stack Exchange
    (`api.stackexchange.com/2.3`) APIs, plus a generic HTML +
    `<meta og:description>` fallback for any other service. All
    fetches go through the campaign proxy via
    `opsec.context.proxy_kwargs`. Per-fetch UA rotation. Errors
    return a `ProfileData` with `.error` set rather than raising,
    so one failed fetch can't crash the batch. 23 unit tests.
  - **Linked-account graph** (`nexusrecon/core/linked_accounts.py`):
    regex extraction of cross-service references from bio text +
    blog URLs. Covers 14 services via URL patterns (GitHub, GitLab,
    Twitter/X, Mastodon, Bluesky, LinkedIn, Reddit, Stack Overflow,
    Instagram, Keybase, Dev.to, Medium, Twitch, YouTube) plus
    labelled-mention patterns (`"Twitter: @handle"`, `"GitHub: x"`)
    for cases without a URL. Self-references skipped (a GitHub
    profile mentioning its own canonical URL doesn't count). Prose
    false-positive filter via stop-word list. 22 unit tests.
  - **Maigret rescore loop**: after the initial Phase A scoring,
    every hit at confidence >= 0.4 has its profile fetched via the
    fetcher, the linked-account extractor runs on the bio, and the
    attribution scorer is re-invoked with the richer profile data
    + a `cross_referenced` flag when another service's bio named
    this exact `(service, handle)` pair. The cross-reference signal
    contributes +0.6 to the profile-coherence sub-score on its own.
    Tunable via `fetch_profiles`, `rescore_floor`, and
    `profile_fetch_concurrency` kwargs. 3 new integration tests.
  - **`cloud_identity` agent prompt extended** to cite specific bio
    text and cross-references in its analysis, not just numeric
    scores. The dispatcher trace now reads like an analyst voice:
    "GitHub bio says 'Senior engineer at GitLab' which matches the
    email domain" rather than "scored 0.78."
  - **Phase C: avatar similarity, timeline clustering, reputation scoring**:
    - **C1 ── Cross-service avatar similarity hashing**
      (`nexusrecon/core/avatar_hash.py`): downloads profile avatars
      for HIGH/MEDIUM band hits, computes 64-bit dHash perceptual
      hashes via the `imagehash` library, clusters images within
      Hamming distance 8 (catches cropping/recompression). Hits in
      a multi-service cluster get treated as cross-referenced
      (same +0.6 boost as B4 linked-account graph). Identicon
      heuristic filters Gravatar/GitHub/Reddit auto-generated
      avatars so default-avatar users don't false-cluster. Optional
      dependency (`pip install nexusrecon[avatar]`); the module
      gracefully no-ops without Pillow + imagehash. 31 unit tests.
    - **C2 ── Account-creation timeline clustering**
      (`nexusrecon/core/timeline_cluster.py`): parses creation
      timestamps from GitHub/GitLab/Reddit/Stack Exchange across
      ISO 8601, Unix epoch seconds, Unix epoch milliseconds, and
      bare-date formats. Clusters accounts created within a
      configurable window (default 30 days). Surfaces clusters of
      size ≥2 to the agent as "these N accounts were created in
      the same window ── consistent with one person setting up
      their presence at one event." 24 unit tests.
    - **C3 ── Reputation-weighted scoring**
      (`nexusrecon/core/reputation.py`): per-service threshold tables
      for GitHub follower count, StackOverflow reputation, Reddit
      karma, GitLab project count. High-rep accounts add up to
      +0.30 to the profile coherence signal ── recognises that a
      real engaged human's account carries more identity evidence
      than a brand-new placeholder account on the same service.
      Per-service thresholds (e.g. SO rep > 1000 = real engineer,
      Reddit karma > 1000 = active user) keep cross-service
      comparisons meaningful. 23 unit tests.
    - **`profile_fetcher.ProfileData` extended** with `avatar_url`,
      `reputation`, `follower_count` fields. All four per-service
      fetchers (GitHub/GitLab/Reddit/Stack Exchange) capture these
      where available; generic HTML fallback reads `<meta og:image>`.
    - **Maigret rescore loop extended** to fetch + hash avatars and
      compute timeline clusters AFTER the Phase B profile-fetch
      pass. Both signals surface in the `account_associations`
      payload as `avatar_cluster_size`/`avatar_cluster_id` and
      `timeline_cluster_size`/`timeline_cluster_id`.
    - **`cloud_identity` agent prompt extended** to cite avatar
      cluster membership ("same image on GitHub and Twitter") and
      timeline cluster ("three accounts created within the same
      month") as concrete identity evidence.
  - **B3 (cross-campaign handle ubiquity tracking)** completes
    Phase B. New module `nexusrecon/core/handle_ubiquity.py`
    provides `HandleUbiquityTracker` ── a SQLite-backed store that
    tracks which handles appear across multiple unrelated campaigns
    and contributes an additional uniqueness penalty proportional to
    the cross-campaign count. Catches the long-tail collisions that
    pass both the Phase A curated common-handles list and the Phase
    B2 census/SSA frequency tables but recur across the operator's
    unrelated work. **Opt-in by default**: the framework ships with
    no tracker bound; operators call `ubiquity_context(tracker)`
    around `run_workflow()` to enable. **Privacy preserving**:
    handles are stored as salted SHA-256 hashes (per-install salt),
    not plaintext, so a leaked DB doesn't disclose investigated
    handles. Default storage at `~/.nexusrecon/handle_ubiquity.db`
    with 0o700 parent directory; configurable via
    `NEXUS_UBIQUITY_DB_PATH`. Commonness curve maps campaign-count
    to commonness: 1 campaign → 0.0, 2-3 → 0.30, 4-10 → 0.60,
    11+ → 0.85. The attribution scorer combines all three uniqueness
    sources (curated list + name freq + ubiquity) via `max()` so a
    handle is "unique" only when all three agree. 27 unit tests +
    2 integration tests pin the recording loop, the privacy
    properties (no plaintext stored, per-install salt isolation),
    and the end-to-end attribution penalty.

### Changed

- 5 reference HTTP tools (`shodan`, `virustotal`, `censys`,
  `fullhunt`, `greynoise`) migrated to inherit from `BaseHTTPTool`.
  Each lost its private `_classify_status()` helper in favour of the
  shared one; error text is now uniform across the registry
  (`"<Provider> auth failure (HTTP 401) - check <KEY>"`,
  `"<Provider> rate limit - back off and retry"`,
  `"<Provider> returned HTTP <code>"`). Behaviour unchanged for the
  52 integration tests covering these tools.
- Same 5 reference tools also spread `**self._proxy_kwargs()` into
  their `httpx.AsyncClient(...)` instantiations so they pick up the
  active campaign proxy URL when the registry has a `ProxyManager`
  bound. The remaining 65 HTTP tools still build raw clients without
  proxy support; see `OPSEC_STATUS.md` for the migration tracker.
- **`holehe_tool.py` now honours OPSEC**: previously the
  `_HEADERS = {"User-Agent": random_ua(), ...}` was module-level,
  freezing the UA at import time so every holehe invocation in the
  same Python process sent the same UA. Headers are now built per
  `run()` call. The internal `httpx.AsyncClient` also now spreads
  `proxy_kwargs()` from `nexusrecon.opsec.context` so holehe's ~121
  outbound probes route through the campaign proxy. Two new wire
  tests (`TestHolehyeProxyAndUaRotation`) catch regressions.
- **`proxy_kwargs()` lifted to a free function** in
  `nexusrecon.opsec.context`. `BaseHTTPTool._proxy_kwargs` still
  exists as a thin wrapper for the migrated tools, but library-
  driven tools (holehe, future maigret-as-library) can call
  `proxy_kwargs()` directly without inheriting from `BaseHTTPTool`.
- **Structural OPSEC wire test**: new
  `TestProxySupportStructural::test_every_basehttp_tool_calls_proxy_kwargs`
  walks every registered `BaseHTTPTool` subclass and grep-asserts
  that its source calls `_proxy_kwargs()`. Catches the next tool
  that inherits from BaseHTTPTool but forgets the proxy spread.
- `CONTRIBUTING.md`: "Adding a new OSINT tool" example rewritten to
  inherit from `BaseHTTPTool` and use `classify_response()`. Hard
  rule #4 reworded from "explicit status-code branches" to "use the
  base class instead of restating the if-tree by hand."
- `examples/sample_run/README.md`: flagged as a walkthrough only;
  the actual checked-in real-target report run is the v0.6.0
  milestone (see `ROADMAP.md`).
- `pyproject.toml`: added `pytest-timeout>=2.3.0` to dev deps and
  set a global `timeout = 120` in `[tool.pytest.ini_options]`. Any
  unit test that exceeds the timeout is doing something it
  shouldn't (real subprocess, real network call, infinite loop).

### Fixed

- `github_recon` and `gitdorker`: replaced blocking `time.sleep(1.1)`
  with `await asyncio.sleep(1.1)` so dork-loop pauses don't block
  the event loop for tools running in parallel.
- **`graph/nodes.py`**: 19 occurrences of `isinstance(x, Exception)`
  guarding `asyncio.gather(return_exceptions=True)` results changed
  to `isinstance(x, BaseException)`. `asyncio.CancelledError` is a
  `BaseException` subclass in Python 3.8+, not `Exception`, so a
  cancelled tool task crashed the phase node with `AttributeError:
  'CancelledError' object has no attribute 'success'`. Same crash
  fired under `pytest-timeout` (the `_pytest.outcomes.Failed`
  exception also inherits from `BaseException`), which is how the
  bug surfaced. Added a regression test
  (`TestPhase1::test_tool_baseexception_does_not_crash`).
- **Test suite cleanup, 7 pre-existing failures**:
  - `test_config.py::test_available_keys_empty` and
    `test_proxy_defaults` were leaking the developer's local `.env`
    into the test process (pydantic-settings reads `.env` by
    default). Fixed with a `clean_env` fixture that clears the
    relevant env vars and passes `_env_file=None` to
    `NexusConfig(...)`.
  - `test_agent_executor.py::test_build_context_with_data` asserted
    on `"Instructions" in context`, a string the production code
    stopped emitting several refactors ago. Replaced with assertions
    against the current B25 "Analysis (write AFTER emitting
    FINDINGS_JSON):" directive.
  - `test_nodes.py::TestPhase7` and `TestPhase8` had stub
    `test_runs_with_minimal_state` tests with no mocks, so they
    triggered real `nuclei` / `httpx` / LLM API calls and hung or
    failed depending on what was installed. Replaced with proper
    `@patch`-based mocks: tool registry returns all-failure, agent
    executor returns canned responses.
  - `test_graph.py::TestRunWorkflow` (3 tests) had no mocks for the
    full-pipeline `run_workflow` call; same root cause as Phase 7/8.
    Added a `mock_workflow_deps` fixture that patches
    `nexusrecon.graph.nodes.get_registry` and `_get_executor` for
    the duration of each test. Unit-suite runtime fell from ~205s
    (7 failures + 30s+ timeouts) to ~7s (all passing).

## [0.5.0] - 2026-05-18 - pre-beta

The first version that has integration-test coverage across the full
tool registry and a documented bug-fix audit trail. Everything below
this line landed during the pre-beta hardening sprint.

### Added

- **351 integration tests** across 13 category files, one TestClass
  per tool, four-test pattern (happy / empty / error / malformed) per
  tool.
- **32 opt-in live tests** in `tests/live/test_live_apis.py` for
  upstream-drift detection. Auto-skipped unless API keys present.
- **`tests/fixtures/`** directory with 120 JSON / HTML / XML / text
  fixtures built from each provider's public API documentation.
- **`TESTING_PLAN.md`**: methodology doc covering the five mocking
  strategies (HTTP / binary / DNS / pure-logic / stub).
- Custom **`ChunkyBar`** progress widget in the TUI runner screen.
- **Live structlog stream panel** in the TUI runner screen. Operators
  can watch the framework's internal logs in real time during a
  campaign.
- **1 Hz live-stats refresh** on the runner screen: elapsed time,
  LLM cost, and counter fields tick smoothly between phase
  boundaries.
- **`@work` worker reference tracking** so the Abort key actually
  cancels the running campaign and saves partial state for resume.
- **Two-press Abort confirmation** to prevent stray keypress kills.

### Fixed

Eighteen tool bugs surfaced and pinned during the test-writing pass.

- `email_format`: regex anchor mismatch made every input resolve to
  `"unknown"`.
- `wayback`: read `.url` / `.status` attributes that don't exist on
  `waybackpy.CDXSnapshot` (real names: `.original` / `.statuscode`).
- `dnstwist`: called non-existent `FuzzDomain` class; actual class
  is `Fuzzer`. Tool was 100% non-functional.
- `pastebin_scan`: didn't base64-decode GitHub Contents API
  responses, so credential regex never matched real leaks.
- `greynoise`, `shodan`, `censys`, `virustotal`, `hunter`,
  `passive_dns`: all silently swallowed 401/429/5xx as empty success
  responses. Operators couldn't tell "no data" from "bad key /
  quota exhausted / provider outage".
- `fullhunt`: read `metadata.all_results` when the documented field
  is `all_results_count`.
- `github_recon`: didn't enforce `GITHUB_TOKEN`; sent requests with
  an empty `Authorization` header which capped the rate at 60 req/hr.
- `cdn_detect`: swallowed DNS + HTTP failures entirely; returned
  `success=True` with no diagnostic when probes failed.
- `aws_recon`: used `S3_REGIONS[:10]` for Lambda URL probes,
  silently excluding three valid EU regions.
- `gcp_recon`: App Engine probe treated `status != 404` as "found",
  so 500-class errors were reported as discovered apps.
- `azure_m365_recon`: inconsistent federation-detection field reads
  vs. Its sibling `azure_tenant_enum`.
- `whois`: reported `result_count=1` for fully-empty responses,
  inflating campaign aggregate metrics.
- `hudsonrock`: 5xx errors stashed in `data["error"]` while
  `success` stayed `True`, hiding provider outages.

### Changed

- TUI runner screen redesigned with bordered phase header, live
  stats panel, activity log, and toggleable structlog stream.
- Wizard's stealth-profile dropdown corrected to the four
  model-validated values (`paranoid / high / normal / loud`); the
  previous `low / medium / high` choices were rejected by
  `ScopeModel` validation, silently breaking campaign launch.
- README rewritten as a fresh-visitor front door; agentic value
  proposition leads, worked example follows.
- Version honesty: codebase, package metadata, banners, and docs now
  consistently reflect `0.5.0` pre-beta.

### Removed

- The non-functional TUI "Pause" binding (the campaign runner has no
  cooperative checkpointing to pause at).

---

## Earlier history

Pre-`0.5.0` activity tracked only in `git log`. The project went
through a "V2 Gold Standard" and "V3 UX Polish" iteration during
internal development before adopting semver with the `0.5.0`
pre-beta release.
