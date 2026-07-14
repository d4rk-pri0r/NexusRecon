# NexusRecon Roadmap

Current state, and the road to 1.0. The plan changed on 2026-06-09: stop
expanding the footprint, perfect the core that already works. Pull requests
welcome; prioritisation is set by the maintainer.

---

## Philosophy: perfect the core, do not widen it

A full honest audit of the build (2026-06-09) reached a blunt conclusion. The
core that a real `nexusrecon run` actually executes (the recon tool fleet, the
report engine, the hash-chained audit log, the TUI) is genuinely good. But a
large amount of high-quality code never runs on the default path, and three of
the loudest marketing claims did not survive contact with a real campaign. The
1.0 plan is therefore not "add more." It is: wire in the crown jewels that were
stranded behind a flag, fix the handful of trust-eroding and operator-burning
bugs, and demote the scaffolding that was built for workflows and audiences
that do not exist yet. Ship a smaller, truer tool.

Everything below is the road to 1.0. There is no "next wave of features." The
items that used to live here (BloodHound ingest, parallel multi-target
campaigns, scope linter, cost preview, marketplace curation, the post-1.0
ecosystem work) are intentionally removed. They expand the footprint, and the
footprint is already wider than one person plus AI can keep excellent.

---

## What actually works today (the core worth perfecting)

When you run `nexusrecon run`, this is what genuinely delivers:

- **The recon fleet.** 97 scope-gated tools, of which roughly 30 are free
  no-key HTTP integrations that fire on a default keyless install. The base
  class turns 401/403/429/5xx into explicit failures instead of silent empties,
  paid-API and breach gating is honest, and the registry returns an explicit
  "prerequisites not met" rather than faking success.
- **The report engine.** The best-integrated subsystem in the build. About 25
  operator-facing deliverables rendered from live state, with deterministic
  CVE-provenance scrubbing so hallucinated CVEs never ship to a client, a
  run-health trust banner, a coverage appendix, and scope-hash plus version
  footers for reproducibility.
- **The hash-chained audit log.** Real tamper-evident JSONL: every tool call
  records a sha256 of the raw response, and `verify_chain()` runs at finalize
  with a real tamper-detection test. This is the strongest single piece of
  differentiation for client-engagement defensibility, and it is load-bearing
  on every run.
- **The TUI.** Drives the same `run_campaign` spine as the CLI, with live event
  streaming, crash-recovery session locks, an abort that cancels the real
  asyncio worker, and a production-grade masked `.env` editor.
- **Personal-identity pivot and pretext intelligence (newly wired in,
  2026-06-09).** The geometric-mean (sender x topic x timing) pretext scoring
  and the corp-to-personal pivot plus credential punch list are the real
  attacker-mindset deliverables. They were previously reachable only behind
  `--use-graph`; they now run on the default path (see item 1 below).

---

## The road to 1.0: perfect-it shortlist

Ranked by leverage. No new footprint. Each item makes something that already
exists actually deliver on its claim.

1. [x] **Wire the crown jewels into the default run.** `phase2_5`
       (personal-identity pivot plus credential punch list) and `phase7_7`
       (relationship graph plus pretext scoring) were tier-0 passive phases
       absent from `core/campaign_runner.py`, so `credential_exposure_paths.md`
       and `spear_phishing_intelligence.md` rendered empty on every default run.
       Both are now on the default path in the correct slots (2_5 after corp
       identity is confirmed, 7_7 after credential harvest). Breach lookups
       stay gated by the scope guard's `allow_breach_db_lookup` constraint and
       phishing-draft generation stays behind `--generate-phishing`. Regression
       guard: `tests/unit/test_campaign_runner_phases.py`. Done 2026-06-09.

2. [x] **Fix the run-health false alarm.** `core/campaign_runner.py` passed a
       hardcoded `entities_count=0` to `end_phase`, so `run_health.entities_total`
       was always 0 and the "entity extraction may be broken" caveat fired on
       every healthy run. A trust feature that cries wolf every time trains the
       operator to ignore it. The runner now reads the real node count from
       `state["entity_graph"]["nodes"]` (persisted by phase4/phase8) and threads
       it into `end_phase`; `run_health` takes the max across phases so the final
       summary reflects the true graph size. Phases before phase4 honestly report
       0. The ginandjuice fixture still flags `zero_entities` because its run
       genuinely extracted none. Regression guard:
       `tests/unit/test_campaign_runner_phases.py`. Done 2026-06-09.

3. [~] **Close the phase6 deanonymization gap.** Active web-probing
       (`/.git/config`, `/.env`, `/admin`) in `graph/nodes.py` fired raw
       `httpx.AsyncClient` outside `registry.execute()`, bypassing proxy, JA3,
       rate limiter, and jitter simultaneously, on the campaign's most exposed
       traffic. Done: phase6 alt-port and content-path probing now routes through
       a new `registry.opsec_http_get()` that mirrors the `execute()` OPSEC
       envelope (per-source rate limiter, stealth jitter, proxy injection via
       `proxy_kwargs()`, JA3/TLS impersonation), degrading to plain httpx when no
       context is bound. Wire-verified in
       `tests/integration/test_opsec_wire.py::TestPhase6ActiveProbingOpsec`.
       Remaining (follow-up): inject proxy env into subprocess tools (subfinder,
       amass, nuclei) and bind OPSEC context in `resume()`. The phase6 hole, the
       one that could get a client-engagement operator burned, is closed.

4. [x] **Make the graph carry real entities and real edges.** On a default run
       `EntityGraph.from_state()` instantiated 5 of 17 entity types and drew no
       CITES/BLOCKS edges, so hypotheses landed as disconnected text and the
       "explain this finding as a graph traversal" capability did not exist.
       Done: `from_state` now builds a domain backbone (DOMAIN nodes +
       HAS_SUBDOMAIN edges), IP and technology nodes from the httpx active-probe
       output (RESOLVES_TO / HAS_TECH), and secret nodes from code-leak output
       (CONTAINS_SECRET, stored as a non-sensitive rule+file label, never the
       raw secret). The reasoning layer now connects to evidence: each
       hypothesis/lead draws mention-based CITES edges to the entities it names,
       and each open question BLOCKS the leads/hypotheses it shares an entity
       with. `reports/engine.py::_entity_graph_html` now rebuilds the real graph
       and delegates to `export_pyvis_html` (the full type-colour map + edge
       labels) instead of reading keys `to_dict()` never emitted. Regression:
       `tests/unit/test_step_0_0_graph_wireup.py::TestEntityGraphEnrichment`.
       Follow-up: thread per-source `ProvenanceRecord` writers (still unwired)
       before re-advertising "per-source provenance."

5. [x] **Broaden degraded-tool detection.** Only 4 of 97 tools overrode
       `assess_result` (whois/nuclei/sslyze/wafw00f), so a silent failure in
       subfinder, amass, httpx, shodan, or github_recon was reported as a
       clean negative, the exact failure this feature was built to kill. Done,
       and scoped so it never cries wolf (a false "degraded" is the real
       harm), after three adversarial verification passes (one running the
       actual binaries) pruned an over-eager first cut. The three subprocess
       tools now capture the process exit code: `run()` fails outright on a
       non-zero exit that parsed nothing (a crashed or misconfigured tool is
       no longer a clean negative) and `assess_result` flags a partial crash
       (non-zero exit with some output). Their exit-0-but-empty failures (dead
       proxy, all sources throttled) are left an honest residual: these tools
       write nothing usable to stderr at default verbosity, so any marker
       heuristic is either inert or a false positive, and closing the gap
       needs the per-source `-stats` signal or a proxy preflight. github_recon
       threads a `_recon_health` bucket that separates GitHub's core-REST and
       `/search/code` rate-limit pools and flags a token-wide 401, a rejected
       repo enumeration, or a code scan where every reaching dork failed
       transiently and none returned data, but never a bare org rate-limit and
       never a bare-domain run (whose `org:<domain>` dorks all 422 on the
       invalid qualifier, tracked as query-rejects rather than failures).
       shodan needed no new field detection (`classify_response` already fails
       its auth/rate-limit/outage responses); its one reachable silent
       failure, an in-scope IP hostname-searched on the wrong endpoint, is now
       surfaced. Regression: `tests/unit/test_wave_f_failure_detection.py` and
       `tests/integration/test_code_tools.py`. Follow-ups noted: per-source
       `-stats` or a proxy preflight for the subprocess exit-0 case, and
       routing IP targets to `/shodan/host` in shodan's `run()`. The other ~90
       tools correctly default to no opinion.

6. [x] **Stop MockLLM masquerading as analysis.** Resolved as label, not
       refuse. Keyless (the default, and the only path the test suite
       exercises) the MockLLM fallback emitted one templated finding through
       the same code path as real agents; the persona reaches the prompt but
       MockLLM ignores it, so every agent produced near-identical boilerplate
       that rendered identically to real analysis in the two detail reports
       (which never showed the Run Health mock banner). Done: `run_agent` now
       stamps `provenance` from the model that actually served the call
       (spoof-proof, independent of the LLM-controlled `source`), and the
       executive summary and full report lead with a blunt "MOCK ANALYSIS:
       templated, not reasoned" banner and badge each mock finding `[MOCK]`.
       The persona test the item asked for is added (a real agent's
       role/goal/backstory reaches the prompt); it also documents that MockLLM
       output does not vary by persona, which is why labeling, not trust, is
       the fix. Separately, the `evidence_auditor` overclaim is dropped: it is
       renamed a citation-completeness check (presence of the four fields), the
       "legal defensibility" and "check every evidence hash" language is
       stripped from the auditor and findings docstrings, and because the
       agent-path evidence hash only digests the model's own prose, findings
       now carry `evidence_integrity="unverified"` and the full report says so.
       The real fix (persist raw tool artifacts and hash those) is a provenance
       subsystem left out of scope. Regression:
       `tests/unit/test_agent_executor.py::TestMockProvenanceLabeling` and
       `tests/unit/test_reports.py::TestMockFindingLabeling`. Done 2026-07-13.

7. [x] **Fix the export-to-sign happy path and STIX SCO schema.** Done.
       `export --format stix2` now writes the canonical `stix2-bundle.json`
       (the exact name `sign` and the receipt expect) instead of
       `findings_export.stix2`, and prints the next-step `sign` hint. `sign`
       auto-discovery accepts both names (canonical first, legacy fallback) and
       its error message lists both. STIX SCO schema fixed: `_base_object` and
       `build_stix_bundle` no longer attach the SDO common properties
       (created / modified / created_by_ref / confidence) to SCOs (domain-name,
       ipv4-addr, ipv6-addr, email-addr, url), which a strict OASIS validator
       rejected; SDOs still carry them, and the `x_` provenance properties (spec
       allowed on SCOs) are preserved. Regression:
       `tests/integration/test_cli.py::TestExportCommand::test_export_stix2_default_filename_is_canonical`
       and `tests/unit/test_phase_4b_stix_export.py::TestObjectMetadata`. Done
       2026-06-09.

8. [x] **Decide the Continuous Confidence Engine.** Resolved: strip and demote
       (option b). It was sold as a core bet but `nexusrecon/verification/` has
       zero production callers (nothing constructs `VerificationOrchestrator` or
       registers the mutation listener outside its own tests), so no
       corroboration, contradiction, or cascade ever runs. An investigation
       confirmed the code is real and unit-tested but that wiring it in is more
       than the two fixes noted here: `from_state` also truncates each
       subdomain's sources to the first one, so corroboration (which needs two
       independent classes on one node) would silently no-op even after the
       source-string and confidence-default fixes. Rather than expand the
       footprint for a payoff concentrated in subdomain corroboration, the docs
       now mark the engine experimental / opt-in / not-wired (README,
       ARCHITECTURE section 14, CHANGELOG) with the tested code kept in-tree.
       Promotion later (the old option a) is purely additive and fully
       reversible; the wiring path and traps are recorded in ARCHITECTURE
       section 14. Done 2026-07-13.

### Honesty cleanup (done 2026-07-13, one noted residual)

- Done: removed the `gowitness` no-op screenshot call from phase6 (it fired up
  to 50 pointless registry round-trips into a stub and populated nothing);
  dropped the now-false "screenshots" claim from the phase6 docstring, the
  agent prompt, and MANUAL.md. The tool stays a registered stub.
- Done: the Cobalt Strike emitter docstring now says the three User-Agent
  headers are a fixed set, not derived from Technology entities (which the code
  never did).
- Done: deleted the dead duplicate `reports/maltego_export.py` and six
  docstring-only report stub modules (`asset_inventory`, `attack_surface`,
  `cloud_posture`, `executive_summary`, `full_report`, `phishing_package`); the
  real logic lives in `reports/engine.py`, and `reports/__init__.py` now imports
  only `engine`.
- Done: `dorks_tool` is marked `stubbed` (its SERP HTML scraping is defeated by
  2026 consent walls) so it returns a clean failure instead of a fake clean
  negative; `conference_speaker_tool` gains an `assess_result` that flags
  degraded on zero talks, since 7 of its 8 conference parsers are placeholders
  so an empty result is missing coverage, not a verified absence.
- Done: `credential_exposure_paths.md`, `spear_phishing_intelligence.md`, and
  `run_health.md` now carry scope-hash plus version footers, and the PDF footer
  reports the real version instead of a hardcoded `v1.0.0`. Residual: a broad
  sweep to strip em-dashes and box-drawing glyphs from ALL generated operator
  prose is not done (only the touched footers are clean); left as a follow-up.

### Release readiness (ship what exists, not new features)

- [ ] **Fresh-VM install verification.** `scripts/verify_install.sh` plus the
      coverage matrix in `docs/install-verification.md` exist. The verifier was
      hardened to a clean one-paste output (it now quiets structlog before
      building the registry, so tool-registration debug no longer buries the
      `RESULT:` line), and the macOS (arm64) row was re-verified 2026-07-14:
      `PASS, 79/97 active` (79, down from 80, after `dorks` was stubbed).
      Maintainer-only remainder: run the verifier on Linux x86_64 and Linux
      arm64 hardware (no VM access from the dev loop) and confirm
      `pipx install nexusrecon` once the package is published to PyPI.
- [x] **The demo gif.** Rendered 2026-07-14 via `vhs docs/demo/nexusrecon.tape`
      and committed at `docs/demo/nexusrecon.gif` (the path the README embeds),
      so README:188 now resolves. Verified frame-by-frame: it faithfully shows
      the current TUI (dashboard with live tool health, the tool catalogue
      filtered to a tool with per-key status, the masked key-edit modal, the
      OPSEC config screen, and the command palette), with no keybinding drift
      and no secrets exposed (tokens masked; config shows only non-secret
      proxy/DNS settings). `make demo` re-renders it (needs `vhs` + `ttyd` +
      `ffmpeg`, installable via `brew install vhs ttyd ffmpeg`).

---

## Demoted out of the 1.0 story

Decision 2026-06-09: keep in-tree, stop polishing, stop advertising as 1.0
capabilities. These are real, often well-tested code, but a default
`nexusrecon run` reaches none of them. They are standalone CLI islands built for
workflows or an audience that does not exist yet. Demoted behind a clearly
labeled experimental posture, not deleted, so the engineering is not lost and
can be promoted later if a real need appears.

- **Continuous Confidence Engine (`verification/`).** Unreached by any run.
  Resolved via item 8: stripped of "core bet" framing and marked experimental /
  opt-in / not-wired across the docs, tested code kept in-tree for a future
  additive promotion.
- **Recon Packs marketplace and Contribution SDK (`packs/`, `sdk/`).** Premature
  infrastructure for a community that does not exist: `DEFAULT_MARKETPLACE_URL`
  is empty, there is no index, and the only first-party pack is not in the load
  path. The SDK scaffolders wire two guardrail modules (`citation_guard`,
  `prompt_versioning`) into every generated agent that have zero production
  callers, so a contributor's agent silently loses its advertised validation.
  Either wire those guardrails into the real executor or remove them from
  scaffold output; do not ship a fake-success seam as a feature.
- **Watch Mode (`watch/`).** As shipped it diffs a frozen `state.json` against
  itself, so "continuous monitoring" structurally cannot observe live drift.
  Relabel honestly as "snapshot diff" or leave parked here. Do not let it imply
  live attack-surface monitoring it cannot do.
- **Strategy framing (`strategy/`).** Keep the dispatch loop (`reflection_node`
  plus the dynamic dispatcher is real and earns its keep). Demote the rest: the
  pre-flight simulation always estimates $0.00 and never enforces its abort,
  `kill_criteria`/`success_criteria`/`tool_budgets` are never read, and the
  bounded-agency approval queue has no resolver. That is a roadmap, not a
  feature.
- **Vision pipeline (`vision/`).** Real multimodal code, but defanged by a
  default `vision_calls` budget of 0 and fed only by hand-supplied artifacts a
  campaign never produces. Keep as a standalone utility; drop it from the
  autonomous-loop pitch.
- **Downstream emitters and importers (`export/downstream/`, `ingest/`).**
  Genuine engineering quality, but all post-run manual subcommands. The signed
  STIX path is worth fixing (item 7) because it is real chain-of-custody value;
  the Cobalt Strike emitter is cleanup-or-cut (see honesty cleanup). The rest
  stay available but out of the marquee story.

---

## Out of scope

Things people sometimes ask for that we will not build. Unchanged.

- **Automated exploitation.** This is recon tooling. Pivot to
  Metasploit / Sliver / Mythic for exploit phases.
- **Stealth-claim-of-attribution evasion.** We do not help operators hide that
  they are running NexusRecon. The tool's purpose is authorised testing, and
  authorised tests do not need to obfuscate the tooling.
- **Anything that bypasses the scope guard.** Hard rule. See `DISCLAIMER.md`.
- **Telemetry / phone-home.** Air-gapped operation is a hard requirement.

---

## Shipped (0.5.x through 0.7.0)

For provenance. The detailed phase-by-phase checklists were removed in the
2026-06-09 roadmap reset; the capabilities below are in the build and described
in `ARCHITECTURE.md`.

- Apache-2.0 license, NOTICE, CONTRIBUTING, SECURITY, CHANGELOG, issue
  templates, CI.
- 12-phase recon pipeline plus credential harvest and pretext intelligence.
- Living Intelligence Graph model layer plus hash-chained audit log.
- Wave F run-honesty and signal-quality work (degraded-vs-empty detection,
  run-health summary, findings-vs-coverage split, cross-phase dedup, CVE
  provenance guard).
- Phase D/E identity attribution, credential correlation, relationship graph,
  and pretext scoring (now wired into the default run).
- OPSEC stack (stealth jitter, rate limiting, proxy injection, opt-in JA3) with
  the known gaps tracked in items 3.
- Report engine with about 25 deliverables, Obsidian export, and the signed
  STIX path (happy path fixed in item 7).
- TUI front door, killer-demo sample run, live-drift CI schedule.
