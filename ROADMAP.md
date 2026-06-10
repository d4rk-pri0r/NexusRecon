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

5. [ ] **Broaden degraded-tool detection.** Today only 4 of 97 tools override
       `assess_result` (whois/nuclei/sslyze/wafw00f), so a silent failure in
       subfinder, amass, httpx, shodan, or github_recon is reported as a clean
       negative, the exact failure this feature was built to kill. Add
       `assess_result` coverage for the high-traffic tools.

6. [ ] **Stop MockLLM masquerading as analysis.** Keyless (the default, and the
       only path the test suite exercises) the persona layer no-ops into
       near-identical word-count boilerplate through the same code path as real
       agents, and those findings flow into shipped reports. Either refuse to
       emit agent findings without a key, or mark every MockLLM finding
       unmistakably in the report. Add the one missing test that asserts persona
       text reaches the prompt and changes output. Separately, the
       `evidence_auditor` "legal-defensibility gate" is defeated by construction
       (findings auto-backfilled with a hash over the LLM's own prose); fix or
       drop the claim.

7. [ ] **Fix the export-to-sign happy path and STIX SCO schema.** `export`
       writes `findings_export.stix2` while `sign` auto-discovers
       `stix2-bundle.json`, so the one advertised crypto-provenance workflow is
       broken on defaults and the error message names the wrong filename. Make
       `sign` discover what `export` writes. Stop attaching SDO-only fields
       (created/modified/created_by_ref/confidence) to SCOs so a strict OASIS
       validator and a real TIP will ingest the bundle. The signed STIX is real
       client value; do not let a filename typo break its only happy path.

8. [ ] **Decide the Continuous Confidence Engine.** It is sold as a core bet but
       `nexusrecon/verification/` has zero production callers: nothing constructs
       `VerificationOrchestrator` or registers the mutation listener outside its
       own tests, so no corroboration, contradiction, or cascade ever runs. Two
       options, no middle state: (a) wire it in, which also requires fixing
       `from_state` source strings to match `SOURCE_INDEPENDENCE_CLASSES` and not
       defaulting confidence to 1.0 (above the 0.99 corroboration cap) or it
       wires in and silently does nothing; or (b) strip the "core bet" framing
       and demote it (see below). Decide before tagging 1.0.

### Honesty cleanup (small, mechanical, do alongside the above)

- Remove the `gowitness` stub call in phase6 (a guaranteed no-op screenshot
  step) or remove the stub from the advertised triage step.
- Fix or cut the Cobalt Strike emitter's docstring, which claims user-agents are
  "derived from observed Technology entities" while the code emits three
  hardcoded UAs. Near-zero value over a public Malleable C2 template.
- Delete the dead duplicate `reports/maltego_export.py` and the docstring-only
  report stub modules that mislead readers about where logic lives.
- `conference_speaker_tool` returns `success=True, talks_found=0` (7 of 8 site
  parsers unconditionally return `[]`) and `dorks_tool` returns
  `success=True, result_count=0` against 2026 consent walls. Make these report
  honest failure instead of a fake clean negative, or mark them stubbed.
- Report footer hygiene: add scope-hash plus version footers to
  `credential_exposure_paths.md`, `spear_phishing_intelligence.md`, and
  `run_health.md`, and fix the PDF footer that hardcodes `v1.0.0`. Strip
  em-dashes and box-drawing glyphs from generated operator prose (they read as
  an AI tell in delivered documents).

### Release readiness (ship what exists, not new features)

- [ ] **Fresh-VM install verification.** `scripts/verify_install.sh` plus the
      coverage matrix in `docs/install-verification.md` exist; the macOS row is
      verified. The two Linux rows (x86_64, arm64) still need a run on that
      hardware, plus `pipx install nexusrecon` confirmed once published.
- [ ] **The 90-second wizard-to-results gif.** Recording setup is committed
      (`make demo`); it is a one-command maintainer step that cannot run in CI.

---

## Demoted out of the 1.0 story

Decision 2026-06-09: keep in-tree, stop polishing, stop advertising as 1.0
capabilities. These are real, often well-tested code, but a default
`nexusrecon run` reaches none of them. They are standalone CLI islands built for
workflows or an audience that does not exist yet. Demoted behind a clearly
labeled experimental posture, not deleted, so the engineering is not lost and
can be promoted later if a real need appears.

- **Continuous Confidence Engine (`verification/`).** Unreached by any run (see
  item 8). Either promote it via item 8 or it stays here, stripped of "core bet"
  framing.
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
