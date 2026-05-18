# NexusRecon Roadmap

Where the project is, what's between us and 1.0, what comes after.
This is a living document, pull requests welcome, but the
prioritisation is set by the maintainer.

---

## Current state: `0.5.0` (pre-beta)

What works today:

- 9-phase reconnaissance pipeline + credential harvest (phase 7.5).
- 89-tool registry with scope-gated execution.
- LLM-driven dynamic dispatcher (lite / full / off).
- Audit chain (hash-chained JSONL), cost tracker, rate limiter.
- 17 deliverable report types (master narrative, top threads,
  asset inventory, phishing package, attack-surface matrix, vuln
  correlation, harvested credentials, etc.).
- TUI front door (welcome screen, new-campaign wizard, runner with
  live structlog stream, results browser, masked .env editor).
- 351 integration tests + 32 live opt-in tests, run in ~5 seconds.

What's still pre-beta about it:

- No real-target end-to-end demo committed to the repo yet.
- OPSEC features (rate limiter / proxy / UA rotation) declared in
  config but not verified at the wire level.
- Several integration paths (BloodHound, Burp Suite) not yet built.
- Some tools still flagged `(stubbed)` in their descriptions
  (gowitness, parts of `gcp_recon`).

---

## Path to `0.6.0`, beta launch

These are the items that have to land before the project goes out to
"thousands of well-trained eyes." Prioritised in execution order;
each is independently testable.

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
- [ ] **`BaseHTTPTool` helper.** Extract the
      "401/403 = auth fail, 429 = rate limit, other non-200 = error"
      pattern from the 9 individual fix commits into a single base
      class so future tools inherit the right behaviour by default.
      Eliminates the silent-swallow bug class structurally.
- [ ] **Live-drift CI schedule.** Run `tests/live/` weekly via
      GitHub Actions (scheduled workflow) with whatever API secrets
      are available, surfacing schema drift on the providers we can
      authenticate against. This is the tripwire for wayback /
      fullhunt class bugs.
- [ ] **Stubbed-tool policy.** Either implement, refuse to register,
      or rename the description to be explicit. Operators shouldn't
      discover a tool is a stub by reading the source mid-campaign.
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

## Path to `1.0.0`, production-ready

Once the beta has run for a meaningful number of cycles and the
beta-blocker work above has shaken out:

### Toolchain integration

- [ ] **Burp Suite project file export.** Discovered URLs + findings
      → an importable `.burp` file.
- [ ] **BloodHound CE JSON.** Azure / M365 federation findings →
      BloodHound graph ingest.
- [ ] **Obsidian-friendly master report.** Verify links / callouts /
      frontmatter render cleanly when dropped into a vault.

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

- [ ] **Out-of-tree tool plugins.** `plugins/example` already exists;
      formalise the discovery protocol so contributors can ship a
      tool as a separate `pip install nexusrecon-plugin-X` package
      and have it register without modifying the core.
- [ ] **Plugin signing.** Optional, but: signed manifests so
      operators can choose to load only verified plugins for
      sensitive engagements.

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

## Post-`1.0`, ecosystem

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
