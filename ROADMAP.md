# NexusRecon Roadmap

Current state, what's left before 1.0, what comes after. Pull requests
welcome; prioritisation is set by the maintainer.

---

## Current state: `0.5.0` (pre-beta)

What works today:

- 9-phase reconnaissance pipeline + credential harvest (phase 7.5).
- Tool registry with scope-gated execution (run `nexusrecon tools` for
  the live count).
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

## Path to `0.6.0`: beta launch

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

## Path to `1.0.0`: production-ready

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

- [ ] **E1** `nexusrecon/core/relationship_graph.py` — human-to-human
      edges as first-class data. Edge fields: ``(source_identity,
      target_identity, interaction_type, strength, last_observed,
      sources)``. Weighted by interaction depth (co-author > follower)
      and recency-decayed.
- [ ] **E2** `nexusrecon/tools/identity/github_social_tool.py` —
      commit co-authors, repo collaborators, issue/PR discussion
      participants, follow graph. Free via GitHub API.
- [ ] **E3** `nexusrecon/tools/identity/mastodon_social_tool.py` —
      follows / boosts / mentions / replies. Federated ActivityPub
      crawling across the major instances. Free.
- [ ] **E4** `nexusrecon/tools/identity/bluesky_social_tool.py` —
      follow + interaction graph via AT Protocol. Free.
- [ ] **E5** `nexusrecon/tools/identity/linkedin_social_tool.py` —
      aggressive scraper / API wrapper. Per the locked-in decision
      above. Returns: title history, current title, connections (or
      a sample), recent activity, mentioned colleagues, endorsements.
      Isolated in this single module so it's swappable if posture
      changes.
- [ ] **E6** `nexusrecon/tools/intel/business_partner_tool.py` —
      partner / customer / vendor relationships from
      Crunchbase (paid API), BuiltWith (tech stack vendors),
      press releases, DNS TXT vendor inference, customer-logos /
      case-study scraping.
- [ ] **E7** `nexusrecon/tools/pretext/conference_speaker_tool.py` —
      scrape conference sites for talks + co-speakers + topic tags.
      DEFCON / BSides / RSA / KubeCon / FOSDEM / company-specific
      events. Co-speaker relationships are a strong pretext signal.
- [ ] **E8** `nexusrecon/tools/pretext/recent_activity_tool.py` —
      time-windowed recent posts, news mentions, announcements,
      changelog / blog updates per target. Powers "what's plausibly
      topical right now."
- [ ] **E9** `nexusrecon/core/pretext_scoring.py` — score
      ``(sender × topic × timing)`` tuples for spear-phishing
      plausibility. Multi-signal weighted with recency decay; never
      claims privacy-invading relationships absent public evidence.
- [ ] **E10** Enhanced `nexusrecon/agents/phishing_drafter.py` —
      accepts the full pretext intelligence: target identity +
      relationship graph + topical interests + recent activity.
      Produces drafts that actually reference real interactions
      rather than generic boilerplate. Still gated on
      ``--generate-phishing``.
- [ ] **E11** Phase wiring + new deliverable
      `spear_phishing_intelligence.md`. Per-target dossier: top 3
      plausible senders, top 3 plausible pretexts, recent activity
      timeline, recommended draft framing.

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
