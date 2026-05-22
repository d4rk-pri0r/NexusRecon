# Phase E Execution Plan — Relationship Graph + Pretext Scoring

Implementation plan for `ROADMAP.md` Phase E (items E1-E11). Drafted
after verifying Phase D is functionally complete (commit 63d4f81 + the
D3/D5 registration fixes that followed).

---

## Foundation Phase E builds on

What's already in place and does NOT need to be rebuilt:

- `RelationshipEdge` dataclass already exists in
  `nexusrecon/core/identity_graph.py:224` with the locked-in shape:
  `(target_identity_id, interaction_type, strength, last_observed, sources)`.
- `Identity.related_to: list[RelationshipEdge]` already a field on the
  Identity model — Phase D populates an empty list; Phase E fills it.
- `--generate-phishing` CLI flag wired through to state at
  `cli/main.py:163` and exposed as `state["generate_phishing_drafts"]`.
- `agents/phishing_drafter.py` exists (35 lines, role/goal/backstory
  only). E10 expands this substantially.
- 8 pretext tools already exist in `tools/pretext/`:
  `crunchbase_tool`, `github_org_members_tool`, `jobs_tool`,
  `linkedin_dorks_tool`, `news_tool`, `public_collab_tool`,
  `sec_edgar_tool`, `wikipedia_tool`. Several overlap with Phase E
  scope — E2/E6/E8 may absorb or extend rather than duplicate.
- Phase 2.5 wiring at `graph/workflow.py:32,38,53` and
  `graph/nodes.py:1055` is the template E11 mirrors.

## Locked architectural decisions (from roadmap)

Do not relitigate without explicit go-ahead:

- **Surface, never execute.** No email sending. Drafts only when
  `--generate-phishing` is set.
- **LinkedIn approach: aggressive.** Unofficial scraper / API wrapper.
  Isolated to a single swappable module (E5).
- **Paid breach DBs fail-fast on missing keys** (post-D5 pattern).
- **Phase D fully before Phase E.** Already satisfied.

## Implementation tiers (dependency-ordered)

### Tier 0 — Data foundation (ships first, blocking everything else)

**E1** `nexusrecon/core/relationship_graph.py`

- Graph-level operations on `RelationshipEdge` objects
  (add / merge / dedup by `(source_identity, target_identity, interaction_type)`)
- Recency-decay function (configurable half-life, default ~180 days)
- Cross-source strength aggregation (multiple sources → higher
  strength, capped at 1.0)
- `build_from_identity_graph()` helper for hydrating from existing state
- Pure-Python module, no network
- Tests: edge dedup, decay math, merge ordering, cycle handling

### Tier 1 — Signal-producing tools (parallel-shippable)

Each tool needs:

1. Class with `@register_tool` decorator
2. Edge-extraction adapter producing `RelationshipEdge` objects
3. Import added to its package `__init__.py` (do NOT repeat the
   D3/D5 registration gap)
4. Unit tests with mocked httpx
5. Integration test with realistic API fixtures

**E2** `tools/identity/github_social_tool.py`
- Sources: commit co-authors (git trailer parsing), repo
  collaborators (`/repos/{org}/{repo}/collaborators`), issue/PR
  discussion participants, follow graph (`/users/{user}/followers`,
  `/users/{user}/following`)
- Free via GitHub API; honors `GITHUB_API_TOKEN` rate-limit raise
- Edge interaction types: `co-author`, `collaborator`, `commenter`,
  `follower`
- May extend / share fixtures with existing `github_org_members_tool`

**E3** `tools/identity/mastodon_social_tool.py`
- Sources: follows / followers / boosts / mentions / replies
- Federated ActivityPub crawl — see open question on instance scope
- Free, anonymous reads OK for public accounts
- Edge interaction types: `follower`, `mention`, `reply`, `boost`

**E4** `tools/identity/bluesky_social_tool.py`
- AT Protocol follow + interaction graph
- Needs `atproto` SDK as a new dependency
- Free; decision needed on app-password auth vs anonymous reads
- Edge interaction types: `follower`, `reply`, `repost`, `mention`

**E5** `tools/identity/linkedin_social_tool.py`
- Aggressive unofficial scraper / API wrapper
- Returns: title history, current title, connection sample, recent
  activity, mentioned colleagues, endorsements
- Isolated module so it's swappable if posture changes
- Coexists with existing `linkedin_dorks_tool` (conservative fallback)
- Library choice: see open question
- Edge interaction types: `colleague`, `endorser`, `recommender`,
  `commenter`

**E6** `tools/intel/business_partner_tool.py`
- Sources: Crunchbase (paid API), BuiltWith (tech-stack vendors),
  press releases, DNS TXT vendor inference, customer-logos /
  case-study scraping
- May absorb existing `tools/pretext/crunchbase_tool.py`
- Org-level relationships, not human-to-human — emits edges
  between corporate identities (or annotates Identity.metadata
  with org context)

**E7** `tools/pretext/conference_speaker_tool.py`
- Scrape conference sites: DEFCON, BSides, RSA, KubeCon, FOSDEM,
  BlackHat, company-specific events
- Co-speaker relationships → strong pretext signal
- Hardcoded site list initially; LLM expansion optional
- Edge interaction type: `co-speaker`

**E8** `tools/pretext/recent_activity_tool.py`
- Time-windowed posts / news mentions / announcements /
  changelog / blog updates per target
- Powers "what's plausibly topical right now"
- Likely consumes / extends existing `news_tool`
- Output is NOT edges — it's `RecentActivity` records consumed by E9
  scoring

### Tier 2 — Scoring (depends on Tier 0 + at least some Tier 1)

**E9** `nexusrecon/core/pretext_scoring.py`

- Score `(sender_identity × topic × timing)` tuples for plausibility
- Multi-signal weighted:
  - Sender plausibility from `RelationshipEdge` strength + recency
  - Topic plausibility from shared interests / recent activity
    overlap between sender and target
  - Timing from how recent the underlying activity is
- Recency-decayed
- Never claims relationships absent public evidence — every score has
  a `sources: list[str]` audit trail
- Pure function, no network
- Output: ranked `PretextCandidate` list per target identity

### Tier 3 — Synthesis (depends on E1-E9)

**E10** Enhanced `agents/phishing_drafter.py`

- Substantially expanded backstory + prompt schema
- Inputs: target identity + relationship graph + topical interests +
  recent activity + top pretext candidates from E9
- Outputs: drafts that reference real interactions rather than
  generic boilerplate
- Still gated on `--generate-phishing` flag
- Tests: prompt regression fixtures with mocked LLM responses

**E11** Phase wiring + new deliverable

- New phase function in `graph/nodes.py` —
  `phase_7_7_pretext_intelligence` (proposed slot: see open question)
- Register in `graph/workflow.py:32,38,53` mirroring Phase 2.5 pattern
- State commits: `relationship_graph`, `pretext_scores`,
  `spear_phishing_intelligence`
- New deliverable in `reports/engine.py`:
  `spear_phishing_intelligence.md` per-target dossier with:
  - Top 3 plausible senders
  - Top 3 plausible pretexts
  - Recent activity timeline
  - Recommended draft framing
- Machine-readable companion: `pretext_candidates.json`

## Cross-cutting concerns

1. **Tool registration discipline**: every `@register_tool` class MUST
   be imported in its package `__init__.py`. The D3/D5 bug demonstrated
   that silent registration gaps slip past tests. Consider a CI lint
   that asserts every `@register_tool` decorator target is importable
   from `nexusrecon.tools`.

2. **OPSEC stack inheritance**: all new HTTP tools inherit from
   `BaseHTTPTool` for rate-limit, proxy, UA rotation, and the
   401/403/429/non-200 classifier.

3. **Fail-fast on missing keys** for paid APIs (Crunchbase,
   LinkedIn auth, etc.) — `requires_keys` populated, `is_available()`
   gates execution.

4. **Test pattern**: mirror Phase D — unit tests with mocked httpx,
   integration tests with realistic API fixtures, full opt-in live
   tests under `tests/live/` for the API-keyed providers.

5. **Publishing posture** (roadmap lines 282-294):
   - Per-employee findings stay in unpublished campaign dir by default
   - Aggregate-only statistics in any published artifact
   - Real credentials never published (already enforced by D7 redaction)
   - Plausible-pretext drafts never published with real target names

## Open architectural decisions

Confirm before starting E1:

1. **Phase slot for E11**: Phase 7.7 (between 7.5 harvest and 8
   attack-surface, so pretext quality feeds attack-surface scoring) vs
   Phase 8.5 (after attack-surface, narrower scope, smaller blast
   radius if it errors).

2. **LinkedIn library choice**: `linkedin-api` (PyPI, unofficial),
   custom scraping, or a third-party service (Phantombuster /
   ScrapeOps / Bright Data)?

3. **Mastodon instance scope**: hardcoded top-N (e.g.
   mastodon.social, hachyderm.io, infosec.exchange, fosstodon.org),
   or LLM-discovered from corp signals?

4. **Conference site list**: hardcoded short list with optional LLM
   expansion, or LLM-only?

5. **Edge persistence**: stored only in `Identity.related_to`, or also
   in a separate top-level state key for fast graph queries
   (`state["relationship_graph"]`)?

6. **Pretext scoring scope**: run for ALL discovered identities, or
   only those flagged as high-value by Phase 8 attack-surface scoring?
   Big cost difference at scale.

## Suggested PR sequencing

1. **PR 1: E1 alone** (~2-3 days). Data foundation, pure Python, no
   external deps. Locks the edge model + scoring math before any tool
   adapter depends on it.

2. **PR 2: E2 + E3 + E4** (free-tier social tools, parallel work).
   Validates the edge-extraction adapter pattern across three
   different APIs.

3. **PR 3: E5** (LinkedIn, isolated). Highest risk-of-change module,
   ships alone so the posture can be revisited without rolling back
   adjacent work.

4. **PR 4: E6 + E7 + E8** (pretext signal tools, parallel work).

5. **PR 5: E9** (scoring). Pure function; depends only on E1's edge
   model + E8's recent-activity records.

6. **PR 6: E10 + E11** (drafter enhancement + phase wiring + report
   deliverable). Final integration.

Total: ~6 PRs, ~3-5 weeks of focused work depending on E5's library
landscape.
