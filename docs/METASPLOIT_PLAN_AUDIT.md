# Audit: IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md vs. Current Codebase

**Date:** 2026-05-27
**Reviewer:** Claude Opus 4.7 (assistant)
**Source plan:** `docs/IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md`
**Question asked:** Compare the plan's asks against the current
codebase, document feasibility, recommend the first step.

This audit is intended to be re-read at the start of each Phase 0
work session so the implementer can ground decisions in what
actually exists today.

## 1. Plan claims vs. observed reality

The plan's Phase 0 "Current State" section is **directionally
correct but materially understated**. Three corrections:

### 1.1 There are THREE graphs in the codebase, not one

The plan mentions only `core/entity_graph.py`. The codebase also
has:

| File | Lines | Purpose |
|---|---|---|
| `core/entity_graph.py` | 385 | NetworkX-backed graph of technical entities (domains, IPs, emails, etc.) with `(type, value)` deduplication. Builds at campaign runtime. |
| `core/identity_graph.py` | 704 | Phase D's first-class `Identity` model — corp + personal identifiers, credential exposures, related-to edges. Pydantic dataclasses; has its own serialization + dedup. |
| `core/relationship_graph.py` | 705 | Phase E's human-to-human edges. Dual storage (per-identity mirror + top-level by_source/by_target). Pure Python. |

**Implication.** The plan's `LivingGraph` is closer to "unify the
three existing graphs" than "build a new substrate from
scratch." The data shapes the plan wants (confidence, sources,
first_seen/last_seen, related-to edges) already exist
separately on each of these — they just don't share a common
representation.

### 1.2 `state["entity_graph"]` is NOT the NetworkX graph

The plan's claim that "It is serialized into `state["entity_graph"]`"
is not what the code does today. Looking at
`graph/nodes.py:638`:

```python
state["entity_graph"] = {
    "subdomains": list(subdomain_intel.keys())[:500],
    "emails": list(emails.keys())[:500],
}
```

This is a **flat name list** — not the NetworkX EntityGraph. The
real EntityGraph is built inside `campaign_runner.py` but its
rich state never reaches the LangGraph state dict. Agents,
reports, and the TUI all consume the flat-dict form.

**Implication.** A surprisingly small change ("actually
serialize the EntityGraph into state, not the truncated name
list") would close most of the agent-doesn't-reason-over-the-
graph gap immediately.

### 1.3 Correlation + Risk agents don't import the EntityGraph at all

```sh
grep "entity_graph\|EntityGraph" agents/correlation.py agents/risk_analyst.py
# (no matches)
```

These two agents are the ones the plan singles out for Phase 0
migration. They currently consume only the flat state buckets
(`subdomain_intel`, `cloud_intel`, `findings`). The plan's
"refactor at least Phase 4 (correlation) and Phase 8 (scoring) to
write primary data into the graph" is therefore really
**introduce graph access where none exists today**, not "expand
existing usage."

## 2. What the plan gets right

The plan's diagnosis is sound where it matters:

- **Flat-bucket intelligence substrate** is correct and biggest
  drag on agent reasoning.
- **Hypotheses / open_questions / leads as `list[str]`** is the
  observed reality (`graph/state.py:80` confirms
  `hypotheses: list[str]`). Promoting these to first-class
  graph citizens is the right call.
- **Provenance as `sources: list[str]`** is true everywhere —
  upgrading to `list[{source, timestamp, evidence_hash, tool}]`
  is a modest schema change that pays for itself.
- **Living-graph-as-source-of-truth** is the correct architectural
  direction — the cost of three separate graphs is real (duplicate
  serialisation logic, no cross-graph queries).

## 3. Data model: closer to done than the plan suggests

Phase 0's "rich node schema" task is largely already implemented
across the three existing graphs:

| Plan asks for | Already in codebase | Gap |
|---|---|---|
| `id` | ✓ `BaseEntity.entity_id` (UUID), `Identity.identity_id` (content-derived hash) | Unify the two id strategies |
| `entity_type` | ✓ `EntityType` enum (17 types) | Add HYPOTHESIS, LEAD, OPEN_QUESTION |
| `value` | ✓ `BaseEntity.value` | — |
| `confidence` | ✓ `BaseEntity.confidence` (0.0-1.0) | — |
| `provenance: list[{...}]` | ✗ Only `sources: list[str]` | **Schema upgrade** |
| `first_seen` / `last_seen` | ✓ both fields exist | — |
| `evidence_hash` per source | ✗ One global hash via audit log; not per-source on the entity | **Wire to entity** |
| Virtual/inferred nodes | Partial — `BaseEntity` supports `confidence < 1.0`, no explicit virtual flag | Add `is_virtual: bool` |

The two real gaps are **provenance schema** and **virtual-node
marker**. Both are additive Pydantic-field changes.

## 4. Query API: partially exists

The plan's example query API:

```python
graph.query_nodes(entity_type="person", min_confidence=0.7)
graph.find_paths(from_entity, to_entity, max_length=4, ...)
graph.get_neighbors(entity_id, edge_type="has_credential", ...)
```

What `EntityGraph` already has:

- `get_entity(entity_id)` ✓
- `get_entities_by_type(entity_type)` ✓ (no min_confidence yet)
- `get_neighbors(entity_id)` ✓ (no edge_type filter)
- `find_path(source_value, target_value, source_type, target_type)` ✓ (no max_length, no relationship_types filter)

What's missing is **filter/predicate richness** on each method —
not the methods themselves. The plan's API can be added as
thin wrappers + parameters on the existing functions.

## 5. Persistence: the gap is real

The plan calls for "Efficient persistence (NetworkX + custom
JSON, or migrate to a proper graph backend later — start with
NetworkX + SQLite sidecar for queries)." Today:

- `EntityGraph.to_dict()` produces nested-list-of-dicts JSON.
- `EntityGraph.from_dict()` reconstructs the NetworkX graph.
- No SQLite, no versioning, no diffing, no time-travel.

For Phase 0 scope this is acceptable. The SQLite-sidecar idea
is good but should NOT be the first thing built — it's
optimisation for a graph size we don't yet have. Stick with
NetworkX + JSON and revisit when a campaign produces >5k nodes.

## 6. Feasibility verdict per Phase 0 task

| Plan task | Feasibility | Notes |
|---|---|---|
| 0.1 Data model & core graph engine | **Medium** | Less greenfield than the plan suggests — extend existing `BaseEntity` + unify with `Identity` rather than write a parallel `LivingNode`. |
| 0.1 Hypothesis / Lead as first-class node types | **Easy** | Add to `EntityType` enum + Pydantic subclass. ~50 LOC. |
| 0.2 State integration | **Easy** | Fix `state["entity_graph"]` to carry the actual NetworkX graph (currently it carries a truncated name list). Most of the value here. |
| 0.2 Migration utilities for old `state.json` | **Easy** | Standard schema-evolution pattern. The existing `from_dict` already tolerates extra keys; load + transform suffices. |
| 0.3 Agent / dispatcher graph_context API | **Medium** | Need to be careful about prompt size — a 5k-node graph won't fit in a prompt. The API is straightforward; the summarisation logic is the harder part. |
| 0.4 Testing | **Easy** | Existing test patterns (`tests/unit/test_entity_graph.py` if it exists, or net new) apply directly. |

**Two items where the plan is overscoped for Phase 0:**

1. **"Time-travel for a campaign"** — useful but premature. Stage
   it as a Phase 5 moonshot, not a Phase 0 must-have.
2. **"Efficient diffing"** — only matters if we add reflective
   "what changed since last reflection" prompts. Defer until
   Phase 1.

## 7. Recommended first step

Given the audit findings, the lowest-risk highest-leverage **first
PR** is what the plan implies but doesn't explicitly call out
as step zero:

### Step 0.0 — "Make the graph that exists actually reach the agents"

A focused PR that does only this:

1. **Stop truncating `state["entity_graph"]`.**
   Replace the flat-name-list assignment at `nodes.py:638`
   with `state["entity_graph"] = entity_graph.to_dict()`. The
   `EntityGraph` instance is already being built; we're just
   surfacing it. Old consumers of the truncated form
   (campaign metadata reports, mostly) get migrated to query
   the real graph.

2. **Promote the EntityGraph to a workflow-level construct.**
   Currently `campaign_runner.py` instantiates one
   `EntityGraph` per campaign and doesn't share it with
   `nodes.py` phase functions. Add it to the
   `CampaignGraphState` (as a Python object, not just the
   serialised dict — the LangGraph state can hold any
   Python value). Every phase that produces entities gets
   to add them; serialisation happens at save time.

3. **Add `HYPOTHESIS`, `LEAD`, `OPEN_QUESTION` to `EntityType`.**
   Plus Pydantic subclasses. The current `state["hypotheses"]`
   list-of-strings becomes a list of `HypothesisEntity` IDs
   pointing into the graph.

4. **Wire a thin `GraphContext` accessor for agents.**
   The correlation + risk-analyst agents get a read-only
   handle to the graph in their `task_data`. Initial API:
   `nodes_of_type(t)`, `count_by_type()`, top-5 most-cited
   entities. No path-finding yet — that's Phase 0.1.

5. **Migration script for old `state.json`.**
   Loads the truncated `entity_graph` field and rebuilds an
   empty `EntityGraph` from the flat buckets. Doesn't
   recover provenance (lost forever for old campaigns) but
   doesn't break the resume path.

**Why this first**

- **Smallest blast radius for biggest signal.** Most of the
  agent-doesn't-reason-over-the-graph gap closes the moment
  agents actually have a graph handle. The data is there;
  just thread it through.
- **Validates the assumption.** If Step 0.0 doesn't visibly
  improve agent outputs (in side-by-side runs), the plan's
  core thesis is suspect and we should revisit before
  committing to the heavier 0.1+ work.
- **Strangler-fig compatible.** None of the existing flat-
  bucket consumers need to change. The graph becomes a NEW
  source of context; the flat dicts remain the primary
  write surface initially. Migrations can follow phase-by-
  phase.
- **Unlocks the testing story.** Once the graph is in state,
  property-based tests on graph operations (which Phase 0.4
  calls for) have something real to assert against.

### What Step 0.0 explicitly does NOT touch

- Provenance schema upgrade (`sources` → list of dicts) — that's
  Step 0.1.
- Identity/Relationship graph unification — that's Step 0.1
  (or its own Step 0.0b if scope creep becomes a problem).
- Living-graph naming — keep using `EntityGraph` until the
  unification PR; rename at the end of the migration so we
  don't generate a churn of "rename touched everything"
  diffs through Phase 0.
- LangGraph state schema breaking changes — `entity_graph`
  key keeps its name; only its value shape changes.

### Estimated effort

- **Code:** ~400 LOC across `nodes.py`, `state.py`,
  `entity_graph.py`, `models/entities.py`, two agent files.
- **Tests:** ~200 LOC of new + ~100 of updates to existing.
- **Documentation:** Update `ARCHITECTURE.md` graph section.
- **Wall clock:** One focused session.

## 8. Updates to the plan document

The plan's Phase 0 should grow a new task **before** 0.1:

> **0.0 Graph Substrate Wire-up.** Surface the existing
> `EntityGraph` into `CampaignGraphState`; add HYPOTHESIS /
> LEAD / OPEN_QUESTION entity types; give agents a read-only
> `GraphContext`. Migration script for old state.json. No
> schema upgrades, no `LivingGraph` rename, no path-finding
> additions. The smallest change that makes the graph
> reach the agents.

And the existing 0.1's first bullet should be updated:

> Old: *"Create `nexusrecon/graph/living_graph.py` (or evolve
> `core/entity_graph.py`)."*
>
> New: *"Evolve `core/entity_graph.py` in place after 0.0
> lands. Rename to `living_graph.py` is the LAST step of
> Phase 0 (not the first) to keep diffs small."*

## 9. Open questions for the project owner

These are deferred decisions that should happen before Step
0.0 lands, not at PR review:

1. **Unification of the three graphs.** Phase D's
   `Identity` and Phase E's `RelationshipEdge` are already
   first-class. Do we converge them into the EntityGraph (a
   PERSON-typed node + edges) in Phase 0, or keep them
   separate and connect via cross-graph references? The
   first is cleaner long-term; the second is less risky in
   the short term.
2. **Confidence-floor for the graph context handed to agents.**
   A 5k-node graph cannot fit in a prompt; we need a
   summarisation strategy. Highest-confidence top-N? Top-N
   most-cited? Phase-specific subset? This decision shapes
   the `GraphContext` API.
3. **Versioning.** Plan calls for "time-travel for a
   campaign." Implementing it pre-emptively in Step 0.0 is
   over-engineering. But is there a known operator need it
   would solve right now?

## 10. Closing recommendation

**Start with Step 0.0 as described above.** It is the
smallest change that validates the plan's core thesis, the
data model is already mostly correct, and the risk profile
(a wire-up commit + tests) is the lowest of any Phase 0
slice.

After Step 0.0 ships and agents demonstrably consume the
graph, proceed to Phase 0.1 with confidence that the rest of
the plan rests on a real foundation, not a hopeful one.

## 11. Step 0.0 — SHIPPED (2026-05-27)

Step 0.0 landed in a single PR matching the §7 spec. Summary
of what changed and where, so future contributors can read
the audit as living history rather than a snapshot.

**Code:**
- `nexusrecon/models/entities.py` — added
  `EntityType.HYPOTHESIS / LEAD / OPEN_QUESTION`,
  `RelationshipType.CITES / BLOCKS`, plus three Pydantic
  subclasses (`HypothesisEntity`, `LeadEntity`,
  `OpenQuestionEntity`) with their type-specific fields
  (statement / cites / status / severity / blocks / suggested
  _tools).
- `nexusrecon/core/entity_graph.py` — added
  `add_hypothesis()` / `add_lead()` / `add_open_question()`
  builders that draw CITES / BLOCKS edges back to the cited
  entities. Added classmethod
  `EntityGraph.from_state(state)` that ingests the flat
  buckets (`subdomain_intel`, `email_intel`, `cloud_intel`,
  `code_intel`, `vuln_intel.enriched_cves`, plus the three
  reasoning-artifact lists) into a real graph.
- `nexusrecon/core/graph_context.py` — NEW. Read-only
  summary wrapper with `count_by_type()`, `top_entities()`,
  `hypotheses()`, `leads()`, `open_questions()`, and a
  composite `to_task_data()` for spreading into agent prompts.
- `nexusrecon/graph/nodes.py` — `phase4_correlation` now
  builds the graph via `from_state`, passes
  `graph_context.to_task_data()` into the correlation
  agent's `task_data`, and serialises the REAL graph into
  `state["entity_graph"]` instead of the previous truncated
  500-entry name list. `phase8_attack_surface` similarly
  passes the graph summary to the risk-analyst agent.

**Tests** (`tests/unit/test_step_0_0_graph_wireup.py`, 33 new):
- New entity types + relationship types + Pydantic default
  shapes.
- `add_hypothesis` / `add_lead` / `add_open_question` create
  the right node type, draw CITES / BLOCKS edges to existing
  entities, silently skip missing entity ids.
- `EntityGraph.from_state(state)` ingests subdomains, emails,
  cloud assets (carrying attribution_confidence), code repos,
  CVEs from enriched_cves, and the three reasoning-artifact
  lists. Idempotent across repeat invocations.
- `GraphContext.to_task_data()` returns the documented shape;
  empty graph yields zero counts.
- Migration: pre-Step-0.0 state.json files with the truncated
  `entity_graph` format load without raising (via
  `EntityGraph.from_dict`'s tolerance) and the resume path
  rebuilds via `from_state`.

**Acceptance criteria for Step 0.0 (from §7):**
- ✓ Stop truncating `state["entity_graph"]`.
- ✓ Promote the EntityGraph to a workflow-level construct
  every phase can write into (via `from_state` + the
  builders).
- ✓ Add HYPOTHESIS / LEAD / OPEN_QUESTION to `EntityType` +
  Pydantic subclasses.
- ✓ `GraphContext` accessor wired into correlation +
  risk-analyst agents.
- ✓ Migration: old state.json files load without crashing.

**What remains for Phase 0.1+ (per the original plan):**
- Provenance schema upgrade (`sources: list[str]` →
  `list[{source, ts, evidence_hash, tool}]`).
- Unification of EntityGraph + IdentityGraph + RelationshipGraph
  (open question §9.1).
- Path-finding API on the EntityGraph (current `find_path`
  doesn't accept relationship_type filter).
- Confidence propagation when a cited entity's confidence
  changes.

Open questions §9 should now be answered before 0.1 begins:
graph unification (§9.1), prompt-summarisation strategy
(§9.2), versioning timing (§9.3).

---

**End of audit.**

Updated when Phase 0 begins shipping; treat the recommendations
in §7 as a contract for the first PR.
