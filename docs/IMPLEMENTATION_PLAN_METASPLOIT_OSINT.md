# NexusRecon — Implementation Plan: The Metasploit of OSINT

**Status:** Authoritative execution plan for Claude Code (or other senior AI coding agents).  
**Version:** 1.0 (Post 2026 Audit)  
**Owner:** Project leadership  
**Target Outcome:** By the completion of this plan, NexusRecon should be recognized as the premier agentic OSINT platform — the functional and cultural equivalent of Metasploit for information gathering and external attack surface intelligence.

**Core Thesis of This Plan**  
NexusRecon already has several world-class elements (hash-chained auditability, disciplined findings model with evidence hashes, broad tool surface, bounded but real dynamic dispatch, strong OPSEC primitives, and a production-grade TUI).  
The gaps preventing Metasploit-level status are:
- A weak, dict-based intelligence substrate instead of a first-class living graph that agents can truly reason over.
- An agentic surface that is still too narrow and rigid.
- An extensibility model that is excellent for tools but weak for higher-order intelligence artifacts (agents, recon strategies, verification logic).
- Verification and confidence as an afterthought rather than a continuously improving core capability.

This plan attacks those four problems ruthlessly while preserving everything that already works.

---

## 1. Vision & Definition of Success

**"The Metasploit of OSINT" means:**

- An operator can state a high-level intent in natural language and receive a coherent, adaptive, auditable campaign plan.
- The system continuously builds and reasons over a rich, queryable, provenance-rich intelligence graph.
- Any skilled practitioner (or skilled AI) can contribute new intelligence capabilities with the same low friction that Metasploit module authors enjoy.
- Verification, corroboration, and confidence scoring are first-class, continuously running concerns — not one-time passes.
- The platform becomes the default backbone that other red-team and security tools integrate with for the recon/intel phase.
- Every major engagement artifact is reproducible, attributable, and defensible in a boardroom or courtroom.

**Measurable Success Criteria (at plan completion):**
- ≥85% of new high-value intelligence capabilities added by the community (not core team) in the prior 6 months.
- The living graph is the primary data structure used by agents, the dispatcher, the TUI, and reports.
- Average time from "new high-value finding" to "corroborated + scored + surfaced in top threads" drops dramatically due to continuous verification.
- A new contributor can add a non-trivial new agent + dispatch strategy + custom report section in < 2 hours following documentation.
- The system supports true multi-turn adaptive campaigns with human-in-the-loop at decision points only.

---

## 2. Guiding Principles (Non-Negotiable)

1. **Auditability & Provenance First** — Nothing is allowed to weaken the existing hash-chained audit log, evidence hashes, or scope enforcement. Every new capability must enhance or at least preserve them.
2. **Bounded Agency with Observability** — We expand the agent's ability to act, but never at the expense of cost caps, scope boundaries, or human auditability. Every LLM decision must be logged with full rationale.
3. **Evolutionary, Not Revolutionary** — We evolve the existing LangGraph + CrewAI + registry architecture. Big rewrites are forbidden unless they are small, reversible, and behind feature flags.
4. **Graph as the Source of Truth** — The `EntityGraph` (and its successor, the Living Intelligence Graph) must become the primary substrate. The flat state dict becomes a materialized view.
5. **Contribution Surface is Sacred** — Any change that increases friction for external contributors is a defect.
6. **Verification is a Continuous Process** — Not an event at the end of a phase.

---

## 3. Phased Roadmap Overview

| Phase | Name | Primary Bets | Duration Target | Exit Criteria |
|-------|------|--------------|------------------|---------------|
| **Phase 0** | Hardening & Graph Foundation | Living Graph (core) + Data Model | 4–6 weeks | Living Graph exists, is persisted, and is used by at least 2 phases + reports |
| **Phase 1** | Strategic Reasoning Layer | Bet #3 (Dispatcher + Planner) | 5–7 weeks | Dispatcher is first-class, planner is operational, full mode is safe |
| **Phase 2** | Verification & Confidence Engine | Bet #4 | 4–6 weeks | Continuous verification loop exists and measurably improves confidence scores |
| **Phase 3** | Agentic Surfaces & Contribution Model | Bet #2 (Extensibility) | 6–8 weeks | Adding a new agent + strategy + report section is as easy as adding a tool |
| **Phase 4** | Intent-Driven & Kill-Chain Integration | Intent entry + handoff formats | 4–5 weeks | Natural language → campaign plan works; clean handoff to exploitation tools |
| **Phase 5+** | Moonshots & Ecosystem | Continuous engine, vision reasoning, community packs | Ongoing | Cultural gravity achieved |

**Important Sequencing Rule**: Phase 0 must be substantially complete before Phase 1 begins in earnest. The graph is the foundation everything else builds upon.

---

## 4. Detailed Implementation Plans

### Phase 0 — Living Intelligence Graph Foundation (Highest Priority)

**Objective**: Replace the current `CampaignGraphState` dict + ad-hoc `EntityGraph` (NetworkX) with a first-class, queryable, persistent, provenance-rich **Living Intelligence Graph** that becomes the central reasoning substrate for agents, the dispatcher, the TUI, and reports.

**Current State (Observed)**:
- `nexusrecon/core/entity_graph.py` already exists and uses NetworkX + custom entity models (`models/entities.py`).
- It does deduplication by `(type, value)`.
- It is serialized into `state["entity_graph"]` but is not the primary structure most code reasons over.
- Most intelligence still lives in flat buckets (`subdomain_intel`, `cloud_intel`, `findings`, etc.).

**Target State**:
- A new `LivingGraph` (or significantly evolved `EntityGraph`) that supports:
  - Rich node/edge attributes (confidence, first_seen, last_seen, sources[], evidence_hashes[], attribution_confidence, etc.).
  - Powerful query interface (neighbors, paths, by_type + filter, temporal, confidence threshold).
  - First-class support for **hypotheses**, **open_questions**, and **ranked_threads** as first-class graph citizens.
  - Versioning / time-travel for a campaign.
  - Efficient serialization + diffing.
- All phase nodes gradually migrate reads/writes to go through the graph.
- The flat state buckets become derived / cache views.

#### Detailed Tasks (Claude Code Execution Order)

**0.1 Data Model & Core Graph Engine**
- [ ] Create `nexusrecon/graph/living_graph.py` (or evolve `core/entity_graph.py`).
- [ ] Define new rich node/edge schemas (Pydantic or dataclasses) extending the existing `models/entities.py`.
  - Required fields on every node: `id`, `entity_type`, `value`, `confidence`, `provenance` (list of `{source, timestamp, evidence_hash, tool_name}`), `first_seen`, `last_seen`.
  - Support for **virtual / inferred nodes** (e.g., "possible_persona" with lower confidence).
- [ ] Implement a clean query API:
  ```python
  graph.query_nodes(entity_type="person", min_confidence=0.7)
  graph.find_paths(from_entity, to_entity, max_length=4, relationship_types=["controls", "owns"])
  graph.get_neighbors(entity_id, edge_type="has_credential", direction="out")
  ```
- [ ] Add support for **Hypothesis** and **Lead** as first-class node types (not just strings in state).
- [ ] Implement efficient persistence (NetworkX + custom JSON, or migrate to a proper graph backend later — start with NetworkX + SQLite sidecar for queries).

**0.2 Integration & Migration**
- [ ] Modify `CampaignGraphState` to contain a serialized `living_graph` instead of (or in addition to) the old `entity_graph`.
- [ ] Create migration utilities for existing `state.json` files.
- [ ] Update `EntityGraph` (or deprecate it) to delegate to the new Living Graph.
- [ ] Refactor at least Phase 1, Phase 4 (correlation), and Phase 8 (scoring) to write primary data into the graph.
- [ ] Update the report engine and TUI reports browser to read from the graph where possible.

**0.3 Agent & Dispatcher Access**
- [ ] Give agents a clean `graph_context` tool / API so they can query the living graph during synthesis (read-only initially).
- [ ] Update the dynamic dispatcher's prompt builder to include rich graph-derived summaries ("3 high-confidence paths from executive emails to public S3 buckets").

**0.4 Testing & Validation**
- [ ] Comprehensive test suite for graph operations (dedup, confidence propagation, path finding, temporal queries).
- [ ] Property-based tests for merge behavior.
- [ ] Migration tests on real campaign artifacts from `campaigns/` and `tests/fixtures/`.

**Acceptance Criteria for Phase 0 Exit**:
- A new campaign run stores >70% of its intelligence primarily in the Living Graph (measurable via state inspection).
- The correlation agent (Phase 4) and risk analyst (Phase 8) demonstrably use graph queries in their reasoning.
- No regression in existing reports or TUI.
- `state.json` files remain backward compatible for at least one release.

**Risks**: Graph query performance at very large campaigns; over-engineering the graph API too early.

---

### Phase 1 — Strategic Reasoning Layer (Bet #3)

**Objective**: Transform the current narrow, prompt-based `dynamic_dispatcher` into a first-class, versioned, auditable **Strategic Reasoning Engine** that can plan, simulate, and adapt at the campaign level. Make the existing `CampaignPlannerAgent` a real, operational component.

**Key Work Items**:

1. **Strategic Reasoning Engine Module** (`nexusrecon/strategy/`)
   - Extract and harden the dispatcher logic.
   - Add a "Strategy" object: a declarative plan (phases, success criteria, kill criteria, tool budgets, dispatch policy).
   - Support pluggable **Dispatch Policies** (lite, aggressive, conservative, domain-specific).

2. **Operationalize the Planner Agent**
   - Wire `CampaignPlannerAgent` into campaign initialization (new `nexusrecon run --plan-only` or during TUI wizard).
   - Planner output becomes the initial `Strategy` object that the reflection node consults.
   - Planner can be re-invoked mid-campaign when major new intel appears.

3. **Simulation & What-If**
   - Before executing a dispatch plan, run a cheap simulation (using cached or synthetic results) to estimate cost, expected new nodes in the graph, and risk of scope creep.
   - Log the simulation alongside the actual decision.

4. **Advanced Dispatch Capabilities (still bounded)**
   - Support "deep pivot" dispatches that can temporarily change dispatch mode for one branch.
   - Explicit "human approval" dispatch items for high-tier or high-cost actions.

5. **Full Audit Surface**
   - Every strategic decision (plan generation, dispatch, policy change) must produce a signed, hash-chained record.

**Detailed Sequencing**:
- Start by refactoring the existing `dynamic_dispatcher.py` into the new `strategy/` package without changing behavior (strangler fig pattern).
- Then add planner integration.
- Then add simulation.
- Finally expose new capabilities behind `dispatch_mode: strategic`.

**Acceptance Criteria**:
- A campaign can be started from a planner-generated strategy.
- The dispatcher can be updated or have new policies added without touching `nodes.py`.
- Simulation is used on every full-mode reflection and measurably reduces wasted tool calls in testing.

---

### Phase 2 — Verification & Continuous Confidence Engine (Bet #4)

**Objective**: Make verification a continuously running background capability rather than a single `EvidenceAuditorAgent` pass at the end.

**Components**:

- **Verification Orchestrator** — Runs after every significant graph change (new nodes/edges from tools or agents).
- **Corroboration Engine** — Multiple independent signals increase confidence (e.g., same subdomain from passive DNS + certificate + active probe + breach corpus).
- **Contradiction Detector** — Flags when new data directly contradicts prior high-confidence findings (with human review queue).
- **Confidence Propagation** — When a high-confidence node (e.g., a confirmed cloud tenant) is downgraded, downstream findings that relied on it have their confidence automatically adjusted.
- **Adversarial Self-Check** — Periodic "red team the graph" agent runs that try to find weak links or over-claimed attributions.

**Integration Points**:
- Hook into the Living Graph's mutation events.
- Surface low-confidence or contradicted findings prominently in the TUI and top threads.
- Feed verification results back into the strategic reasoning layer ("we have low corroboration on the main identity cluster — dispatch more identity tools").

**Acceptance Criteria**:
- Running a campaign twice against the same target with additional data sources produces measurably higher average confidence on overlapping findings.
- The system can automatically downgrade a previously "high" finding when contradictory evidence appears later in the same campaign.

---

### Phase 3 — World-Class Contribution & Agentic Surfaces (Bet #2)

**Objective**: Make extending the *intelligence* layer (agents, strategies, verification rules, custom graph node types, report sections) as trivial and delightful as adding a Metasploit module.

**Concrete Deliverables**:

1. **Recon Pack Format** (directory + manifest)
   - `manifest.yaml` declaring agents, dispatch policies, required tools, graph schemas, report templates.
   - Auto-registration on load (similar to `@register_tool`).

2. **Agent Development Kit**
   - Cookiecutter / `nexusrecon agent new` CLI command.
   - Standard template with tests, prompt versioning, citation guardrails built-in.
   - Hot-reload support in dev mode.

3. **Strategy / Dispatch Policy SDK**
   - Clean interface for writing custom dispatch policies.
   - Ability to register policies by name and select them at runtime (`--dispatch-policy my_corp_aggressive`).

4. **First-Class Graph Extension Points**
   - Community can register new `EntityType`s and `RelationshipType`s with serialization rules.

5. **Marketplace / Registry Concept** (initially simple)
   - `nexusrecon packs list` / install from GitHub or local directory.
   - Versioning and compatibility checks.

**Acceptance Criteria**:
- A contributor can add a new "Supply Chain Intel" agent + two supporting tools + a custom report section + a dispatch policy that prefers supply-chain tools, and have it work in a campaign, in under 90 minutes following the docs.
- 3–5 high-quality community recon packs exist within 3 months of this phase shipping.

---

### Phase 4 — Intent-Driven Entry + Kill-Chain Handoff

- High-quality natural language campaign planner (building on Phase 1).
- Structured "Intel Package" export format (JSON Schema) that vulnerability scanners, C2 frameworks, and ticketing systems can consume directly.
- Bidirectional handoff: ability to import findings from other tools into the Living Graph.

---

## 5. Extended / Moonshot Items (Phase 5+)

- **Continuous / Watch Mode** — Long-running sensors that trigger micro-campaigns on material changes.
- **Multi-Modal Reasoning** — Vision model integration for screenshots, leaked documents, and slide decks.
- **Fleet-Level Learning** (privacy-preserving) — Pattern extraction across many campaigns to improve default strategies.
- **Adversarial Red-Teaming of the Platform Itself** — Built-in capability to attack the recon process (detect when the target is feeding us poisoned data).
- **Formal Verification / Provenance Cryptography** — Cryptographic receipts for high-stakes findings.

These are deliberately sequenced after the four core bets.

---

## 6. Cross-Cutting Requirements

- **Testing Discipline**: Every new major component requires property-based tests + golden master tests on real campaign artifacts.
- **Performance**: The Living Graph must support campaigns with 10,000+ nodes and 50,000+ edges without degrading the TUI or phase execution.
- **OPSEC & Cost**: Every expansion of agency must be accompanied by corresponding improvements in simulation, caps, and human oversight surfaces.
- **Documentation & DX**: Every new abstraction gets "How to extend this" documentation before the feature is considered complete.
- **TUI Co-evolution**: The TUI must be updated in lockstep to expose the power of the new graph and strategic layer (see prior TUI upgrade plan).

---

## 7. How Claude Code (or Any Implementer) Should Work This Plan

1. **Never skip Phase 0** validation before moving on.
2. Use the strangler fig pattern aggressively — evolve in place behind feature flags (`NEXUSRECON_LIVING_GRAPH=experimental`).
3. For every major change, produce:
   - Updated architecture diagram section
   - Migration guide for existing campaign data
   - Performance & cost impact analysis
4. Treat the audit log and evidence hash invariants as sacred — any PR that weakens them must be rejected.
5. Prioritize contributor experience over clever internals.

---

## 8. Final Success Definition

When this plan (through Phase 4) is substantially complete, a senior red teamer or OSINT professional should be able to say, without exaggeration:

> "This is what Metasploit did for exploitation, but for the entire external intelligence and attack surface discovery phase. I reach for NexusRecon first, I trust its output, I contribute to it, and the community around it makes me better at my job."

This is an ambitious but achievable bar if the four core bets are executed with discipline and the guiding principles are never compromised.

---

**End of Plan**

This document is the single source of truth for the transformation. Update it as phases complete and new realities are discovered. All major work should reference specific sections of this plan.

---

## Appendix A — Phase 0 Granular Execution Playbook (Most Important)

This section gives Claude Code (or any implementer) a week-by-week, file-by-file execution guide for the highest-leverage phase.

### Week-by-Week Breakdown

**Week 1: Graph Core & Schema**
1. Read `nexusrecon/core/entity_graph.py` and `nexusrecon/models/entities.py` in full.
2. Create `nexusrecon/graph/living_graph.py`.
3. Define `LivingNode` and `LivingEdge` Pydantic models in `nexusrecon/models/graph.py` (new file).
4. Implement core `LivingGraph` class with:
   - `add_node(entity: LivingNode) -> str`
   - `add_edge(source_id, target_id, relationship: LivingEdge)`
   - Strong deduplication logic using `(entity_type, canonical_value)` + fuzzy matching for common cases (e.g., `example.com` vs `www.example.com`).
   - `merge_node` logic that intelligently combines provenance lists and takes `max(confidence)`.
5. Add powerful query methods (start simple but powerful):
   - `get_nodes_by_type(entity_type, min_confidence=0.0)`
   - `find_shortest_paths(source_id, target_id, max_length=5)`
   - `get_attack_surface_nodes(min_confidence=0.6)`
6. Implement serialization (`to_dict()`, `from_dict()`) that is a superset of the old format for compatibility.
7. Write a battery of unit tests in `tests/unit/test_living_graph.py`.

**Week 2: State Integration & Persistence**
1. Extend `CampaignGraphState` (in `graph/state.py`) with `living_graph: dict` (serialized form).
2. Modify `campaign_runner.py` and the workflow initialization to construct a `LivingGraph` from the initial state.
3. Create a `GraphStore` helper that can load/save the graph alongside the flat state.
4. Update `core/campaign.py` (or wherever state is loaded) to support the new format.
5. Build a one-time migration script: `scripts/migrate_state_to_living_graph.py` that can process old `state.json` files.
6. Ensure the TUI dashboard and reports browser can still render old campaigns.

**Week 3–4: Phase Migration (Start with Correlation & Scoring)**
- Refactor `phase4_correlation` in `nodes.py` to primarily operate on the graph:
  - Read candidate entities from the graph.
  - Create `HYPOTHESIS` and `LEAD` nodes with edges.
  - Write corroborated findings back as enriched nodes + new `Finding` records that point to graph node IDs.
- Do the same for `phase8_attack_surface` / `risk_analyst`.
- Update the `score_findings` function in `core/scoring.py` to accept (and prefer) a `LivingGraph`.
- Add graph-derived context to the prompts sent to the correlation and risk agents.

**Week 5: Agent & Dispatcher Integration + Polish**
- Create a `GraphContextProvider` class that agents can use (read-only queries + safe write of new inferences).
- Update the dynamic dispatcher prompt builder (`graph/dynamic_dispatcher.py`) to include rich graph summaries.
- Add graph diffing / change detection so the reflection node can answer "what materially changed since last reflection?"
- Performance tuning: ensure 5k–10k node graphs remain fast.
- Full test pass + migration of 3–5 real campaign artifacts.
- Update `ARCHITECTURE.md` with a new "Living Intelligence Graph" section.

### Concrete Interface Sketch (Target for LivingGraph)

```python
class LivingGraph:
    def add_entity(self, entity: LivingEntity) -> str: ...
    def add_relationship(self, rel: LivingRelationship) -> str: ...
    def query(self, spec: GraphQuery) -> list[LivingNode]: ...
    def get_attack_paths(self, target_confidence: float = 0.7) -> list[AttackPath]: ...
    def propagate_confidence(self, changed_node_id: str): ...
    def to_state_dict(self) -> dict: ...
    @classmethod
    def from_state_dict(cls, data: dict) -> "LivingGraph": ...
```

This level of specificity should allow Claude Code to implement with high fidelity.

---

## Appendix B — Key Files That Will Change the Most

- `nexusrecon/graph/state.py`
- `nexusrecon/core/entity_graph.py` (likely renamed/evolved)
- `nexusrecon/graph/nodes.py` (especially phase4, phase8, reflection_node)
- `nexusrecon/graph/dynamic_dispatcher.py`
- `nexusrecon/models/entities.py` + new `models/graph.py`
- `nexusrecon/core/scoring.py`
- `nexusrecon/reports/engine.py`
- `nexusrecon/agents/correlation.py` and `risk_analyst.py`
- `nexusrecon/graph/living_graph.py` (new)
- `nexusrecon/strategy/` (new package in Phase 1)

---

## Appendix C — How to Track Progress

Create a GitHub Project or simple Markdown checklist in `docs/PHASE0_CHECKLIST.md` that mirrors the granular tasks above. Update it at the end of every coding session.

Every merged PR for this plan **must** reference the section numbers from this document (e.g., "Implements Phase 0 Week 2, tasks 2.3 and 2.5").

This level of traceability is what separates a vision document from an executable transformation plan.