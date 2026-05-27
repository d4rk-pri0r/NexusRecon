"""Read-only graph-summary accessor for agents.

Step 0.0 of ARCHITECTURE.md §13-22: give
agents a clean handle to the campaign's :class:`EntityGraph`
so they can reason over a real graph instead of the flat
state buckets.

The accessor is intentionally narrow — agents get summary
methods (counts, top-N, recent edges) but cannot mutate the
graph. Mutation lives behind the phase functions that own the
canonical write path; the agent's role is to synthesize.

Why a wrapper instead of handing the agent the raw graph
- **Prompt budget**: a 5k-node graph won't fit in any LLM
  context window. The accessor's job is to shape "what's
  worth telling the agent right now" so the prompt stays
  small.
- **Surface lock**: the agent code paths are the most
  load-bearing places in the system — exposing the bare
  NetworkX API would make refactoring the underlying graph
  storage impossible without breaking every agent.
- **Audit**: every call through the wrapper can be logged
  later if we want a "what did the agent see?" trace.

The summary shape (what ``to_task_data()`` returns) is the
contract agents depend on. Adding fields is backward
compatible; removing or renaming is a breaking change that
requires updating every agent that consumes it.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from nexusrecon.core.entity_graph import EntityGraph


class GraphContext:
    """Read-only graph-summary wrapper for agent consumption.

    Construct from an :class:`EntityGraph` instance; pass the
    resulting object's ``to_task_data()`` output into the
    agent's ``task_data`` so the LLM sees graph-derived
    context as part of its prompt.

    Example:

        graph = EntityGraph.from_state(state)
        ctx = GraphContext(graph)
        executor.run_agent(
            "correlation",
            task_data={**existing_data, **ctx.to_task_data()},
            ...,
        )
    """

    #: Default cap on per-type top-N lists. Keeps the agent
    #: prompt under ~500 tokens of graph context.
    DEFAULT_TOP_N: int = 10

    def __init__(self, graph: EntityGraph) -> None:
        self._g = graph

    # ── Aggregates ──────────────────────────────────────────────

    def count_by_type(self) -> dict[str, int]:
        """``{entity_type: count}`` for every type present.

        Cheap (one pass over node-data); safe to call from a
        prompt-building loop."""
        counts: Counter[str] = Counter()
        for _, data in self._g.graph.nodes(data=True):
            t = data.get("entity_type", "unknown")
            counts[t] += 1
        return dict(counts)

    def total_entities(self) -> int:
        return self._g.graph.number_of_nodes()

    def total_relationships(self) -> int:
        return self._g.graph.number_of_edges()

    # ── Sampling ────────────────────────────────────────────────

    def top_entities(
        self,
        entity_type: str | None = None,
        *,
        limit: int = DEFAULT_TOP_N,
        min_confidence: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Return up to ``limit`` entities, optionally filtered
        by type + confidence floor.

        Sorted by ``confidence`` descending (high-confidence
        items lead the list — the agent's prompt budget is
        spent on the strongest signal first), with ties broken
        by ``last_seen`` descending so fresh data wins. Older
        / lower-confidence data is dropped past the cap."""
        rows: list[dict[str, Any]] = []
        for _, data in self._g.graph.nodes(data=True):
            if entity_type and data.get("entity_type") != entity_type:
                continue
            conf = float(data.get("confidence", 1.0) or 0.0)
            if conf < min_confidence:
                continue
            rows.append(dict(data))
        rows.sort(
            key=lambda d: (
                -float(d.get("confidence", 0.0) or 0.0),
                d.get("last_seen", ""),
            ),
        )
        return rows[:limit]

    def hypotheses(self, *, limit: int = DEFAULT_TOP_N) -> list[str]:
        """Convenience: just the hypothesis statements, sorted
        as ``top_entities`` does."""
        return [
            (r.get("statement") or r.get("value") or "")
            for r in self.top_entities("hypothesis", limit=limit)
        ]

    def leads(self, *, limit: int = DEFAULT_TOP_N) -> list[str]:
        return [
            (r.get("statement") or r.get("value") or "")
            for r in self.top_entities("lead", limit=limit)
        ]

    def open_questions(self, *, limit: int = DEFAULT_TOP_N) -> list[str]:
        return [
            (r.get("question") or r.get("value") or "")
            for r in self.top_entities("open_question", limit=limit)
        ]

    # ── Composite output for agents ─────────────────────────────

    # ── Phase 0.1 phase-aware + most-cited summaries ────────────

    def most_cited_entities(
        self,
        *,
        limit: int = DEFAULT_TOP_N,
        entity_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return entities ranked by inbound CITES + edge count.

        "Most-cited" = how many hypotheses / leads / open-
        questions point at this node, plus general inbound
        edges from other entities. High values are the entities
        the campaign's reasoning rests on the most ── the
        single domain everyone keeps citing; the email that
        five different tools surfaced.

        Inverse of the existing ``top_entities()`` which sorts
        by confidence — most-cited captures "what does the
        campaign keep returning to," which a confidence
        ranking misses (a low-confidence node many tools
        cite is more interesting than a high-confidence
        loner).

        Args:
            limit: Cap on returned entries.
            entity_types: When provided, only nodes of these
                types are considered (the citation counts
                still include edges from any source type).
        """
        # Cheap inbound-degree count across all edge types.
        # NetworkX's in_degree is O(1) per node.
        scored: list[tuple[int, dict[str, Any]]] = []
        for nid, data in self._g.graph.nodes(data=True):
            if entity_types and data.get("entity_type") not in entity_types:
                continue
            in_deg = self._g.graph.in_degree(nid)
            if in_deg == 0:
                continue
            scored.append((in_deg, dict(data)))
        # Highest in-degree first; ties broken by confidence
        # descending so a tie between a 1.0-confidence and a
        # 0.5-confidence entity puts the operator-trustworthy
        # one in front.
        scored.sort(
            key=lambda kv: (
                -kv[0],
                -float(kv[1].get("confidence", 0.0) or 0.0),
            ),
        )
        return [data for _, data in scored[:limit]]

    #: Per-phase entity-type focus. Maps a phase identifier to
    #: the entity types whose top-N + most-cited lists are most
    #: useful to that phase's agent. Phase 0.1 of the
    #: METASPLOIT_PLAN: phase-specific subsets keep the prompt
    #: budget under control on large campaigns ── the
    #: correlation agent doesn't need every CVE the vuln phase
    #: surfaced, just the entities and hypotheses to correlate.
    PHASE_FOCUS_TYPES: dict[str, list[str]] = {
        "phase4_correlation": [
            "subdomain", "email", "person",
            "cloud_asset", "repository",
            "hypothesis", "lead", "open_question",
        ],
        "phase8_attack_surface": [
            "subdomain", "cloud_asset", "secret", "cve",
            "url", "technology",
            "lead",
        ],
        "phase7_7_pretext_intelligence": [
            "person", "email", "social_account", "username",
            "organization",
        ],
        # Fallback for any phase not in the map: cover the high-
        # signal types from to_task_data's defaults.
        "default": [
            "domain", "subdomain", "email", "person",
            "cloud_asset", "repository", "secret",
            "technology", "cve",
        ],
    }

    def for_phase(
        self, phase: str, *, top_n: int = DEFAULT_TOP_N,
    ) -> dict[str, Any]:
        """Phase-tailored summary for inclusion in an agent's
        ``task_data``.

        Builds the same shape as ``to_task_data()`` but
        restricts ``top_entities`` + ``most_cited`` to the
        types that phase actually reasons over (per
        :data:`PHASE_FOCUS_TYPES`). Keeps the prompt budget
        under control as the graph grows.

        Schema (under ``graph_summary``):

            {
              "total_entities": int,
              "total_relationships": int,
              "by_type": {entity_type: count},
              "top_entities": {entity_type: [values...]},
              "most_cited": [{...node...}, ...],
              "hypotheses": [...],
              "leads": [...],
              "open_questions": [...],
              "phase": <phase identifier>,
            }
        """
        focus = self.PHASE_FOCUS_TYPES.get(
            phase, self.PHASE_FOCUS_TYPES["default"],
        )
        by_type = self.count_by_type()
        top_per_type: dict[str, list[str]] = {}
        for t in focus:
            if t not in by_type:
                continue
            top_per_type[t] = [
                str(r.get("value") or "")
                for r in self.top_entities(t, limit=top_n)
            ]
        # Most-cited: cross-type ranking restricted to the
        # focus types. Tells the agent which entities the
        # current campaign keeps coming back to.
        most_cited = [
            {
                "value": r.get("value"),
                "entity_type": r.get("entity_type"),
                "confidence": r.get("confidence"),
            }
            for r in self.most_cited_entities(
                limit=top_n, entity_types=focus,
            )
        ]
        return {
            "graph_summary": {
                "phase": phase,
                "total_entities": self.total_entities(),
                "total_relationships": self.total_relationships(),
                "by_type": by_type,
                "top_entities": top_per_type,
                "most_cited": most_cited,
                "hypotheses": self.hypotheses(limit=top_n),
                "leads": self.leads(limit=top_n),
                "open_questions": self.open_questions(limit=top_n),
            },
        }

    def to_task_data(self, *, top_n: int = DEFAULT_TOP_N) -> dict[str, Any]:
        """One-shot dict suitable for spreading into an agent's
        ``task_data``.

        Schema:

            {
              "graph_summary": {
                "total_entities": int,
                "total_relationships": int,
                "by_type": {entity_type: count},
                "top_entities": {entity_type: [values …]},
                "hypotheses": [str …],
                "leads": [str …],
                "open_questions": [str …],
              }
            }

        Keys nest under ``graph_summary`` so the agent's prompt
        builder can render them as one section heading rather
        than leak them into the rest of the task_data
        namespace. ``top_entities`` is a per-type list of just
        the entity ``value`` strings, capped at ``top_n``."""
        by_type = self.count_by_type()
        top_per_type: dict[str, list[str]] = {}
        # Cover the high-signal entity types only — full
        # coverage of every type would blow the prompt budget.
        focus_types = (
            "domain", "subdomain", "email", "person",
            "cloud_asset", "repository", "secret",
            "technology", "cve",
        )
        for t in focus_types:
            if t not in by_type:
                continue
            top_per_type[t] = [
                str(r.get("value") or "")
                for r in self.top_entities(t, limit=top_n)
            ]

        return {
            "graph_summary": {
                "total_entities": self.total_entities(),
                "total_relationships": self.total_relationships(),
                "by_type": by_type,
                "top_entities": top_per_type,
                "hypotheses": self.hypotheses(limit=top_n),
                "leads": self.leads(limit=top_n),
                "open_questions": self.open_questions(limit=top_n),
            },
        }
