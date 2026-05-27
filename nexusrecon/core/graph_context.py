"""Read-only graph-summary accessor for agents.

Step 0.0 of ``IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md``: give
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
