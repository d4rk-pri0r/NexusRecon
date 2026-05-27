"""Verification Orchestrator — fan out graph-mutation events
to registered verifiers, record verdicts.

The orchestrator is the bridge between the EntityGraph's
mutation hook (Phase 2 PR A added it) and the verification
machinery. Lifecycle:

  1. Construct with a graph + state ref (state holds
     ``verification_log``).
  2. Register one or more :class:`Verifier` instances (the
     :class:`CorroborationEngine` is the only one bundled in
     PR A; PR B/C/D add more).
  3. Call :meth:`attach` to register the orchestrator's
     callback with the graph's mutation listener system.
  4. As the campaign runs, mutations fire callbacks → fan out
     to verifiers → verdicts land in ``state["verification_log"]``
     and the campaign audit log.

Why not a plain function? Two reasons:

- We need to hold the audit-log reference, the state dict,
  and the verifier list together — a class is the simplest
  way to keep them grouped.
- PR D adds adversarial-self-check runs that need to schedule
  follow-up work; carrying the orchestrator object lets us
  attach that without changing every call site.

A :class:`Verifier` is anything with a ``name`` attribute and
a ``verify(event, graph) -> Verdict | None`` method. Verdicts
must be dataclasses with a ``to_dict()`` method so the audit
log gets a structured record.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import structlog

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Protocol
# ──────────────────────────────────────────────────────────────────────


class Verifier(Protocol):
    """Anything that can answer ``verify(event, graph)``.

    The protocol is intentionally minimal — concrete verifiers
    (CorroborationEngine, ContradictionDetector,
    ConfidencePropagator, …) each define their own verdict
    shapes. The orchestrator only cares that the verdict has
    a ``to_dict()`` method so it can serialise into the
    audit trail."""

    name: str

    def verify(self, event: dict[str, Any], graph: Any) -> Any | None:
        ...


# ──────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────


@dataclass
class _VerifierEntry:
    """Internal record so we can carry per-verifier config
    (priority, enabled-flag) without polluting the public
    :class:`Verifier` protocol. Reserved for future PRs; today
    it's just a thin wrapper."""

    verifier: Verifier


class VerificationOrchestrator:
    """Coordinates verifiers in response to graph mutations.

    Public surface:
      - ``register(verifier)`` — append a verifier
      - ``attach(graph)`` — register the orchestrator with the
        graph's mutation listener system
      - ``on_mutation(event)`` — the callback the graph calls;
        also callable directly from tests
      - ``run_after_mutation(event)`` — alias of
        ``on_mutation`` for callers that want the more
        explicit name
    """

    def __init__(
        self,
        *,
        state: dict[str, Any] | None = None,
        audit_log: Any | None = None,
    ) -> None:
        self.state: dict[str, Any] = state if state is not None else {}
        self.audit_log = audit_log
        self._verifiers: list[_VerifierEntry] = []
        self._attached_graph: Any | None = None

    # ── Registration ─────────────────────────────────────────

    def register(self, verifier: Verifier) -> None:
        """Append a verifier to the dispatch list. Verifiers run
        in registration order — corroboration before
        contradiction before propagation matches the natural
        flow ("did new agreement raise confidence? did new
        signal contradict an existing claim? did anything
        downstream need updating?"). Operators can re-order
        by clearing + re-registering."""
        self._verifiers.append(_VerifierEntry(verifier=verifier))

    def clear(self) -> None:
        """Drop every registered verifier. Mainly for tests."""
        self._verifiers.clear()

    @property
    def verifiers(self) -> list[Verifier]:
        """Read-only view of the registered verifiers (most
        callers want the bare list, not the wrapper objects)."""
        return [e.verifier for e in self._verifiers]

    # ── Graph attachment ─────────────────────────────────────

    def attach(self, graph: Any) -> None:
        """Register this orchestrator's mutation callback with
        ``graph``. Idempotent: a second call on the same graph
        is a no-op (we track the attached graph by identity so
        repeat ``attach`` from a re-resumed campaign doesn't
        double-fire verifiers)."""
        if self._attached_graph is graph:
            return
        graph.register_mutation_listener(self.on_mutation)
        self._attached_graph = graph

    # ── Mutation handling ────────────────────────────────────

    def on_mutation(self, event: dict[str, Any]) -> list[Any]:
        """Dispatch one event to every registered verifier.

        Returns the list of verdicts (may include ``None``
        entries for verifiers that didn't care about this
        event). Verdicts are also appended to
        ``state["verification_log"]`` and the audit log.

        Per-verifier exceptions are swallowed + logged at
        debug so a broken verifier can't break the campaign
        that's writing to the graph (this is the third defense
        — :meth:`EntityGraph._emit_mutation` is the second,
        the verifier's own try/except blocks are the first)."""
        if self._attached_graph is None:
            # Tests sometimes call ``on_mutation`` without an
            # attached graph; fall back to the graph implied
            # by the event when present.
            graph = event.get("_graph")
        else:
            graph = self._attached_graph
        if graph is None:
            log.debug("Verification dispatch: no graph available")
            return []

        verdicts: list[Any] = []
        log_entries: list[dict[str, Any]] = []
        timestamp = datetime.now(UTC).isoformat()

        for entry in self._verifiers:
            verifier = entry.verifier
            try:
                verdict = verifier.verify(event, graph)
            except Exception as exc:
                log.warning(
                    "Verifier raised — continuing",
                    verifier=verifier.name, error=str(exc),
                )
                verdict = None

            verdicts.append(verdict)
            if verdict is None:
                continue

            # Build the structured record the verification log
            # uses. Verdicts ARE dataclasses with ``to_dict``;
            # the protocol contract requires it.
            try:
                body = verdict.to_dict()
            except AttributeError:
                body = {"value": str(verdict)}
            record = {
                "timestamp": timestamp,
                "verifier": verifier.name,
                "event_kind": str(event.get("kind", "")),
                **body,
            }
            log_entries.append(record)

            if self.audit_log is not None:
                try:
                    self.audit_log.log_agent_action(
                        agent=f"verifier:{verifier.name}",
                        action="verification_verdict",
                        details=record,
                    )
                except Exception as exc:
                    log.debug(
                        "Audit log write failed", error=str(exc),
                    )

        if log_entries:
            existing = list(self.state.get("verification_log") or [])
            existing.extend(log_entries)
            self.state["verification_log"] = existing

        return verdicts

    # Alias matching the plan's terminology.
    run_after_mutation = on_mutation
