"""Dispatch policies — pluggable rules for the strategic engine.

A ``DispatchPolicy`` answers three questions for the dynamic
dispatcher:

  1. **Should the dispatcher fire at all for this phase?**
     (``should_dispatch_for_phase``)
  2. **How many calls can it make in one cycle?**
     (``max_per_cycle``)
  3. **How many calls can it make over the campaign's lifetime?**
     (``max_total``)

Today the dispatcher hardcodes the answers via module-level
constants:

    LITE_DISPATCH_PHASES = frozenset({"phase1", "phase4", "phase7"})
    MAX_PER_CYCLE = 5
    MAX_TOTAL = 30

After Phase 1 PR A, the same answers come from a
``DispatchPolicy`` instance the dispatcher consults. The default
behavior is preserved (``LitePolicy`` matches the old hardcoded
values byte-for-byte); operator-defined policies can be added
without touching the dispatcher module.

Concrete policies bundled today
- :class:`LitePolicy` ── safety-default. Dispatches only after
  Phase 1, 4, 7. Caps at 5/cycle and 30 total.
- :class:`FullPolicy` ── every reflection triggers dispatch.
  Caps at 5/cycle and 50 total.
- :class:`OffPolicy` ── never dispatches. Used by ``--dispatch-mode
  off``.

Operator-defined policies subclass :class:`DispatchPolicy`
and override the three knobs. Future ``aggressive``,
``conservative``, ``corp_red_team`` policies live here without
touching the dispatcher.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DispatchPolicy(ABC):
    """Abstract base for a dispatch policy.

    Subclasses set ``name`` + the three knobs (``max_per_cycle``,
    ``max_total``, ``eligible_phases``) and the default
    ``should_dispatch_for_phase`` implementation does the right
    thing. Policies that need more sophisticated phase-eligibility
    logic (e.g. "only dispatch after we've seen at least 3
    findings") override ``should_dispatch_for_phase`` directly.
    """

    name: str = ""
    """Operator-facing identifier. Surfaced in the dispatch
    audit log + the TUI status bar."""

    max_per_cycle: int = 5
    """Cap on dispatches within one ``reflection_node`` call.
    Prevents a single LLM hallucination from kicking off 50
    tools."""

    max_total: int = 30
    """Cap on dispatches across the entire campaign. Hard
    OPSEC stop ── once exceeded the dispatcher stops firing
    regardless of new triggers."""

    eligible_phases: frozenset[str] = field(default_factory=frozenset)
    """Phases after which the dispatcher MAY fire. Empty
    frozenset means 'no phase is eligible' (i.e. dispatcher
    is off)."""

    @abstractmethod
    def should_dispatch_for_phase(self, phase: str) -> bool:
        """True when the dispatcher should consider firing after
        ``phase`` completes. The base implementation just checks
        ``eligible_phases`` membership; subclasses can layer
        additional rules (state-based, time-based, cost-based)."""
        ...


@dataclass
class LitePolicy(DispatchPolicy):
    """Safety-default policy. Dispatches only after the
    high-signal phases (1 / 4 / 7) ── matches the previous
    ``LITE_DISPATCH_PHASES`` hardcode."""

    name: str = "lite"
    max_per_cycle: int = 5
    max_total: int = 30
    eligible_phases: frozenset[str] = field(
        default_factory=lambda: frozenset({"phase1", "phase4", "phase7"}),
    )

    def should_dispatch_for_phase(self, phase: str) -> bool:
        return phase in self.eligible_phases


@dataclass
class FullPolicy(DispatchPolicy):
    """Every reflection triggers dispatch. Higher total cap
    because the dispatcher runs more times."""

    name: str = "full"
    max_per_cycle: int = 5
    max_total: int = 50
    # Empty eligible_phases ── ``should_dispatch_for_phase``
    # always returns True regardless.
    eligible_phases: frozenset[str] = field(default_factory=frozenset)

    def should_dispatch_for_phase(self, phase: str) -> bool:
        # Full mode: dispatch after every phase.
        return True


@dataclass
class OffPolicy(DispatchPolicy):
    """Dispatcher is never invoked. The ``--dispatch-mode off``
    surface from the CLI maps to this."""

    name: str = "off"
    max_per_cycle: int = 0
    max_total: int = 0
    eligible_phases: frozenset[str] = field(default_factory=frozenset)

    def should_dispatch_for_phase(self, phase: str) -> bool:
        return False


#: Registry of bundled policies, keyed by ``name``. Operators
#: select via the existing ``--dispatch-mode`` CLI flag (the
#: name strings ``lite`` / ``full`` / ``off`` are preserved).
#: Adding a new bundled policy = adding one entry here.
_BUNDLED_POLICIES: dict[str, type[DispatchPolicy]] = {
    "lite": LitePolicy,
    "full": FullPolicy,
    "off":  OffPolicy,
}


def get_policy(name: str) -> DispatchPolicy:
    """Resolve a policy by name.

    Falls back to :class:`LitePolicy` for unknown names — same
    posture as the existing dispatcher, which treats anything
    not in ``("lite", "full", "off")`` as ``lite``. The
    fallback is silent rather than raising because operator-
    facing flags shouldn't break campaigns on a typo; the
    dispatcher logs the resolved policy name so the operator
    can spot the fallback in the audit trail.
    """
    cls = _BUNDLED_POLICIES.get(name.lower(), LitePolicy)
    return cls()


def register_policy(name: str, cls: type[DispatchPolicy]) -> None:
    """Plugin hook for operator-defined policies.

    A future ``nexusrecon-plugin-<x>`` package can register its
    own policy at import time so operators select it via
    ``--dispatch-mode <name>``. Phase 3 of the toolchain plan
    (Plugin SDK) wires this through the entry-points
    discovery mechanism.
    """
    _BUNDLED_POLICIES[name.lower()] = cls
