"""Strategic Reasoning Engine — Phase 1 of METASPLOIT_PLAN.

The dispatcher's job to date has been narrow: given a phase
boundary and the state so far, ask the LLM for follow-up tool
calls and execute the resulting plan. Useful, but ad-hoc — the
caps, eligibility rules, and decision rationale all live inside
the dispatcher module with no abstraction operators can swap.

Phase 1 of the plan elevates this into a first-class **Strategic
Reasoning Engine**:

  - **Strategy** (``strategy.plan``): a declarative campaign
    plan — which phases run, success criteria, kill criteria,
    tool budgets, dispatch policy. Drives the LangGraph workflow
    instead of the workflow being hardcoded.
  - **DispatchPolicy** (``strategy.policy``): pluggable rules
    for "when does the dispatcher fire and how much can it do?"
    The current ``lite`` / ``full`` / ``off`` dispatch modes
    become concrete policy instances; operator-defined policies
    can be added without touching ``dynamic_dispatcher.py``.
  - **Simulation** (``strategy.simulation``, follow-up PR):
    cheap pre-execution estimation of cost + expected graph
    growth + scope-creep risk.
  - **Audit** (``strategy.audit``, follow-up PR): every
    strategic decision (plan generation, dispatch, policy
    change) produces a signed hash-chained record.

Sequencing per the plan (§Phase 1 → Detailed Sequencing):
1. PR A: strategy package scaffold + ``DispatchPolicy`` interface;
   ``run_dynamic_dispatch`` consults the policy for caps + eligibility
   instead of module-level constants.  ← **THIS PR**
2. PR B: operationalise the ``CampaignPlannerAgent``; new
   ``--plan-only`` CLI mode.
3. PR C: simulation + what-if.
4. PR D: audit surface + advanced bounded-agency capabilities.

Backward compatibility: existing campaign launches that don't
explicitly pick a policy get the same behavior they had before
(the ``lite`` policy is the default; same caps, same phase
eligibility). Phase 1 is additive; nothing breaks.
"""
from nexusrecon.strategy.plan import Strategy
from nexusrecon.strategy.planner import plan_campaign, replan
from nexusrecon.strategy.policy import (
    DispatchPolicy,
    FullPolicy,
    LitePolicy,
    OffPolicy,
    get_policy,
)
from nexusrecon.strategy.simulation import (
    SimulatedItem,
    SimulationResult,
    append_simulation_log,
    simulate_dispatch_plan,
)

__all__ = [
    "DispatchPolicy",
    "FullPolicy",
    "LitePolicy",
    "OffPolicy",
    "SimulatedItem",
    "SimulationResult",
    "Strategy",
    "append_simulation_log",
    "get_policy",
    "plan_campaign",
    "replan",
    "simulate_dispatch_plan",
]
