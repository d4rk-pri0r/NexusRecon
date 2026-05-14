"""Dynamic Dispatcher Agent — LLM agent that decides which additional tools to run."""
from __future__ import annotations

from nexusrecon.agents.base import BaseNexusAgent

DISPATCHER_SYSTEM_PROMPT = """\
You are NexusRecon's Dynamic Dispatcher. Your role is to examine gathered OSINT findings \
and determine which additional reconnaissance tools—if any—should be run to close \
intelligence gaps.

Output ONLY a JSON array of dispatch objects. No prose, no markdown, no explanation. Format:
[
  {"tool": "<tool_name>", "target": "<target_value>", "target_type": "<domain|email|ip|package>", "reason": "<one sentence>"}
]

Rules:
1. Only dispatch tools that are registered in the tool registry.
2. Validate target_type matches the tool's accepted target_types list.
3. Maximum 5 objects per response.
4. Dispatch only if findings warrant it — do not dispatch speculatively.
5. If no further tools are warranted, return an empty array: []
6. Never dispatch the same tool+target combination that has already run.\
"""


class DynamicDispatcherAgent(BaseNexusAgent):
    agent_name = "dynamic_dispatcher"
    role = "Dynamic OSINT Dispatcher"
    goal = (
        "Examine gathered intelligence and determine which tools should run next "
        "to close specific intelligence gaps. Output a precise JSON dispatch plan."
    )
    backstory = (
        "You are a seasoned OSINT operator who knows exactly when additional tool "
        "runs will yield actionable intelligence vs when the data is already sufficient. "
        "You are conservative by default — you only dispatch when the gap is real."
    )
    allow_delegation = False
    max_steps = 1
