# Dynamic Dispatch Agent Loop

_Reference guide for the NexusRecon self-steering reconnaissance loop._

---

## Overview

Between every two phases the **reflection node** checks whether additional targeted
tool calls are needed. If so it invokes the **Dynamic Dispatcher Agent**, which asks
the configured LLM to propose a short list of extra tool runs, executes them, and
merges their results back into the graph state.

```
Phase N complete
       │
       ▼
reflection_node ──── dispatch_mode == "off"? ──► skip
       │
       │ off?  skip
       │ lite?  only run for LITE_DISPATCH_PHASES
       │ full?  always run
       ▼
run_dynamic_dispatch()
       │
       ├─► _build_dispatch_prompt(state)
       │          │ LLM
       │          ▼
       ├─► _parse_dispatch_plan(llm_output)   # fail-safe JSON extraction
       │
       ├─► _validate_plan(plan, state)         # registry check + target_type + dedup
       │
       ├─► enforce MAX_PER_CYCLE cap (slice to first 5)
       │
       ├─► _execute_plan(plan, state)          # ToolRegistry.execute() per item
       │
       └─► merge results into category state keys
```

---

## Dispatch Modes

| Mode | Behaviour | When to use |
|------|-----------|-------------|
| `off` | Dispatcher never runs | Air-gapped, budget-sensitive, or CI runs |
| `lite` | Runs only after phases 1, 4, and 7 | Default — good balance of depth vs. cost |
| `full` | Runs after every phase | Maximum coverage; higher LLM cost |

Set via `--dispatch-mode` on the CLI or `dispatch_mode` in the campaign state dict.

```bash
nexusrecon run --scope scope.yaml --dispatch-mode full
nexusrecon run --scope scope.yaml --dispatch-mode off
```

---

## Hard Caps

| Constant | Value | Effect |
|----------|-------|--------|
| `MAX_PER_CYCLE` | 5 | LLM may propose many items; only the first 5 are executed per invocation |
| `MAX_TOTAL` | 30 | Total items in `dynamic_dispatch_log` across the entire campaign; dispatcher exits immediately if this is reached |

These caps prevent runaway token spend and infinite tool loops.

---

## Phases That Trigger Lite Dispatch

```python
LITE_DISPATCH_PHASES = {"phase1", "phase4", "phase7"}
```

Phase 1 (passive footprinting) produces the most discovery surface; phase 4 is the
correlation pivot; phase 7 has fresh CVE/KEV data to act on immediately.

---

## Dispatch Prompt Design

The dispatcher prompt includes:

1. **Current phase** and `completed_phases`
2. **Seeds** (initial targets)
3. A **summary of populated state keys** — which intel dicts are non-empty
4. A **findings snippet** (first 10 finding titles)
5. **Already-dispatched pairs** `(tool, target)` to prevent re-runs
6. A JSON schema for the required output format

The LLM must respond with a JSON array only (no markdown, no prose). Non-JSON
output is treated as an empty plan — no tools are dispatched.

### Required LLM output format

```json
[
  {
    "tool": "apk_analyzer",
    "target": "com.acme.mobileapp",
    "target_type": "package",
    "reason": "Android app discovered via Play Store listing"
  },
  {
    "tool": "shodan",
    "target": "vpn.acme.com",
    "target_type": "domain",
    "reason": "VPN subdomain found; scan for exposed services"
  }
]
```

---

## Validation Rules

After parsing, each proposed dispatch item is checked:

1. **Tool exists** — `tool` must be a key in `get_registry()`
2. **Target type matches** — `target_type` must be in `tool.target_types`
3. **No duplicate pairs** — `(tool, target)` must not already appear in `dynamic_dispatch_log`

Items that fail any check are silently dropped. An item that passes all three is
added to the validated plan.

---

## CATEGORY_TO_STATE_KEY Mapping

When a tool finishes, its `ToolResult.data` is merged into the appropriate state
key using this mapping:

| Tool category | State key |
|---------------|-----------|
| `domain` | `domain_intel` |
| `subdomain` | `subdomain_intel` |
| `dns` | `domain_intel` |
| `certificate` | `domain_intel` |
| `email` | `email_intel` |
| `identity` | `identity_intel` |
| `breach` | `breach_intel` |
| `infrastructure` | `infra_intel` |
| `cloud` / `cloud_aws` / `cloud_azure` / `cloud_gcp` | `cloud_intel` |
| `code` / `secret` | `code_intel` |
| `web` | `infra_intel` |
| `vulnerability` | `vuln_intel` |
| `mobile` | `mobile_intel` |
| `social` | `social_intel` |
| `pretext` / `news` | `pretext_intel` |

The state key is updated via `state[state_key][target] = tool_result_data`.

---

## Dynamic Trigger Hints

Every `OSINTTool` subclass may define a `dynamic_trigger_hints` list. These are
short English phrases that the dispatcher prompt surfaces to the LLM as signals for
when this tool should be dispatched:

```python
@register_tool
class APKAnalyzerTool(OSINTTool):
    name = "apk_analyzer"
    dynamic_trigger_hints = [
        "android app discovered",
        "play store app found",
    ]
```

The hints are injected into the prompt's tool-available section so the LLM can
reason about _why_ a tool is relevant to the current findings.

---

## Dispatch Log Format

Each executed item is appended to `state["dynamic_dispatch_log"]`:

```json
{
  "tool": "apk_analyzer",
  "target": "com.acme.mobileapp",
  "target_type": "package",
  "reason": "Android app discovered via Play Store listing",
  "phase": "phase2",
  "timestamp": "2026-05-12T11:00:00Z",
  "success": true
}
```

The log is serialized into `state.json` at campaign end and visible in the
`full_report.md` under the _Dynamic Intelligence Augmentation_ section.

---

## Extending the Dispatcher

### Adding a new tool category

1. Add the new `Category` enum value to `nexusrecon/tools/base.py`.
2. Add a mapping entry to `CATEGORY_TO_STATE_KEY` in
   `nexusrecon/graph/dynamic_dispatcher.py`.
3. Add the corresponding state key to `CampaignGraphState` in
   `nexusrecon/graph/state.py`.
4. Initialize it to an empty dict in `conftest._base_state()` and in
   `nexusrecon/cli/main.py` state initialization.

### Writing a dispatchable tool

```python
@register_tool
class MyTool(OSINTTool):
    name = "my_tool"
    tier = Tier.T1
    category = Category.WEB        # picks up web → infra_intel mapping
    requires_keys = []
    description = "Scan for exposed admin interfaces"
    target_types = ["domain"]      # must match what dispatcher will put in target_type
    dynamic_trigger_hints = [
        "admin panel fingerprinted",
        "cms detected",
    ]

    async def run(self, target: str, **kwargs) -> ToolResult:
        ...
```

---

## Testing

Unit tests for the dispatcher live in `tests/unit/test_dynamic_dispatcher.py` (22
tests). Smoke tests that exercise the full dispatch path are in
`tests/smoke/test_e2e_campaign.py` (tests 4 and 5).

Run just the dispatcher tests:

```bash
pytest tests/unit/test_dynamic_dispatcher.py -v
```

Run the smoke suite:

```bash
./smoke_test.sh
# or
nexusrecon smoke
```
