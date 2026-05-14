# Example Plugin

This directory demonstrates the NexusRecon plugin contract.

## Adding a New Tool

1. Create a Python file in `plugins/` or `nexusrecon/tools/<category>/`
2. Import the base class and decorator:
   ```python
   from nexusrecon.tools.base import OSINTTool, Tier, Category, ToolResult
   from nexusrecon.tools.registry import register_tool
   ```
3. Decorate your class with `@register_tool` and implement `run()`
4. Set required metadata: `name`, `tier`, `category`, `requires_keys`, `description`

## Adding a New Agent

1. Create a file in `nexusrecon/agents/`
2. Inherit from `BaseNexusAgent` and define `role`, `goal`, `backstory`
3. Wire the agent into the LangGraph workflow in `nexusrecon/graph/workflow.py`

## Adding a New Report Section

1. Create a method in `nexusrecon/reports/engine.py`
2. Call it from `generate_all()`
3. The method should return the output file path

## Tool Categories

Available categories in `Category` enum:
- `DOMAIN`, `SUBDOMAIN`, `DNS`, `CERTIFICATE`
- `EMAIL`, `IDENTITY`, `BREACH`
- `CLOUD`, `CLOUD_AWS`, `CLOUD_AZURE`, `CLOUD_GCP`
- `CODE`, `SECRET`
- `INFRASTRUCTURE`, `WEB`, `VULNERABILITY`
- `PRETEXT`, `SOCIAL`, `MOBILE`, `NEWS`

## Tier Levels

- `T0` — Pure passive (no contact with target infra)
- `T1` — Semi-passive (DNS, passive DNS, WHOIS)
- `T2` — Light active (HTTP probes, screenshots)
- `T3` — Active (brute force, fuzzing)
