"""
Example Plugin — Custom OSINT Tool

This demonstrates the plugin contract for adding new tools to NexusRecon.

To add your own tool:
1. Copy this file to your plugins directory
2. Modify the class metadata (name, tier, category, etc.)
3. Implement the run() method
4. The @register_tool decorator handles automatic registration

The tool will be available in the registry and will respect scope,
tier limits, caching, and rate limiting automatically.
"""

from __future__ import annotations
from typing import Any, Dict, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ExamplePluginTool(OSINTTool):
    """
    Example tool that queries a custom API.

    Replace the implementation below with your actual tool logic.
    """

    # ── Required metadata ──────────────────────────────────────
    name = "example_plugin"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []  # e.g., ["my_api_key"]
    description = "Example plugin tool — replace with your implementation"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        """
        Execute the tool against a target.

        Args:
            target: The target to scan (domain, IP, email, etc.)
            **kwargs: Additional parameters from the agent or workflow.

        Returns:
            ToolResult with success status, data, and metadata.
        """
        # Example implementation — replace with actual logic
        try:
            # If your tool requires an API key:
            # key = self.config.get_secret("my_api_key")
            # if not key:
            #     return ToolResult(success=False, source=self.name, error="API key not set")

            # Make an API call:
            # async with httpx.AsyncClient() as client:
            #     resp = await client.get(f"https://api.example.com/v1/query?domain={target}")
            #     data = resp.json()

            # For now, return a placeholder result
            return ToolResult(
                success=True,
                source=self.name,
                data={"message": f"This is an example tool run against {target}"},
                result_count=1,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))
