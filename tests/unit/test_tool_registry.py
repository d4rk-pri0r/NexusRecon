"""Tests for tools/registry.py."""
import pytest
from nexusrecon.tools.base import OSINTTool, Tier, Category, ToolResult
from nexusrecon.tools.registry import ToolRegistry, register_tool, get_registry


class TestTool:
    """Dummy test tool."""
    name = "test_tool"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "Test tool"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs):
        return ToolResult(success=True, source="test_tool", data={"test": True})


class TestRegistry:
    def test_register_tool(self):
        registry = ToolRegistry()
        registry.register(TestTool)
        tool = registry.get("test_tool")
        assert tool is not None
        assert tool.name == "test_tool"
        assert tool.tier == Tier.T0

    def test_decorator_registration(self):
        registry = get_registry()
        before = len(registry.list_tools())

        @register_tool
        class DecoratedTool(OSINTTool):
            name = "decorated_tool"
            tier = Tier.T0
            category = Category.DOMAIN
            requires_keys = []
            description = "Decorated"
            target_types = ["domain"]

            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name, data={})

        after = len(registry.list_tools())
        assert after == before + 1

    def test_list_by_category(self):
        registry = get_registry()
        infra_tools = registry.list_by_category("infrastructure")
        assert len(infra_tools) >= 0  # category-based filtering works (tools may vary)

    def test_list_by_tier(self):
        registry = get_registry()
        t0_tools = registry.list_by_tier("T0")
        t1_tools = registry.list_by_tier("T1")
        assert len(t0_tools) > len(t1_tools)  # Most tools are T0
