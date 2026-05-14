"""Tests for tools/base.py — OSINTTool base class and ToolResult."""
import pytest
from nexusrecon.tools.base import OSINTTool, Tier, Category, ToolResult


def test_tool_tier_enum():
    assert Tier.T0.value == "T0"
    assert Tier.T1.value == "T1"
    assert Tier.T2.value == "T2"
    assert Tier.T3.value == "T3"
    assert list(Tier) == [Tier.T0, Tier.T1, Tier.T2, Tier.T3]


def test_category_enum():
    assert Category.DOMAIN.value == "domain"
    assert Category.CLOUD_AZURE.value == "cloud_azure"
    assert Category.VULNERABILITY.value == "vulnerability"


def test_toolresult_defaults():
    r = ToolResult(success=True, source="test")
    assert r.success is True
    assert r.source == "test"
    assert r.data is None
    assert r.error is None
    assert r.runtime_ms == 0
    assert r.cached is False
    assert r.result_count == 0
    assert r.tier == "T0"
    assert r.metadata == {}


def test_toolresult_with_data():
    r = ToolResult(success=True, source="test", data={"key": "val"}, result_count=5)
    assert r.data == {"key": "val"}
    assert r.result_count == 5


def test_toolresult_error():
    r = ToolResult(success=False, source="test", error="Something failed")
    assert r.success is False
    assert r.error == "Something failed"


def test_toolresult_raw_output():
    r = ToolResult(success=True, source="test", raw_output="stdout data")
    assert r.raw_output == "stdout data"


def test_toolresult_tier():
    r = ToolResult(success=True, source="test", tier="T2")
    assert r.tier == "T2"


    async def run(self, target: str, **kwargs):
        return ToolResult(success=True, source=self.name, data={"target": target})


@pytest.mark.asyncio
async def test_concrete_tool_run():
    tool = _ConcreteTool()
    result = await tool.run("example.com")
    assert result.success is True
    assert result.source == "test_tool"
    assert result.data == {"target": "example.com"}


def test_concrete_tool_attributes():
    tool = _ConcreteTool()
    assert tool.name == "test_tool"
    assert tool.tier == Tier.T0
    assert tool.category == Category.DOMAIN
    assert tool.cost_per_run_usd == 0.0
    assert tool.reliability == 0.95
    assert tool.binary_required is None


@pytest.mark.asyncio
async def test_tool_requires_keys_validation():
    """Test that is_available returns False when keys are missing."""
    class KeyedTool(OSINTTool):
        name = "keyed_tool"
        tier = Tier.T0
        category = Category.DOMAIN
        requires_keys = ["nonexistent_key_xyz"]
        description = "Keyed tool"
        target_types = ["domain"]

        async def run(self, target, **kwargs):
            return ToolResult(success=True, source=self.name, data={})

    tool = KeyedTool()
    available = tool.is_available()
    assert available is False


def test_tool_abstract_method():
    """OSINTTool cannot be instantiated directly."""
    with pytest.raises(TypeError):
        OSINTTool()


# ── Concrete tool (prefix with _ so pytest doesn't collect as test class) ──

class _ConcreteTool(OSINTTool):
    """Minimal concrete tool for testing the base class."""
    name = "test_tool"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "A test tool"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs):
        return ToolResult(success=True, source=self.name, data={"target": target})
