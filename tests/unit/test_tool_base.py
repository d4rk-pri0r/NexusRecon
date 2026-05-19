"""Tests for tools/base.py, OSINTTool/BaseHTTPTool base classes and ToolResult."""
import httpx
import pytest

from nexusrecon.tools.base import BaseHTTPTool, Category, OSINTTool, Tier, ToolResult


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


# ──────────────────────────────────────────────────────────────────────────
# BaseHTTPTool ── status-code classifier
# ──────────────────────────────────────────────────────────────────────────
#
# The base class extracts the "401/403 = auth, 429 = rate, other non-2xx
# = error" pattern that previously lived in nine individual tool files.
# The tests below pin the contract: subclasses get uniform error text
# without restating the if-tree, and the helper stays out of the way on
# 2xx and any caller-declared "soft failure" codes.


class _ExampleHTTPTool(BaseHTTPTool):
    """Concrete BaseHTTPTool stand-in for classify_response() tests."""
    name = "example_api"
    provider_label = "Example"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = ["example_api_key"]
    description = "Example HTTP tool"
    target_types = ["domain"]

    async def run(self, target, **kwargs):  # pragma: no cover (not exercised)
        return ToolResult(success=False, source=self.name, error="not implemented")


class _NoKeyHTTPTool(BaseHTTPTool):
    """BaseHTTPTool subclass with no key requirements ── exercises the
    branch where the auth-fail error must NOT append a ``check <KEY>``
    suffix."""
    name = "open_api"
    provider_label = "Open"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "Keyless HTTP tool"
    target_types = ["domain"]

    async def run(self, target, **kwargs):  # pragma: no cover
        return ToolResult(success=False, source=self.name, error="not implemented")


class _SoftFailureHTTPTool(BaseHTTPTool):
    """BaseHTTPTool subclass that declares 404 as a soft-success ──
    matches the Hudson Rock 'not in database' semantic."""
    name = "soft_api"
    provider_label = "Soft"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "HTTP tool that treats 404 as zero-result success"
    target_types = ["domain"]
    soft_failure_codes = (404,)

    async def run(self, target, **kwargs):  # pragma: no cover
        return ToolResult(success=False, source=self.name, error="not implemented")


def _resp(status: int) -> httpx.Response:
    """Build a Response with the given status code. No real request made."""
    return httpx.Response(status, request=httpx.Request("GET", "https://example.com/"))


def test_classify_returns_none_on_2xx() -> None:
    tool = _ExampleHTTPTool()
    assert tool.classify_response(_resp(200)) is None
    assert tool.classify_response(_resp(201), endpoint="/create") is None
    assert tool.classify_response(_resp(204)) is None


def test_classify_401_returns_auth_failure_with_key_hint() -> None:
    tool = _ExampleHTTPTool()
    result = tool.classify_response(_resp(401), endpoint="/lookup")
    assert result is not None
    assert result.success is False
    assert result.source == "example_api"
    assert "Example auth failure" in result.error
    assert "on /lookup" in result.error
    assert "HTTP 401" in result.error
    assert "EXAMPLE_API_KEY" in result.error


def test_classify_403_treated_as_auth_failure() -> None:
    tool = _ExampleHTTPTool()
    result = tool.classify_response(_resp(403))
    assert result is not None
    assert result.success is False
    assert "auth failure" in result.error
    assert "HTTP 403" in result.error


def test_classify_429_returns_rate_limit() -> None:
    tool = _ExampleHTTPTool()
    result = tool.classify_response(_resp(429), endpoint="/search")
    assert result is not None
    assert result.success is False
    assert "rate limit" in result.error.lower()
    assert "back off" in result.error.lower()
    assert "on /search" in result.error


def test_classify_5xx_returns_http_code() -> None:
    tool = _ExampleHTTPTool()
    for status in (500, 502, 503, 504):
        result = tool.classify_response(_resp(status))
        assert result is not None
        assert result.success is False
        assert str(status) in result.error


def test_classify_400_returns_http_code() -> None:
    """4xx other than 401/403/429 still surfaces, not silent."""
    tool = _ExampleHTTPTool()
    result = tool.classify_response(_resp(418))
    assert result is not None
    assert result.success is False
    assert "418" in result.error


def test_classify_endpoint_label_omitted_when_blank() -> None:
    """No ``on <endpoint>`` fragment in the error message if not supplied."""
    tool = _ExampleHTTPTool()
    result = tool.classify_response(_resp(503))
    assert result is not None
    assert " on " not in result.error  # no dangling "on " with no endpoint


def test_classify_keyless_tool_omits_check_hint() -> None:
    """Tools with no ``requires_keys`` shouldn't get a "- check <KEY>" tail
    appended to auth errors, the hint would be empty and ugly."""
    tool = _NoKeyHTTPTool()
    result = tool.classify_response(_resp(401))
    assert result is not None
    assert "auth failure" in result.error
    assert "check" not in result.error


def test_classify_soft_failure_codes_return_none() -> None:
    """A tool that declares 404 in ``soft_failure_codes`` should get
    None back ── caller treats it as a zero-result success case."""
    tool = _SoftFailureHTTPTool()
    assert tool.classify_response(_resp(404)) is None
    # Other non-success codes still produce a failure.
    result = tool.classify_response(_resp(500))
    assert result is not None
    assert "500" in result.error


def test_classify_provider_label_defaults_from_name() -> None:
    """If ``provider_label`` isn't set, the helper title-cases the
    snake_case ``name`` for the error message."""

    class _UnlabeledTool(BaseHTTPTool):
        name = "snake_case_api"
        tier = Tier.T0
        category = Category.DOMAIN
        requires_keys = []
        description = "Unlabeled HTTP tool"
        target_types = ["domain"]

        async def run(self, target, **kwargs):  # pragma: no cover
            return ToolResult(success=False, source=self.name)

    tool = _UnlabeledTool()
    result = tool.classify_response(_resp(503))
    assert result is not None
    assert "Snake Case Api" in result.error
