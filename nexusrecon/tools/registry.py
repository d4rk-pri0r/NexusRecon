"""
Tool registry with @register_tool decorator.

The registry tracks all tool classes by name and category.
Tools are auto-discovered when their module is imported.
The registry validates tier, scope, and availability before execution.
"""

from __future__ import annotations

import hashlib
import json
import time
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type

import structlog

from nexusrecon.opsec.context import proxy_context
from nexusrecon.tools.base import OSINTTool, ToolResult

if TYPE_CHECKING:
    from nexusrecon.core.audit import AuditLog
    from nexusrecon.core.cache import Cache
    from nexusrecon.core.scope import ScopeGuard
    from nexusrecon.opsec.profiles import StealthProfile
    from nexusrecon.opsec.proxy import ProxyManager
    from nexusrecon.opsec.rate_limiter import RateLimiter

log = structlog.get_logger(__name__)


class ToolRegistry:
    """
    Global tool registry.  Singleton — use get_registry().

    Stores tool instances by name.  Provides an execute() wrapper that
    enforces scope, checks the cache, audit-logs every call, and delegates
    to the tool's run() method.

    OPSEC enforcement (rate limiter + proxy manager) is also applied at
    execute() time when ``set_campaign_context`` has been called with a
    stealth profile. The rate limiter sleeps before each tool.run() call
    according to the per-source token-bucket. The proxy URL is propagated
    via ``nexusrecon.opsec.context.proxy_context`` so HTTP tools can
    read it (via ``BaseHTTPTool._proxy_kwargs()``) when building their
    ``httpx.AsyncClient``.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, OSINTTool] = {}
        self._scope_guard: Optional["ScopeGuard"] = None
        self._cache: Optional["Cache"] = None
        self._audit_log: Optional["AuditLog"] = None
        self._stealth_profile: Optional["StealthProfile"] = None
        self._rate_limiter: Optional["RateLimiter"] = None
        self._proxy_manager: Optional["ProxyManager"] = None

    def set_campaign_context(
        self,
        scope_guard: "ScopeGuard",
        cache: Optional["Cache"] = None,
        audit_log: Optional["AuditLog"] = None,
        stealth_profile: Optional["StealthProfile"] = None,
        rate_limiter: Optional["RateLimiter"] = None,
        proxy_manager: Optional["ProxyManager"] = None,
    ) -> None:
        """
        Bind campaign-scoped services to the registry.

        Must be called once at campaign start (before any phase node runs)
        so that execute() can enforce scope, use the cache, write the
        audit trail, apply rate limits, and route through the configured
        proxy.

        ``rate_limiter`` and ``proxy_manager`` are optional ── when not
        provided, execute() falls back to the previous no-OPSEC behaviour
        (no per-source delays, direct outbound connections). When provided,
        the rate limiter awaits its per-source token bucket before each
        tool.run() and the proxy URL is propagated to the tool via the
        ``proxy_context`` ContextVar.
        """
        self._scope_guard = scope_guard
        self._cache = cache
        self._audit_log = audit_log
        self._stealth_profile = stealth_profile
        self._rate_limiter = rate_limiter
        self._proxy_manager = proxy_manager

    def clear_campaign_context(self) -> None:
        """Detach campaign services (call at campaign end or in tests)."""
        self._scope_guard = None
        self._cache = None
        self._audit_log = None
        self._stealth_profile = None
        self._rate_limiter = None
        self._proxy_manager = None

    def register(self, tool_cls: Type[OSINTTool]) -> None:
        """Register a tool class by instantiating it and storing by name."""
        tool = tool_cls()
        self._tools[tool.name] = tool
        log.debug("Registered tool", name=tool.name, tier=tool.tier.value, category=tool.category.value)

    def get(self, name: str) -> Optional[OSINTTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, str]]:
        def _requires(tool: OSINTTool) -> str:
            parts = []
            if tool.requires_keys:
                parts.extend(tool.requires_keys)
            if tool.binary_required:
                parts.append(f"bin:{tool.binary_required}")
            return ", ".join(parts) if parts else ""

        return [
            {
                "name": t.name,
                "tier": t.tier.value,
                "category": t.category.value,
                "available": str(t.is_available()),
                "description": t.description,
                "requires": _requires(t),
            }
            for t in self._tools.values()
        ]

    def list_by_category(self, category: str) -> List[OSINTTool]:
        return [t for t in self._tools.values() if t.category.value == category]

    def list_by_tier(self, tier: str) -> List[OSINTTool]:
        return [t for t in self._tools.values() if t.tier.value == tier]

    def available_tools(self) -> List[OSINTTool]:
        return [t for t in self._tools.values() if t.is_available()]

    async def execute(
        self,
        tool_name: str,
        target: str,
        target_type: str = "domain",
        **kwargs: Any,
    ) -> ToolResult:
        """
        Scope-enforced, cached, audit-logged tool execution.

        Replaces calling tool.run() directly.  All phase nodes should call
        this method so that scope, caching, and auditing are always applied.
        """
        from nexusrecon.core.scope import OutOfScopeError, TierViolationError

        tool = self.get(tool_name)
        if tool is None:
            return ToolResult(success=False, source=tool_name, error=f"Tool '{tool_name}' not registered")

        if not tool.is_available():
            return ToolResult(success=False, source=tool_name, error=f"Tool '{tool_name}' prerequisites not met")

        # ── Scope + tier gate ──────────────────────────────────────────────────
        if self._scope_guard is not None:
            try:
                self._scope_guard.validate_target(target, target_type, tool_name, tool.tier.value)
            except OutOfScopeError as exc:
                if self._audit_log:
                    self._audit_log.log_scope_violation(target, exc.reason, tool_name)
                log.warning("Scope violation — tool blocked", tool=tool_name, target=target, reason=exc.reason)
                return ToolResult(success=False, source=tool_name, error=str(exc))
            except TierViolationError as exc:
                if self._audit_log:
                    self._audit_log.log_tier_violation(tool_name, exc.tool_tier, exc.max_tier)
                log.warning("Tier violation — tool blocked", tool=tool_name, tier=exc.tool_tier, max=exc.max_tier)
                return ToolResult(success=False, source=tool_name, error=str(exc))

        # ── Cache lookup ───────────────────────────────────────────────────────
        cache_key: Any = {"target": target, **{k: v for k, v in kwargs.items() if isinstance(v, (str, int, float, bool))}}
        if self._cache is not None:
            cached_data = self._cache.get(tool_name, cache_key)
            if cached_data is not None:
                if self._audit_log:
                    self._audit_log.log_tool_result(tool_name, target, "cached", 0, 0, cached=True)
                return ToolResult(success=True, source=tool_name, data=cached_data, cached=True)

        # ── OPSEC: rate-limit per source (token bucket + burst detector) ──────
        # When a stealth profile is bound to the registry, this awaits the
        # configured per-source token bucket before letting the tool fire.
        # Paranoid profile produces ~0.1 req/s per source; loud is unbounded.
        if self._rate_limiter is not None:
            await self._rate_limiter.wait(tool_name)

        # ── Audit: tool start ──────────────────────────────────────────────────
        if self._audit_log:
            self._audit_log.log_tool_start(tool_name, tool.tier.value, target, json.dumps(kwargs, default=str)[:500])

        # ── OPSEC: propagate proxy URL via ContextVar so the tool's
        # httpx.AsyncClient picks it up via BaseHTTPTool._proxy_kwargs() ──────
        proxy_url: Optional[str] = None
        if self._proxy_manager is not None and self._proxy_manager.available:
            proxy_url = self._proxy_manager.get_proxy_for_source(tool_name)

        # ── Execute ────────────────────────────────────────────────────────────
        t0 = time.monotonic()
        with proxy_context(proxy_url):
            result = await tool.run(target, target_type=target_type, **kwargs)
        runtime_ms = int((time.monotonic() - t0) * 1000)
        result.runtime_ms = runtime_ms

        # ── Cache store ────────────────────────────────────────────────────────
        if self._cache is not None and result.success and result.data is not None:
            self._cache.set(tool_name, cache_key, result.data)

        # ── Audit: result / error ──────────────────────────────────────────────
        if self._audit_log:
            if result.success:
                raw = json.dumps(result.data, default=str)
                response_hash = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
                self._audit_log.log_tool_result(
                    tool_name, target, response_hash, runtime_ms, result.result_count
                )
            else:
                self._audit_log.log_tool_error(tool_name, target, result.error or "(no error message provided by tool)")

        return result


# ── Decorator ────────────────────────────────────────────────────────────────

def register_tool(cls: Type[OSINTTool]) -> Type[OSINTTool]:
    """
    Decorator that auto-registers a tool class in the global registry.

    Usage:
        @register_tool
        class SubfinderTool(OSINTTool):
            name = "subfinder"
            ...
    """
    get_registry().register(cls)
    return cls


@lru_cache(maxsize=1)
def get_registry() -> ToolRegistry:
    """Return the singleton tool registry."""
    return ToolRegistry()
