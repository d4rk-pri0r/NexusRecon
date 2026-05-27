"""
Tool registry with @register_tool decorator.

The registry tracks all tool classes by name and category.
Tools are auto-discovered when their module is imported.
The registry validates tier, scope, and availability before execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time
from functools import lru_cache
from typing import TYPE_CHECKING, Any

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
        self._tools: dict[str, OSINTTool] = {}
        self._scope_guard: ScopeGuard | None = None
        self._cache: Cache | None = None
        self._audit_log: AuditLog | None = None
        self._stealth_profile: StealthProfile | None = None
        self._rate_limiter: RateLimiter | None = None
        self._proxy_manager: ProxyManager | None = None
        # TUI-8: per-tool invocation history. Bounded deque per
        # tool, keyed by tool name. Each entry is a dict with
        # ``timestamp``, ``runtime_ms``, ``success``, ``error``,
        # ``cached``. The Tools screen's detail pane reads this
        # to show recent invocations + avg duration + last error
        # without instrumenting the registry further.
        from collections import deque
        self._invocation_history: dict[str, deque[dict[str, Any]]] = {}
        # Cap per-tool history at 50 entries. Cheap; the typical
        # campaign fires each tool a handful of times.
        self._invocation_history_cap: int = 50

    def set_campaign_context(
        self,
        scope_guard: ScopeGuard,
        cache: Cache | None = None,
        audit_log: AuditLog | None = None,
        stealth_profile: StealthProfile | None = None,
        rate_limiter: RateLimiter | None = None,
        proxy_manager: ProxyManager | None = None,
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

    @property
    def audit_log(self):
        """Phase 1 PR D: read-only accessor so the strategic
        modules (planner, dispatcher) can write hash-chained
        audit entries without re-plumbing the campaign object.
        Returns ``None`` when no campaign context is bound."""
        return self._audit_log
        self._proxy_manager = None

    def register(self, tool_cls: type[OSINTTool]) -> None:
        """Register a tool class by instantiating it and storing by name."""
        tool = tool_cls()
        self._tools[tool.name] = tool
        log.debug("Registered tool", name=tool.name, tier=tool.tier.value, category=tool.category.value)

    def get(self, name: str) -> OSINTTool | None:
        return self._tools.get(name)

    # ── TUI-8: invocation history ──────────────────────────────────────

    def _record_invocation(
        self,
        *,
        tool_name: str,
        runtime_ms: int,
        success: bool,
        error: str | None,
        target: str,
        cached: bool,
    ) -> None:
        """Append one invocation record to the per-tool history.

        Cheap (deque.append is O(1)); cap is enforced via the
        deque's ``maxlen``. This is purely an in-memory surface —
        durable provenance lives in the audit log."""
        from collections import deque
        from datetime import datetime, timezone
        bucket = self._invocation_history.get(tool_name)
        if bucket is None:
            bucket = deque(maxlen=self._invocation_history_cap)
            self._invocation_history[tool_name] = bucket
        bucket.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "runtime_ms": int(runtime_ms),
            "success": bool(success),
            "error": error,
            "target": target,
            "cached": bool(cached),
        })

    def invocations_for(self, tool_name: str) -> list[dict[str, Any]]:
        """Return the in-memory invocation history for ``tool_name``
        as a plain list, newest-last. Empty list if the tool was
        never invoked this session."""
        bucket = self._invocation_history.get(tool_name)
        if bucket is None:
            return []
        return list(bucket)

    def invocation_summary(self, tool_name: str) -> dict[str, Any]:
        """Aggregate stats for the Tools detail pane.

        Returns a dict with: ``count``, ``avg_runtime_ms``,
        ``last_status``, ``last_error``, ``last_timestamp``.
        Empty buckets return zeros / Nones so callers can render
        the section unconditionally without if-checks everywhere.
        """
        records = self.invocations_for(tool_name)
        if not records:
            return {
                "count": 0,
                "avg_runtime_ms": 0,
                "last_status": None,
                "last_error": None,
                "last_timestamp": None,
            }
        runtimes = [r["runtime_ms"] for r in records if not r["cached"]]
        avg = int(sum(runtimes) / len(runtimes)) if runtimes else 0
        last = records[-1]
        # Surface the most-recent ERROR even if newer success calls
        # have happened — operators want to know the last thing
        # that went wrong, not just the last call's outcome.
        last_error = None
        for r in reversed(records):
            if r.get("error"):
                last_error = r["error"]
                break
        return {
            "count": len(records),
            "avg_runtime_ms": avg,
            "last_status": "success" if last["success"] else "error",
            "last_error": last_error,
            "last_timestamp": last["timestamp"],
        }

    def list_tools(self) -> list[dict[str, str]]:
        def _requires(tool: OSINTTool) -> str:
            parts = []
            if tool.requires_keys:
                parts.extend(tool.requires_keys)
            if tool.binary_required:
                parts.append(f"bin:{tool.binary_required}")
            return ", ".join(parts) if parts else ""

        def _optional(tool: OSINTTool) -> str:
            return ", ".join(tool.optional_keys) if tool.optional_keys else ""

        def _describe(tool: OSINTTool) -> str:
            # Surface the [STUB] prefix prominently so operators don't
            # discover a tool is a stub by reading the source mid-
            # campaign. Avoid double-prefixing if the description
            # already starts with the marker.
            desc = tool.description or ""
            if tool.stubbed and not desc.startswith("[STUB]"):
                desc = f"[STUB] {desc}".rstrip()
            return desc

        return [
            {
                "name": t.name,
                "tier": t.tier.value,
                "category": t.category.value,
                "available": str(t.is_available()),
                "description": _describe(t),
                "requires": _requires(t),
                "optional": _optional(t),
                "stubbed": str(t.stubbed),
            }
            for t in self._tools.values()
        ]

    def list_by_category(self, category: str) -> list[OSINTTool]:
        return [t for t in self._tools.values() if t.category.value == category]

    def list_by_tier(self, tier: str) -> list[OSINTTool]:
        return [t for t in self._tools.values() if t.tier.value == tier]

    def available_tools(self) -> list[OSINTTool]:
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
                # TUI-8: cache hits count as invocations for the
                # tool's recent-activity surface.
                self._record_invocation(
                    tool_name=tool_name,
                    runtime_ms=0,
                    success=True,
                    error=None,
                    target=target,
                    cached=True,
                )
                return ToolResult(success=True, source=tool_name, data=cached_data, cached=True)

        # ── OPSEC: rate-limit per source (token bucket + burst detector) ──────
        # When a stealth profile is bound to the registry, this awaits the
        # configured per-source token bucket before letting the tool fire.
        # Paranoid profile produces ~0.1 req/s per source; loud is unbounded.
        if self._rate_limiter is not None:
            await self._rate_limiter.wait(tool_name)

        # ── OPSEC: stealth-profile jitter ─────────────────────────────────────
        # The rate limiter handles per-source pacing (token bucket); this
        # adds a uniform random delay on top so the cadence between any
        # two tool invocations isn't deterministically spaced. Paranoid
        # promises 3-10s jitter; the previous registry never read these
        # fields, so the promise was a config-time fiction. ``delay_max=0``
        # (loud profile, or no profile bound) short-circuits.
        if self._stealth_profile is not None:
            dmin = float(getattr(self._stealth_profile, "request_delay_min", 0.0) or 0.0)
            dmax = float(getattr(self._stealth_profile, "request_delay_max", 0.0) or 0.0)
            if dmax > 0.0 and dmax >= dmin:
                await asyncio.sleep(random.uniform(dmin, dmax))

        # ── Audit: tool start ──────────────────────────────────────────────────
        if self._audit_log:
            self._audit_log.log_tool_start(tool_name, tool.tier.value, target, json.dumps(kwargs, default=str)[:500])

        # ── OPSEC: propagate proxy URL via ContextVar so the tool's
        # httpx.AsyncClient picks it up via BaseHTTPTool._proxy_kwargs() ──────
        proxy_url: str | None = None
        if self._proxy_manager is not None and self._proxy_manager.available:
            proxy_url = self._proxy_manager.get_proxy_for_source(tool_name)

        # ── Execute ────────────────────────────────────────────────────────────
        t0 = time.monotonic()
        with proxy_context(proxy_url):
            result = await tool.run(target, target_type=target_type, **kwargs)
        runtime_ms = int((time.monotonic() - t0) * 1000)
        result.runtime_ms = runtime_ms

        # TUI-8: record into in-memory invocation history so the
        # Tools detail pane can show "recent invocations / avg
        # duration / last error" without re-reading the audit log.
        self._record_invocation(
            tool_name=tool_name,
            runtime_ms=runtime_ms,
            success=result.success,
            error=result.error,
            target=target,
            cached=False,
        )

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

def register_tool(cls: type[OSINTTool]) -> type[OSINTTool]:
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
