"""
OSINT tool base class and type system.

Every tool in NexusRecon inherits from OSINTTool and declares:
  - name, tier (T0-T3), category, cost, reliability
  - requires_keys (list of env var names for API keys)
  - binary_required (CLI tool path if needed)
  - output_schema (Pydantic model for structured output)

Tools are executed via the tool registry which enforces scope,
tier limits, caching, rate limiting, and audit logging.
"""

from __future__ import annotations

import abc
import asyncio
import random
import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypeVar

import httpx
import structlog

from nexusrecon.core.config import get_config

log = structlog.get_logger(__name__)


class Tier(StrEnum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


class Category(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    DNS = "dns"
    CERTIFICATE = "certificate"
    EMAIL = "email"
    IDENTITY = "identity"
    BREACH = "breach"
    CLOUD = "cloud"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"
    CODE = "code"
    SECRET = "secret"
    INFRASTRUCTURE = "infrastructure"
    WEB = "web"
    VULNERABILITY = "vulnerability"
    PRETEXT = "pretext"
    SOCIAL = "social"
    MOBILE = "mobile"
    NEWS = "news"


@dataclass
class ToolResult:
    """
    Standardized result wrapper for every tool invocation.

    Every tool returns this — never raw dicts or lists.
    The result carries metadata needed for audit, caching, and entity extraction.
    """

    success: bool
    source: str
    data: Any = None
    error: str | None = None
    raw_output: str | None = None
    runtime_ms: int = 0
    cached: bool = False
    result_count: int = 0
    tier: str = "T0"
    metadata: dict[str, Any] = field(default_factory=dict)
    #: Wave F-A1: the tool ran without raising, but its output is
    #: implausibly empty for this target ── i.e. a silent failure
    #: masquerading as a clean negative (sslyze returning no TLS data
    #: on an HTTPS host, whois returning no fields for a resolving
    #: domain, nuclei exiting non-zero, a WAF probe that never reached
    #: the host). ``success`` stays True (the call completed); consumers
    #: and the run-health summary read ``degraded`` to avoid reporting
    #: "found nothing" when the truth is "did not actually assess".
    #: Set centrally by the registry from :meth:`OSINTTool.assess_result`.
    degraded: bool = False
    degraded_reason: str | None = None


class OSINTTool(abc.ABC):
    """
    Abstract base for all OSINT tools.

    Subclasses must implement:
      - run(target: str) -> ToolResult
    And should set:
      - name, tier, category, reliability, requires_keys, binary_required
    """

    name: str = "base"
    tier: Tier = Tier.T0
    category: Category = Category.DOMAIN
    cost_per_run_usd: float = 0.0
    avg_runtime_sec: int = 30
    reliability: float = 0.95
    requires_keys: list[str] = []
    #: Env vars the tool ENHANCES with but doesn't require — providing
    #: them unlocks higher rate limits, paid endpoints, or richer
    #: response fields. ``is_available()`` ignores these (a tool with
    #: only ``optional_keys`` runs unauthenticated). The TUI surfaces
    #: them in the per-tool detail pane so operators can configure
    #: them from one place; without this declaration an enhancement
    #: key would be invisible in the UI.
    optional_keys: list[str] = []
    binary_required: str | None = None
    description: str = ""
    target_types: list[str] = ["domain"]  # domain, ip, email, etc.
    dynamic_trigger_hints: list[str] = []  # hints for dynamic dispatcher (Move 4)
    # When True, the tool is registered for discoverability ("we know
    # this surface exists") but is intentionally not functional yet.
    # ``is_available()`` returns False so the registry keeps the tool
    # out of ``available_tools()`` and ``registry.list_tools()`` flags
    # it with a ``[STUB]`` prefix. Set to True on tools whose ``run()``
    # is a placeholder; clear when a real implementation lands.
    stubbed: bool = False
    # Wave F-A2: True when running this tool necessarily consumes a paid
    # / metered API (Shodan, Censys, paid breach DBs, etc.). The registry
    # skips paid tools as ``policy_skipped`` when the engagement sets
    # ``allow_paid_apis: false`` ── even if a key is configured globally.
    # Breach databases are gated separately via ``category == BREACH`` and
    # ``allow_breach_db_lookup``; a paid breach DB sets BOTH. Keep this
    # conservative: only mark tools with no usable free/unauthenticated
    # tier, so a paid-APIs-off engagement never silently loses free recon.
    paid_api: bool = False

    def __init__(self) -> None:
        self.config = get_config()
        if not self.is_available():
            log.debug("Tool prerequisites not met at init", tool=self.name)

    @abc.abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        """Execute the tool against a target. Must be implemented by subclasses."""
        ...

    def is_available(self) -> bool:
        """Return True if this tool can run (keys + binaries present).

        Stubbed tools (``stubbed=True``) always return False ── the
        registry keeps them visible in ``list_tools()`` (operators can
        see the surface is planned) but excludes them from
        ``available_tools()`` so the dispatcher never selects them.
        """
        if self.stubbed:
            return False
        for key in self.requires_keys:
            if not self.config.get_secret(key):
                return False
        if self.binary_required:
            import shutil
            return shutil.which(self.binary_required) is not None
        return True

    def assess_result(
        self,
        result: "ToolResult",
        target: str,
        target_type: str = "domain",
    ) -> str | None:
        """Wave F-A1: judge whether a *successful* result is plausible.

        Called by the registry after ``run()`` returns ``success=True``.
        Return a short reason string when the result is implausibly empty
        for this target ── i.e. the tool almost certainly failed to do its
        job rather than genuinely finding nothing (a TLS scan with no cert,
        a WHOIS with no fields for a live domain, a scanner that exited with
        an error). The registry sets ``result.degraded`` + ``degraded_reason``
        from the return value. Return ``None`` (the default) to express no
        opinion ── most tools, and any tool whose emptiness is a legitimate
        negative, should leave this unimplemented.

        Keep overrides conservative: a false ``degraded`` is noise, so only
        flag emptiness that a healthy run could not produce. Inspect
        ``result.data`` rather than ``result_count`` where the count means
        something other than "did the tool work" (e.g. sslyze counts
        vulnerabilities, not scan success).
        """
        return None

    def run_subprocess(
        self,
        cmd: list[str],
        timeout_sec: int = 300,
        cwd: str | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess (for CLI tools like subfinder, gitleaks, etc.)."""
        log.debug("Running subprocess", cmd=cmd)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=cwd,
        )


class BaseHTTPTool(OSINTTool):
    """
    Base class for tools that hit an upstream HTTP API.

    Provides ``classify_response()``, a status-code helper that turns the
    common provider error codes (401/403/429/5xx) into populated
    ``ToolResult(success=False)`` values. Replaces the bare
    ``if resp.status_code == 200`` gate that previously masked auth
    failures, rate-limits, and provider outages as silent empty
    responses, the #1 source of bugs the 0.5.0 test sprint surfaced.

    Subclasses customise via two class attributes:

      - ``provider_label``: human-readable provider name used in error
        messages, e.g. ``"VirusTotal"``. Defaults to ``cls.name`` with
        underscores replaced by spaces and title-cased.
      - ``soft_failure_codes``: HTTP status codes that ``classify_response``
        should NOT treat as failures. The caller handles them as
        zero-result success cases. Example: Hudson Rock returns 404 for
        "email not in database", which is a legitimate empty answer.

    Usage:

        @register_tool
        class ExampleTool(BaseHTTPTool):
            name = "example"
            provider_label = "Example"
            requires_keys = ["example_api_key"]
            ...

            async def run(self, target, **kwargs):
                key = self.config.get_secret("example_api_key")
                if not key:
                    return ToolResult(
                        success=False, source=self.name,
                        error="EXAMPLE_API_KEY not set",
                    )
                try:
                    async with httpx.AsyncClient(...) as client:
                        resp = await client.get(f"/lookup/{target}")
                        fail = self.classify_response(resp, "lookup")
                        if fail is not None:
                            return fail
                        ...
                except Exception as exc:
                    return ToolResult(success=False, source=self.name, error=str(exc))
    """

    provider_label: str | None = None
    soft_failure_codes: tuple[int, ...] = ()

    @property
    def _provider(self) -> str:
        return self.provider_label or self.name.replace("_", " ").title()

    @staticmethod
    def _proxy_kwargs() -> dict[str, Any]:
        """Return httpx-compatible proxy kwargs for the active campaign.

        Thin wrapper around :func:`nexusrecon.opsec.context.proxy_kwargs`
        ── kept as an instance-level method here so the migrated reference
        tools can read ``self._proxy_kwargs()`` idiomatically. Non-
        BaseHTTPTool subclasses (``holehe``, ``maigret``, etc.) should
        import ``proxy_kwargs`` directly from ``opsec.context``.
        """
        from nexusrecon.opsec.context import proxy_kwargs

        return proxy_kwargs()

    def classify_response(
        self,
        resp: httpx.Response,
        endpoint: str = "",
    ) -> ToolResult | None:
        """
        Convert provider error codes into explicit ``ToolResult`` failures.

        Returns ``None`` if the response is 2xx, or if its status code is
        in :attr:`soft_failure_codes` (caller continues processing).
        Returns a populated ``ToolResult(success=False)`` otherwise.

        - 401 / 403: auth failure. Includes a "check <KEY>" hint built
          from :attr:`requires_keys`.
        - 429: rate limit. Caller should back off.
        - Any other non-2xx: returns the status code in the error so the
          operator can correlate with provider status pages.
        """
        if resp.is_success:
            return None
        if resp.status_code in self.soft_failure_codes:
            return None

        endpoint_label = f" on {endpoint}" if endpoint else ""

        if resp.status_code in (401, 403):
            keys_hint = ""
            if self.requires_keys:
                names = " / ".join(k.upper() for k in self.requires_keys)
                keys_hint = f" - check {names}"
            return ToolResult(
                success=False,
                source=self.name,
                error=(
                    f"{self._provider} auth failure{endpoint_label} "
                    f"(HTTP {resp.status_code}){keys_hint}"
                ),
            )
        if resp.status_code == 429:
            return ToolResult(
                success=False,
                source=self.name,
                error=(
                    f"{self._provider} rate limit{endpoint_label} - "
                    f"back off and retry"
                ),
            )
        return ToolResult(
            success=False,
            source=self.name,
            error=f"{self._provider}{endpoint_label} returned HTTP {resp.status_code}",
        )


# Convenience for type hints
T = TypeVar("T", bound=OSINTTool)


# ── Transient-failure retry (Wave F-A4) ──────────────────────────────────────

#: HTTP statuses that are transient server-side failures worth retrying.
#: Deliberately excludes 429 (rate limit ── stealth profiles back off via the
#: rate limiter; auto-retrying would fight that) and all 4xx (deterministic).
TRANSIENT_RETRY_STATUSES: tuple[int, ...] = (502, 503, 504)


async def http_get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 2,
    backoff_base: float = 0.5,
    retry_statuses: tuple[int, ...] = TRANSIENT_RETRY_STATUSES,
    **kwargs: Any,
) -> httpx.Response:
    """GET with bounded exponential backoff on transient failures.

    Retries on the configured 5xx statuses and on connect/read timeouts and
    transport errors, up to ``retries`` extra attempts (so ``retries=2`` means
    three tries total). Backoff is ``backoff_base * 2**attempt`` plus a little
    jitter. Load-bearing passive sources (crt.sh, certstream) flap with 502s;
    a single retry usually clears them, and without it one upstream hiccup
    silently guts subdomain enumeration for the whole campaign.

    On exhaustion this returns the last response (e.g. the final 502) so the
    caller still classifies and reports it ── the retry never hides the
    failure, it just gives the upstream a chance to recover first. Timeouts /
    transport errors are re-raised after the last attempt so the caller's
    existing ``except`` path records the reason.
    """
    resp: httpx.Response | None = None
    for attempt in range(retries + 1):
        try:
            resp = await client.get(url, **kwargs)
        except (httpx.TimeoutException, httpx.TransportError):
            if attempt < retries:
                await asyncio.sleep(backoff_base * (2 ** attempt) + random.uniform(0, 0.25))
                continue
            raise
        if resp.status_code in retry_statuses and attempt < retries:
            await asyncio.sleep(backoff_base * (2 ** attempt) + random.uniform(0, 0.25))
            continue
        return resp
    return resp  # exhausted retries on a transient status; hand back the last
