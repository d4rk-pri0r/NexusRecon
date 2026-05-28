"""Wire-level OPSEC verification.

These tests assert that the OPSEC primitives (rate limiter, proxy
manager, UA pool) actually take effect when a tool runs through the
``ToolRegistry.execute()`` path ── not just that the primitives work in
isolation. The ROADMAP item this covers:

> OPSEC features (rate limiter / proxy / UA rotation) declared in
> config but not verified at the wire level.

Each test sets up a registry with a custom stealth profile + proxy
manager, fires one of the migrated reference tools (shodan etc.)
through ``registry.execute()``, captures the outbound HTTP request
stream, and asserts on what the wire saw.

What "wire" means here: we intercept at the ``httpx.AsyncClient`` layer
via ``respx`` so no real network traffic happens, but the assertions
are about the *requests the client would have sent*, including their
headers and the proxy kwargs passed at client construction.
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import httpx
import pytest
import respx
from httpx import Response

from nexusrecon.opsec.proxy import ProxyManager
from nexusrecon.opsec.rate_limiter import SourceRateLimiter
from nexusrecon.tools.intel.shodan_tool import ShodanTool
from nexusrecon.tools.intel.virustotal_tool import VirusTotalTool
from nexusrecon.tools.registry import ToolRegistry


def _build_registry_with_tool(tool, **opsec) -> ToolRegistry:
    """Helper: a fresh ToolRegistry with one tool registered and the
    given opsec primitives bound. Real ``ToolRegistry`` is normally a
    process-global singleton; we sidestep that by instantiating directly
    so each test gets isolated state."""
    registry = ToolRegistry()
    registry._tools[tool.name] = tool
    registry.set_campaign_context(
        scope_guard=None,  # type: ignore[arg-type]
        **opsec,
    )
    return registry


# ──────────────────────────────────────────────────────────────────────────
# Rate-limit enforcement at execute() time
# ──────────────────────────────────────────────────────────────────────────


class TestRateLimitWireEnforcement:
    """``registry.execute()`` awaits the rate limiter before tool.run().

    These tests use synthetic profiles with measurable rates so the test
    runtime stays in the 100-500ms range ── too slow to be a unit test,
    too fast to make CI grumpy."""

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_low_rate_limit_delays_consecutive_calls(self, _secret):
        """Rate=5 req/s on a single source means two back-to-back calls
        should accumulate ~200ms of wait between them. The first call
        spends the bucket; the second waits for refill."""
        # Capacity=1 makes this measurable: 1st call instant, 2nd waits 1/rate.
        limiter = SourceRateLimiter(
            source_rates={"shodan": 5.0, "default": 5.0},
            burst_detection_enabled=False,
        )
        # Force capacity to 1 on the bucket so the bucket is fully spent
        # after the first acquire.
        bucket = limiter._get_bucket("shodan")
        bucket.capacity = 1.0
        bucket._tokens = 1.0

        registry = _build_registry_with_tool(
            ShodanTool(), rate_limiter=limiter,
        )

        with respx.mock:
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            t0 = time.monotonic()
            await registry.execute("shodan", "example.com", "domain")
            await registry.execute("shodan", "example.com", "domain")
            elapsed = time.monotonic() - t0

        # Floor at 100ms ── 1/rate = 200ms, with scheduler slack we expect
        # at least 100ms accumulated wait for the second call.
        assert elapsed >= 0.1, f"expected rate-limit delay, elapsed={elapsed:.3f}s"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_no_rate_limiter_means_no_delay(self, _secret):
        """When no rate limiter is bound (None), the call should be near
        instant. Pin this so future "always-on rate limit" defaults don't
        creep in silently."""
        registry = _build_registry_with_tool(
            ShodanTool(), rate_limiter=None,
        )
        with respx.mock:
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            t0 = time.monotonic()
            await registry.execute("shodan", "example.com", "domain")
            elapsed = time.monotonic() - t0
        assert elapsed < 0.5

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_paranoid_profile_serialises_concurrent_tools(self, _secret):
        """Paranoid profile (capacity=1, low rate) makes ``asyncio.gather``
        of two tools run sequentially rather than in parallel.

        The point of paranoid mode is "1-thread sequential requests" ── if
        two tools fire in parallel through ``execute()`` and the rate
        limiter doesn't serialise them, the operator's claim of stealth
        is a lie."""
        # Custom limiter: capacity=1, rate=10 req/s so 2nd call waits ~100ms.
        # ``default`` covers both tools so they share the bucket.
        limiter = SourceRateLimiter(
            source_rates={"default": 10.0},
            burst_detection_enabled=False,
        )
        # Build a SHARED bucket the way the paranoid profile intends:
        # use ``available_tools=...`` lookup so both tool names map to
        # the same bucket via the ``default`` rate. The current
        # ``SourceRateLimiter`` uses per-tool-name buckets ── so to
        # observe sequencing we use the same name for both calls.

        registry = _build_registry_with_tool(
            ShodanTool(), rate_limiter=limiter,
        )
        # Pre-drain the shodan bucket so the very first call spends it.
        bucket = limiter._get_bucket("shodan")
        bucket.capacity = 1.0
        bucket._tokens = 1.0

        with respx.mock:
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            t0 = time.monotonic()
            await asyncio.gather(
                registry.execute("shodan", "example.com", "domain"),
                registry.execute("shodan", "example.com", "domain"),
                registry.execute("shodan", "example.com", "domain"),
            )
            elapsed = time.monotonic() - t0

        # 3 calls, rate=10, capacity=1: 1st instant, 2nd waits 100ms,
        # 3rd waits 100ms more ── floor 100ms for accumulated waits.
        assert elapsed >= 0.1, f"paranoid serialisation not observed: {elapsed:.3f}s"


# ──────────────────────────────────────────────────────────────────────────
# Proxy injection at the httpx layer
# ──────────────────────────────────────────────────────────────────────────


class TestProxyWireInjection:
    """When a ProxyManager is bound to the registry, the migrated HTTP
    tools must pass the proxy URL to ``httpx.AsyncClient(...)``.

    We capture the kwargs by patching ``httpx.AsyncClient.__init__`` and
    asserting on the recorded args ── more direct than introspecting an
    already-built client."""

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_shodan_uses_proxy_when_manager_set(self, _secret):
        proxy_mgr = ProxyManager(proxy_url="http://capture.local:8080")
        registry = _build_registry_with_tool(
            ShodanTool(), proxy_manager=proxy_mgr,
        )

        recorded_kwargs = []
        original_init = httpx.AsyncClient.__init__

        def _capture_init(self, *args, **kwargs):
            recorded_kwargs.append(kwargs)
            return original_init(self, *args, **kwargs)

        with respx.mock, patch.object(httpx.AsyncClient, "__init__", _capture_init):
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            await registry.execute("shodan", "example.com", "domain")

        # Find the AsyncClient init from shodan_tool (it constructs one).
        # The captured list includes any respx-internal clients too, so
        # we filter to the one with the shodan base_url.
        shodan_init = next(
            (k for k in recorded_kwargs if k.get("base_url") == "https://api.shodan.io"),
            None,
        )
        assert shodan_init is not None, "shodan never built an httpx client"
        assert shodan_init.get("proxy") == "http://capture.local:8080"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_virustotal_uses_proxy_when_manager_set(self, _secret):
        proxy_mgr = ProxyManager(proxy_url="socks5://127.0.0.1:9050")
        registry = _build_registry_with_tool(
            VirusTotalTool(), proxy_manager=proxy_mgr,
        )

        recorded_kwargs = []
        original_init = httpx.AsyncClient.__init__

        def _capture_init(self, *args, **kwargs):
            recorded_kwargs.append(kwargs)
            return original_init(self, *args, **kwargs)

        with respx.mock, patch.object(httpx.AsyncClient, "__init__", _capture_init):
            respx.get(url__startswith="https://www.virustotal.com").mock(
                return_value=Response(200, json={"data": {"attributes": {}}})
            )
            await registry.execute("virustotal", "example.com", "domain")

        vt_init = next(
            (k for k in recorded_kwargs
             if k.get("base_url") == "https://www.virustotal.com/api/v3"),
            None,
        )
        assert vt_init is not None
        assert vt_init.get("proxy") == "socks5://127.0.0.1:9050"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_no_proxy_when_manager_unbound(self, _secret):
        """Without a proxy manager bound, the httpx client must NOT have
        ``proxy`` set. Pin this so a regression doesn't accidentally
        force-proxy a campaign that didn't ask for one."""
        registry = _build_registry_with_tool(
            ShodanTool(), proxy_manager=None,
        )

        recorded_kwargs = []
        original_init = httpx.AsyncClient.__init__

        def _capture_init(self, *args, **kwargs):
            recorded_kwargs.append(kwargs)
            return original_init(self, *args, **kwargs)

        with respx.mock, patch.object(httpx.AsyncClient, "__init__", _capture_init):
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            await registry.execute("shodan", "example.com", "domain")

        shodan_init = next(
            (k for k in recorded_kwargs if k.get("base_url") == "https://api.shodan.io"),
            None,
        )
        assert shodan_init is not None
        assert "proxy" not in shodan_init

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_proxy_context_unwinds_between_calls(self, _secret):
        """After execute() returns, the context var must reset. A second
        call without a proxy manager must NOT inherit the first call's
        proxy. This is the 'no cross-campaign leak' invariant."""
        proxy_mgr = ProxyManager(proxy_url="http://campaign-a:8080")
        registry_a = _build_registry_with_tool(
            ShodanTool(), proxy_manager=proxy_mgr,
        )
        registry_b = _build_registry_with_tool(
            ShodanTool(), proxy_manager=None,
        )

        recorded = []
        original_init = httpx.AsyncClient.__init__

        def _capture_init(self, *args, **kwargs):
            recorded.append(kwargs)
            return original_init(self, *args, **kwargs)

        with respx.mock, patch.object(httpx.AsyncClient, "__init__", _capture_init):
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            await registry_a.execute("shodan", "example.com", "domain")
            await registry_b.execute("shodan", "example.com", "domain")

        shodan_inits = [k for k in recorded
                        if k.get("base_url") == "https://api.shodan.io"]
        assert len(shodan_inits) == 2
        assert shodan_inits[0].get("proxy") == "http://campaign-a:8080"
        assert "proxy" not in shodan_inits[1]


# ──────────────────────────────────────────────────────────────────────────
# UA rotation observed in actual outbound requests
# ──────────────────────────────────────────────────────────────────────────


class TestUARotationOnWire:
    """``random_ua()`` works in isolation (covered in test_opsec.py). This
    asserts that *over a series of tool invocations*, the UA seen at the
    wire layer actually varies. The ROADMAP target: "User-Agent values
    actually rotate per request (or per session)."

    We pick FullHunt because it puts ``random_ua()`` directly in its
    request headers ── the variation should be observable on every call.
    """

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_fullhunt_rotates_user_agent_across_calls(self, _secret):
        from nexusrecon.tools.intel.fullhunt_tool import FullHuntTool
        registry = _build_registry_with_tool(FullHuntTool())

        seen_uas: list[str] = []

        def _record_ua(request):
            seen_uas.append(request.headers.get("User-Agent", ""))
            return Response(200, json={"hosts": [], "metadata": {}})

        with respx.mock:
            respx.get(url__startswith="https://fullhunt.io").mock(
                side_effect=_record_ua,
            )
            for _ in range(20):
                await registry.execute("fullhunt", "example.com", "domain")

        distinct = set(seen_uas)
        assert len(seen_uas) == 20
        # Statistically: 20 picks from a ~35-entry pool ── expected distinct
        # is around 14. Floor at 5 to stay non-flaky on unlucky RNG runs.
        assert len(distinct) >= 5, (
            f"only {len(distinct)} distinct UAs across 20 calls ── rotation broken"
        )


# ──────────────────────────────────────────────────────────────────────────
# Source-routed proxy: per-tool proxy rules
# ──────────────────────────────────────────────────────────────────────────


class TestSourceRoutedProxy:
    """``ProxyManager.add_rule`` routes specific tools through specific
    proxies. Used for e.g. routing OSINT-sensitive providers through Tor
    while leaving rest-of-internet on a corporate proxy."""

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_per_source_rule_routes_correct_proxy(self, _secret):
        proxy_mgr = ProxyManager(
            proxy_url="http://corp:8080",
            tor_proxy="socks5://127.0.0.1:9050",
        )
        proxy_mgr.add_rule("shodan", "tor")  # shodan goes through Tor

        registry = _build_registry_with_tool(
            ShodanTool(), proxy_manager=proxy_mgr,
        )

        recorded = []
        original_init = httpx.AsyncClient.__init__

        def _capture_init(self, *args, **kwargs):
            recorded.append(kwargs)
            return original_init(self, *args, **kwargs)

        with respx.mock, patch.object(httpx.AsyncClient, "__init__", _capture_init):
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            await registry.execute("shodan", "example.com", "domain")

        shodan_init = next(
            (k for k in recorded if k.get("base_url") == "https://api.shodan.io"),
            None,
        )
        assert shodan_init is not None
        # Per-source rule wins over the default current proxy.
        assert shodan_init.get("proxy") == "socks5://127.0.0.1:9050"


# ──────────────────────────────────────────────────────────────────────────
# Non-BaseHTTPTool proxy support: holehe (and other library-driven tools)
# ──────────────────────────────────────────────────────────────────────────


class TestHolehyeProxyAndUaRotation:
    """Holehe inherits from OSINTTool, not BaseHTTPTool, but it still
    needs proxy support and per-call UA rotation. These tests pin both
    properties so a regression that re-froze the UA at module scope or
    re-removed ``**proxy_kwargs()`` from the AsyncClient ctor fails
    loud."""

    async def test_holehe_uses_proxy_when_manager_set(self):
        """Critical: when a proxy is bound, holehe's ~121 outbound
        probes must go through it. Pre-Day-7 fix they bypassed it."""
        try:
            from nexusrecon.tools.identity.holehe_tool import HoloTool
        except ImportError:
            pytest.skip("holehe library not installed in this env")

        proxy_mgr = ProxyManager(proxy_url="http://capture.local:8080")
        registry = _build_registry_with_tool(
            HoloTool(), proxy_manager=proxy_mgr,
        )

        recorded_kwargs = []
        original_init = httpx.AsyncClient.__init__

        def _capture_init(self, *args, **kwargs):
            recorded_kwargs.append(kwargs)
            return original_init(self, *args, **kwargs)

        # Holehe imports its own modules at runtime which would do real
        # network calls. Patch holehe.core.get_functions to return an
        # empty list so the only httpx.AsyncClient construction we see
        # is holehe's own ── then we can assert on its kwargs.
        with patch.object(httpx.AsyncClient, "__init__", _capture_init), \
             patch("holehe.core.import_submodules", return_value={}), \
             patch("holehe.core.get_functions", return_value=[]):
            await registry.execute("holehe", "test@example.com", "email")

        # At least one captured init should be holehe's (no base_url
        # set, since holehe uses the AsyncClient without a base URL).
        # We identify it by the absence of base_url and presence of
        # the follow_redirects=True flag holehe uses.
        holehe_init = next(
            (k for k in recorded_kwargs
             if "base_url" not in k and k.get("follow_redirects") is True),
            None,
        )
        assert holehe_init is not None, (
            "holehe never built an httpx client (or its init kwargs "
            "have changed shape ── update this test if so)"
        )
        assert holehe_init.get("proxy") == "http://capture.local:8080", (
            "holehe is NOT routing through the configured proxy ── this "
            "is the 'OPSEC declared but bypassed' regression Day 6 "
            "fixed. Make sure holehe_tool.py spreads **proxy_kwargs() "
            "into its httpx.AsyncClient(...) call."
        )

    async def test_holehe_rotates_ua_across_invocations(self):
        """A second invocation should see a different User-Agent in
        most cases ── statistically guaranteed across ~50 calls against
        a 35-entry pool. Pre-Day-7 fix every invocation in the same
        process used the same UA (frozen at module import)."""
        try:
            from nexusrecon.tools.identity.holehe_tool import HoloTool
        except ImportError:
            pytest.skip("holehe library not installed in this env")

        tool = HoloTool()
        registry = _build_registry_with_tool(tool)

        seen_uas = []
        original_init = httpx.AsyncClient.__init__

        def _capture_init(self, *args, **kwargs):
            headers = kwargs.get("headers", {})
            if "User-Agent" in headers and "base_url" not in kwargs:
                seen_uas.append(headers["User-Agent"])
            return original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", _capture_init), \
             patch("holehe.core.import_submodules", return_value={}), \
             patch("holehe.core.get_functions", return_value=[]):
            for _ in range(20):
                await registry.execute("holehe", "test@example.com", "email")

        distinct = set(seen_uas)
        assert len(seen_uas) == 20, (
            f"expected 20 holehe invocations, got {len(seen_uas)}"
        )
        # 20 picks from a ~35-entry pool: ~14 distinct expected. Floor
        # at 5 to dodge unlucky RNG runs.
        assert len(distinct) >= 5, (
            f"holehe only used {len(distinct)} distinct UAs across 20 "
            f"invocations ── module-level UA freeze regression?"
        )


# ──────────────────────────────────────────────────────────────────────────
# Structural test: every BaseHTTPTool subclass uses _proxy_kwargs
# ──────────────────────────────────────────────────────────────────────────


class TestProxySupportStructural:
    """Catch tools that are positioned to consume the proxy but don't.

    Every ``BaseHTTPTool`` subclass should call ``self._proxy_kwargs()``
    somewhere in its source. A subclass that doesn't is a silent
    regression: the OPSEC layer is bound but the tool ignores it. This
    test walks the source for each registered BaseHTTPTool subclass and
    asserts the call appears.

    Non-``BaseHTTPTool`` HTTP tools (holehe, maigret etc.) are caught by
    their dedicated wire tests above ── this test only covers the
    BaseHTTPTool inheritance chain."""

    def test_every_basehttp_tool_calls_proxy_kwargs(self):
        from inspect import getsourcefile
        from pathlib import Path

        import nexusrecon.tools.intel.censys_tool  # noqa: F401
        import nexusrecon.tools.intel.fullhunt_tool  # noqa: F401
        import nexusrecon.tools.intel.greynoise_tool  # noqa: F401

        # Import the tool modules so subclasses register themselves.
        import nexusrecon.tools.intel.shodan_tool  # noqa: F401
        import nexusrecon.tools.intel.virustotal_tool  # noqa: F401
        from nexusrecon.tools.base import BaseHTTPTool

        violators = []
        for cls in BaseHTTPTool.__subclasses__():
            # Skip private test fixtures (their source file is a test
            # module, not a tool ── they don't need to call
            # _proxy_kwargs to satisfy this contract).
            if cls.__name__.startswith("_"):
                continue
            src_file = getsourcefile(cls)
            if not src_file:
                continue
            # Skip anything that lives under tests/ ── another safety
            # net for test-helper classes that aren't real tools.
            if "/tests/" in src_file:
                continue
            src = Path(src_file).read_text()
            if "_proxy_kwargs()" not in src and "proxy_kwargs()" not in src:
                violators.append((cls.__name__, src_file))

        assert not violators, (
            "These BaseHTTPTool subclasses don't call _proxy_kwargs() ── "
            "they'll silently bypass the campaign proxy:\n"
            + "\n".join(f"  {name}  ({src})" for name, src in violators)
        )

    def test_every_basehttp_tool_sets_user_agent(self):
        """Mirror of the proxy structural check, for User-Agent.

        Until this guard landed, four BaseHTTPTool subclasses
        (shodan, virustotal, greynoise, censys) shipped with
        httpx's default ``python-httpx/<version>`` header ── a
        perfect fingerprint signal for any provider running WAF
        rules against scripted clients, and a flat contradiction
        of the OPSEC docs' "User-Agent rotation per request"
        promise. Pin the invariant so future subclasses can't
        regress."""
        from inspect import getsourcefile
        from pathlib import Path

        import nexusrecon.tools.intel.censys_tool  # noqa: F401
        import nexusrecon.tools.intel.fullhunt_tool  # noqa: F401
        import nexusrecon.tools.intel.greynoise_tool  # noqa: F401
        import nexusrecon.tools.intel.shodan_tool  # noqa: F401
        import nexusrecon.tools.intel.virustotal_tool  # noqa: F401
        from nexusrecon.tools.base import BaseHTTPTool

        violators = []
        for cls in BaseHTTPTool.__subclasses__():
            if cls.__name__.startswith("_"):
                continue
            src_file = getsourcefile(cls)
            if not src_file or "/tests/" in src_file:
                continue
            src = Path(src_file).read_text()
            # Accept either the helper invocation OR a literal UA
            # header (some tools build headers from a constant).
            if "random_ua" not in src and "User-Agent" not in src:
                violators.append((cls.__name__, src_file))

        assert not violators, (
            "These BaseHTTPTool subclasses ship with the default "
            "httpx User-Agent ── they leak `python-httpx/<ver>` "
            "to every provider, contradicting the rotating-UA "
            "OPSEC promise:\n"
            + "\n".join(f"  {name}  ({src})" for name, src in violators)
        )


# ──────────────────────────────────────────────────────────────────────────
# Stealth-profile jitter at execute() time
# ──────────────────────────────────────────────────────────────────────────


from dataclasses import replace as _dc_replace  # noqa: E402

from nexusrecon.opsec.profiles import get_profile  # noqa: E402


class TestStealthProfileJitterOnWire:
    """The :class:`StealthProfile` declares ``request_delay_min`` and
    ``request_delay_max`` but until the registry was wired to read
    them they were config-time fiction. Paranoid promised 3-10s
    jitter; the wire stayed deterministic at the rate-limiter's
    spacing.

    These tests pin the actual wire behavior:

      - When a profile with non-zero ``request_delay_*`` is bound,
        :meth:`ToolRegistry.execute` sleeps in that range BEFORE
        calling ``tool.run()``.
      - When no profile is bound (or ``loud`` with
        ``request_delay_max=0``), no jitter applies.
      - The jitter is applied IN ADDITION to the rate-limiter
        spacing (token bucket + jitter compose).
    """

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_synthetic_profile_jitter_observable(self, _secret):
        """A synthetic profile with delay_min=0.15s, delay_max=0.25s
        must add ~150-250ms per execute() call. Using small values
        keeps the test fast while still demonstrating the wire-
        level effect."""
        profile = _dc_replace(
            get_profile("normal"),
            request_delay_min=0.15,
            request_delay_max=0.25,
            source_rates={"default": 1000.0, "shodan": 1000.0},
            burst_detection_enabled=False,
        )
        registry = _build_registry_with_tool(
            ShodanTool(),
            stealth_profile=profile,
            rate_limiter=SourceRateLimiter(
                source_rates=profile.source_rates,
                burst_detection_enabled=False,
            ),
        )
        with respx.mock:
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0}),
            )
            t0 = time.monotonic()
            await registry.execute("shodan", "example.com", "domain")
            elapsed = time.monotonic() - t0

        # Floor is the declared min minus a small slack for scheduler
        # noise; ceiling is the declared max plus slack for the tool
        # body itself (with respx mocked the body is sub-ms).
        assert 0.1 <= elapsed <= 1.0, (
            f"jitter outside declared range: elapsed={elapsed:.3f}s "
            f"(expected ~0.15-0.25s + tool body)"
        )

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_loud_profile_does_not_add_jitter(self, _secret):
        """The loud profile sets ``request_delay_max=0``. The registry
        must short-circuit and add no delay ── operators who pick
        loud explicitly opted out of stealth latency."""
        profile = get_profile("loud")
        registry = _build_registry_with_tool(
            ShodanTool(),
            stealth_profile=profile,
        )
        with respx.mock:
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0}),
            )
            t0 = time.monotonic()
            await registry.execute("shodan", "example.com", "domain")
            elapsed = time.monotonic() - t0

        # No rate limiter, no jitter, mocked tool body → instant.
        assert elapsed < 0.2, (
            f"loud profile added unexpected delay: {elapsed:.3f}s"
        )

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_no_profile_means_no_jitter(self, _secret):
        """When the registry has no stealth profile bound (test
        harness default), execute() must NOT introduce jitter. Pin
        this so a future "always-jitter" default doesn't sneak in."""
        registry = _build_registry_with_tool(ShodanTool())  # no opsec
        with respx.mock:
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0}),
            )
            t0 = time.monotonic()
            await registry.execute("shodan", "example.com", "domain")
            elapsed = time.monotonic() - t0

        assert elapsed < 0.2, (
            f"no-profile path added unexpected delay: {elapsed:.3f}s"
        )

    async def test_paranoid_profile_jitter_range_documented(self):
        """The paranoid profile's promised range is 3-10s. This pins
        the declaration (the prior test runs a synthetic profile so
        unit-test wall-clock stays low; this confirms the SHIPPED
        profile keeps the documented range)."""
        profile = get_profile("paranoid")
        assert profile.request_delay_min == 3.0
        assert profile.request_delay_max == 10.0

    async def test_zero_min_zero_max_is_safe(self):
        """``random.uniform(0, 0)`` returns 0.0 ── verify the
        registry's check tolerates a zero-zero range without
        adding spurious work."""
        profile = _dc_replace(
            get_profile("normal"),
            request_delay_min=0.0,
            request_delay_max=0.0,
        )
        registry = _build_registry_with_tool(
            ShodanTool(), stealth_profile=profile,
        )
        with respx.mock, patch(
            "nexusrecon.core.config.NexusConfig.get_secret",
            return_value="fake-key",
        ):
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0}),
            )
            t0 = time.monotonic()
            await registry.execute("shodan", "example.com", "domain")
            elapsed = time.monotonic() - t0
        assert elapsed < 0.2


# ──────────────────────────────────────────────────────────────────────────
# OPSEC manifest — single integration assertion across primitives
# ──────────────────────────────────────────────────────────────────────────


class TestOpsecManifest:
    """Single end-to-end test verifying that when paranoid is bound
    to the registry, the wire reflects ALL of:

      - Proxy URL injected into the httpx client.
      - User-Agent rotates across calls.
      - Rate limiter spaces calls per source.
      - Profile jitter adds non-zero per-call delay.

    The other test classes pin each primitive in isolation. This
    one pins the composition ── the assertion is that none of them
    bypass each other when stacked. Uses a synthetic-rate profile
    to keep wall-clock manageable."""

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_all_primitives_take_effect_in_one_run(self, _secret):
        profile = _dc_replace(
            get_profile("paranoid"),
            # Compress the wall-clock so the test runs in <1s.
            request_delay_min=0.05,
            request_delay_max=0.10,
            source_rates={"default": 1000.0, "shodan": 1000.0},
            burst_detection_enabled=False,
        )
        proxy_mgr = ProxyManager(
            proxy_url="http://127.0.0.1:18080",
        )
        rate_limiter = SourceRateLimiter(
            source_rates=profile.source_rates,
            burst_detection_enabled=False,
        )
        registry = _build_registry_with_tool(
            ShodanTool(),
            stealth_profile=profile,
            rate_limiter=rate_limiter,
            proxy_manager=proxy_mgr,
        )

        # Capture the proxy kwarg at client init + UA header at
        # request-time (the two live in different layers — proxy is
        # an AsyncClient construction kwarg, UA is a per-request
        # header — so we hook both).
        seen_proxies: list[str | None] = []
        seen_uas: set[str] = set()

        real_init = httpx.AsyncClient.__init__

        def _record_init(self, *args, **kwargs):
            seen_proxies.append(kwargs.get("proxy"))
            return real_init(self, *args, **kwargs)

        def _record_request(request: httpx.Request):
            ua = request.headers.get("User-Agent", "")
            if ua:
                seen_uas.add(ua)
            return Response(200, json={"matches": [], "total": 0})

        N = 4
        with respx.mock, patch.object(
            httpx.AsyncClient, "__init__", _record_init,
        ):
            respx.get(url__startswith="https://api.shodan.io").mock(
                side_effect=_record_request,
            )
            t0 = time.monotonic()
            for _ in range(N):
                await registry.execute("shodan", "example.com", "domain")
            elapsed = time.monotonic() - t0

        # Proxy: every call carried the manager's URL.
        assert all(p == "http://127.0.0.1:18080" for p in seen_proxies), (
            f"some calls bypassed the proxy: {seen_proxies}"
        )
        # UA: at least 2 distinct values across 4 calls. Random
        # sampling could theoretically collide on a tiny pool, but
        # the default pool is 14+ entries so 4 picks with collision
        # are vanishingly rare.
        assert len(seen_uas) >= 2, (
            f"UA rotation absent across {N} calls: only saw {seen_uas}"
        )
        # Jitter: N calls × 0.05s floor = ~0.2s floor. We can't
        # tighten the ceiling without flakiness, but the floor is
        # the load-bearing assertion ── if jitter is silently
        # disabled, elapsed collapses to <0.1s.
        assert elapsed >= 0.15, (
            f"jitter not observed across {N} calls: elapsed={elapsed:.3f}s"
        )


# ──────────────────────────────────────────────────────────────────────────
# Production binding: build_opsec actually wires the stack into the registry
# ──────────────────────────────────────────────────────────────────────────


from types import SimpleNamespace  # noqa: E402

from nexusrecon.opsec.setup import ProxyRequiredError, build_opsec  # noqa: E402
from nexusrecon.tools.base import (  # noqa: E402
    Category,
    OSINTTool,
    Tier,
    ToolResult,
)


def _fake_scope(profile: str = "high", require_proxy: bool = False):
    return SimpleNamespace(
        constraints=SimpleNamespace(stealth_profile=profile, require_proxy=require_proxy)
    )


def _fake_config(proxy_url=None, tor_proxy=None):
    return SimpleNamespace(proxy_url=proxy_url, tor_proxy=tor_proxy)


class _CtxProbe(OSINTTool):
    name = "ctx_probe"
    tier = Tier.T0
    category = Category.WEB
    requires_keys = []
    target_types = ["domain"]
    seen: list[dict] = []

    async def run(self, target, **kwargs):
        from nexusrecon.opsec.context import proxy_kwargs
        type(self).seen.append(proxy_kwargs())
        return ToolResult(success=True, source=self.name, data={}, result_count=0)


class TestProductionOpsecBinding:
    """The CLI/TUI used to bind only scope_guard/cache/audit, leaving the
    OPSEC stack inert in production despite passing wire tests. build_opsec
    is the helper both now use; these pin that it produces a live stack."""

    def test_build_opsec_returns_profile_rate_limiter_proxy(self):
        from nexusrecon.opsec.rate_limiter import RateLimiter
        opsec = build_opsec(_fake_scope("paranoid"), _fake_config(proxy_url="socks5://127.0.0.1:9050"))
        assert opsec["stealth_profile"].name.value == "paranoid"
        assert isinstance(opsec["rate_limiter"], RateLimiter)
        assert opsec["proxy_manager"].available is True

    def test_no_proxy_configured_means_unavailable(self):
        opsec = build_opsec(_fake_scope("loud"), _fake_config())
        assert opsec["proxy_manager"].available is False

    def test_require_proxy_without_proxy_raises(self):
        with pytest.raises(ProxyRequiredError):
            build_opsec(_fake_scope("paranoid", require_proxy=True), _fake_config())

    def test_require_proxy_with_proxy_ok(self):
        opsec = build_opsec(
            _fake_scope("paranoid", require_proxy=True),
            _fake_config(proxy_url="http://127.0.0.1:8080"),
        )
        assert opsec["proxy_manager"].available is True

    def test_bound_stack_applies_proxy_on_execute(self):
        # End-to-end: the build_opsec output, when bound, makes execute()
        # propagate the configured proxy to the tool (the production path).
        reg = ToolRegistry()
        reg.register(_CtxProbe)
        _CtxProbe.seen = []
        opsec = build_opsec(_fake_scope("loud"), _fake_config(proxy_url="http://proxy.test:3128"))
        reg.set_campaign_context(scope_guard=None, **opsec)
        asyncio.run(reg.execute("ctx_probe", "example.com"))
        assert _CtxProbe.seen[-1] == {"proxy": "http://proxy.test:3128"}
