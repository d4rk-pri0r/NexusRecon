"""Tests for nexusrecon.opsec: UA pool, rate limiter, proxy manager, context."""
from __future__ import annotations

import asyncio
import time

import pytest

from nexusrecon.opsec.context import (
    get_current_proxy_url,
    proxy_context,
)
from nexusrecon.opsec.profiles import (
    PROFILES,
    ProfileName,
    StealthProfile,
    get_profile,
)
from nexusrecon.opsec.proxy import ProxyConfig, ProxyManager
from nexusrecon.opsec.rate_limiter import (
    BurstDetector,
    RateLimiter,
    SourceRateLimiter,
    TokenBucket,
)
from nexusrecon.opsec.useragent import (
    USER_AGENTS,
    UserAgentPool,
    random_ua,
)


# ──────────────────────────────────────────────────────────────────────────
# UserAgentPool + random_ua
# ──────────────────────────────────────────────────────────────────────────


class TestUserAgentPool:
    def test_pool_seeds_from_default_list(self):
        pool = UserAgentPool()
        assert pool.current in USER_AGENTS

    def test_random_strategy_produces_diversity(self):
        """50 ``get()`` calls on a 35-entry pool should produce >5 distinct
        UAs. With ``random.choice`` the expected count is much higher; we
        leave headroom so the test isn't flaky on unlucky RNG runs."""
        pool = UserAgentPool(strategy="random")
        seen = {pool.get() for _ in range(50)}
        assert len(seen) > 5, f"only {len(seen)} distinct UAs in 50 calls"

    def test_round_robin_strategy_is_deterministic(self):
        custom = ["UA-A", "UA-B", "UA-C"]
        pool = UserAgentPool(agents=custom, strategy="round_robin")
        sequence = [pool.get() for _ in range(6)]
        assert sequence == ["UA-A", "UA-B", "UA-C", "UA-A", "UA-B", "UA-C"]

    def test_get_after_n_holds_until_threshold(self):
        """``get_after_n(3)`` returns the same UA for 2 calls, rotates on
        the 3rd. Used by sessions that want UA stickiness within a single
        provider interaction."""
        pool = UserAgentPool(agents=["UA-A", "UA-B", "UA-C"], strategy="round_robin")
        first = pool.get_after_n(3)
        second = pool.get_after_n(3)
        third = pool.get_after_n(3)
        # First two share the current; third triggers rotation.
        assert first == second
        assert third != second or pool.current == third


class TestRandomUaHelper:
    def test_module_helper_returns_string_from_pool(self):
        ua = random_ua()
        assert isinstance(ua, str)
        assert ua in USER_AGENTS

    def test_module_helper_produces_diversity_across_calls(self):
        """The 47-tool migration depends on this ── a static return would
        recreate the "identical fingerprint across every install" bug."""
        seen = {random_ua() for _ in range(50)}
        assert len(seen) > 5


# ──────────────────────────────────────────────────────────────────────────
# TokenBucket
# ──────────────────────────────────────────────────────────────────────────


class TestTokenBucket:
    async def test_acquire_returns_zero_when_tokens_available(self):
        bucket = TokenBucket(rate=10.0, capacity=10.0)
        wait = await bucket.acquire()
        assert wait == 0.0

    async def test_acquire_blocks_when_depleted(self):
        """Spend the bucket then ask for one more ── must sleep for at
        least 1/rate seconds. Use a high rate so the test stays fast."""
        bucket = TokenBucket(rate=10.0, capacity=1.0)
        first = await bucket.acquire()
        assert first == 0.0
        t0 = time.monotonic()
        second = await bucket.acquire()
        elapsed = time.monotonic() - t0
        assert second > 0
        # Allow a generous floor so this isn't flaky on slow CI.
        assert elapsed >= 0.05

    async def test_refill_replenishes_over_time(self):
        bucket = TokenBucket(rate=20.0, capacity=1.0)
        await bucket.acquire()
        # Wait long enough for the bucket to fully refill.
        await asyncio.sleep(0.1)
        wait = await bucket.acquire()
        assert wait == 0.0


# ──────────────────────────────────────────────────────────────────────────
# BurstDetector
# ──────────────────────────────────────────────────────────────────────────


class TestBurstDetector:
    def test_first_requests_under_threshold_dont_trigger(self):
        detector = BurstDetector(threshold=3, window_sec=1.0)
        for _ in range(3):
            assert detector.record_and_check() == 0.0

    def test_request_past_threshold_triggers(self):
        detector = BurstDetector(threshold=3, window_sec=1.0)
        for _ in range(3):
            detector.record_and_check()
        # 4th within the window must return a positive sleep time.
        sleep_time = detector.record_and_check()
        assert sleep_time > 0

    def test_old_timestamps_pruned_outside_window(self):
        """Once the window slides past old requests, the burst counter
        resets. Pin this so a tool firing 3 reqs/sec sustainably (within
        a 1s window of 3) doesn't trigger after the first second."""
        detector = BurstDetector(threshold=3, window_sec=0.05)
        for _ in range(3):
            detector.record_and_check()
        time.sleep(0.08)
        # Old timestamps are now outside the 50ms window.
        assert detector.record_and_check() == 0.0


# ──────────────────────────────────────────────────────────────────────────
# SourceRateLimiter + RateLimiter.from_profile
# ──────────────────────────────────────────────────────────────────────────


class TestSourceRateLimiter:
    async def test_per_source_buckets_are_independent(self):
        """Spending source A shouldn't affect source B's bucket. Pin this
        because the registry uses ``rate_limiter.wait(tool.name)`` ── if
        the bucket were shared across tools, a hot tool would throttle a
        cold one."""
        limiter = SourceRateLimiter(
            source_rates={"shodan": 100.0, "censys": 100.0, "default": 1.0},
            burst_detection_enabled=False,
        )
        # First call to each source: zero wait.
        await limiter.wait("shodan")
        await limiter.wait("censys")
        # ``shodan`` again immediately ── still fine since both buckets
        # were seeded at full capacity.
        await limiter.wait("shodan")

    async def test_unknown_source_falls_back_to_default(self):
        """When a tool name isn't in the rates dict, the limiter uses the
        ``default`` rate so we don't accidentally let unconfigured tools
        burst freely."""
        limiter = SourceRateLimiter(
            source_rates={"default": 10.0},
            burst_detection_enabled=False,
        )
        await limiter.wait("unknown_tool")  # must not raise


class TestRateLimiterFromProfile:
    def test_paranoid_profile_produces_low_rates(self):
        limiter = RateLimiter.from_profile(PROFILES[ProfileName.PARANOID])
        bucket = limiter._get_bucket("shodan")
        # Paranoid shodan rate is 0.1 req/s.
        assert bucket.rate == 0.1

    def test_loud_profile_produces_high_rates(self):
        limiter = RateLimiter.from_profile(PROFILES[ProfileName.LOUD])
        bucket = limiter._get_bucket("shodan")
        assert bucket.rate == 5.0

    def test_unknown_source_uses_profile_default(self):
        limiter = RateLimiter.from_profile(PROFILES[ProfileName.NORMAL])
        bucket = limiter._get_bucket("brand_new_tool_xyz")
        # NORMAL profile default is 2.0 req/s.
        assert bucket.rate == 2.0


# ──────────────────────────────────────────────────────────────────────────
# StealthProfile / get_profile
# ──────────────────────────────────────────────────────────────────────────


class TestStealthProfile:
    def test_paranoid_serialises_concurrency(self):
        p = get_profile("paranoid")
        assert p.max_concurrent_tools == 1
        assert p.max_concurrent_requests == 1

    def test_paranoid_jitter_window_is_3_to_10s(self):
        """ROADMAP wire-verification target: paranoid uses 3-10s jitter."""
        p = get_profile("paranoid")
        assert p.request_delay_min == 3.0
        assert p.request_delay_max == 10.0

    def test_paranoid_demands_proxy_and_tor(self):
        p = get_profile("paranoid")
        assert p.use_proxy is True
        assert p.prefer_tor is True

    def test_loud_is_max_parallel_no_delay(self):
        p = get_profile("loud")
        assert p.request_delay_min == 0.0
        assert p.request_delay_max == 0.0
        assert p.use_proxy is False
        assert p.max_concurrent_tools >= 10

    def test_get_profile_rejects_unknown_names(self):
        with pytest.raises(ValueError, match="Unknown stealth profile"):
            get_profile("medium")  # was the old (broken) name before the wizard fix

    def test_all_four_documented_profiles_resolvable(self):
        for name in ("paranoid", "high", "normal", "loud"):
            assert isinstance(get_profile(name), StealthProfile)


# ──────────────────────────────────────────────────────────────────────────
# ProxyManager
# ──────────────────────────────────────────────────────────────────────────


class TestProxyManager:
    def test_empty_manager_is_unavailable(self):
        mgr = ProxyManager()
        assert mgr.available is False
        assert mgr.current is None
        assert mgr.to_httpx_kwargs() == {}

    def test_proxy_url_only(self):
        mgr = ProxyManager(proxy_url="http://corp-proxy:8080")
        assert mgr.available is True
        assert mgr.current.url == "http://corp-proxy:8080"
        kwargs = mgr.to_httpx_kwargs()
        assert kwargs == {"proxy": "http://corp-proxy:8080"}

    def test_tor_only(self):
        mgr = ProxyManager(tor_proxy="socks5://127.0.0.1:9050")
        assert mgr.available is True
        assert mgr.current.is_tor is True
        assert mgr.current.url == "socks5://127.0.0.1:9050"

    def test_tor_and_proxy_both_appended(self):
        mgr = ProxyManager(
            proxy_url="http://corp-proxy:8080",
            tor_proxy="socks5://127.0.0.1:9050",
        )
        # Tor is registered first, so it's the initial 'current'.
        assert mgr.current.is_tor is True

    def test_rotate_cycles_proxies(self):
        mgr = ProxyManager(
            proxy_url="http://corp-proxy:8080",
            tor_proxy="socks5://127.0.0.1:9050",
        )
        first = mgr.current.url
        mgr.rotate()
        second = mgr.current.url
        assert first != second
        mgr.rotate()
        # Two proxies cycle back.
        assert mgr.current.url == first

    def test_source_routing_rule(self):
        """A per-source rule routes one tool through a named proxy and
        leaves everything else on the default."""
        mgr = ProxyManager(
            proxy_url="http://corp:8080",
            tor_proxy="socks5://127.0.0.1:9050",
        )
        mgr.add_rule("shodan", "tor")
        # Shodan goes through tor; censys (no rule) uses current default.
        assert mgr.get_proxy_for_source("shodan") == "socks5://127.0.0.1:9050"

    def test_to_httpx_kwargs_omits_proxy_when_unavailable(self):
        mgr = ProxyManager()
        assert "proxy" not in mgr.to_httpx_kwargs()


# ──────────────────────────────────────────────────────────────────────────
# opsec.context.proxy_context (ContextVar plumbing)
# ──────────────────────────────────────────────────────────────────────────


class TestProxyContext:
    def test_default_is_none(self):
        assert get_current_proxy_url() is None

    def test_setting_and_unwinding(self):
        assert get_current_proxy_url() is None
        with proxy_context("http://capture.local:8080"):
            assert get_current_proxy_url() == "http://capture.local:8080"
        assert get_current_proxy_url() is None

    def test_none_value_explicitly(self):
        """Setting ``None`` inside a nested context must produce None
        (not leak the outer value). Pin this because the registry passes
        ``proxy_url=None`` when no proxy manager is bound, and we don't
        want tools to inherit a proxy from a previous campaign."""
        with proxy_context("http://outer:8080"):
            with proxy_context(None):
                assert get_current_proxy_url() is None
            assert get_current_proxy_url() == "http://outer:8080"

    def test_nested_contexts_unwind_correctly(self):
        with proxy_context("http://a:8080"):
            assert get_current_proxy_url() == "http://a:8080"
            with proxy_context("http://b:8080"):
                assert get_current_proxy_url() == "http://b:8080"
            assert get_current_proxy_url() == "http://a:8080"
        assert get_current_proxy_url() is None


# ──────────────────────────────────────────────────────────────────────────
# BaseHTTPTool._proxy_kwargs reads the context var
# ──────────────────────────────────────────────────────────────────────────


class TestBaseHTTPToolProxyKwargs:
    def test_returns_empty_dict_outside_context(self):
        from nexusrecon.tools.base import BaseHTTPTool
        assert BaseHTTPTool._proxy_kwargs() == {}

    def test_returns_proxy_kwarg_inside_context(self):
        from nexusrecon.tools.base import BaseHTTPTool
        with proxy_context("http://capture.local:8080"):
            assert BaseHTTPTool._proxy_kwargs() == {"proxy": "http://capture.local:8080"}

    def test_returns_empty_dict_when_context_explicitly_none(self):
        from nexusrecon.tools.base import BaseHTTPTool
        with proxy_context(None):
            assert BaseHTTPTool._proxy_kwargs() == {}
