"""Optional JA3 / TLS-fingerprint impersonation client.

Roadmap reference: ``ROADMAP.md`` beta blocker "JA3 / TLS-fingerprint
client" -- outbound TLS otherwise looks like one Python httpx version to
every provider. The capability is an OPT-IN ``make_http_client`` factory
that, when a ``tls_impersonate`` target is active AND the optional
``curl_cffi`` extra is installed, routes OPSEC-aware tools through
curl_cffi's browser-impersonating client instead of plain httpx.

These tests pin the full fallback matrix and the hard constraints:

  - default install (flag off) is byte-for-byte today's httpx path;
  - flag-on-but-extra-missing degrades to httpx and says so once;
  - flag-on-with-extra builds the impersonating adapter, preserving
    proxy + User-Agent + base_url + timeout and translating curl_cffi
    transport/timeout errors to their httpx equivalents so the retry
    helper keeps working;
  - the ContextVar unwinds (no cross-campaign leak);
  - the profile/config gate ships closed;
  - curl_cffi is never promoted to a hard dependency.

Everything is CI-safe: the impersonation construction/wire tests use a
fake AsyncSession (no real network, no real curl_cffi required), and the
one real-curl_cffi round-trip is localhost-only and skips when the extra
is absent.
"""
from __future__ import annotations

import json
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from nexusrecon.opsec.context import (
    get_current_tls_impersonate,
    tls_impersonate_context,
)
from nexusrecon.tools import base
from nexusrecon.tools.base import make_http_client

# ──────────────────────────────────────────────────────────────────────
# Fakes
# ──────────────────────────────────────────────────────────────────────


class _FakeResp:
    """A curl_cffi-Response-shaped stand-in (status_code/ok/json, no
    is_success -- that is the httpx-ism the adapter synthesises)."""

    def __init__(self, status_code: int = 200, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = {}
        self.text = ""
        self.content = b""
        self.url = ""
        self.ok = 200 <= status_code < 300

    def json(self):
        return self._payload


class _FakeAsyncSession:
    """Records construction kwargs and requests; stands in for
    ``curl_cffi.requests.AsyncSession`` so the impersonation path is
    exercised with no real curl_cffi and no network."""

    instances: list[_FakeAsyncSession] = []

    def __init__(self, **kwargs):
        self.init_kwargs = kwargs
        self.requests: list[tuple] = []
        self.closed = False
        _FakeAsyncSession.instances.append(self)

    async def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        return _FakeResp(200, {"matches": [], "total": 0})

    async def close(self):
        self.closed = True


@pytest.fixture
def fake_curl(monkeypatch):
    """Force the impersonation path on with a fake AsyncSession bound, so
    these tests run identically whether or not curl_cffi is installed."""
    _FakeAsyncSession.instances.clear()
    monkeypatch.setattr(base, "_HAS_CURL_CFFI", True)
    monkeypatch.setattr(base, "AsyncSession", _FakeAsyncSession)
    return _FakeAsyncSession


# ──────────────────────────────────────────────────────────────────────
# Fallback matrix
# ──────────────────────────────────────────────────────────────────────


class TestFallbackMatrix:
    def test_flag_off_returns_plain_httpx(self):
        """No impersonation target active: the literal httpx.AsyncClient,
        so the default install and existing respx tests are unaffected."""
        client = make_http_client(base_url="https://x", timeout=5.0)
        assert isinstance(client, httpx.AsyncClient)

    def test_flag_on_lib_absent_degrades_and_warns(self, monkeypatch):
        """Operator asked for impersonation but curl_cffi is missing: must
        return plain httpx AND log once so they know they did not get it."""
        from structlog.testing import capture_logs
        monkeypatch.setattr(base, "_HAS_CURL_CFFI", False)
        monkeypatch.setattr(base, "_tls_fallback_warned", False)
        with capture_logs() as cap:
            with tls_impersonate_context("chrome120"):
                client = make_http_client(base_url="https://x")
        assert isinstance(client, httpx.AsyncClient)
        assert any("curl_cffi" in e.get("event", "") for e in cap), (
            "flag-on-but-missing-extra must warn about curl_cffi"
        )

    def test_flag_on_lib_absent_warns_only_once(self, monkeypatch):
        from structlog.testing import capture_logs
        monkeypatch.setattr(base, "_HAS_CURL_CFFI", False)
        monkeypatch.setattr(base, "_tls_fallback_warned", False)
        with capture_logs() as cap:
            with tls_impersonate_context("chrome120"):
                make_http_client()
                make_http_client()
                make_http_client()
        warnings = [e for e in cap if "curl_cffi" in e.get("event", "")]
        assert len(warnings) == 1, f"expected one warning, got {len(warnings)}"

    def test_flag_on_lib_present_builds_adapter(self, fake_curl):
        with tls_impersonate_context("chrome120"):
            client = make_http_client(base_url="https://x")
        assert isinstance(client, base._ImpersonateClient)
        assert len(fake_curl.instances) == 1
        assert fake_curl.instances[0].init_kwargs.get("impersonate") == "chrome120"


# ──────────────────────────────────────────────────────────────────────
# Adapter kwarg mapping
# ──────────────────────────────────────────────────────────────────────


class TestAdapterKwargMapping:
    def test_preserves_proxy_headers_timeout_baseurl(self, fake_curl):
        with tls_impersonate_context("chrome120"):
            make_http_client(
                base_url="https://api.example.com",
                headers={"User-Agent": "UA-X", "x-apikey": "k"},
                timeout=15.0,
                proxy="http://capture.local:8080",
            )
        kw = fake_curl.instances[0].init_kwargs
        assert kw["base_url"] == "https://api.example.com"
        assert kw["headers"]["User-Agent"] == "UA-X"
        assert kw["timeout"] == 15.0
        # proxy passes through unchanged: httpx and curl_cffi both accept it.
        assert kw["proxy"] == "http://capture.local:8080"
        assert kw["impersonate"] == "chrome120"

    def test_remaps_follow_redirects_and_drops_http2(self, fake_curl):
        with tls_impersonate_context("chrome120"):
            make_http_client(follow_redirects=True, http2=True, timeout=10.0)
        kw = fake_curl.instances[0].init_kwargs
        assert kw.get("allow_redirects") is True
        assert "follow_redirects" not in kw
        assert "http2" not in kw, "httpx-only kwarg must be dropped under curl_cffi"


# ──────────────────────────────────────────────────────────────────────
# Response shim (is_success synthesis)
# ──────────────────────────────────────────────────────────────────────


class TestResponseShim:
    def test_is_success_synthesised(self):
        ok = base._ImpersonateResponse(_FakeResp(204))
        bad = base._ImpersonateResponse(_FakeResp(404))
        assert ok.is_success is True
        assert ok.is_error is False
        assert bad.is_success is False
        assert bad.is_error is True

    def test_attributes_delegate_to_raw(self):
        resp = base._ImpersonateResponse(_FakeResp(200, {"k": "v"}))
        assert resp.status_code == 200
        assert resp.json() == {"k": "v"}

    def test_raise_for_status(self):
        base._ImpersonateResponse(_FakeResp(200)).raise_for_status()  # no raise
        with pytest.raises(httpx.HTTPError):
            base._ImpersonateResponse(_FakeResp(500)).raise_for_status()


# ──────────────────────────────────────────────────────────────────────
# Exception translation (so http_get_with_retry keeps working)
# ──────────────────────────────────────────────────────────────────────


class TestExceptionTranslation:
    async def test_curl_timeout_becomes_httpx_timeout(self, fake_curl):
        from curl_cffi.requests.errors import RequestsError

        class _TimingOutSession(_FakeAsyncSession):
            async def request(self, method, url, **kwargs):
                err = RequestsError("operation timed out")
                err.code = base._ImpersonateClient._CURL_TIMEOUT_CODE
                raise err

        with patch.object(base, "AsyncSession", _TimingOutSession):
            with tls_impersonate_context("chrome120"):
                client = make_http_client(base_url="https://x")
                with pytest.raises(httpx.TimeoutException):
                    await client.get("/y")

    async def test_curl_transport_error_becomes_httpx_transport(self, fake_curl):
        from curl_cffi.requests.errors import RequestsError

        class _FailingSession(_FakeAsyncSession):
            async def request(self, method, url, **kwargs):
                err = RequestsError("connection refused")
                err.code = 7  # CURLE_COULDNT_CONNECT, not a timeout
                raise err

        with patch.object(base, "AsyncSession", _FailingSession):
            with tls_impersonate_context("chrome120"):
                client = make_http_client(base_url="https://x")
                with pytest.raises(httpx.TransportError):
                    await client.get("/y")


# ──────────────────────────────────────────────────────────────────────
# ContextVar lifecycle
# ──────────────────────────────────────────────────────────────────────


class TestContextVarLifecycle:
    def test_context_unwinds(self):
        assert get_current_tls_impersonate() is None
        with tls_impersonate_context("chrome120"):
            assert get_current_tls_impersonate() == "chrome120"
        assert get_current_tls_impersonate() is None

    def test_none_target_is_noop_returns_httpx(self, fake_curl):
        with tls_impersonate_context(None):
            client = make_http_client()
        assert isinstance(client, httpx.AsyncClient)
        assert fake_curl.instances == []


# ──────────────────────────────────────────────────────────────────────
# Gate defaults (ships closed)
# ──────────────────────────────────────────────────────────────────────


class TestGateShipsClosed:
    def test_all_profiles_default_to_no_impersonation(self):
        from nexusrecon.opsec.profiles import get_profile
        for name in ("paranoid", "high", "normal", "loud"):
            assert get_profile(name).tls_impersonate is None, (
                f"profile {name} ships with impersonation ON"
            )

    def test_config_defaults_off_and_reads_env(self, monkeypatch):
        from nexusrecon.core.config import NexusConfig
        # Default: off.
        monkeypatch.delenv("NEXUS_TLS_IMPERSONATE", raising=False)
        assert NexusConfig().tls_impersonate is None
        # Env override is read.
        monkeypatch.setenv("NEXUS_TLS_IMPERSONATE", "chrome120")
        assert NexusConfig().tls_impersonate == "chrome120"


# ──────────────────────────────────────────────────────────────────────
# Dependency hygiene
# ──────────────────────────────────────────────────────────────────────


class TestDependencyHygiene:
    def test_curl_cffi_is_optional_not_core(self):
        """curl_cffi must live ONLY under optional-dependencies.tls, never
        in the core dependency list, so the default install stays light."""
        root = Path(__file__).resolve().parents[2]
        data = tomllib.loads((root / "pyproject.toml").read_text())
        core = " ".join(data["project"]["dependencies"]).lower()
        assert "curl_cffi" not in core and "curl-cffi" not in core, (
            "curl_cffi leaked into core dependencies; it must stay an extra"
        )
        tls_extra = " ".join(
            data["project"]["optional-dependencies"]["tls"]
        ).lower()
        assert "curl_cffi" in tls_extra or "curl-cffi" in tls_extra


# ──────────────────────────────────────────────────────────────────────
# Wire preservation through registry.execute()
# ──────────────────────────────────────────────────────────────────────


class TestImpersonationWire:
    """A profile's tls_impersonate must reach the adapter through
    registry.execute() while the campaign proxy and rotating UA are still
    applied -- impersonation must not silently drop the other OPSEC."""

    async def test_profile_impersonate_reaches_adapter_with_proxy_and_ua(
        self, fake_curl,
    ):
        from nexusrecon.opsec.profiles import ProfileName, StealthProfile
        from nexusrecon.opsec.proxy import ProxyManager
        from nexusrecon.tools.intel.shodan_tool import ShodanTool
        from nexusrecon.tools.registry import ToolRegistry

        profile = StealthProfile(
            name=ProfileName.PARANOID,
            tls_impersonate="chrome120",
            request_delay_min=0.0,
            request_delay_max=0.0,  # keep the test fast (no jitter)
        )
        proxy_mgr = ProxyManager(proxy_url="http://capture.local:8080")

        registry = ToolRegistry()
        registry._tools["shodan"] = ShodanTool()
        registry.set_campaign_context(
            scope_guard=None,  # type: ignore[arg-type]
            proxy_manager=proxy_mgr,
            stealth_profile=profile,
        )

        with patch(
            "nexusrecon.core.config.NexusConfig.get_secret",
            return_value="fake-key",
        ):
            await registry.execute("shodan", "example.com", "domain")

        sess = next(
            (s for s in fake_curl.instances
             if s.init_kwargs.get("base_url") == "https://api.shodan.io"),
            None,
        )
        assert sess is not None, "shodan never built the impersonating client"
        assert sess.init_kwargs.get("impersonate") == "chrome120"
        assert sess.init_kwargs.get("proxy") == "http://capture.local:8080", (
            "impersonation dropped the campaign proxy"
        )
        assert "User-Agent" in sess.init_kwargs.get("headers", {}), (
            "impersonation dropped the rotating User-Agent header"
        )

    async def test_no_profile_target_keeps_plain_httpx(self):
        """A profile with tls_impersonate=None (the default) must NOT build
        the adapter -- shodan stays on plain httpx, captured at the
        httpx.AsyncClient layer exactly like before this feature."""
        import respx
        from httpx import Response

        from nexusrecon.opsec.profiles import ProfileName, StealthProfile
        from nexusrecon.tools.intel.shodan_tool import ShodanTool
        from nexusrecon.tools.registry import ToolRegistry

        profile = StealthProfile(
            name=ProfileName.LOUD,
            request_delay_min=0.0,
            request_delay_max=0.0,
        )
        registry = ToolRegistry()
        registry._tools["shodan"] = ShodanTool()
        registry.set_campaign_context(
            scope_guard=None,  # type: ignore[arg-type]
            stealth_profile=profile,
        )

        built = []
        original_init = httpx.AsyncClient.__init__

        def _capture(self, *args, **kwargs):
            built.append(kwargs)
            return original_init(self, *args, **kwargs)

        with patch(
            "nexusrecon.core.config.NexusConfig.get_secret",
            return_value="fake-key",
        ), respx.mock, patch.object(httpx.AsyncClient, "__init__", _capture):
            respx.get(url__startswith="https://api.shodan.io").mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            await registry.execute("shodan", "example.com", "domain")

        assert any(
            k.get("base_url") == "https://api.shodan.io" for k in built
        ), "shodan should have built a plain httpx client with no target set"


# ──────────────────────────────────────────────────────────────────────
# Real curl_cffi round-trip (localhost only; skipped without the extra)
# ──────────────────────────────────────────────────────────────────────


class TestRealCurlCffiRoundTrip:
    async def test_localhost_get_through_real_adapter(self):
        if not base._HAS_CURL_CFFI:
            pytest.skip("curl_cffi extra not installed")

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def do_GET(self):
                body = json.dumps({
                    "path": self.path,
                    "ua": self.headers.get("User-Agent"),
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        srv = HTTPServer(("127.0.0.1", 0), _Handler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tls_impersonate_context("chrome120"):
                async with make_http_client(
                    base_url=f"http://127.0.0.1:{port}",
                    headers={"User-Agent": "UA-ROUNDTRIP"},
                    timeout=5.0,
                ) as client:
                    assert isinstance(client, base._ImpersonateClient)
                    resp = await client.get("/probe", params={"q": "1"})
                    # The synthesised httpx-ism the tools rely on.
                    assert resp.is_success is True
                    assert resp.status_code == 200
                    payload = resp.json()
                    assert payload["path"].startswith("/probe")
                    assert payload["ua"] == "UA-ROUNDTRIP"
        finally:
            srv.shutdown()
