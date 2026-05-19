# OPSEC Status

Where the framework actually enforces operational security at the wire
level, and where it's still declared-only. Honest accounting so an
operator running `paranoid` mode knows what's currently real and what's
on the roadmap.

This file is the source of truth for the OPSEC migration tracked in
`ROADMAP.md`. Update it when you migrate a tool or wire a new
campaign-runner code path.

---

## What's wired (verified at the wire level)

| Control | How it works | Verified by |
|---|---|---|
| **UserAgent rotation** | `nexusrecon/opsec/useragent.py::random_ua()` picks a fresh UA from a 35-entry pool on every call. 47 tools call it directly when building their `httpx` headers. | `tests/unit/test_opsec.py::TestRandomUaHelper`; `tests/integration/test_opsec_wire.py::TestUARotationOnWire::test_fullhunt_rotates_user_agent_across_calls` |
| **Per-source rate limiting** | When `ToolRegistry.set_campaign_context(rate_limiter=...)` is called, `registry.execute()` awaits `rate_limiter.wait(tool.name)` before invoking `tool.run()`. Token-bucket per source, with `RateLimiter.from_profile(StealthProfile)` building rates from the profile. | `tests/integration/test_opsec_wire.py::TestRateLimitWireEnforcement` |
| **Proxy injection** | When `set_campaign_context(proxy_manager=...)` is called, `registry.execute()` sets `nexusrecon.opsec.context.proxy_context` to the resolved per-source proxy URL. `BaseHTTPTool._proxy_kwargs()` reads the ContextVar and returns `{"proxy": url}` (or `{}`) for tools to spread into their `httpx.AsyncClient(...)` call. | `tests/integration/test_opsec_wire.py::TestProxyWireInjection` |
| **Source-routed proxy rules** | `ProxyManager.add_rule(source, proxy_name)` routes specific tools through specific proxies (e.g. shodan via Tor, everything else via corp proxy). Honoured by `registry.execute()` through `proxy_manager.get_proxy_for_source(tool_name)`. | `tests/integration/test_opsec_wire.py::TestSourceRoutedProxy` |
| **Burst detection** | `BurstDetector` sliding-window check that triggers a sleep when N+1 requests land inside the window. Wired into `SourceRateLimiter.wait()`. | `tests/unit/test_opsec.py::TestBurstDetector` |
| **Stealth profile resolution** | `get_profile("paranoid"|"high"|"normal"|"loud")` returns the documented dataclass. Rejects unknown names (was the `low/medium/high` wizard bug in 0.5.0 pre-migration). | `tests/unit/test_opsec.py::TestStealthProfile` |

---

## What's NOT wired yet

These are gaps the wire-verification tests would catch ── there's no
campaign code path today that triggers them, but if/when there is, the
tests above will start asserting on them.

### Tool migration (proxy support)

**Wired (consume the proxy context):**

- 5 `BaseHTTPTool` subclasses: `shodan`, `virustotal`, `censys`,
  `fullhunt`, `greynoise` ── spread `**self._proxy_kwargs()` into
  their httpx clients.
- 2 library-driven tools that consume `proxy_kwargs()` directly via
  the free function in `nexusrecon.opsec.context`: `holehe` (rotates
  UA per call too, post-fix) and the inner client `maigret` would
  use if/when its subprocess CLI supports proxy flags.

**Not wired (still need migration):**

- ~63 HTTP tools that build raw `httpx.AsyncClient(...)` calls in
  their `run()` methods without consulting either `_proxy_kwargs()`
  or `proxy_kwargs()`. They will silently bypass the proxy manager.

To migrate a tool:

1. Change parent from `OSINTTool` to `BaseHTTPTool` (if the tool fits
   the JSON-HTTP-API shape and benefits from `classify_response`).
2. Add `provider_label = "..."` if the auto-derived name is ugly.
3. Replace any private `_classify_status` helper with calls to
   `self.classify_response(resp, endpoint=...)`.
4. Spread `**self._proxy_kwargs()` into every `httpx.AsyncClient(...)`
   call inside `run()`.
5. For tools that can't reasonably inherit from `BaseHTTPTool`
   (subprocess wrappers, library-driven tools): import
   `from nexusrecon.opsec.context import proxy_kwargs` and spread
   `**proxy_kwargs()` into the AsyncClient ctor directly.
6. Run the tool's integration tests to confirm no regression.

**Structural test catches new tools that miss the migration:**
`tests/integration/test_opsec_wire.py::TestProxySupportStructural::test_every_basehttp_tool_calls_proxy_kwargs`
walks every registered `BaseHTTPTool` subclass and asserts the source
calls `_proxy_kwargs()`. A tool that inherits from BaseHTTPTool but
doesn't consume the helper fails the test.

Track per-tool migration in PRs that follow the
`feat(tools): migrate <tool> to BaseHTTPTool` pattern.

### Campaign-runner integration

`ToolRegistry.set_campaign_context()` accepts `stealth_profile`,
`rate_limiter`, and `proxy_manager` keyword args, but the
**campaign runner does not yet pass them**. Today every campaign runs
with `rate_limiter=None` and `proxy_manager=None`, which means:

- The rate limiter exists but is dormant during campaigns.
- The proxy manager exists but is dormant during campaigns.
- The TUI's stealth-profile selection (paranoid/high/normal/loud) is
  read into the scope file, validated, persisted in the campaign
  state, but never actually translated into `RateLimiter.from_profile`
  + `ProxyManager(...)` + `set_campaign_context(...)`.

To close this gap, the campaign runner at
`nexusrecon/core/campaign.py` needs:

```python
profile = get_profile(scope.constraints.stealth_profile)
rate_limiter = RateLimiter.from_profile(profile)
proxy_manager = ProxyManager(
    proxy_url=config.proxy_url,
    tor_proxy=config.tor_proxy,
)
registry.set_campaign_context(
    scope_guard=scope_guard,
    cache=cache,
    audit_log=audit_log,
    stealth_profile=profile,
    rate_limiter=rate_limiter,
    proxy_manager=proxy_manager,
)
```

This is a small wire-up but it crosses several modules. Separate PR.

### TLS / JA3 fingerprinting

Python's `httpx` (via `httpcore` + `h11`) presents a recognisable TLS
handshake and JA3 hash, which is identical across every install of
NexusRecon today. The ROADMAP lists `curl_cffi` (or similar
JA3-friendly client) as the long-term answer for tools aimed at
production red-team use.

Status: not started. Tracked as a `1.0.0` item, not a beta blocker.
Adding it means swapping `httpx` for `curl_cffi.AsyncSession` in
`BaseHTTPTool` (and matching the API surface), or making it
configurable per profile.

---

## How to verify your campaign actually does what you think

After the campaign-runner gap above is closed:

1. Start a campaign with `--stealth-profile paranoid`.
2. Run `mitmproxy` on `localhost:8080`, set `NEXUS_PROXY_URL=http://localhost:8080`.
3. Watch the mitmproxy flow tab:
   - Requests should arrive serially (no parallel bursts).
   - Inter-request delay should be 3-10 seconds per source.
   - User-Agent should vary across requests.
   - Every request should arrive *through* the proxy (no direct
     connections to e.g. `api.shodan.io`).

If any of those don't hold, file a bug against this file's "What's
wired" table ── the wiring is the lie, the wire is the truth.
