"""Build and bind the per-campaign OPSEC stack to the tool registry.

``ToolRegistry.execute()`` applies stealth jitter, per-source rate limiting,
and proxy routing only when those primitives are bound via
``set_campaign_context``. Until this helper existed, the CLI and TUI bound
only ``scope_guard`` / ``cache`` / ``audit_log`` — so the entire OPSEC stack
(the scope's ``stealth_profile``, ``NEXUS_PROXY_URL`` / ``NEXUS_TOR_PROXY``)
was config-time fiction in production: read, documented, wire-tested in
isolation, but never actually applied to a real campaign's traffic.

``build_opsec`` closes that gap: it constructs the stealth profile from the
engagement's ``stealth_profile`` constraint, a rate limiter from that
profile, and a proxy manager from the configured proxy, ready to spread into
``set_campaign_context``.
"""
from __future__ import annotations

from typing import Any

import structlog

from nexusrecon.opsec.profiles import get_profile
from nexusrecon.opsec.proxy import ProxyManager
from nexusrecon.opsec.rate_limiter import RateLimiter

log = structlog.get_logger(__name__)


class ProxyRequiredError(Exception):
    """The engagement set ``require_proxy`` but no proxy is configured.

    Failing loud here is the point: an operator who demanded all traffic go
    through a proxy must not have the campaign silently fall back to direct
    connections.
    """


def build_opsec(scope_model: Any, config: Any) -> dict[str, Any]:
    """Return the ``stealth_profile`` / ``rate_limiter`` / ``proxy_manager``
    kwargs to spread into ``ToolRegistry.set_campaign_context``.

    Reads the stealth profile from ``scope_model.constraints.stealth_profile``
    and the proxy from ``config`` (``NEXUS_PROXY_URL`` / ``NEXUS_TOR_PROXY``).
    Raises :class:`ProxyRequiredError` when ``require_proxy`` is set but no
    proxy is available.
    """
    profile = get_profile(scope_model.constraints.stealth_profile)
    rate_limiter = RateLimiter.from_profile(profile)
    proxy_manager = ProxyManager(
        proxy_url=getattr(config, "proxy_url", None),
        tor_proxy=getattr(config, "tor_proxy", None),
    )

    if getattr(scope_model.constraints, "require_proxy", False) and not proxy_manager.available:
        raise ProxyRequiredError(
            "Engagement constraint require_proxy is set, but no proxy is "
            "configured. Set NEXUS_PROXY_URL (or NEXUS_TOR_PROXY) before "
            "launching, or clear require_proxy in the scope."
        )

    log.info(
        "OPSEC stack bound to registry",
        stealth_profile=profile.name.value,
        proxy_available=proxy_manager.available,
        prefer_tor=profile.prefer_tor,
        delay_range=(profile.request_delay_min, profile.request_delay_max),
    )
    return {
        "stealth_profile": profile,
        "rate_limiter": rate_limiter,
        "proxy_manager": proxy_manager,
    }
