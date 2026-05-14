"""Proxy manager — SOCKS5, Tor, custom proxy chain support."""

from __future__ import annotations
from typing import List, Optional
from dataclasses import dataclass, field

import structlog

log = structlog.get_logger(__name__)


@dataclass
class ProxyConfig:
    url: str  # e.g. socks5://127.0.0.1:9050
    name: str = ""
    is_tor: bool = False
    country: Optional[str] = None


class ProxyManager:
    """
    Manages outbound proxy configuration.

    Supports SOCKS5, Tor, and custom proxy chains.
    Per-source routing rules can be added for advanced OPSEC.
    """

    def __init__(self, proxy_url: Optional[str] = None, tor_proxy: Optional[str] = None) -> None:
        self._proxies: List[ProxyConfig] = []
        self._current_index = 0
        self._source_rules: dict[str, str] = {}  # source -> proxy name

        if tor_proxy:
            self._proxies.append(ProxyConfig(url=tor_proxy, name="tor", is_tor=True))
        if proxy_url and proxy_url != tor_proxy:
            self._proxies.append(ProxyConfig(url=proxy_url, name="custom"))

    @property
    def available(self) -> bool:
        return len(self._proxies) > 0

    @property
    def current(self) -> Optional[ProxyConfig]:
        if self._proxies:
            return self._proxies[self._current_index]
        return None

    def get_proxy_for_source(self, source: str) -> Optional[str]:
        """Get the proxy URL for a specific source, or default."""
        if source in self._source_rules:
            for p in self._proxies:
                if p.name == self._source_rules[source]:
                    return p.url
        if self._proxies:
            return self._proxies[self._current_index].url
        return None

    def rotate(self) -> None:
        """Rotate to the next proxy in the chain."""
        if self._proxies:
            self._current_index = (self._current_index + 1) % len(self._proxies)

    def add_rule(self, source: str, proxy_name: str) -> None:
        """Route a specific source through a specific proxy."""
        self._source_rules[source] = proxy_name

    def to_httpx_kwargs(self, source: Optional[str] = None) -> dict:
        """Return httpx-compatible proxy kwargs."""
        proxy_url = self.get_proxy_for_source(source) if source else (self.current.url if self.current else None)
        if proxy_url:
            return {"proxy": proxy_url}
        return {}
