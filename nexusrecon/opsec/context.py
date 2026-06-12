"""
Per-campaign OPSEC context propagation.

The OPSEC layer (rate limiter, proxy manager, stealth profile) lives on
the tool registry but tools build their own ``httpx.AsyncClient``
instances inside ``run()`` ── so they need a way to read the active
proxy URL without depending on the registry directly. A ``ContextVar``
solves this cleanly:

  1. ``registry.execute()`` enters ``proxy_context(proxy_url)`` before
     calling ``tool.run()``.
  2. The tool's ``BaseHTTPTool._proxy_kwargs()`` helper reads the var
     and returns ``{}`` or ``{"proxy": url}`` to spread into the
     ``httpx.AsyncClient(...)`` call.
  3. The context var unwinds when execute() returns, so subsequent
     calls outside the registry get a clean ``None``.

This pattern keeps tools loosely coupled to the registry while still
making the stealth-profile proxy setting actually take effect at the
wire level.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

# ContextVar of Optional[str] for the active outbound proxy URL.
# ``None`` means no proxy (direct connection); a string is an
# httpx-compatible proxy URL (``http://...``, ``socks5://...``, etc.).
_current_proxy_url: ContextVar[str | None] = ContextVar(
    "nexus_opsec_proxy_url", default=None
)


def get_current_proxy_url() -> str | None:
    """Return the proxy URL set by the enclosing ``proxy_context``, or None."""
    return _current_proxy_url.get()


def proxy_kwargs() -> dict[str, Any]:
    """Return httpx-compatible proxy kwargs for the active campaign.

    Returns ``{}`` when no proxy is active, or ``{"proxy": url}`` when
    ``proxy_context`` has been entered with a non-None URL. Designed for
    tools that build their own ``httpx.AsyncClient`` ── either via
    ``BaseHTTPTool`` (which exposes this as ``self._proxy_kwargs()``) or
    directly from ``OSINTTool`` subclasses that need proxy support
    without inheriting from BaseHTTPTool. Tools like ``holehe`` and
    ``maigret`` fall in the second category: they manage their own
    client lifecycle through a library or subprocess, but should still
    respect the campaign proxy.

    Usage from a non-BaseHTTPTool::

        from nexusrecon.opsec.context import proxy_kwargs

        async with httpx.AsyncClient(
            headers={...},
            timeout=10.0,
            **proxy_kwargs(),
        ) as client:
            ...
    """
    url = get_current_proxy_url()
    if url:
        return {"proxy": url}
    return {}


def proxy_env() -> dict[str, str]:
    """Return subprocess environment overrides routing CLI tools through the
    campaign proxy.

    The subprocess analogue of :func:`proxy_kwargs`. Returns ``{}`` when no
    proxy is active, or a dict setting ``HTTP_PROXY`` / ``HTTPS_PROXY`` /
    ``ALL_PROXY`` (plus the lowercase variants) to the active proxy URL when
    ``proxy_context`` has been entered with a non-None URL.

    Go tools (subfinder, amass, nuclei) and most CLI utilities honour the
    standard ``*_PROXY`` environment variables; ``ALL_PROXY`` additionally
    carries ``socks5://`` support. Threading these into the child environment
    makes the campaign proxy apply to tools that never touch httpx, closing the
    gap where a paranoid engagement could be deanonymised by its own
    enumeration subprocesses while the HTTP tool fleet was correctly proxied.

    Launch the subprocess with ``env={**os.environ, **proxy_env()}`` so the
    rest of the environment (``PATH``, ``HOME``) is preserved; when this
    returns ``{}`` the caller should pass ``env=None`` so the child inherits
    the parent environment unchanged.
    """
    url = get_current_proxy_url()
    if not url:
        return {}
    return {
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "ALL_PROXY": url,
        "http_proxy": url,
        "https_proxy": url,
        "all_proxy": url,
    }


@contextmanager
def proxy_context(url: str | None) -> Iterator[None]:
    """Set the proxy URL for the duration of the ``with`` block.

    Usage from inside the registry::

        with proxy_context(self._proxy_manager.current.url if ... else None):
            result = await tool.run(target)

    Tools call ``get_current_proxy_url()`` (or ``BaseHTTPTool._proxy_kwargs()``)
    from inside ``run()`` to read the active value.
    """
    token = _current_proxy_url.set(url)
    try:
        yield
    finally:
        _current_proxy_url.reset(token)


# ContextVar of Optional[str] for the active JA3 / TLS-impersonation
# target. ``None`` means the default plain-httpx client; a string is a
# curl_cffi impersonate target such as ``"chrome120"``. Mirrors the proxy
# ContextVar: the registry sets it around ``tool.run()`` and the
# ``make_http_client`` factory reads it at client construction. Unlike the
# proxy (a per-request kwarg), impersonation changes the client class, so
# it is consumed by the factory, not spread as a kwarg.
_current_tls_impersonate: ContextVar[str | None] = ContextVar(
    "nexus_opsec_tls_impersonate", default=None
)


def get_current_tls_impersonate() -> str | None:
    """Return the TLS-impersonation target set by the enclosing
    ``tls_impersonate_context``, or None for the default httpx client."""
    return _current_tls_impersonate.get()


@contextmanager
def tls_impersonate_context(target: str | None) -> Iterator[None]:
    """Set the TLS-impersonation target for the duration of the ``with``
    block. ``None`` (the default) is a no-op: ``make_http_client`` returns
    a plain ``httpx.AsyncClient``. Entered alongside ``proxy_context`` in
    ``registry.execute()`` so it unwinds with the same per-call scope and
    never leaks across campaigns."""
    token = _current_tls_impersonate.set(target)
    try:
        yield
    finally:
        _current_tls_impersonate.reset(token)
