"""LLM provider backends for NexusRecon.

Narrow public surface:

- ``auth``: provider contracts, credential-store metadata, login/status
  delegation, secret redaction, and :class:`LLMAuthenticationError`.
- ``cli_backend``: ``OAuthCLIChatModel`` — official-CLI inference with
  subscription billing.
- ``factory``: auth-mode resolution and client construction
  (``build_llm_from_config``).
- ``mock``: the explicit ``provider=mock`` deterministic LLM.
"""
from __future__ import annotations

from nexusrecon.llm.auth import (
    PROVIDER_CONTRACTS,
    LLMAuthenticationError,
    LLMProviderError,
)
from nexusrecon.llm.cli_backend import OAuthCLIChatModel, OAuthCLIResponse
from nexusrecon.llm.factory import (
    OAuthKeyFallback,
    build_llm_from_config,
    oauth_login_available,
    resolve_llm_auth_mode,
)
from nexusrecon.llm.mock import MockLLM, MockLLMResponse

__all__ = [
    "LLMAuthenticationError",
    "LLMProviderError",
    "MockLLM",
    "MockLLMResponse",
    "OAuthCLIChatModel",
    "OAuthCLIResponse",
    "OAuthKeyFallback",
    "PROVIDER_CONTRACTS",
    "build_llm_from_config",
    "oauth_login_available",
    "resolve_llm_auth_mode",
]
