"""LLM client factory — auth-mode resolution + client construction.

Implements the provider-OAuth resolution contract:

1. ``mock`` and ``ollama`` bypass auth resolution entirely.
2. ``api_key`` mode requires the selected provider's key and returns a
   direct LangChain API-key client.
3. ``oauth`` / ``auto`` prefer a usable official-CLI login.
4. When OAuth is unavailable (or a runtime auth failure is returned), the
   selected provider's API key is used when present (``OAuthKeyFallback``).
5. When neither exists, a clear :class:`LLMAuthenticationError` is raised
   naming the exact login command AND the API-key variable. Operators who
   want the deterministic mock select ``provider=mock`` — NexusRecon never
   silently falls back to MockLLM.
"""
from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from typing import Any

import structlog
from pydantic import SecretStr

from nexusrecon.llm.auth import (
    PROVIDER_CONTRACTS,
    LLMAuthenticationError,
    build_auth_status,
    capture_runner,
    normalize_provider,
)
from nexusrecon.llm.cli_backend import OAuthCLIChatModel
from nexusrecon.llm.mock import MockLLM

#: SecretStr field names per provider, used with ``config.get_secret``.
_API_KEY_FIELDS: dict[str, str] = {
    "openai": "openai_api_key",
    "anthropic": "anthropic_api_key",
    "xai": "xai_api_key",
}

XAI_BASE_URL = "https://api.x.ai/v1"
_DEFAULT_API_MODELS = {
    "anthropic": "claude-opus-4-5",
    "openai": "gpt-4o",
    "xai": "grok-3-mini",
}
logger = structlog.get_logger(__name__)


def resolve_llm_auth_mode(config: Any) -> str:
    """Return the effective auth mode: ``auto`` when unset."""
    mode = getattr(config, "llm_auth_mode", None)
    if mode is None or not isinstance(mode, str):
        return "auto"
    if mode not in ("oauth", "api_key", "auto"):
        raise ValueError(
            f"Unsupported LLM auth mode {mode!r}. Choose from auto, oauth, api_key."
        )
    return mode


def _config_timeout(config: Any, default: int = 600) -> int:
    raw = getattr(config, "llm_cli_timeout", None)
    try:
        return int(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default


def _provider_api_key(config: Any, provider: str) -> str | None:
    """Fetch the provider key through ``config.get_secret`` when available."""
    field = _API_KEY_FIELDS[provider]
    getter = getattr(config, "get_secret", None)
    if callable(getter):
        try:
            return getter(field)
        except TypeError:
            pass
    return getattr(config, field, None)


def oauth_login_available(
    provider: str,
    env: Mapping[str, str] | None = None,
    which: Callable[[str], str | None] | None = None,
) -> bool:
    """Return True when the provider's official CLI has a usable login.

    openai/anthropic are probed via their official status command
    (keyring-backed logins without a store file count as valid). xai has no
    documented status probe, so cheap store-metadata presence
    (~/.grok/auth.json) is the readiness signal.
    """
    provider = normalize_provider(provider)
    if provider not in PROVIDER_CONTRACTS:
        return False
    contract = PROVIDER_CONTRACTS[provider]
    resolver = which if which is not None else shutil.which
    if not callable(resolver) or not resolver(contract.binary):
        return False
    base_env = env if env is not None else os.environ
    runner = None if provider == "xai" else capture_runner
    status = build_auth_status(provider, env=base_env, which=resolver, runner=runner)
    return status.get("status") == "subscription" or (
        provider == "xai" and status.get("status") == "store_present"
    )


# ──────────────────────────────────────────────────────────────────────
# Direct API-key clients
# ──────────────────────────────────────────────────────────────────────


def _stamp_model_name(client: Any, model: str | None) -> Any:
    """Ensure ``.model_name`` exists for telemetry.

    ``ChatOpenAI`` exposes ``model_name`` natively, but ``ChatAnthropic`` and
    ``ChatOllama`` only expose ``model``. LangChain-shaped consumers
    (AgentExecutor) read ``model_name``, so stamp it on for those classes.
    """
    if not hasattr(client, "model_name") and model:
        object.__setattr__(client, "model_name", model)
    return client


def _build_ollama_client(config: Any, model: str | None, temperature: float) -> Any:
    from langchain_ollama import ChatOllama

    ollama_model = getattr(config, "ollama_model", None) or model or "llama3.1:8b"
    base_url = getattr(config, "ollama_base_url", "http://localhost:11434")
    client = ChatOllama(
        model=ollama_model,
        base_url=base_url,
        temperature=float(temperature or 0.1),
    )
    return _stamp_model_name(client, ollama_model)


def _build_api_key_client(
    provider: str, model: str | None, temperature: float, api_key: str
) -> Any:
    """Direct metered API-key client for the selected provider."""
    effective_model = model or _DEFAULT_API_MODELS[provider]
    secret_key = SecretStr(api_key)
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        client = ChatAnthropic(
            model=effective_model,
            temperature=float(temperature or 0.1),
            api_key=secret_key,
        )
        return _stamp_model_name(client, effective_model)

    from langchain_openai import ChatOpenAI

    if provider == "xai":
        # xAI must be reached at the xAI endpoint, never the OpenAI default.
        return ChatOpenAI(
            model=effective_model,
            temperature=float(temperature or 0.1),
            api_key=secret_key,
            base_url=XAI_BASE_URL,
        )
    if provider == "openai":
        return ChatOpenAI(
            model=effective_model,
            temperature=float(temperature or 0.1),
            api_key=secret_key,
        )
    raise ValueError(f"Unsupported provider for API-key client: {provider!r}")


# ──────────────────────────────────────────────────────────────────────
# OAuth → API-key fallback wrapper
# ──────────────────────────────────────────────────────────────────────


class OAuthKeyFallback:
    """Subscription (OAuth CLI) primary with a metered API-key fallback.

    When the OAuth primary fails with :class:`LLMAuthenticationError`
    (expired session / failed refresh), the call is retried against the
    direct API-key client so an operator who configured both never hits a
    dead stop.
    """

    def __init__(self, *, primary: Any, fallback: Any) -> None:
        self.primary = primary
        self.fallback = fallback
        self.model_name = getattr(primary, "model_name", None) or "oauth-fallback"

    def invoke(self, messages: Any) -> Any:
        try:
            return self.primary.invoke(messages)
        except LLMAuthenticationError:
            logger.warning(
                "llm_oauth_fallback_to_api_key",
                provider=getattr(self.primary, "provider", "unknown"),
            )
            return self.fallback.invoke(messages)


# ──────────────────────────────────────────────────────────────────────
# Factory entry point
# ──────────────────────────────────────────────────────────────────────


def build_llm_from_config(config: Any) -> Any:
    """Build the LLM client for a NexusConfig (or test double)."""
    raw_provider = getattr(config, "llm_provider", None)
    # A real provider is always a string. Non-string / unset values (test
    # doubles, programmatic callers without a provider) map to the explicit
    # mock rather than being treated as a configured provider.
    requested_provider = (
        raw_provider.strip().lower() if isinstance(raw_provider, str) else "mock"
    )
    provider = normalize_provider(requested_provider)
    mode = resolve_llm_auth_mode(config)
    model = getattr(config, "llm_model", None)
    fields_set = getattr(config, "model_fields_set", None)
    if (
        provider in {"openai", "xai"}
        and isinstance(fields_set, set)
        and "llm_model" not in fields_set
    ):
        # The global config default is Anthropic-specific. Let maintained
        # OpenAI/xAI CLIs choose their current provider default unless the
        # operator explicitly set NEXUS_LLM_MODEL.
        model = None
    temperature = getattr(config, "llm_temperature", 0.1)

    # Explicit air-gapped / test provider — bypasses auth resolution.
    if provider == "mock":
        return MockLLM()
    # Local model provider — bypasses auth resolution.
    if provider == "ollama":
        return _build_ollama_client(config, model, float(temperature or 0.1))

    if provider not in PROVIDER_CONTRACTS:
        raise ValueError(
            f"Unsupported LLM provider {requested_provider!r}. Choose from "
            "anthropic, openai, openai-codex, xai, ollama, mock."
        )

    api_key = _provider_api_key(config, provider)

    if mode == "api_key":
        if not api_key:
            raise LLMAuthenticationError(provider)
        logger.info(
            "llm_backend_selected",
            provider=provider,
            auth_mode="api_key",
            backend="direct_sdk",
            model=model,
        )
        return _build_api_key_client(provider, model, float(temperature or 0.1), api_key)

    # oauth / auto: prefer a usable official-CLI login.
    if oauth_login_available(provider):
        cli = OAuthCLIChatModel(
            provider,
            env=os.environ,
            model_name=model,
            cli_timeout=_config_timeout(config),
        )
        if api_key:
            # Subscription first; fall back to the metered key if the login
            # later fails to refresh.
            logger.info(
                "llm_backend_selected",
                provider=provider,
                auth_mode=mode,
                backend="official_cli_with_api_key_fallback",
                model=model,
            )
            return OAuthKeyFallback(
                primary=cli,
                fallback=_build_api_key_client(
                    provider, model, float(temperature or 0.1), api_key
                ),
            )
        logger.info(
            "llm_backend_selected",
            provider=provider,
            auth_mode=mode,
            backend="official_cli",
            model=model,
        )
        return cli

    if api_key:
        logger.info(
            "llm_backend_selected",
            provider=provider,
            auth_mode="api_key_fallback",
            backend="direct_sdk",
            model=model,
        )
        return _build_api_key_client(provider, model, float(temperature or 0.1), api_key)

    # No OAuth login and no key: clear remediation, never a silent MockLLM.
    raise LLMAuthenticationError(provider)


__all__ = [
    "OAuthKeyFallback",
    "build_llm_from_config",
    "oauth_login_available",
    "resolve_llm_auth_mode",
]
