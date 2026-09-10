"""Provider-OAuth authentication layer for NexusRecon LLM backends.

This module owns the *contracts* for delegating login + status to each
provider's maintained official CLI. NexusRecon deliberately never
re-implements OAuth / PKCE / device / refresh protocols (provider-oauth
plan); the official binary owns the credential lifecycle and its store.

Security invariants (locked by ``tests/unit/test_llm_auth.py``):

  * ``build_oauth_env`` strips every provider key and base-URL override so
    a claimed subscription call cannot silently become a metered key call.
  * ``login_command`` argv never carries a prompt or a credential.
  * ``build_auth_status`` never returns token values.
  * ``redact_secrets`` removes key / JWT / Bearer-shaped substrings from any
    surfaced text, so error messages never leak credentials.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Env vars that must never reach an OAuth CLI subprocess. If a key/base-URL
#: override leaked through, a metered API-key call could silently replace the
#: intended subscription call.
OAUTH_STRIPPED_ENV_KEYS: frozenset[str] = frozenset({
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "CODEX_API_KEY",
    "OPENAI_BASE_URL",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "XAI_BASE_URL",
})

# Key/JWT/Bearer-shaped substrings that must never survive surfacing.
SECRET_SHAPES: tuple[str, ...] = (
    "sk-ant-api03-",
    "sk-",
    "xai-",
    "eyJhbGciOiJIUzI1NiJ9.",
    "Bearer ",
)

_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # OpenAI API keys (incl. the anthropic-format sk-ant-... which shares the
    # sk- prefix); order matters: longest / most specific first.
    re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]*"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]+"),
    re.compile(r"(?<![A-Za-z0-9])xai-[A-Za-z0-9_\-]+"),
    # "Bearer <token>" — remove the whole phrase so the "Bearer " shape
    # cannot survive.
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]+"),
    # JWT: header.payload.signature base64url runs.
    re.compile(r"eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+"),
)


@dataclass(frozen=True)
class ProviderContract:
    """Everything NexusRecon knows about a provider's official login.

    Values are locked by provider-contract tests (official binary, credential
    store location, refresh owner = the official CLI).
    """

    provider: str
    binary: str
    store_env_var: str
    store_dir_name: str
    store_file_name: str
    refresh_owner: str = "official_cli"
    api_key_env_var: str = ""
    #: Official non-interactive status probe argv. Empty tuple means the
    #: provider has no documented status probe and readiness is derived from
    #: cheap store-metadata presence.
    status_command: tuple[str, ...] = ()


PROVIDER_ALIASES: dict[str, str] = {
    "openai-codex": "openai",
}


PROVIDER_CONTRACTS: dict[str, ProviderContract] = {
    "openai": ProviderContract(
        provider="openai",
        binary="codex",
        store_env_var="CODEX_HOME",
        store_dir_name=".codex",
        store_file_name="auth.json",
        api_key_env_var="OPENAI_API_KEY",
        status_command=("codex", "login", "status"),
    ),
    "anthropic": ProviderContract(
        provider="anthropic",
        binary="claude",
        store_env_var="CLAUDE_CONFIG_DIR",
        store_dir_name=".claude",
        store_file_name=".credentials.json",
        api_key_env_var="ANTHROPIC_API_KEY",
        status_command=("claude", "auth", "status"),
    ),
    "xai": ProviderContract(
        provider="xai",
        binary="grok",
        store_env_var="GROK_HOME",
        store_dir_name=".grok",
        store_file_name="auth.json",
        api_key_env_var="XAI_API_KEY",
        # xAI Grok Build has no documented non-interactive status probe; the
        # plan's cheap readiness signal is store presence (~/.grok/auth.json).
        status_command=(),
    ),
}


def normalize_provider(provider: str) -> str:
    """Return the canonical provider id for a public provider name."""
    normalized = provider.strip().lower()
    return PROVIDER_ALIASES.get(normalized, normalized)


def _require_contract(provider: str) -> ProviderContract:
    canonical = normalize_provider(provider)
    try:
        return PROVIDER_CONTRACTS[canonical]
    except KeyError:
        choices = sorted({*PROVIDER_CONTRACTS, *PROVIDER_ALIASES})
        raise ValueError(
            f"Unknown provider {provider!r}. Choose from "
            f"{', '.join(choices)}."
        ) from None


# ──────────────────────────────────────────────────────────────────────
# Secret redaction
# ──────────────────────────────────────────────────────────────────────


def redact_secrets(text: str) -> str:
    """Replace key / JWT / Bearer-shaped substrings with a redaction marker.

    Safe remediation prose (e.g. ``run codex login``) and non-secret
    detail (e.g. ``401``) survive. Plain text is returned unchanged.
    """
    if not text:
        return text
    redacted = text
    for pattern in _REDACTION_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    # Mop up orphaned prefixes with no token body (e.g. a trailing "sk-").
    redacted = re.sub(
        r"(?<![A-Za-z0-9])xai-(?![A-Za-z0-9_\-])", "[REDACTED]", redacted
    )
    redacted = re.sub(
        r"(?<![A-Za-z0-9])sk-(?![A-Za-z0-9_\-])", "[REDACTED]", redacted
    )
    return redacted


class LLMProviderError(Exception):
    """Sanitized non-authentication failure from an official provider CLI."""

    def __init__(self, provider: str, message: str) -> None:
        self.provider = provider
        super().__init__(redact_secrets(message))


class LLMAuthenticationError(LLMProviderError):
    """Provider authentication failure surfaced to the operator.

    The message is run through :func:`redact_secrets` before it is stored,
    so it can never carry a token. When ``message`` is omitted a
    remediation message is generated from the provider contract, naming the
    exact official login command AND the API-key variable.
    """

    def __init__(self, provider: str, message: str | None = None) -> None:
        requested_provider = provider.strip().lower()
        canonical_provider = normalize_provider(requested_provider)
        self.provider = canonical_provider
        contract = PROVIDER_CONTRACTS.get(canonical_provider)
        if message:
            detail = message.rstrip().rstrip(".")
            if contract:
                login = " ".join(login_command(canonical_provider))
                full = (
                    f"{detail}. To recover, run `{login}` or set "
                    f"{contract.api_key_env_var} for direct API-key billing."
                )
            else:
                full = detail
        elif contract:
            login = " ".join(login_command(canonical_provider))
            full = (
                f"No usable {requested_provider} authentication is available. "
                f"Log in with the official CLI (`{login}`) or set "
                f"{contract.api_key_env_var} for direct API-key billing."
            )
        else:
            full = f"No usable {requested_provider!r} authentication is available."
        LLMProviderError.__init__(self, canonical_provider, full)


def _classify_cli_auth(provider: str, stdout: str) -> str:
    """Classify status output without retaining credential-bearing text.

    Only an explicitly identified subscription is allowed to receive zero-cost
    subscription billing. Stored API credentials and ambiguous status output
    fail closed so they cannot bypass the campaign budget.
    """
    if provider == "openai":
        status_text = stdout.lower()
        if "logged in using chatgpt" in status_text:
            return "subscription"
        if "api key" in status_text:
            return "api_key"
        return "unknown"

    if provider == "anthropic":
        try:
            payload = json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            return "unknown"
        if not isinstance(payload, dict) or not payload.get("loggedIn"):
            return "none"
        method = str(payload.get("authMethod") or "").lower()
        subscription = str(payload.get("subscriptionType") or "").lower()
        if method == "api_key":
            return "api_key"
        if method in {"claude.ai", "oauth", "oauth_token"} and subscription in {
            "pro", "max", "team", "enterprise", "business",
        }:
            return "subscription"
        return "unknown"

    return "unknown"


# ──────────────────────────────────────────────────────────────────────
# Login command construction
# ──────────────────────────────────────────────────────────────────────


def login_command(provider: str, device: bool = False) -> list[str]:
    """Return the exact login argv for a provider's official CLI.

    Never includes a prompt or a credential. Anthropic rejects ``device``
    with a clear message pointing at its interactive auth-code paste flow.
    """
    provider = normalize_provider(provider)
    _require_contract(provider)
    if provider == "openai":
        return ["codex", "login"] + (["--device-auth"] if device else [])
    if provider == "xai":
        return ["grok", "login", "--device-auth" if device else "--oauth"]
    # anthropic
    if device:
        raise ValueError(
            "anthropic login does not support --device login; the Claude "
            "Code CLI's interactive auth-code paste flow is part of "
            "`claude auth login` — run it and paste the code when prompted."
        )
    return ["claude", "auth", "login"]


# ──────────────────────────────────────────────────────────────────────
# Credential-store metadata
# ──────────────────────────────────────────────────────────────────────


def store_metadata(
    provider: str,
    env: Mapping[str, str] | None = None,
    home: str | Path | None = None,
) -> dict[str, Any]:
    """Return cheap metadata about the provider's official credential store.

    ``env`` may override the store root (``CODEX_HOME`` / ``CLAUDE_CONFIG_DIR``
    / ``GROK_HOME``); otherwise ``home`` (or ``$HOME``) is used. The dict
    contains only presence/location info — never credential values.
    """
    canonical_provider = normalize_provider(provider)
    contract = _require_contract(canonical_provider)
    env = env or {}
    if home is None:
        home = env.get("HOME") or Path.home()
    override = env.get(contract.store_env_var)
    if override:
        root = Path(override)
        store_path = root / contract.store_file_name
    else:
        root = Path(home)
        store_path = root / contract.store_dir_name / contract.store_file_name
    return {
        "provider": canonical_provider,
        "store_env_var": contract.store_env_var,
        "store_dir_name": contract.store_dir_name,
        "store_file_name": contract.store_file_name,
        "store_path": str(store_path),
        "exists": store_path.exists(),
    }


# ──────────────────────────────────────────────────────────────────────
# OAuth subprocess environment
# ──────────────────────────────────────────────────────────────────────


def build_oauth_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a copy of ``env`` with every provider key/base-URL override removed.

    The caller's dict is never mutated. When ``env`` is ``None`` a copy of
    ``os.environ`` is scrubbed.
    """
    clean = dict(os.environ if env is None else env)
    for key in OAUTH_STRIPPED_ENV_KEYS:
        clean.pop(key, None)
    return clean


# ──────────────────────────────────────────────────────────────────────
# Login + status delegation
# ──────────────────────────────────────────────────────────────────────


def _default_login_runner(argv: list[str], env: dict[str, str] | None = None, **kwargs: Any) -> int:
    """Run an interactive login with inherited stdio so the official CLI can
    open its browser / prompt for an auth code directly on the terminal."""
    result = subprocess.run(argv, env=env)
    return result.returncode


def run_login(
    provider: str,
    device: bool = False,
    env: Mapping[str, str] | None = None,
    runner: Callable[..., Any] | None = None,
) -> int:
    """Delegate a login to the provider's official CLI.

    ``runner`` is injected for tests; by default the CLI streams directly to
    the terminal and its output is never captured or logged. Returns the
    process exit code — never a credential.
    """
    argv = login_command(provider, device=device)
    clean_env = build_oauth_env(env)
    executor = runner if runner is not None else _default_login_runner
    try:
        return executor(argv, env=clean_env)
    except OSError:
        contract = _require_contract(provider)
        raise LLMAuthenticationError(
            provider,
            f"Official {contract.binary} CLI is not installed or unavailable on PATH",
        ) from None


def capture_runner(argv: list[str], env: dict[str, str] | None = None, **kwargs: Any) -> Any:
    """Capture stdout/stderr (used by non-interactive status probes)."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(argv, env=env, **kwargs)


def build_auth_status(
    provider: str,
    env: Mapping[str, str] | None = None,
    home: str | Path | None = None,
    which: Callable[[str], str | None] | None = None,
    runner: Callable[..., Any] | None = None,
    probe_timeout: float = 10,
) -> dict[str, Any]:
    """Build a readiness status dict for a provider without exposing values.

    Resolution:
      1. binary missing on PATH → ``missing_binary``
      2. ``runner`` supplied (openai/anthropic) → classify the official status
         output; only an explicit subscription is ``subscription`` ready
      3. otherwise store presence is an unverified hint (always for xai).

    The returned dict carries presence booleans, paths, and a coarse auth kind
    only — never status stdout, tokens, or key values.
    """
    canonical_provider = normalize_provider(provider)
    contract = _require_contract(canonical_provider)
    base_env: Mapping[str, str] = os.environ if env is None else env
    resolver = which if which is not None else shutil.which
    binary_path = resolver(contract.binary) if callable(resolver) else None
    meta = store_metadata(canonical_provider, env=base_env, home=home)
    status: dict[str, Any] = {
        "provider": canonical_provider,
        "binary": contract.binary,
        "binary_path": binary_path,
        "binary_present": bool(binary_path),
        "store_present": bool(meta["exists"]),
        "store_path": meta["store_path"],
        "refresh_owner": contract.refresh_owner,
        "auth_kind": "none",
        "api_key_env_var": contract.api_key_env_var,
    }
    if not binary_path:
        status["status"] = "missing_binary"
        return status

    # xai: no documented status probe — cheap store presence is the signal.
    if runner is not None and canonical_provider != "xai":
        argv = list(contract.status_command)
        try:
            result = runner(
                argv,
                env=build_oauth_env(base_env),
                timeout=probe_timeout,
            )
            rc = result if isinstance(result, int) else getattr(result, "returncode", None)
            if rc != 0:
                status["status"] = "not_logged_in"
                status["auth_kind"] = "none"
            else:
                output = "" if isinstance(result, int) else str(
                    getattr(result, "stdout", "") or ""
                )
                auth_kind = _classify_cli_auth(canonical_provider, output)
                status["auth_kind"] = auth_kind
                status["status"] = {
                    "subscription": "subscription",
                    "api_key": "api_billed",
                    "none": "not_logged_in",
                    "unknown": "unknown_login",
                }[auth_kind]
        except Exception:
            status["status"] = "not_logged_in"
        return status

    if canonical_provider == "xai":
        status["status"] = "store_present" if meta["exists"] else "not_logged_in"
        status["auth_kind"] = "oauth_unverified" if meta["exists"] else "none"
    else:
        status["status"] = "store_present" if meta["exists"] else "not_logged_in"
        status["auth_kind"] = "unknown" if meta["exists"] else "none"
    return status


__all__ = [
    "LLMAuthenticationError",
    "LLMProviderError",
    "OAUTH_STRIPPED_ENV_KEYS",
    "PROVIDER_ALIASES",
    "PROVIDER_CONTRACTS",
    "ProviderContract",
    "build_auth_status",
    "build_oauth_env",
    "capture_runner",
    "login_command",
    "normalize_provider",
    "redact_secrets",
    "run_login",
    "store_metadata",
]
