"""OAuth CLI inference backend — runs each provider's official CLI.

``OAuthCLIChatModel`` is a LangChain-shaped chat model whose ``invoke()``
executes the provider's maintained official CLI in a private empty working
directory, feeds the prompt on stdin (openai/anthropic) or via a 0600
prompt file (xai), parses the CLI's stdout contract with the per-provider
parser, and returns a subscription-backed response
(``billing_mode="subscription"``, zero estimated USD).

The parsers are driven by placeholder fixtures under
``tests/fixtures/llm_auth/`` that cite the upstream CLI/document contract
each represents.

Security invariants:
  * argv never contains the prompt or a credential;
  * the subprocess environment is scrubbed of provider keys/base URLs;
  * auth failures raise sanitized ``LLMAuthenticationError`` (no key / JWT /
    Bearer-shaped text survives);
  * multimodal (image) input is refused with a clear error pointing at the
    provider's API-key mode — image bytes are never silently dropped.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn

from nexusrecon.llm.auth import (
    PROVIDER_CONTRACTS,
    LLMAuthenticationError,
    LLMProviderError,
    build_oauth_env,
)

#: Default system prompt handed to the official CLIs. Static text only —
#: never the operator prompt, never a secret.
_DEFAULT_SYSTEM_PROMPT = (
    "You are NexusRecon, an agentic OSINT orchestration engine. "
    "Produce precise, evidence-based analysis and follow the operator's "
    "output-format instructions exactly."
)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _raise_cli_failure(provider: str, detail: str) -> NoReturn:
    """Raise auth failures separately from transport/contract failures."""
    lowered = detail.lower()
    auth_markers = (
        "authentication", "unauthorized", "not logged in", "please login",
        "please log in", "invalid api key", "invalid bearer", "session expired",
        "oauth session", "http 401", "status 401", " 401 ",
    )
    error_type = (
        LLMAuthenticationError
        if any(marker in lowered for marker in auth_markers)
        else LLMProviderError
    )
    raise error_type(provider, detail)


# ──────────────────────────────────────────────────────────────────────
# Per-provider CLI output parsers
# ──────────────────────────────────────────────────────────────────────


def parse_codex_jsonl(stdout: str) -> tuple[str, dict[str, int]]:
    """Parse ``codex exec --json`` NDJSON into ``(content, usage)``.

    Success shape (codex_success.jsonl): ``item.completed`` carrying the
    final ``assistant_message`` text, then ``turn.completed`` carrying
    ``usage``. Auth failure shape: a ``turn.failed`` event whose
    ``error.message`` names the failed authentication → sanitized
    :class:`LLMAuthenticationError`.
    """
    content_parts: list[str] = []
    usage: dict[str, Any] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        etype = obj.get("type")
        if etype == "turn.failed":
            err = obj.get("error") or {}
            message = err.get("message") if isinstance(err, dict) else str(err)
            _raise_cli_failure(
                "openai", message or "codex CLI reported a failed turn"
            )
        if etype == "item.completed":
            item = obj.get("item") or {}
            if isinstance(item, dict) and (
                item.get("type") == "agent_message"
                or item.get("item_type") in {"agent_message", "assistant_message"}
            ):
                text = item.get("text")
                if isinstance(text, str) and text.strip():
                    content_parts.append(text)
        elif etype == "turn.completed":
            u = obj.get("usage")
            if isinstance(u, dict):
                usage = u
    if not content_parts:
        raise LLMProviderError(
            "openai", "codex CLI completed without a final agent message"
        )
    content = content_parts[-1]
    return content, {
        "input_tokens": _as_int(usage.get("input_tokens")),
        "output_tokens": _as_int(usage.get("output_tokens")),
    }


def parse_claude_json(data: str) -> tuple[str, dict[str, int]]:
    """Parse ``claude -p --output-format json`` result envelopes.

    Success shape (claude_success.json): ``result`` envelope with
    ``type/subtype/result/usage``. Error shape: ``is_error: true`` envelope
    whose ``result`` names the failed authentication → sanitized
    :class:`LLMAuthenticationError`.
    """
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, TypeError) as exc:
        raise LLMProviderError(
            "anthropic", f"claude CLI returned non-JSON output: {exc}"
        ) from exc
    if not isinstance(obj, dict):
        raise LLMProviderError(
            "anthropic", "claude CLI returned an unexpected result envelope"
        )
    if obj.get("is_error") or obj.get("subtype") == "error" or obj.get("type") == "error":
        detail = obj.get("result") or obj.get("error") or data
        if isinstance(detail, dict):
            detail = json.dumps(detail)
        _raise_cli_failure("anthropic", str(detail))
    result = obj.get("result")
    if not isinstance(result, str) or not result.strip():
        raise LLMProviderError(
            "anthropic", "claude CLI success envelope omitted result text"
        )
    raw_usage = obj.get("usage")
    usage = raw_usage if isinstance(raw_usage, dict) else {}
    return result, {
        "input_tokens": _as_int(usage.get("input_tokens")),
        "output_tokens": _as_int(usage.get("output_tokens")),
    }


def parse_grok_json(data: str) -> tuple[str, dict[str, int]]:
    """Parse ``grok --output-format json`` output.

    Success shape (grok_success.json): single JSON object with ``text`` +
    ``usage``. Failure shape: plain-text stderr (grok_auth_error.txt)
    naming the failed authentication → sanitized
    :class:`LLMAuthenticationError` naming the login command + key var.
    """
    text = data.strip()
    if not text:
        raise LLMProviderError("xai", "grok CLI produced empty output")
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict):
        raw_usage = obj.get("usage")
        usage = raw_usage if isinstance(raw_usage, dict) else {}
        result_text = obj.get("text")
        if isinstance(result_text, str) and result_text.strip():
            parsed_usage = {
                "input_tokens": _as_int(usage.get("input_tokens")),
                "output_tokens": _as_int(usage.get("output_tokens")),
            } if usage else {}
            return result_text, parsed_usage
        detail = obj.get("error") or obj.get("message") or text
        if isinstance(detail, dict):
            detail = json.dumps(detail)
        _raise_cli_failure("xai", str(detail))
    # Plain-text stderr from a JSON invocation is a failure. Only recognized
    # auth markers trigger API-key fallback; everything else stays visible.
    _raise_cli_failure("xai", text)


# ──────────────────────────────────────────────────────────────────────
# Default subprocess runner
# ──────────────────────────────────────────────────────────────────────


def _default_inference_runner(
    argv: list[str], env: dict[str, str] | None = None, **kwargs: Any
) -> Any:
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    cwd = kwargs.pop("cwd", None)
    timeout = kwargs.pop("timeout", None)
    return subprocess.run(argv, env=env, cwd=cwd, timeout=timeout, **kwargs)


# ──────────────────────────────────────────────────────────────────────
# Response object
# ──────────────────────────────────────────────────────────────────────


class OAuthCLIResponse:
    """Subscription-backed response: zero-cost, token-counted."""

    billing_mode = "subscription"

    def __init__(
        self,
        model_name: str,
        content: str,
        usage_metadata: dict[str, int] | None = None,
    ) -> None:
        self.model_name = model_name
        self.content = content
        self.usage_metadata = usage_metadata or {}
        self.response_metadata: dict[str, Any] = {"model_name": model_name}

    def __str__(self) -> str:
        return self.content


# ──────────────────────────────────────────────────────────────────────
# OAuth CLI chat model
# ──────────────────────────────────────────────────────────────────────


class OAuthCLIChatModel:
    """Text-only, LangChain-shaped chat model backed by a provider's CLI.

    ``invoke()`` builds the official CLI argv, runs it in a private empty
    working directory with a scrubbed environment, and parses stdout. The
    runner is injectable so tests never spawn a real binary.
    """

    def __init__(
        self,
        provider: str,
        *,
        runner: Callable[..., Any] | None = None,
        env: Mapping[str, str] | None = None,
        workdir: str | Path | None = None,
        model_name: str | None = None,
        cli_timeout: int | None = None,
        system_prompt: str | None = None,
    ) -> None:
        if provider not in PROVIDER_CONTRACTS:
            raise ValueError(
                f"Unsupported OAuth provider {provider!r}; choose from "
                f"{', '.join(sorted(PROVIDER_CONTRACTS))}."
            )
        self.provider = provider
        self._contract = PROVIDER_CONTRACTS[provider]
        self._model_override = model_name
        self.model_name = model_name or f"{self._contract.binary}-default"
        self.runner = runner if runner is not None else _default_inference_runner
        self.env = build_oauth_env(env if env is not None else os.environ)
        self.workdir = workdir
        if cli_timeout is not None:
            self.cli_timeout = cli_timeout
        else:
            try:
                self.cli_timeout = int(os.environ.get("NEXUS_LLM_CLI_TIMEOUT") or 600)
            except (TypeError, ValueError):
                self.cli_timeout = 600
        self.system_prompt = (
            system_prompt if system_prompt is not None else _DEFAULT_SYSTEM_PROMPT
        )

    # ── Prompt coercion ────────────────────────────────────────────

    @staticmethod
    def _content_blocks_to_text(content: list[Any], key_var: str) -> str:
        """Flatten LangChain content blocks to text; refuse image content."""
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype in ("text", "input_text", "output_text", "tool_result"):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif btype in ("image_url", "image", "image_file"):
                raise NotImplementedError(
                    f"The {key_var} provider OAuth CLI backend is text-only and "
                    "cannot transmit image content. Set NEXUS_LLM_AUTH_MODE=api_key "
                    f"and {key_var} to use API-key mode for vision (or keep using "
                    "the text-based PDF-vision fallback)."
                )
            else:
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
                else:
                    raise NotImplementedError(
                        f"The {key_var} provider OAuth CLI backend is text-only and "
                        f"cannot transmit {btype or 'unknown'} content. Set "
                        "NEXUS_LLM_AUTH_MODE=api_key and "
                        f"{key_var} to use API-key mode for non-text input."
                    )
        return "\n".join(parts)

    def _coerce_prompt(self, messages: Any) -> str:
        """Reduce a string / BaseMessage list / message list to plain text."""
        key_var = self._contract.api_key_env_var
        if isinstance(messages, str):
            return messages
        if isinstance(messages, (list, tuple)):
            parts: list[str] = []
            for message in messages:
                if isinstance(message, str):
                    parts.append(message)
                    continue
                if isinstance(message, dict):
                    content = message.get("content")
                else:
                    content = getattr(message, "content", None)
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    parts.append(self._content_blocks_to_text(content, key_var))
            text = "\n\n".join(p for p in parts if p)
            if not text:
                raise ValueError("empty prompt")
            return text
        content = getattr(messages, "content", messages)
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return self._content_blocks_to_text(content, key_var)
        raise TypeError(f"Unsupported prompt type: {type(messages).__name__}")

    # ── Command construction ───────────────────────────────────────

    def _inference_argv(self, prompt_path: str | None = None) -> list[str]:
        """Build the official inference argv. Never contains the prompt body."""
        if self.provider == "openai":
            argv = ["codex", "exec", "--json", "--ephemeral"]
            if self._model_override:
                argv += ["--model", self._model_override]
            argv += [
                "--sandbox", "read-only", "--skip-git-repo-check",
                "--ignore-user-config", "--ignore-rules", "-",
            ]
            return argv
        if self.provider == "anthropic":
            argv = [
                "claude", "--safe-mode", "-p", "--output-format", "json",
                "--tools", "", "--no-session-persistence",
            ]
            if self._model_override:
                argv += ["--model", self._model_override]
            if self.system_prompt:
                argv += ["--system-prompt", self.system_prompt]
            return argv
        if self.provider == "xai":
            if not prompt_path:
                raise ValueError("grok inference requires a --prompt-file path")
            argv = [
                "grok", "--prompt-file", str(prompt_path),
                "--output-format", "json", "--tools", "",
                "--no-plan", "--no-subagents", "--no-memory",
                "--disable-web-search", "--max-turns", "1", "--verbatim",
            ]
            if self._model_override:
                argv += ["--model", self._model_override]
            if self.system_prompt:
                argv += ["--system-prompt-override", self.system_prompt]
            return argv
        raise ValueError(f"Unsupported provider: {self.provider}")

    # ── Workdir lifecycle ──────────────────────────────────────────

    @contextmanager
    def _workdir(self) -> Any:
        if self.workdir is not None:
            Path(self.workdir).mkdir(parents=True, exist_ok=True)
            yield str(self.workdir)
        else:
            wd = tempfile.mkdtemp(prefix="nexus_oauth_cli_")
            try:
                yield wd
            finally:
                shutil.rmtree(wd, ignore_errors=True)

    # ── invoke ─────────────────────────────────────────────────────

    def invoke(self, messages: Any) -> OAuthCLIResponse:
        """Run the official CLI and return a subscription-backed response."""
        prompt = self._coerce_prompt(messages)
        with self._workdir() as wd:
            if self.provider == "xai":
                return self._invoke_grok(prompt, wd)
            argv = self._inference_argv()
            try:
                result = self.runner(
                    argv, env=self.env, input=prompt,
                    cwd=wd, timeout=self.cli_timeout,
                )
            except subprocess.TimeoutExpired:
                raise LLMProviderError(
                    self.provider,
                    f"Official {self._contract.binary} CLI timed out after "
                    f"{self.cli_timeout} seconds",
                ) from None
            except OSError:
                raise LLMProviderError(
                    self.provider,
                    f"Official {self._contract.binary} CLI is not installed or unavailable on PATH",
                ) from None
            return self._finalize(result)

    def _invoke_grok(self, prompt: str, wd: str) -> OAuthCLIResponse:
        fd, raw_path = tempfile.mkstemp(dir=wd, prefix="nexus_grok_prompt_", suffix=".txt")
        try:
            # The prompt file is private (0600) while the CLI reads it and is
            # deleted immediately after the CLI returns.
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(prompt)
            argv = self._inference_argv(prompt_path=raw_path)
            try:
                result = self.runner(
                    argv, env=self.env, cwd=wd, timeout=self.cli_timeout,
                )
            except subprocess.TimeoutExpired:
                raise LLMProviderError(
                    self.provider,
                    f"Official {self._contract.binary} CLI timed out after "
                    f"{self.cli_timeout} seconds",
                ) from None
            except OSError:
                raise LLMProviderError(
                    self.provider,
                    f"Official {self._contract.binary} CLI is not installed or unavailable on PATH",
                ) from None
            return self._finalize(result)
        finally:
            try:
                os.unlink(raw_path)
            except OSError:
                pass

    def _finalize(self, result: Any) -> OAuthCLIResponse:
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""
        rc = getattr(result, "returncode", 0)
        parser = {
            "openai": parse_codex_jsonl,
            "anthropic": parse_claude_json,
            "xai": parse_grok_json,
        }[self.provider]

        if rc != 0:
            raw = (stderr or stdout).strip()
            if raw:
                # Let the parser classify auth failures (raising a sanitized
                # LLMAuthenticationError); non-auth failures fall through to
                # the generic sanitized error below.
                try:
                    parser(raw)
                except LLMProviderError:
                    raise
                except Exception:
                    pass
            raise LLMProviderError(
                self.provider,
                raw or f"{self._contract.binary} exited with status {rc}",
            )

        content, usage = parser(stdout)
        return OAuthCLIResponse(self.model_name, content, usage)


__all__ = [
    "OAuthCLIChatModel",
    "OAuthCLIResponse",
    "parse_claude_json",
    "parse_codex_jsonl",
    "parse_grok_json",
]
