"""Recorded-fixture integration tests for ``nexusrecon/llm/cli_backend``.

Contract under test:

- ``OAuthCLIChatModel`` — a LangChain-shaped chat model whose invoke() runs
  the provider's official CLI in a private empty temp dir, parses its stdout
  via the per-provider parser, and returns a subscription-backed response
  (``billing_mode="subscription"``, zero-cost).
- ``parse_codex_jsonl`` / ``parse_claude_json`` / ``parse_grok_json`` — the
  three CLI output parsers, driven by placeholder fixtures under
  ``tests/fixtures/llm_auth/`` that cite the upstream CLI/document contract
  they represent.
- Sanitized errors: auth failures raise ``LLMAuthenticationError`` whose
  message contains no key/JWT/Bearer-shaped substring.
- Multimodal input to a text-only OAuth adapter fails clearly instead of
  silently dropping image bytes.

These tests exercise the production adapters without touching real credential
stores. Live smoke tests remain opt-in and run only when an official CLI login
already exists on disk.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
from types import SimpleNamespace

import pytest

from tests.fixtures import load_text_fixture

# ── Import helpers ─────────────────────────────────────────────────────


def _cli():
    import nexusrecon.llm.cli_backend as m
    return m


def _auth():
    import nexusrecon.llm.auth as m
    return m


CODE_X_SUCCESS_TEXT = (
    "Analysis: Acme's passive footprint concentrates on four live subdomains "
    "and one exposed admin console.\nFINDINGS_JSON:[]"
)
CLAUDE_SUCCESS_TEXT = (
    "Analysis: the external surface is governed by a single M365 tenant with "
    "federation enabled.\nFINDINGS_JSON:[]"
)
GROK_SUCCESS_TEXT = (
    "Analysis: two public buckets expose backup artifacts and a hardcoded AWS "
    "key.\nFINDINGS_JSON:[]"
)


class _FakeRunner:
    """Test double for the injectable subprocess runner.

    Captures the argv/env the model built and returns canned stdout/stderr/
    returncode, so no test ever spawns a real CLI.
    """

    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.argv: list[str] = []
        self.env: dict[str, str] = {}
        self.calls = 0

    def __call__(self, argv, env=None, **kwargs):
        self.argv = list(argv)
        self.env = dict(env or {})
        self.calls += 1
        return SimpleNamespace(
            stdout=self.stdout, stderr=self.stderr, returncode=self.returncode
        )


def _has_secret_shape(text: str) -> bool:
    for shape in ("sk-", "xai-", "eyJhbGciOiJIUzI1NiJ9", "Bearer "):
        if shape in text:
            return True
    return False


# ──────────────────────────────────────────────────────────────────────
# Per-provider output parsers (driven by fixtures)
# ──────────────────────────────────────────────────────────────────────


class TestCodexParser:
    def test_success_fixture_parses_content_and_usage(self):
        m = _cli()
        stdout = load_text_fixture("llm_auth/codex_success.jsonl")
        content, usage = m.parse_codex_jsonl(stdout)
        assert content == CODE_X_SUCCESS_TEXT
        assert usage["input_tokens"] == 1200
        assert usage["output_tokens"] == 300

    def test_auth_error_fixture_raises_sanitized_error(self):
        m = _cli()
        a = _auth()
        stdout = load_text_fixture("llm_auth/codex_auth_error.jsonl")
        with pytest.raises(a.LLMAuthenticationError) as ei:
            m.parse_codex_jsonl(stdout)
        msg = str(ei.value)
        assert not _has_secret_shape(msg)
        # The safe remediation prose survives.
        assert "codex login" in msg

    def test_success_event_without_agent_message_is_rejected(self):
        m = _cli()
        a = _auth()
        with pytest.raises(a.LLMProviderError, match="agent message"):
            m.parse_codex_jsonl(
                '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}'
            )


class TestClaudeParser:
    def test_success_fixture_parses_content_and_usage(self):
        m = _cli()
        data = load_text_fixture("llm_auth/claude_success.json")
        content, usage = m.parse_claude_json(data)
        assert content == CLAUDE_SUCCESS_TEXT
        assert usage["input_tokens"] == 5000
        assert usage["output_tokens"] == 1200

    def test_auth_error_fixture_raises_sanitized_error(self):
        m = _cli()
        a = _auth()
        data = load_text_fixture("llm_auth/claude_auth_error.json")
        with pytest.raises(a.LLMAuthenticationError) as ei:
            m.parse_claude_json(data)
        msg = str(ei.value)
        assert not _has_secret_shape(msg)
        assert "claude auth login" in msg

    def test_success_envelope_without_result_is_provider_error(self):
        m = _cli()
        a = _auth()
        with pytest.raises(a.LLMProviderError, match="result text"):
            m.parse_claude_json(
                '{"type":"result","subtype":"success","is_error":false}'
            )


class TestGrokParser:
    def test_success_fixture_parses_content_and_usage(self):
        m = _cli()
        data = load_text_fixture("llm_auth/grok_success.json")
        content, usage = m.parse_grok_json(data)
        assert content == GROK_SUCCESS_TEXT
        assert usage["input_tokens"] == 900
        assert usage["output_tokens"] == 410

    def test_success_without_usage_still_returns_text(self):
        m = _cli()
        content, usage = m.parse_grok_json(
            '{"text":"valid OAuth result","stopReason":"end_turn"}'
        )
        assert content == "valid OAuth result"
        assert usage == {}

    def test_auth_error_fixture_raises_sanitized_error(self):
        m = _cli()
        a = _auth()
        stderr = load_text_fixture("llm_auth/grok_auth_error.txt")
        with pytest.raises(a.LLMAuthenticationError) as ei:
            m.parse_grok_json(stderr)
        msg = str(ei.value)
        assert not _has_secret_shape(msg)
        assert "grok login --oauth" in msg
        assert "XAI_API_KEY" in msg


# ──────────────────────────────────────────────────────────────────────
# OAuthCLIChatModel
# ──────────────────────────────────────────────────────────────────────


class TestOAuthCLIChatModel:
    def test_codex_success_round_trip(self, tmp_path):
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/codex_success.jsonl"),
            returncode=0,
        )
        model = m.OAuthCLIChatModel(
            "openai", runner=runner, env={"PATH": "/usr/bin"}, workdir=tmp_path
        )
        resp = model.invoke("Find exposed admin consoles for acme.com")
        assert resp.content == CODE_X_SUCCESS_TEXT
        assert resp.usage_metadata["input_tokens"] == 1200
        assert resp.usage_metadata["output_tokens"] == 300
        # A subscription-backed OAuth response: zero-cost, token-counted.
        assert resp.billing_mode == "subscription"

    def test_claude_success_round_trip(self, tmp_path):
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/claude_success.json"), returncode=0
        )
        model = m.OAuthCLIChatModel(
            "anthropic", runner=runner, env={"PATH": "/usr/bin"}, workdir=tmp_path
        )
        resp = model.invoke("Map the M365 federation for the target")
        assert resp.content == CLAUDE_SUCCESS_TEXT
        assert resp.usage_metadata["input_tokens"] == 5000
        assert resp.usage_metadata["output_tokens"] == 1200
        assert resp.billing_mode == "subscription"

    def test_grok_success_round_trip(self, tmp_path):
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/grok_success.json"), returncode=0
        )
        model = m.OAuthCLIChatModel(
            "xai", runner=runner, env={"PATH": "/usr/bin"}, workdir=tmp_path
        )
        resp = model.invoke("Which buckets are public for acme?")
        assert resp.content == GROK_SUCCESS_TEXT
        assert resp.usage_metadata["input_tokens"] == 900
        assert resp.usage_metadata["output_tokens"] == 410
        assert resp.billing_mode == "subscription"

    def test_model_name_is_populated_for_telemetry(self, tmp_path):
        m = _cli()
        model = m.OAuthCLIChatModel(
            "anthropic",
            runner=_FakeRunner(stdout=load_text_fixture("llm_auth/claude_success.json")),
            env={"PATH": "/usr/bin"},
            workdir=tmp_path,
        )
        assert isinstance(model.model_name, str) and model.model_name


class TestInferenceCommandConstruction:
    def test_codex_argv_has_no_prompt_or_secret(self, tmp_path):
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/codex_success.jsonl"), returncode=0
        )
        prompt = "classify these subdomains for acme.com sk-PLACEHOLDER_SECRET"
        model = m.OAuthCLIChatModel("openai", runner=runner, workdir=tmp_path)
        model.invoke(prompt)
        argv = " ".join(runner.argv)
        assert runner.argv[0] == "codex"
        assert "--json" in runner.argv
        # Prompt is fed on stdin; it must never appear in argv.
        assert "classify" not in argv
        assert not _has_secret_shape(argv)

    def test_grok_argv_uses_prompt_file_not_inline_prompt(self, tmp_path):
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/grok_success.json"), returncode=0
        )
        prompt = "summarize the public exposure xai-PLACEHOLDER_SECRET"
        model = m.OAuthCLIChatModel("xai", runner=runner, workdir=tmp_path)
        model.invoke(prompt)
        assert runner.argv[0] == "grok"
        assert "--output-format" in runner.argv
        assert "summarize" not in " ".join(runner.argv)
        assert not _has_secret_shape(" ".join(runner.argv))

    def test_grok_prompt_file_is_0600(self, tmp_path):
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/grok_success.json"), returncode=0
        )
        observations: dict = {}

        def capturing(argv, env=None, **kwargs):
            for i, arg in enumerate(argv):
                if arg == "--prompt-file":
                    path = argv[i + 1]
                    observations["path"] = path
                    observations["mode"] = stat.S_IMODE(os.stat(path).st_mode)
                    observations["content"] = open(path, encoding="utf-8").read()
            return SimpleNamespace(
                stdout=runner.stdout, stderr=runner.stderr, returncode=runner.returncode
            )

        prompt = "0600 permission check"
        model = m.OAuthCLIChatModel("xai", runner=capturing, workdir=tmp_path)
        model.invoke(prompt)
        assert "mode" in observations, "runner was never handed --prompt-file"
        assert observations["mode"] == 0o600, (
            f"prompt file must be 0600 while the CLI reads it; got "
            f"{oct(observations['mode'])}"
        )
        assert observations["content"] == prompt
        assert not os.path.exists(observations["path"]), (
            "private Grok prompt file must be deleted after the CLI returns"
        )

    def test_invoke_env_is_scrubbed_of_provider_keys(self, tmp_path):
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/claude_success.json"), returncode=0
        )
        model = m.OAuthCLIChatModel(
            "anthropic",
            runner=runner,
            env={
                "PATH": "/usr/bin",
                "ANTHROPIC_API_KEY": "sk-ant-api03-PLACEHOLDER",
                "OPENAI_API_KEY": "sk-PLACEHOLDER",
                "XAI_API_KEY": "xai-PLACEHOLDER",
                "ANTHROPIC_BASE_URL": "https://PLACEHOLDER.example",
            },
            workdir=tmp_path,
        )
        model.invoke("hello")
        for stripped in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY",
            "ANTHROPIC_BASE_URL",
        ):
            assert stripped not in runner.env, stripped
        assert runner.env["PATH"] == "/usr/bin"

    @pytest.mark.parametrize(
        "provider,model_name",
        [
            ("openai", "gpt-5.3-codex"),
            ("anthropic", "claude-opus-4-6"),
            ("xai", "grok-4.20-beta"),
        ],
    )
    def test_configured_model_is_passed_to_official_cli(
        self, tmp_path, provider, model_name
    ):
        m = _cli()
        model = m.OAuthCLIChatModel(
            provider, model_name=model_name, workdir=tmp_path
        )
        prompt_path = str(tmp_path / "prompt.txt") if provider == "xai" else None
        argv = model._inference_argv(prompt_path=prompt_path)
        assert "--model" in argv
        assert argv[argv.index("--model") + 1] == model_name


class TestOAuthCLIChatModelErrors:
    def test_nonzero_exit_with_auth_stderr_raises_sanitized(self, tmp_path):
        m = _cli()
        a = _auth()
        runner = _FakeRunner(
            stderr=load_text_fixture("llm_auth/grok_auth_error.txt"),
            returncode=1,
        )
        model = m.OAuthCLIChatModel("xai", runner=runner, workdir=tmp_path)
        with pytest.raises(a.LLMAuthenticationError) as ei:
            model.invoke("hello")
        msg = str(ei.value)
        assert not _has_secret_shape(msg)
        assert "grok login --oauth" in msg

    def test_missing_provider_binary_is_actionable(self, tmp_path):
        m = _cli()
        a = _auth()

        def missing(_argv, **_kwargs):
            raise FileNotFoundError("codex")

        model = m.OAuthCLIChatModel(
            "openai", runner=missing, env={}, workdir=tmp_path
        )
        with pytest.raises(a.LLMProviderError) as exc:
            model.invoke("hello")
        assert "codex" in str(exc.value)
        assert "PATH" in str(exc.value)

    def test_timeout_is_actionable_and_never_echoes_prompt(self, tmp_path):
        m = _cli()
        a = _auth()
        private_prompt = "private-campaign-context"

        def timeout(argv, **_kwargs):
            raise subprocess.TimeoutExpired(argv, timeout=1)

        model = m.OAuthCLIChatModel(
            "openai", runner=timeout, env={}, workdir=tmp_path, cli_timeout=1
        )
        with pytest.raises(a.LLMProviderError) as exc:
            model.invoke(private_prompt)
        message = str(exc.value)
        assert "timed out" in message.lower()
        assert private_prompt not in message
        assert "API_KEY" not in message


class TestMultimodalRefusal:
    """OAuth adapters are text-only: refuse rather than silently drop images."""

    def test_image_content_raises_clear_unsupported_error(self, tmp_path):
        m = _cli()
        multimodal_messages = [{
            "role": "user",
            "content": [
                {"type": "text", "text": "Describe this screenshot"},
                {"type": "image_url",
                 "image_url": {"url": "data:image/png;base64,AAAA"}},
            ],
        }]
        model = m.OAuthCLIChatModel("openai", workdir=tmp_path)
        with pytest.raises(NotImplementedError) as ei:
            model.invoke(multimodal_messages)
        msg = str(ei.value)
        # It must point the operator at API-key mode for vision, not drop bytes.
        assert re.search(r"api[_-]?key", msg, re.IGNORECASE)
        assert "OPENAI_API_KEY" in msg

    @pytest.mark.parametrize("provider,key_var", [
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("xai", "XAI_API_KEY"),
    ])
    def test_multimodal_refusal_names_provider_key_var(
        self, tmp_path, provider, key_var
    ):
        m = _cli()
        msg_in = [{
            "role": "user",
            "content": [
                {"type": "text", "text": "text"},
                {"type": "image_url",
                 "image_url": {"url": "data:image/png;base64,AAAA"}},
            ],
        }]
        model = m.OAuthCLIChatModel(provider, workdir=tmp_path)
        with pytest.raises(NotImplementedError) as ei:
            model.invoke(msg_in)
        assert key_var in str(ei.value)

    def test_plain_text_messages_still_work(self, tmp_path):
        """Text-based PDF-vision fallback (text-only messages) stays usable."""
        m = _cli()
        runner = _FakeRunner(
            stdout=load_text_fixture("llm_auth/claude_success.json"), returncode=0
        )
        model = m.OAuthCLIChatModel("anthropic", runner=runner, workdir=tmp_path)
        text_messages = [{"role": "user", "content": "Summarize this PDF text."}]
        resp = model.invoke(text_messages)
        assert resp.content == CLAUDE_SUCCESS_TEXT

    def test_unknown_nontext_block_is_refused_not_silently_dropped(self, tmp_path):
        m = _cli()
        messages = [{
            "role": "user",
            "content": [
                {"type": "text", "text": "Transcribe this"},
                {"type": "audio", "source": {"data": "PLACEHOLDER"}},
            ],
        }]
        model = m.OAuthCLIChatModel("anthropic", workdir=tmp_path)
        with pytest.raises(NotImplementedError, match="text-only"):
            model.invoke(messages)


class TestAuthTyperCommands:
    """The public login/status surface delegates to the maintained CLI layer."""

    def test_browser_login_delegates_without_capturing_credentials(self):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app

        with patch("nexusrecon.llm.auth.run_login", return_value=0) as login:
            result = CliRunner().invoke(app, ["auth", "login", "anthropic"])
        assert result.exit_code == 0, result.output
        login.assert_called_once_with("anthropic", device=False)
        assert "logged in" in result.output.lower()
        assert not _has_secret_shape(result.output)

    def test_device_login_delegates_exact_provider_choice(self):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app

        with patch("nexusrecon.llm.auth.run_login", return_value=0) as login:
            result = CliRunner().invoke(
                app, ["auth", "login", "openai", "--device"]
            )
        assert result.exit_code == 0, result.output
        login.assert_called_once_with("openai", device=True)

    def test_openai_codex_login_alias_delegates_to_existing_auth_layer(self):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app

        with patch("nexusrecon.llm.auth.run_login", return_value=0) as login:
            result = CliRunner().invoke(
                app, ["auth", "login", "openai-codex", "--device"]
            )
        assert result.exit_code == 0, result.output
        login.assert_called_once_with("openai-codex", device=True)

    def test_openai_codex_status_alias_uses_canonical_codex_contract(self):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app

        status = {
            "provider": "openai",
            "binary": "codex",
            "binary_present": True,
            "store_present": True,
            "status": "subscription",
            "auth_kind": "subscription",
        }
        with patch("nexusrecon.llm.auth.build_auth_status", return_value=status) as probe:
            result = CliRunner().invoke(
                app, ["auth", "status", "--provider", "openai-codex"]
            )
        assert result.exit_code == 0, result.output
        probe.assert_called_once()
        assert probe.call_args.args[0] == "openai"
        assert "codex" in result.output.lower()
        assert "subscription login ready" in result.output.lower()

    def test_status_reports_all_providers_without_secret_values(self):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app

        def fake_status(provider, **kwargs):
            return {
                "provider": provider,
                "binary": {"openai": "codex", "anthropic": "claude", "xai": "grok"}[provider],
                "binary_present": True,
                "store_present": provider != "xai",
                "status": "subscription" if provider != "xai" else "not_logged_in",
                "auth_kind": "subscription" if provider != "xai" else "none",
            }

        with patch("nexusrecon.llm.auth.build_auth_status", side_effect=fake_status):
            result = CliRunner().invoke(app, ["auth", "status"])
        assert result.exit_code == 0, result.output
        for provider in ("openai", "anthropic", "xai"):
            assert provider in result.output.lower()
        assert not _has_secret_shape(result.output)

    def test_grok_store_presence_is_labeled_unverified(self):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app

        status = {
            "provider": "xai",
            "binary": "grok",
            "binary_present": True,
            "store_present": True,
            "status": "store_present",
            "auth_kind": "oauth_unverified",
            "api_key_env_var": "XAI_API_KEY",
        }
        with patch("nexusrecon.llm.auth.build_auth_status", return_value=status):
            result = CliRunner().invoke(app, ["auth", "status", "--provider", "xai"])
        assert result.exit_code == 0, result.output
        assert "validated on use" in result.output.lower()
        assert "not logged in" not in result.output.lower()

    @pytest.mark.parametrize(
        "status_code,expected",
        [
            ("api_billed", "api-billed cli login"),
            ("unknown_login", "login type unverified"),
        ],
    )
    def test_non_subscription_cli_login_is_never_labeled_subscription(
        self, status_code, expected
    ):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app

        status = {
            "provider": "openai",
            "binary": "codex",
            "binary_present": True,
            "store_present": True,
            "status": status_code,
            "auth_kind": "api_key" if status_code == "api_billed" else "unknown",
            "api_key_env_var": "OPENAI_API_KEY",
        }
        with patch("nexusrecon.llm.auth.build_auth_status", return_value=status):
            result = CliRunner().invoke(
                app, ["auth", "status", "--provider", "openai"]
            )
        assert result.exit_code == 0, result.output
        assert expected in result.output.lower()
        assert "subscription login ready" not in result.output.lower()

    def test_login_missing_binary_is_reported_without_traceback(self):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from nexusrecon.cli.main import app
        from nexusrecon.llm.auth import LLMAuthenticationError

        with patch(
            "nexusrecon.llm.auth.run_login",
            side_effect=LLMAuthenticationError(
                "openai", "Official codex CLI is not installed or on PATH"
            ),
        ):
            result = CliRunner().invoke(app, ["auth", "login", "openai"])
        assert result.exit_code == 1
        assert "codex" in result.output
        assert "PATH" in result.output
        assert "Traceback" not in result.output
