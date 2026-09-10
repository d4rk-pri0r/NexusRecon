"""Behavior tests for the provider-OAuth authentication layer.

The suite locks the public contracts implemented by ``nexusrecon/llm/auth.py``
and ``nexusrecon/llm/factory.py``:

``nexusrecon/llm/auth.py``
    - ``PROVIDER_CONTRACTS`` / ``ProviderContract``: official binary, store
      location/env var, refresh owner, and login browser/device argv per
      provider. ``login_command()``/``store_metadata()``/``run_login()``
      ``build_oauth_env()``/``build_auth_status()``/``redact_secrets()``.
    - ``LLMAuthenticationError``: the one auth error type the CLI/API layer
      surfaces, with a message that never carries tokens.

``nexusrecon/llm/factory.py``
    - ``resolve_llm_auth_mode``, ``oauth_login_available``,
      ``build_llm_from_config``, and the OAuth→API-key ``OAuthKeyFallback``
      wrapper.

These tests import production modules through small helpers so each contract
can be patched and exercised independently without touching real credentials.
"""
from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import patch

import pytest

# ── Import helpers ─────────────────────────────────────────────────────
# Imports happen inside helpers so each test can independently patch module
# collaborators without collection-time side effects.


def _auth():
    import nexusrecon.llm.auth as m
    return m


def _factory():
    import nexusrecon.llm.factory as m
    return m


def _cli_backend():
    import nexusrecon.llm.cli_backend as m
    return m


PROVIDERS = ("openai", "anthropic", "xai")

# Key-shaped placeholder substrings that must NEVER survive surfacing.
SECRET_SHAPES = (
    "sk-ant-api03-",
    "sk-",
    "xai-",
    "eyJhbGciOiJIUzI1NiJ9.",  # JWT header segment
    "Bearer ",
)


def _assert_no_secret_shapes(text: str) -> None:
    for shape in SECRET_SHAPES:
        assert shape not in text, f"secret-shaped text leaked through: {shape!r}"


# ──────────────────────────────────────────────────────────────────────
# Provider contracts
# ──────────────────────────────────────────────────────────────────────


class TestProviderContracts:
    """The contract table: official binaries, stores, and refresh owner."""

    def test_binaries_are_the_providers_official_clis(self):
        m = _auth()
        expected = {"openai": "codex", "anthropic": "claude", "xai": "grok"}
        assert set(m.PROVIDER_CONTRACTS) == {"openai", "anthropic", "xai"}
        for provider, binary in expected.items():
            assert m.PROVIDER_CONTRACTS[provider].binary == binary, provider

    def test_stores_documented_per_provider(self):
        m = _auth()
        c_openai = m.PROVIDER_CONTRACTS["openai"]
        assert c_openai.store_env_var == "CODEX_HOME"
        assert c_openai.store_dir_name == ".codex"
        assert c_openai.store_file_name == "auth.json"

        c_anthropic = m.PROVIDER_CONTRACTS["anthropic"]
        assert c_anthropic.store_env_var == "CLAUDE_CONFIG_DIR"
        assert c_anthropic.store_dir_name == ".claude"
        assert c_anthropic.store_file_name == ".credentials.json"

        c_xai = m.PROVIDER_CONTRACTS["xai"]
        assert c_xai.store_env_var == "GROK_HOME"
        assert c_xai.store_dir_name == ".grok"
        assert c_xai.store_file_name == "auth.json"

    def test_refresh_owner_is_the_official_cli_not_nexusrecon(self):
        m = _auth()
        for provider in PROVIDERS:
            c = m.PROVIDER_CONTRACTS[provider]
            assert c.refresh_owner == "official_cli", provider
            assert c.api_key_env_var, provider

    def test_api_key_env_vars_match_plan(self):
        m = _auth()
        expected = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "xai": "XAI_API_KEY",
        }
        for provider, env_var in expected.items():
            assert m.PROVIDER_CONTRACTS[provider].api_key_env_var == env_var

    def test_openai_codex_is_a_thin_alias_not_a_duplicate_contract(self):
        m = _auth()
        assert m.PROVIDER_ALIASES == {"openai-codex": "openai"}
        assert m.normalize_provider("openai-codex") == "openai"
        assert m.normalize_provider("OPENAI-CODEX") == "openai"
        assert "openai-codex" not in m.PROVIDER_CONTRACTS


class TestLoginCommands:
    def test_browser_login_argv_is_exact(self):
        m = _auth()
        assert m.login_command("openai") == ["codex", "login"]
        assert m.login_command("openai-codex") == ["codex", "login"]
        assert m.login_command("anthropic") == ["claude", "auth", "login"]
        assert m.login_command("xai") == ["grok", "login", "--oauth"]

    def test_device_login_argv_is_exact(self):
        m = _auth()
        assert m.login_command("openai", device=True) == [
            "codex", "login", "--device-auth",
        ]
        assert m.login_command("openai-codex", device=True) == [
            "codex", "login", "--device-auth",
        ]
        assert m.login_command("xai", device=True) == [
            "grok", "login", "--device-auth",
        ]

    def test_anthropic_rejects_device_login_with_clear_message(self):
        m = _auth()
        with pytest.raises(ValueError) as ei:
            m.login_command("anthropic", device=True)
        msg = str(ei.value).lower()
        assert "device" in msg
        assert "paste" in msg  # points at the CLI auth-code paste fallback

    def test_login_argv_contains_no_prompt_or_secret(self):
        m = _auth()
        for provider in PROVIDERS:
            argv = m.login_command(provider)
            for arg in argv:
                assert "prompt" not in arg.lower()
                _assert_no_secret_shapes(arg)


class TestStoreMetadata:
    def test_default_home_paths(self, tmp_path):
        m = _auth()
        openai_meta = m.store_metadata("openai", env={}, home=tmp_path)
        assert openai_meta["store_path"] == str(tmp_path / ".codex" / "auth.json")
        anthropic_meta = m.store_metadata("anthropic", env={}, home=tmp_path)
        assert anthropic_meta["store_path"] == str(
            tmp_path / ".claude" / ".credentials.json"
        )
        xai_meta = m.store_metadata("xai", env={}, home=tmp_path)
        assert xai_meta["store_path"] == str(tmp_path / ".grok" / "auth.json")

    def test_env_override_wins_over_home(self, tmp_path):
        m = _auth()
        meta = m.store_metadata(
            "openai", env={"CODEX_HOME": str(tmp_path / "custom")}, home=tmp_path
        )
        assert meta["store_path"] == str(tmp_path / "custom" / "auth.json")

    def test_exists_reflects_file_presence(self, tmp_path):
        m = _auth()
        missing = m.store_metadata("xai", env={}, home=tmp_path)
        assert missing["exists"] is False
        store = tmp_path / ".grok"
        store.mkdir()
        (store / "auth.json").touch()
        present = m.store_metadata("xai", env={}, home=tmp_path)
        assert present["exists"] is True


class TestBuildOAuthEnv:
    """A claimed subscription call must not silently become a metered key call."""

    def test_strips_all_provider_keys_and_base_url_overrides(self):
        m = _auth()
        dirty = {
            "PATH": "/usr/bin",
            "HOME": "/home/tester",
            "NEXUS_LLM_CLI_TIMEOUT": "600",
            "OPENAI_API_KEY": "sk-PLACEHOLDER",
            "ANTHROPIC_API_KEY": "sk-ant-api03-PLACEHOLDER",
            "XAI_API_KEY": "xai-PLACEHOLDER",
            "CODEX_API_KEY": "sk-PLACEHOLDER",
            "OPENAI_BASE_URL": "https://PLACEHOLDER.example/v1",
            "ANTHROPIC_BASE_URL": "https://PLACEHOLDER.example",
            "ANTHROPIC_AUTH_TOKEN": "synthetic-auth-token",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "CLAUDE_CODE_USE_VERTEX": "1",
            "CLAUDE_CODE_USE_FOUNDRY": "1",
            "ANTHROPIC_BEDROCK_BASE_URL": "https://PLACEHOLDER.example",
            "ANTHROPIC_VERTEX_BASE_URL": "https://PLACEHOLDER.example",
            "ANTHROPIC_FOUNDRY_BASE_URL": "https://PLACEHOLDER.example",
            "CLAUDE_CODE_OAUTH_TOKEN": "oauth-token-placeholder",
            "XAI_BASE_URL": "https://PLACEHOLDER.example/v1",
            "UNRELATED_VAR": "keep-me",
        }
        clean = m.build_oauth_env(dirty)
        for stripped in (
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY",
            "CODEX_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL",
            "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
            "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
            "ANTHROPIC_FOUNDRY_BASE_URL", "XAI_BASE_URL",
        ):
            assert stripped not in clean, stripped
        # Non-secret runtime variables survive.
        assert clean["PATH"] == "/usr/bin"
        assert clean["HOME"] == "/home/tester"
        assert clean["NEXUS_LLM_CLI_TIMEOUT"] == "600"
        assert clean["UNRELATED_VAR"] == "keep-me"
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in clean

    def test_default_env_and_no_mutation(self):
        m = _auth()
        base = {"OPENAI_API_KEY": "sk-PLACEHOLDER", "PATH": "/bin"}
        snapshot = dict(base)
        clean = m.build_oauth_env(base)
        assert base == snapshot  # caller's dict untouched
        assert "OPENAI_API_KEY" not in clean


class TestLoginDelegation:
    """CLI browser/device paths delegate exact argv without capturing secrets."""

    def _fake_runner(self, captured):
        def runner(argv, env=None, **kwargs):
            captured["argv"] = list(argv)
            captured["env"] = dict(env or {})
            return 0
        return runner

    def test_run_login_delegates_exact_browser_argv(self):
        m = _auth()
        captured: dict = {}
        rc = m.run_login(
            "openai",
            env={"PATH": "/usr/bin", "OPENAI_API_KEY": "sk-PLACEHOLDER"},
            runner=self._fake_runner(captured),
        )
        assert rc == 0
        assert captured["argv"] == ["codex", "login"]
        # The env handed to the CLI must already be scrubbed of key material.
        assert "OPENAI_API_KEY" not in captured["env"]

    def test_run_login_delegates_exact_device_argv(self):
        m = _auth()
        captured: dict = {}
        m.run_login(
            "xai",
            device=True,
            env={"PATH": "/usr/bin", "XAI_API_KEY": "xai-PLACEHOLDER"},
            runner=self._fake_runner(captured),
        )
        assert captured["argv"] == ["grok", "login", "--device-auth"]
        assert "XAI_API_KEY" not in captured["env"]

    def test_run_login_streams_and_returns_nothing_credential(self):
        m = _auth()
        captured: dict = {}
        result = m.run_login(
            "anthropic",
            env={"PATH": "/usr/bin"},
            runner=self._fake_runner(captured),
        )
        assert captured["argv"] == ["claude", "auth", "login"]
        # The call returns only an exit/status signal — never captured output.
        assert not isinstance(result, str)

    def test_run_login_missing_binary_is_actionable(self):
        m = _auth()

        def missing(_argv, **_kwargs):
            raise FileNotFoundError("codex")

        with pytest.raises(m.LLMAuthenticationError) as exc:
            m.run_login("openai", runner=missing, env={})
        message = str(exc.value)
        assert "codex" in message
        assert "PATH" in message
        assert "OPENAI_API_KEY" in message


class TestAuthStatus:
    def _which(self, binary):
        def which(name):
            return f"/usr/local/bin/{name}" if name == binary else None
        return which

    def test_status_never_returns_token_values(self, tmp_path):
        m = _auth()
        for provider in PROVIDERS:
            contract = m.PROVIDER_CONTRACTS[provider]
            status = m.build_auth_status(
                provider,
                env={},
                home=tmp_path,
                which=self._which(contract.binary),
            )
            _assert_no_secret_shapes(str(status))

    def test_missing_binary_is_handled(self, tmp_path):
        m = _auth()
        status = m.build_auth_status(
            "openai", env={}, home=tmp_path, which=lambda name: None
        )
        assert status["provider"] == "openai"
        assert status["binary"] == "codex"
        assert status["binary_present"] is False
        assert status["status"] == "missing_binary"

    def test_probe_reporting_not_logged_in(self, tmp_path):
        m = _auth()

        def not_logged_in(argv, **kwargs):
            assert argv == ["codex", "login", "status"]
            return SimpleNamespace(returncode=1, stdout="Not logged in", stderr="")

        status = m.build_auth_status(
            "openai",
            env={},
            home=tmp_path,
            which=self._which("codex"),
            runner=not_logged_in,
        )
        assert status["binary_present"] is True
        assert status["store_present"] is False
        assert status["status"] == "not_logged_in"

    def test_store_metadata_fallback_without_runner(self, tmp_path):
        m = _auth()
        status = m.build_auth_status(
            "openai", env={}, home=tmp_path, which=self._which("codex")
        )
        assert status["binary_present"] is True
        assert status["store_present"] is False
        assert status["status"] == "not_logged_in"

    def test_official_status_wins_without_file_store(self, tmp_path):
        m = _auth()

        def logged_in(argv, **kwargs):
            assert argv == ["codex", "login", "status"]
            return SimpleNamespace(returncode=0, stdout="Logged in using ChatGPT", stderr="")

        status = m.build_auth_status(
            "openai",
            env={},
            home=tmp_path,
            which=self._which("codex"),
            runner=logged_in,
        )
        assert status["store_present"] is False  # keyring-backed login is valid
        assert status["status"] == "subscription"
        assert status["auth_kind"] == "subscription"

    def test_codex_stored_api_key_login_is_not_subscription(self, tmp_path):
        m = _auth()

        def api_login(_argv, **_kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout="Logged in using an API key - [masked]",
                stderr="",
            )

        status = m.build_auth_status(
            "openai", env={}, home=tmp_path,
            which=self._which("codex"), runner=api_login,
        )
        assert status["status"] == "api_billed"
        assert status["auth_kind"] == "api_key"

    def test_claude_pro_login_is_subscription(self, tmp_path):
        m = _auth()

        def pro_login(_argv, **_kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    '{"loggedIn":true,"authMethod":"claude.ai",'
                    '"apiProvider":"firstParty","subscriptionType":"pro",'
                    '"apiKeySource":"/login managed key"}'
                ),
                stderr="",
            )

        status = m.build_auth_status(
            "anthropic", env={}, home=tmp_path,
            which=self._which("claude"), runner=pro_login,
        )
        assert status["status"] == "subscription"
        assert status["auth_kind"] == "subscription"

    def test_claude_console_api_login_is_not_subscription(self, tmp_path):
        m = _auth()

        def api_login(_argv, **_kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    '{"loggedIn":true,"authMethod":"api_key",'
                    '"apiProvider":"firstParty"}'
                ),
                stderr="",
            )

        status = m.build_auth_status(
            "anthropic", env={}, home=tmp_path,
            which=self._which("claude"), runner=api_login,
        )
        assert status["status"] == "api_billed"
        assert status["auth_kind"] == "api_key"

    def test_claude_unknown_login_type_fails_closed_for_subscription(self, tmp_path):
        m = _auth()

        def ambiguous(_argv, **_kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    '{"loggedIn":true,"authMethod":"oauth_token",'
                    '"apiProvider":"firstParty"}'
                ),
                stderr="",
            )

        status = m.build_auth_status(
            "anthropic", env={}, home=tmp_path,
            which=self._which("claude"), runner=ambiguous,
        )
        assert status["status"] == "unknown_login"
        assert status["auth_kind"] == "unknown"

    def test_xai_store_presence_is_unverified_until_inference(self, tmp_path):
        m = _auth()
        store = tmp_path / ".grok"
        store.mkdir()
        (store / "auth.json").touch()  # presence only; Grok validates/refreshes on use
        status = m.build_auth_status(
            "xai", env={}, home=tmp_path, which=self._which("grok")
        )
        assert status["store_present"] is True
        assert status["status"] == "store_present"

    def test_status_probe_inherits_current_environment_when_env_omitted(
        self, tmp_path, monkeypatch
    ):
        m = _auth()
        monkeypatch.setenv("NEXUS_STATUS_SENTINEL", "present")

        def logged_in(argv, env=None, **kwargs):
            assert env is not None
            assert env["NEXUS_STATUS_SENTINEL"] == "present"
            return SimpleNamespace(
                returncode=0, stdout="Logged in using ChatGPT", stderr=""
            )

        status = m.build_auth_status(
            "openai", home=tmp_path, which=self._which("codex"), runner=logged_in
        )
        assert status["status"] == "subscription"

    def test_status_probe_timeout_is_configurable(self, tmp_path):
        m = _auth()

        def probe(_argv, **kwargs):
            assert kwargs["timeout"] == 2
            return SimpleNamespace(
                returncode=0, stdout="Logged in using ChatGPT", stderr=""
            )

        status = m.build_auth_status(
            "openai", env={}, home=tmp_path, which=self._which("codex"),
            runner=probe, probe_timeout=2,
        )
        assert status["status"] == "subscription"


class TestRedactSecrets:
    def test_redacts_key_shaped_and_jwt_shaped_text(self):
        m = _auth()
        dirty = (
            "surfaced stderr: 401 with sk-ant-api03-ABCDEF0123456789 and "
            "sk-proj-XYZ123 plus xai-AAAAAAAA0000 and bearer "
            "eyJhbGciOiJIUzI1NiJ9.REPLACE.REPLACE and Bearer tok123 "
            "and then please run codex login to continue"
        )
        clean = m.redact_secrets(dirty)
        _assert_no_secret_shapes(clean)
        # Safe remediation prose survives redaction.
        assert "codex login" in clean
        assert "401" in clean
        # A redaction marker is left behind rather than silently deleting.
        assert re.search(r"\[?REDACTED\]?", clean, re.IGNORECASE)

    def test_plain_text_unchanged(self):
        m = _auth()
        text = "Everything is fine; the risk-assessment found no secret here."
        assert m.redact_secrets(text) == text

    def test_runtime_auth_error_always_includes_safe_remediation(self):
        m = _auth()
        err = m.LLMAuthenticationError("anthropic", "OAuth refresh failed")
        message = str(err)
        assert "claude auth login" in message
        assert "ANTHROPIC_API_KEY" in message
        _assert_no_secret_shapes(message)


# ──────────────────────────────────────────────────────────────────────
# Factory: auth-mode resolution + client construction
# ──────────────────────────────────────────────────────────────────────


class _FakeConfig:
    """Deterministic stand-in for NexusConfig — never touches .env or os.environ."""

    def __init__(self, **overrides):
        self.llm_provider = "openai"
        self.llm_model = "gpt-4o"
        self.llm_temperature = 0.2
        self.llm_auth_mode = "auto"
        self.llm_cli_timeout = 600
        self.ollama_model = "llama3.1:8b"
        self.ollama_base_url = "http://localhost:11434"
        self._secrets: dict[str, str] = {}
        for key, value in overrides.items():
            setattr(self, key, value)

    def set_secret(self, name, value):
        self._secrets[name] = value

    def get_secret(self, name):
        return self._secrets.get(name)


class TestResolveAuthMode:
    def test_defaults_to_auto_when_unset(self):
        m = _factory()
        cfg = SimpleNamespace(llm_provider="openai")  # no llm_auth_mode attr
        assert m.resolve_llm_auth_mode(cfg) == "auto"

    def test_explicit_modes_survive(self):
        m = _factory()
        for mode in ("auto", "oauth", "api_key"):
            cfg = _FakeConfig(llm_auth_mode=mode)
            assert m.resolve_llm_auth_mode(cfg) == mode

    def test_invalid_mode_is_rejected_not_silently_treated_as_auto(self):
        m = _factory()
        with pytest.raises(ValueError, match="auth mode"):
            m.resolve_llm_auth_mode(_FakeConfig(llm_auth_mode="typo"))

    def test_nexus_config_rejects_invalid_auth_mode_and_timeout(self):
        from pydantic import ValidationError

        from nexusrecon.core.config import NexusConfig

        with pytest.raises(ValidationError):
            NexusConfig.model_validate({"NEXUS_LLM_AUTH_MODE": "typo"})
        with pytest.raises(ValidationError):
            NexusConfig.model_validate({"NEXUS_LLM_CLI_TIMEOUT": 0})

    def test_xai_key_is_reported_in_config_availability(self):
        from nexusrecon.core.config import NexusConfig

        cfg = NexusConfig.model_validate({"XAI_API_KEY": "synthetic-placeholder"})
        assert cfg.available_keys()["xai_api_key"] is True

    def test_real_config_accepts_openai_codex_provider_value(self):
        from nexusrecon.core.config import NexusConfig

        cfg = NexusConfig.model_validate(
            {"NEXUS_LLM_PROVIDER": "openai-codex", "NEXUS_LLM_AUTH_MODE": "auto"}
        )
        assert cfg.llm_provider == "openai-codex"


class TestFactoryPreservation:
    """Explicit API-key, Ollama, and mock paths still work."""

    def test_mock_provider_bypasses_auth_resolution(self):
        m = _factory()
        cfg = _FakeConfig(llm_provider="mock")  # no keys, no oauth
        llm = m.build_llm_from_config(cfg)
        assert getattr(llm, "model_name", None) == "mock_llm"
        out = llm.invoke("nothing useful here at all")
        assert "No significant intelligence findings" in out.content

    def test_ollama_provider_bypasses_auth_resolution(self):
        m = _factory()
        cfg = _FakeConfig(llm_provider="ollama")  # no keys, no oauth
        llm = m.build_llm_from_config(cfg)
        assert type(llm).__name__ == "ChatOllama"
        assert llm.model_name == "llama3.1:8b"

    def test_api_key_mode_anthropic_is_direct_chat_client(self):
        m = _factory()
        cfg = _FakeConfig(
            llm_provider="anthropic",
            llm_model="claude-opus-4-5",
            llm_auth_mode="api_key",
        )
        cfg.set_secret("anthropic_api_key", "sk-ant-api03-PLACEHOLDER")
        llm = m.build_llm_from_config(cfg)
        assert type(llm).__name__ == "ChatAnthropic"
        assert llm.model_name == "claude-opus-4-5"

    def test_api_key_mode_openai_is_direct_chat_client(self):
        m = _factory()
        cfg = _FakeConfig(llm_provider="openai", llm_auth_mode="api_key")
        cfg.set_secret("openai_api_key", "sk-PLACEHOLDER")
        llm = m.build_llm_from_config(cfg)
        assert type(llm).__name__ == "ChatOpenAI"
        assert llm.model_name == "gpt-4o"

    def test_xai_api_key_client_shaped_with_xai_base_url_and_its_key_only(self):
        m = _factory()
        xai_key = "xai-PLACEHOLDER_TESTKEY"
        cfg = _FakeConfig(
            llm_provider="xai",
            llm_model="grok-3-mini",
            llm_auth_mode="api_key",
        )
        cfg.set_secret("xai_api_key", xai_key)
        llm = m.build_llm_from_config(cfg)
        assert type(llm).__name__ == "ChatOpenAI"
        assert llm.model_name == "grok-3-mini"
        # xAI must be reached at the xAI endpoint, never the OpenAI default.
        assert llm.openai_api_base == "https://api.x.ai/v1"
        # The client is keyed with the XAI key and nothing else.
        assert llm.openai_api_key.get_secret_value() == xai_key

    def test_backend_selection_log_names_mode_but_never_key(self):
        m = _factory()
        api_key = "xai-PLACEHOLDER_PRIVATE"
        cfg = _FakeConfig(
            llm_provider="xai",
            llm_model="grok-3-mini",
            llm_auth_mode="api_key",
        )
        cfg.set_secret("xai_api_key", api_key)
        with patch("nexusrecon.llm.factory.logger") as logger:
            m.build_llm_from_config(cfg)
        calls = str(logger.mock_calls)
        assert "xai" in calls
        assert "api_key" in calls
        assert api_key not in calls


class TestFactoryAuthModeSelection:
    def test_oauth_login_available_requires_explicit_subscription_kind(self):
        m = _factory()
        def which(_name):
            return "/usr/local/bin/provider-cli"

        with patch(
            "nexusrecon.llm.factory.build_auth_status",
            return_value={"status": "api_billed", "auth_kind": "api_key"},
        ):
            assert m.oauth_login_available("openai", env={}, which=which) is False
        with patch(
            "nexusrecon.llm.factory.build_auth_status",
            return_value={"status": "subscription", "auth_kind": "subscription"},
        ):
            assert m.oauth_login_available("openai", env={}, which=which) is True

    def test_oauth_login_available_selects_oauth_backend(self):
        m = _factory()
        cfg = _FakeConfig(llm_provider="openai", llm_auth_mode="auto")
        with patch("nexusrecon.llm.factory.oauth_login_available", return_value=True):
            llm = m.build_llm_from_config(cfg)
        assert type(llm).__name__ == "OAuthCLIChatModel"

    def test_openai_codex_alias_selects_existing_codex_oauth_adapter(self):
        m = _factory()
        cfg = _FakeConfig(
            llm_provider="openai-codex",
            llm_model="gpt-5-codex",
            llm_auth_mode="auto",
        )
        with patch("nexusrecon.llm.factory.oauth_login_available", return_value=True) as available:
            llm = m.build_llm_from_config(cfg)
        available.assert_called_once_with("openai")
        assert type(llm).__name__ == "OAuthCLIChatModel"
        assert llm.provider == "openai"
        assert llm.model_name == "gpt-5-codex"
        assert llm._inference_argv()[llm._inference_argv().index("--model") + 1] == "gpt-5-codex"

    def test_provider_only_openai_codex_uses_codex_cli_default_model(self):
        from nexusrecon.core.config import NexusConfig

        m = _factory()
        cfg = NexusConfig.model_validate(
            {"NEXUS_LLM_PROVIDER": "openai-codex", "NEXUS_LLM_AUTH_MODE": "auto"}
        )
        assert "llm_model" not in cfg.model_fields_set
        with patch("nexusrecon.llm.factory.oauth_login_available", return_value=True):
            llm = m.build_llm_from_config(cfg)
        assert llm.model_name == "codex-default"
        assert "--model" not in llm._inference_argv()

    def test_openai_codex_alias_retains_configured_key_fallback(self):
        m = _factory()
        cfg = _FakeConfig(llm_provider="openai-codex", llm_auth_mode="auto")
        cfg.set_secret("openai_api_key", "«redacted:sk-…»")
        with patch("nexusrecon.llm.factory.oauth_login_available", return_value=False):
            llm = m.build_llm_from_config(cfg)
        assert type(llm).__name__ == "ChatOpenAI"

    def test_auto_without_oauth_falls_back_to_api_key_client(self):
        m = _factory()
        cfg = _FakeConfig(llm_provider="openai", llm_auth_mode="auto")
        cfg.set_secret("openai_api_key", "sk-PLACEHOLDER")
        with patch("nexusrecon.llm.factory.oauth_login_available", return_value=False):
            llm = m.build_llm_from_config(cfg)
        assert type(llm).__name__ == "ChatOpenAI"

    def test_auto_without_oauth_or_key_raises_clear_error(self):
        m = _auth()
        f = _factory()
        cfg = _FakeConfig(llm_provider="openai", llm_auth_mode="auto")
        with patch("nexusrecon.llm.factory.oauth_login_available", return_value=False):
            with pytest.raises(m.LLMAuthenticationError) as ei:
                f.build_llm_from_config(cfg)
        msg = str(ei.value)
        # Remediation: the exact login command AND the API-key variable.
        assert "codex login" in msg
        assert "OPENAI_API_KEY" in msg
        _assert_no_secret_shapes(msg)

    def test_api_key_mode_missing_key_raises_clear_error(self):
        m = _auth()
        f = _factory()
        cases = {
            "openai": ("codex login", "OPENAI_API_KEY"),
            "anthropic": ("claude auth login", "ANTHROPIC_API_KEY"),
            "xai": ("grok login --oauth", "XAI_API_KEY"),
        }
        for provider, (login_cmd, key_var) in cases.items():
            cfg = _FakeConfig(llm_provider=provider, llm_auth_mode="api_key")
            with pytest.raises(m.LLMAuthenticationError) as ei:
                f.build_llm_from_config(cfg)
            msg = str(ei.value)
            assert login_cmd in msg, provider
            assert key_var in msg, provider
            _assert_no_secret_shapes(msg)


class TestOAuthKeyFallback:
    """OAuth invocation failure falls back to the direct API-key client."""

    def test_auth_failure_on_primary_falls_back(self):
        m = _auth()
        f = _factory()
        primary = SimpleNamespace(
            invoke=lambda messages: (_ for _ in ()).throw(
                m.LLMAuthenticationError("openai", "token expired")
            )
        )
        fallback_hits: list[object] = []
        fallback = SimpleNamespace(
            invoke=lambda messages: fallback_hits.append(messages) or "fallback-ok"
        )
        model = f.OAuthKeyFallback(primary=primary, fallback=fallback)
        result = model.invoke("do the thing")
        assert fallback_hits == ["do the thing"]
        assert result == "fallback-ok"

    def test_successful_primary_is_used_not_fallback(self):
        f = _factory()
        primary = SimpleNamespace(invoke=lambda messages: "primary-ok")
        fallback = SimpleNamespace(invoke=lambda messages: "fallback-ok")
        model = f.OAuthKeyFallback(primary=primary, fallback=fallback)
        assert model.invoke("hi") == "primary-ok"

    def test_fallback_log_never_contains_upstream_token_text(self):
        a = _auth()
        f = _factory()
        primary = SimpleNamespace(
            provider="openai",
            invoke=lambda _messages: (_ for _ in ()).throw(
                a.LLMAuthenticationError("openai", "expired eyJhbG...NiJ9.abc.sig")
            ),
        )
        fallback = SimpleNamespace(invoke=lambda _messages: "ok")
        with patch("nexusrecon.llm.factory.logger") as logger:
            result = f.OAuthKeyFallback(primary=primary, fallback=fallback).invoke("hi")
        assert result == "ok"
        calls = str(logger.mock_calls)
        assert "openai" in calls
        assert "eyJ" not in calls

    def test_transport_failure_does_not_switch_to_metered_key(self):
        a = _auth()
        f = _factory()
        fallback_hits: list[object] = []
        primary = SimpleNamespace(
            provider="openai",
            invoke=lambda _messages: (_ for _ in ()).throw(
                a.LLMProviderError("openai", "transport timed out")
            ),
        )
        fallback = SimpleNamespace(
            invoke=lambda messages: fallback_hits.append(messages) or "unexpected"
        )
        model = f.OAuthKeyFallback(primary=primary, fallback=fallback)
        with pytest.raises(a.LLMProviderError, match="timed out"):
            model.invoke("hi")
        assert fallback_hits == []
