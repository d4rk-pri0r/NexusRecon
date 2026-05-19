"""Tests for core/config.py ── NexusConfig."""
import os

import pytest

from nexusrecon.core.config import NexusConfig


# Env vars that the "default values" tests assume are not set. A local
# developer ``.env`` would otherwise win over the field defaults via
# pydantic-settings' ``env > .env > default`` precedence, masking real
# default-behavior regressions. Each test that asserts on defaults clears
# the relevant vars via this fixture AND passes ``_env_file=None`` to
# NexusConfig so the file isn't read either.
_DEFAULT_TEST_VARS = (
    "NEXUS_PROXY_URL", "NEXUS_TOR_PROXY",
    "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
    "VIRUSTOTAL_API_KEY", "GREYNOISE_API_KEY", "HUNTER_API_KEY",
    "HAVEIBEENPWNED_API_KEY", "GITHUB_TOKEN",
    "SECURITYTRAILS_API_KEY", "URLSCAN_API_KEY", "ABUSEIPDB_API_KEY",
    "INTELX_API_KEY", "DEHASHED_API_KEY", "NEWSAPI_API_KEY",
    "ADZUNA_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
)


@pytest.fixture
def clean_env(monkeypatch):
    """Strip env vars that would otherwise win over field defaults."""
    for var in _DEFAULT_TEST_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


class TestNexusConfig:
    def test_default_values(self):
        cfg = NexusConfig()
        assert cfg.llm_provider == "anthropic"
        assert cfg.llm_model == "claude-opus-4-5"
        assert cfg.llm_temperature == 0.1
        assert cfg.log_level == "INFO"
        assert cfg.output_dir == "./campaigns"

    def test_dns_resolver_list_default(self):
        cfg = NexusConfig()
        resolvers = cfg.dns_resolver_list()
        assert len(resolvers) >= 2
        assert "1.1.1.1" in resolvers

    def test_available_keys_empty(self, clean_env):
        # ``_env_file=None`` overrides the model_config's ``env_file=".env"``
        # so a developer's local .env doesn't leak real keys into the test.
        cfg = NexusConfig(_env_file=None)
        keys = cfg.available_keys()
        assert isinstance(keys, dict)
        assert all(v is False for v in keys.values())

    def test_available_keys_with_env(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test-key-123")
        cfg = NexusConfig()
        keys = cfg.available_keys()
        assert keys.get("shodan_api_key") is True

    def test_get_secret_missing(self):
        cfg = NexusConfig()
        result = cfg.get_secret("nonexistent_field")
        assert result is None

    def test_get_secret_with_env(self, monkeypatch):
        monkeypatch.setenv("HUNTER_API_KEY", "hunter-key")
        cfg = NexusConfig()
        result = cfg.get_secret("hunter_api_key")
        assert result == "hunter-key"

    def test_ollama_defaults(self):
        cfg = NexusConfig()
        assert cfg.ollama_base_url == "http://localhost:11434"
        assert cfg.ollama_model == "llama3.1:8b"

    def test_proxy_defaults(self, clean_env):
        cfg = NexusConfig(_env_file=None)
        assert cfg.proxy_url is None
        assert cfg.tor_proxy is None

    def test_log_format_default(self):
        cfg = NexusConfig()
        assert cfg.log_format == "json"

    def test_dry_run_default(self):
        cfg = NexusConfig()
        assert cfg.dry_run is False

    def test_apply_client_overlay_nonexistent(self):
        cfg = NexusConfig()
        result = cfg.apply_client_overlay("/nonexistent/path.yml")
        assert result is cfg  # Returns self

    def test_llm_model_customizable(self):
        # Use the field alias NEXUS_LLM_MODEL since pydantic alias is required
        cfg = NexusConfig(**{"NEXUS_LLM_MODEL": "gpt-4"})
        assert cfg.llm_model == "gpt-4", f"Expected gpt-4, got {cfg.llm_model}"
