"""Tests for core/config.py — NexusConfig."""
import os
from nexusrecon.core.config import NexusConfig


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

    def test_available_keys_empty(self):
        cfg = NexusConfig()
        keys = cfg.available_keys()
        assert isinstance(keys, dict)
        # All should be False (no env vars set in test)
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

    def test_proxy_defaults(self):
        cfg = NexusConfig()
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
