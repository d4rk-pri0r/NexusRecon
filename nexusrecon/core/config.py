"""
NexusRecon configuration management.

Loads from .env (via pydantic-settings), environment variables, and
optional per-client config overlays.  API keys are never logged.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class NexusConfig(BaseSettings):
    """
    All configuration lives here.  Values are sourced from (in priority order):
      1. Environment variables
      2. .env file in the working directory
      3. Defaults defined below
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="NEXUS_",
        extra="ignore",
        case_sensitive=False,
    )

    # ── LLM ────────────────────────────────────────────────────
    llm_provider: str = Field(default="anthropic", alias="NEXUS_LLM_PROVIDER")
    llm_model: str = Field(default="claude-opus-4-5", alias="NEXUS_LLM_MODEL")
    llm_temperature: float = Field(default=0.1, alias="NEXUS_LLM_TEMPERATURE")
    anthropic_api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    openai_api_key: SecretStr | None = Field(default=None, alias="OPENAI_API_KEY")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama3.1:8b", alias="OLLAMA_MODEL")

    # ── API Keys — Infrastructure ───────────────────────────────
    shodan_api_key: SecretStr | None = Field(default=None, alias="SHODAN_API_KEY")
    censys_api_id: SecretStr | None = Field(default=None, alias="CENSYS_API_ID")
    censys_api_secret: SecretStr | None = Field(default=None, alias="CENSYS_API_SECRET")
    virustotal_api_key: SecretStr | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    greynoise_api_key: SecretStr | None = Field(default=None, alias="GREYNOISE_API_KEY")
    binaryedge_api_key: SecretStr | None = Field(default=None, alias="BINARYEDGE_API_KEY")
    fullhunt_api_key: SecretStr | None = Field(default=None, alias="FULLHUNT_API_KEY")
    abuseipdb_api_key: SecretStr | None = Field(default=None, alias="ABUSEIPDB_API_KEY")
    urlscan_api_key: SecretStr | None = Field(default=None, alias="URLSCAN_API_KEY")
    securitytrails_api_key: SecretStr | None = Field(default=None, alias="SECURITYTRAILS_API_KEY")

    # ── API Keys — Identity ─────────────────────────────────────
    hunter_api_key: SecretStr | None = Field(default=None, alias="HUNTER_API_KEY")
    haveibeenpwned_api_key: SecretStr | None = Field(default=None, alias="HAVEIBEENPWNED_API_KEY")
    dehashed_username: str | None = Field(default=None, alias="DEHASHED_USERNAME")
    dehashed_api_key: SecretStr | None = Field(default=None, alias="DEHASHED_API_KEY")
    # HudsonRock Cavalier — optional; unlocks full credential detail (D6)
    hudsonrock_api_key: SecretStr | None = Field(default=None, alias="HUDSONROCK_API_KEY")
    intelx_api_key: SecretStr | None = Field(default=None, alias="INTELX_API_KEY")
    emailrep_api_key: SecretStr | None = Field(default=None, alias="EMAILREP_API_KEY")
    newsapi_api_key: SecretStr | None = Field(default=None, alias="NEWSAPI_API_KEY")
    adzuna_app_id: str | None = Field(default=None, alias="ADZUNA_APP_ID")
    adzuna_api_key: SecretStr | None = Field(default=None, alias="ADZUNA_API_KEY")

    # ── API Keys — Code ─────────────────────────────────────────
    github_token: SecretStr | None = Field(default=None, alias="GITHUB_TOKEN")
    gitlab_token: SecretStr | None = Field(default=None, alias="GITLAB_TOKEN")

    # ── Cloud ───────────────────────────────────────────────────
    aws_access_key_id: SecretStr | None = Field(default=None, alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: SecretStr | None = Field(default=None, alias="AWS_SECRET_ACCESS_KEY")
    aws_default_region: str = Field(default="us-east-1", alias="AWS_DEFAULT_REGION")

    # ── OPSEC ───────────────────────────────────────────────────
    proxy_url: str | None = Field(default=None, alias="NEXUS_PROXY_URL")
    tor_proxy: str | None = Field(default=None, alias="NEXUS_TOR_PROXY")
    dns_resolvers: str = Field(default="1.1.1.1,8.8.8.8", alias="NEXUS_DNS_RESOLVERS")

    # ── Storage ─────────────────────────────────────────────────
    output_dir: str = Field(default="./campaigns", alias="NEXUS_OUTPUT_DIR")
    db_path: str = Field(default="./nexusrecon.db", alias="NEXUS_DB_PATH")

    # ── Debug ───────────────────────────────────────────────────
    log_level: str = Field(default="INFO", alias="NEXUS_LOG_LEVEL")
    log_format: str = Field(default="json", alias="NEXUS_LOG_FORMAT")
    dry_run: bool = Field(default=False, alias="NEXUS_DRY_RUN")

    def get_secret(self, field_name: str) -> str | None:
        """Safely retrieve a secret value by field name.

        Returns ``None`` rather than an empty string when the value resolves to
        ``""`` so that an empty shell export (``export SHODAN_API_KEY=``) does
        not silently beat a real value in ``.env``.  pydantic-settings precedence
        is ``env > .env > default`` — an empty env var wins over a populated
        ``.env`` entry, so callers that do ``if get_secret(...):`` would silently
        fall through to a degraded mode (e.g. MockLLM) with no warning.
        """
        val = getattr(self, field_name, None)
        if val is None:
            return None
        if isinstance(val, SecretStr):
            v = val.get_secret_value()
            return v if v else None  # treat empty secret as absent
        s = str(val).strip()
        return s if s else None

    def dns_resolver_list(self) -> list[str]:
        return [r.strip() for r in self.dns_resolvers.split(",") if r.strip()]

    def available_keys(self) -> dict[str, bool]:
        """Return dict of key availability (without exposing values)."""
        key_fields = [
            "shodan_api_key", "censys_api_id", "virustotal_api_key",
            "greynoise_api_key", "hunter_api_key", "haveibeenpwned_api_key",
            "github_token", "securitytrails_api_key", "urlscan_api_key",
            "abuseipdb_api_key", "intelx_api_key", "dehashed_api_key",
            "newsapi_api_key", "adzuna_api_key",
            "anthropic_api_key", "openai_api_key",
        ]
        return {f: getattr(self, f) is not None for f in key_fields}

    def apply_client_overlay(self, overlay_path: str | Path) -> NexusConfig:
        """Return a new NexusConfig with per-client YAML values merged on top.

        Does NOT mutate self — the lru_cached singleton must stay pristine so
        other callers are not affected by per-campaign overlays.
        """
        overlay_path = Path(overlay_path)
        if not overlay_path.exists():
            return self
        data: dict[str, Any] = yaml.safe_load(overlay_path.read_text()) or {}
        # Build a fresh instance from current values, then apply overlay
        base_values = self.model_dump()
        base_values.update({k: v for k, v in data.items() if k in base_values})
        return NexusConfig.model_validate(base_values)


@lru_cache(maxsize=1)
def get_config() -> NexusConfig:
    """Return the singleton config instance."""
    return NexusConfig()
