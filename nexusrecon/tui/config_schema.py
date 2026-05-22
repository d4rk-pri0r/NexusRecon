"""Declarative schema for the TUI Configuration screen.

Each category is a group of related environment variables the operator
might tune. The schema drives the two-pane layout: categories appear in
the left list, variables in the right table. Adding a new env var the
TUI should expose = adding one dict entry here, nothing else.

Field semantics:
    key        : env var name (matches .env line)
    label      : human-friendly column display (defaults to key)
    sensitive  : True for keys / tokens / passwords — masked by default
    help       : one-line guidance shown in the edit modal
    choices    : optional list of valid values for select-style inputs
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConfigVar:
    key: str
    help: str
    sensitive: bool = False
    label: str | None = None
    choices: list[str] | None = None

    def display_label(self) -> str:
        return self.label or self.key


@dataclass
class ConfigCategory:
    id: str
    name: str
    description: str
    vars: list[ConfigVar] = field(default_factory=list)


# ── Schema ──────────────────────────────────────────────────────────────

CATEGORIES: list[ConfigCategory] = [
    ConfigCategory(
        id="llm",
        name="🤖 LLM Provider",
        description="Which LLM the platform uses for agent synthesis.",
        vars=[
            ConfigVar(
                key="NEXUS_LLM_PROVIDER",
                help="anthropic (recommended) · openai · ollama",
                choices=["anthropic", "openai", "ollama"],
            ),
            ConfigVar(
                key="NEXUS_LLM_MODEL",
                help="Model ID. e.g. claude-sonnet-4-6, gpt-4o, llama3.1:8b",
            ),
            ConfigVar(
                key="NEXUS_LLM_TEMPERATURE",
                help="Sampling temperature 0.0–1.0 (0.1 recommended)",
            ),
            ConfigVar(
                key="ANTHROPIC_API_KEY",
                sensitive=True,
                help="From console.anthropic.com → API keys. Format: sk-ant-...",
            ),
            ConfigVar(
                key="OPENAI_API_KEY",
                sensitive=True,
                help="From platform.openai.com/api-keys. Format: sk-...",
            ),
            ConfigVar(
                key="OLLAMA_BASE_URL",
                help="Local Ollama endpoint. Default: http://localhost:11434",
            ),
            ConfigVar(
                key="OLLAMA_MODEL",
                help="Local model. Must already be pulled: ollama pull <name>",
            ),
        ],
    ),
    ConfigCategory(
        id="intel",
        name="🛰  Infrastructure Intel",
        description="API keys for host/service/cert intelligence sources.",
        vars=[
            ConfigVar("SHODAN_API_KEY", "shodan.io — free tier or one-time membership ~$5–$59.", sensitive=True),
            ConfigVar("CENSYS_API_ID", "censys.io — paired with CENSYS_API_SECRET. 250 q/mo free.", sensitive=True),
            ConfigVar("CENSYS_API_SECRET", "censys.io secret — pairs with CENSYS_API_ID.", sensitive=True),
            ConfigVar("VIRUSTOTAL_API_KEY", "virustotal.com — 500 q/day free.", sensitive=True),
            ConfigVar("GREYNOISE_API_KEY", "viz.greynoise.io — community tier free.", sensitive=True),
            ConfigVar("ABUSEIPDB_API_KEY", "abuseipdb.com — 1000 q/day free.", sensitive=True),
            ConfigVar("URLSCAN_API_KEY", "urlscan.io — 5000 q/day free.", sensitive=True),
            ConfigVar("BINARYEDGE_API_KEY", "binaryedge.io — 250 q/mo free.", sensitive=True),
            ConfigVar("FULLHUNT_API_KEY", "fullhunt.io — 100 q/day free.", sensitive=True),
            ConfigVar("ZOOMEYE_API_KEY", "zoomeye.org — free tier.", sensitive=True),
            ConfigVar("NETLAS_API_KEY", "app.netlas.io — free tier.", sensitive=True),
            ConfigVar("IPINFO_API_KEY", "ipinfo.io — 50k/mo free without a key; key unlocks fields.", sensitive=True),
            ConfigVar("LEAKIX_API_KEY", "leakix.net — optional, raises rate limit.", sensitive=True),
            ConfigVar("SECURITYTRAILS_API_KEY", "securitytrails.com — 50 q/mo free.", sensitive=True),
        ],
    ),
    ConfigCategory(
        id="passive",
        name="📡 Passive Sources",
        description="Optional keys for sources that work without auth (raise rate limit).",
        vars=[
            ConfigVar("OTX_API_KEY", "AlienVault OTX — optional.", sensitive=True),
            ConfigVar("CERTSPOTTER_API_KEY", "sslmate.com — optional.", sensitive=True),
            ConfigVar("CHAOS_API_KEY", "ProjectDiscovery Chaos — free via Discord verification.", sensitive=True),
        ],
    ),
    ConfigCategory(
        id="identity",
        name="👤 Email & Identity",
        description="Email harvesting, breach lookup, identity correlation.",
        vars=[
            ConfigVar("HUNTER_API_KEY", "hunter.io — 50 searches/mo free.", sensitive=True),
            ConfigVar("EMAILREP_API_KEY", "emailrep.io — free low-volume.", sensitive=True),
            ConfigVar("HAVEIBEENPWNED_API_KEY", "haveibeenpwned.com — paid only, $3.50/mo.", sensitive=True),
            ConfigVar("DEHASHED_USERNAME", "dehashed.com — paired with DEHASHED_API_KEY.", sensitive=False),
            ConfigVar("DEHASHED_API_KEY", "dehashed.com secret.", sensitive=True),
            ConfigVar("INTELX_API_KEY", "intelx.io — paid.", sensitive=True),
            ConfigVar("LEAKCHECK_API_KEY", "leakcheck.io — paid from $9/mo.", sensitive=True),
        ],
    ),
    ConfigCategory(
        id="vuln",
        name="🛡  Vulnerability Intel",
        description="CVE enrichment + exploit availability.",
        vars=[
            ConfigVar("VULNERS_API_KEY", "vulners.com — free tier.", sensitive=True),
        ],
    ),
    ConfigCategory(
        id="pretext",
        name="🎭 Pretext & HUMINT",
        description="Org/people intel for social engineering preparation.",
        vars=[
            ConfigVar("CRUNCHBASE_API_KEY", "crunchbase.com — Enterprise tier only.", sensitive=True),
            ConfigVar("BING_SEARCH_API_KEY", "Azure Bing Search — optional. Enables live linkedin_dorks/public_collab.", sensitive=True),
        ],
    ),
    ConfigCategory(
        id="code",
        name="💻 Code & Repo",
        description="GitHub / GitLab / Bitbucket access for code recon.",
        vars=[
            ConfigVar("GITHUB_TOKEN", "github.com → Settings → Developer settings → PAT (classic). Scopes: public_repo, read:org, read:user. Unlocks 5 tools.", sensitive=True),
            ConfigVar("GITLAB_TOKEN", "gitlab.com PAT.", sensitive=True),
            ConfigVar("BITBUCKET_TOKEN", "bitbucket.org app password.", sensitive=True),
        ],
    ),
    ConfigCategory(
        id="cloud",
        name="☁  Cloud Credentials",
        description="AWS credentials for account-level recon (operator-owned accounts only).",
        vars=[
            ConfigVar("AWS_ACCESS_KEY_ID", "Use a least-privilege IAM user. NEVER root.", sensitive=True),
            ConfigVar("AWS_SECRET_ACCESS_KEY", "Paired with AWS_ACCESS_KEY_ID.", sensitive=True),
            ConfigVar("AWS_DEFAULT_REGION", "e.g. us-east-1"),
        ],
    ),
    ConfigCategory(
        id="opsec",
        name="🕵  OPSEC / Network",
        description="Proxy, Tor, DNS resolver settings. Affect every outbound request.",
        vars=[
            ConfigVar("NEXUS_PROXY_URL", "SOCKS5 proxy URL or empty to disable."),
            ConfigVar("NEXUS_TOR_PROXY", "Tor SOCKS5 — default socks5://127.0.0.1:9050"),
            ConfigVar("NEXUS_DNS_RESOLVERS", "Comma-separated. Default: 1.1.1.1,8.8.8.8,9.9.9.9"),
            ConfigVar("NEXUS_VALIDATE_VIA_TOR", "true|false — route --validate-creds calls through Tor.",
                     choices=["true", "false"]),
        ],
    ),
    ConfigCategory(
        id="storage",
        name="💾 Storage",
        description="Where campaign output and state are written.",
        vars=[
            ConfigVar("NEXUS_OUTPUT_DIR", "Campaign output root. Default: ./campaigns"),
            ConfigVar("NEXUS_DB_PATH", "SQLite state/cache path. Default: ./nexusrecon.db"),
        ],
    ),
    ConfigCategory(
        id="debug",
        name="🔧 Debug / Dev",
        description="Logging + dry-run defaults.",
        vars=[
            ConfigVar("NEXUS_LOG_LEVEL", "DEBUG | INFO | WARNING | ERROR",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"]),
            ConfigVar("NEXUS_LOG_FORMAT", "json | text", choices=["json", "text"]),
            ConfigVar("NEXUS_DRY_RUN", "true|false — global dry-run mode default.",
                     choices=["true", "false"]),
        ],
    ),
]


# Special pseudo-category: external binaries (read-only inventory)
BINARIES_CATEGORY = ConfigCategory(
    id="_binaries",
    name="🔌 External Binaries",
    description="Tool binaries on PATH. Read-only — install via shell/brew/go install.",
    vars=[],  # populated at render time from the registry
)


def all_categories() -> list[ConfigCategory]:
    """Categories in the order they appear in the left pane, with the
    binaries inventory appended at the end."""
    return CATEGORIES + [BINARIES_CATEGORY]


def find_var(key: str) -> ConfigVar | None:
    """Lookup helper used by the edit modal to fetch help text + choices."""
    for cat in CATEGORIES:
        for v in cat.vars:
            if v.key == key:
                return v
    return None


def find_category_for_var(key: str) -> tuple[ConfigCategory, ConfigVar] | None:
    """Return the ``(category, var)`` pair that owns ``key``, or
    ``None`` when the key isn't in the schema.

    Used by the Tools browser's deep-link ── pressing ``c`` on a
    tool jumps the operator straight to that env var's row in the
    Config screen, not back to the top-level category list.
    """
    for cat in CATEGORIES:
        for v in cat.vars:
            if v.key == key:
                return cat, v
    return None
