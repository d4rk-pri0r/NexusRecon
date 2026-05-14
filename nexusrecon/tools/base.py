"""
OSINT tool base class and type system.

Every tool in NexusRecon inherits from OSINTTool and declares:
  - name, tier (T0-T3), category, cost, reliability
  - requires_keys (list of env var names for API keys)
  - binary_required (CLI tool path if needed)
  - output_schema (Pydantic model for structured output)

Tools are executed via the tool registry which enforces scope,
tier limits, caching, rate limiting, and audit logging.
"""

from __future__ import annotations

import abc
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar

import structlog

from nexusrecon.core.config import get_config

log = structlog.get_logger(__name__)


class Tier(str, Enum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


class Category(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    DNS = "dns"
    CERTIFICATE = "certificate"
    EMAIL = "email"
    IDENTITY = "identity"
    BREACH = "breach"
    CLOUD = "cloud"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"
    CODE = "code"
    SECRET = "secret"
    INFRASTRUCTURE = "infrastructure"
    WEB = "web"
    VULNERABILITY = "vulnerability"
    PRETEXT = "pretext"
    SOCIAL = "social"
    MOBILE = "mobile"
    NEWS = "news"


@dataclass
class ToolResult:
    """
    Standardized result wrapper for every tool invocation.

    Every tool returns this — never raw dicts or lists.
    The result carries metadata needed for audit, caching, and entity extraction.
    """

    success: bool
    source: str
    data: Any = None
    error: Optional[str] = None
    raw_output: Optional[str] = None
    runtime_ms: int = 0
    cached: bool = False
    result_count: int = 0
    tier: str = "T0"
    metadata: Dict[str, Any] = field(default_factory=dict)


class OSINTTool(abc.ABC):
    """
    Abstract base for all OSINT tools.

    Subclasses must implement:
      - run(target: str) -> ToolResult
    And should set:
      - name, tier, category, reliability, requires_keys, binary_required
    """

    name: str = "base"
    tier: Tier = Tier.T0
    category: Category = Category.DOMAIN
    cost_per_run_usd: float = 0.0
    avg_runtime_sec: int = 30
    reliability: float = 0.95
    requires_keys: List[str] = []
    binary_required: Optional[str] = None
    description: str = ""
    target_types: List[str] = ["domain"]  # domain, ip, email, etc.
    dynamic_trigger_hints: List[str] = []  # hints for dynamic dispatcher (Move 4)

    def __init__(self) -> None:
        self.config = get_config()
        if not self.is_available():
            log.debug("Tool prerequisites not met at init", tool=self.name)

    @abc.abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        """Execute the tool against a target. Must be implemented by subclasses."""
        ...

    def is_available(self) -> bool:
        """Return True if this tool can run (keys + binaries present)."""
        for key in self.requires_keys:
            if not self.config.get_secret(key):
                return False
        if self.binary_required:
            import shutil
            return shutil.which(self.binary_required) is not None
        return True

    def run_subprocess(
        self,
        cmd: List[str],
        timeout_sec: int = 300,
        cwd: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess (for CLI tools like subfinder, gitleaks, etc.)."""
        log.debug("Running subprocess", cmd=cmd)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=cwd,
        )


# Convenience for type hints
T = TypeVar("T", bound=OSINTTool)
