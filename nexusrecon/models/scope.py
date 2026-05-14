"""
Scope model — parses and validates the engagement scope YAML.

The scope file is the single source of truth for what is authorized.
Every tool invocation must pass through the ScopeGuard before execution.
This file defines the data model; enforcement logic lives in core/scope.py.
"""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class CloudTenants(BaseModel):
    m365: List[str] = Field(default_factory=list)
    aws_accounts: List[str] = Field(default_factory=list)
    azure_subscriptions: List[str] = Field(default_factory=list)
    gcp_projects: List[str] = Field(default_factory=list)


class InScopeItems(BaseModel):
    domains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)
    asns: List[str] = Field(default_factory=list)
    cloud_tenants: CloudTenants = Field(default_factory=CloudTenants)
    github_orgs: List[str] = Field(default_factory=list)
    github_users: List[str] = Field(default_factory=list)
    email_domains: List[str] = Field(default_factory=list)


class OutOfScopeItems(BaseModel):
    domains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)
    third_parties: List[str] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)


class ScopeItems(BaseModel):
    in_scope: InScopeItems = Field(default_factory=InScopeItems)
    out_of_scope: OutOfScopeItems = Field(default_factory=OutOfScopeItems)


class EngagementInfo(BaseModel):
    client: str
    engagement_id: str
    authorized_by: str
    authorization_date: str
    signed_sow_hash: str
    start_date: str
    end_date: str
    rules_of_engagement_doc: Optional[str] = None
    engagement_type: Optional[str] = "red_team"  # red_team, pentest, bug_bounty

    @field_validator("signed_sow_hash")
    @classmethod
    def validate_sow_hash(cls, v: str) -> str:
        if not v.startswith("sha256:"):
            raise ValueError(
                "signed_sow_hash must start with 'sha256:'. "
                "Compute with: sha256sum <sow_document>"
            )
        return v


class EngagementConstraints(BaseModel):
    max_tier: str = "T1"
    stealth_profile: str = "high"
    allow_breach_db_lookup: bool = True
    allow_paid_apis: bool = True
    max_llm_cost_usd: float = 50.0
    max_runtime_hours: Optional[float] = None
    llm_provider: Optional[str] = None  # override env default
    require_proxy: bool = False
    dns_resolvers: List[str] = Field(default_factory=list)

    @field_validator("max_tier")
    @classmethod
    def validate_tier(cls, v: str) -> str:
        valid = {"T0", "T1", "T2", "T3"}
        if v not in valid:
            raise ValueError(f"max_tier must be one of {valid}, got '{v}'")
        return v

    @field_validator("stealth_profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        valid = {"paranoid", "high", "normal", "loud"}
        if v not in valid:
            raise ValueError(f"stealth_profile must be one of {valid}, got '{v}'")
        return v


class ScopeModel(BaseModel):
    """
    Complete engagement scope model.

    Parsed from the YAML scope file.  The scope_hash field is computed
    from the raw YAML content and embedded in every output artifact for
    legal defensibility.
    """

    engagement: EngagementInfo
    scope: ScopeItems = Field(default_factory=ScopeItems)
    constraints: EngagementConstraints = Field(default_factory=EngagementConstraints)

    # Internal — set after loading from file
    scope_hash: Optional[str] = None
    scope_file_path: Optional[str] = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScopeModel":
        """Load and validate a scope YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {path}")

        raw = path.read_text(encoding="utf-8")
        data: Dict[str, Any] = yaml.safe_load(raw)

        obj = cls.model_validate(data)
        obj.scope_hash = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        obj.scope_file_path = str(path.resolve())
        return obj

    def tier_value(self) -> int:
        """Return integer tier level (0-3) for comparison."""
        return int(self.constraints.max_tier[1])

    def summary(self) -> str:
        """Short human-readable scope summary."""
        e = self.engagement
        s = self.scope.in_scope
        lines = [
            f"Client:       {e.client}",
            f"Engagement:   {e.engagement_id}",
            f"Authorized:   {e.authorized_by} ({e.authorization_date})",
            f"Period:       {e.start_date} → {e.end_date}",
            f"Max Tier:     {self.constraints.max_tier}",
            f"Stealth:      {self.constraints.stealth_profile}",
            f"Domains:      {', '.join(s.domains) or 'none'}",
            f"IP Ranges:    {', '.join(s.ip_ranges) or 'none'}",
            f"ASNs:         {', '.join(s.asns) or 'none'}",
            f"M365 Tenants: {', '.join(s.cloud_tenants.m365) or 'none'}",
            f"AWS Accounts: {', '.join(s.cloud_tenants.aws_accounts) or 'none'}",
            f"Scope Hash:   {self.scope_hash}",
        ]
        return "\n".join(lines)
