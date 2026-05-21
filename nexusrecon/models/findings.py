"""
Finding model — the atomic intelligence unit in NexusRecon.

EVERY finding MUST have: source, timestamp, raw_evidence_hash, confidence.
Findings without all four are rejected at the EvidenceAuditor stage.
The Evidence Auditor is not advisory — it drops uncited findings.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class ConfidenceLevel(StrEnum):
    CONFIRMED = "confirmed"    # 0.9–1.0: verified by multiple independent sources
    HIGH = "high"              # 0.7–0.89: single reliable/authoritative source
    MEDIUM = "medium"          # 0.5–0.69: plausible, single source, unverified
    LOW = "low"                # 0.2–0.49: circumstantial, needs corroboration
    SPECULATIVE = "speculative" # 0.0–0.19: hypothesis only


class FindingSeverity(StrEnum):
    CRITICAL = "critical"  # Immediate exploitation possible
    HIGH = "high"          # Significant risk, exploit likely with effort
    MEDIUM = "medium"      # Moderate risk, supporting role in attack chain
    LOW = "low"            # Low immediate risk, useful for recon
    INFO = "info"          # Informational, no direct risk


class FindingCategory(StrEnum):
    CLOUD_EXPOSURE = "cloud_exposure"
    CREDENTIAL_LEAK = "credential_leak"
    EMAIL_SECURITY = "email_security"
    SUBDOMAIN_EXPOSURE = "subdomain_exposure"
    CODE_EXPOSURE = "code_exposure"
    IDENTITY_EXPOSURE = "identity_exposure"
    VULNERABILITY = "vulnerability"
    INFRASTRUCTURE = "infrastructure"
    PHISHING_VECTOR = "phishing_vector"
    SUPPLY_CHAIN = "supply_chain"
    DATA_EXPOSURE = "data_exposure"
    SOCIAL_INTELLIGENCE = "social_intelligence"
    VENDOR_INTEL = "vendor_intel"
    EXECUTIVE_EXPOSURE = "executive_exposure"
    NETWORK_EXPOSURE = "network_exposure"
    M365_AZURE = "m365_azure"
    AWS = "aws"
    GCP = "gcp"


class Finding(BaseModel):
    """
    Atomic intelligence unit with mandatory citation.

    All four citation fields (source, timestamp, raw_evidence_hash, confidence)
    are required.  Use Finding.create() as the preferred factory to ensure
    the evidence hash is computed correctly.
    """

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    category: str                   # FindingCategory value or custom string
    severity: FindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel

    # ── Mandatory citation fields ──────────────────────────────
    source: str                     # Tool name or source identifier
    source_url: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_evidence_hash: str          # sha256:<hex> of raw_evidence
    raw_evidence: str               # JSON-serialized raw tool output

    # ── Asset linkage ──────────────────────────────────────────
    affected_assets: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)

    # ── Attack relevance ───────────────────────────────────────
    attack_vector: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)

    # ── Remediation ────────────────────────────────────────────
    recommendation: str | None = None
    remediation_effort: str | None = None  # low, medium, high

    # ── Engagement metadata ────────────────────────────────────
    engagement_id: str | None = None
    phase: str | None = None
    tags: list[str] = Field(default_factory=list)
    is_verified: bool = False
    verified_by: str | None = None
    verified_at: datetime | None = None

    @model_validator(mode="after")
    def validate_evidence_hash(self) -> Finding:
        """Verify that raw_evidence_hash matches raw_evidence."""
        if self.raw_evidence and self.raw_evidence_hash:
            expected = "sha256:" + hashlib.sha256(
                self.raw_evidence.encode()
            ).hexdigest()
            if self.raw_evidence_hash != expected:
                raise ValueError(
                    f"Evidence hash mismatch for finding '{self.title}'. "
                    "raw_evidence_hash does not match raw_evidence content."
                )
        return self

    @classmethod
    def create(
        cls,
        *,
        title: str,
        description: str,
        category: str,
        severity: FindingSeverity,
        confidence: float,
        source: str,
        raw_evidence: Any,
        **kwargs: Any,
    ) -> Finding:
        """
        Preferred factory method.  Computes evidence hash automatically.

        Args:
            raw_evidence: Any JSON-serializable object (dict, list, str, etc.).
                         The raw output from the tool that produced this finding.
        """
        raw_str = json.dumps(raw_evidence, default=str, sort_keys=True)
        evidence_hash = "sha256:" + hashlib.sha256(raw_str.encode()).hexdigest()

        if confidence >= 0.9:
            conf_level = ConfidenceLevel.CONFIRMED
        elif confidence >= 0.7:
            conf_level = ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            conf_level = ConfidenceLevel.MEDIUM
        elif confidence >= 0.2:
            conf_level = ConfidenceLevel.LOW
        else:
            conf_level = ConfidenceLevel.SPECULATIVE

        return cls(
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            confidence_level=conf_level,
            source=source,
            raw_evidence_hash=evidence_hash,
            raw_evidence=raw_str,
            **kwargs,
        )

    def is_citation_complete(self) -> bool:
        """Returns True if all four mandatory citation fields are populated."""
        return bool(
            self.source
            and self.timestamp
            and self.raw_evidence_hash
            and self.confidence >= 0.0
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, converting datetimes to ISO strings."""
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        if self.verified_at:
            data["verified_at"] = self.verified_at.isoformat()
        return data
