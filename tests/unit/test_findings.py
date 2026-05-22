"""Tests for models/findings.py — Finding model."""

import pytest

from nexusrecon.models.findings import (
    ConfidenceLevel,
    Finding,
    FindingCategory,
    FindingSeverity,
)


class TestFindingCategory:
    def test_values(self):
        assert FindingCategory.CLOUD_EXPOSURE.value == "cloud_exposure"
        assert FindingCategory.CREDENTIAL_LEAK.value == "credential_leak"
        assert FindingCategory.VULNERABILITY.value == "vulnerability"


class TestFindingSeverity:
    def test_ordering(self):
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.INFO.value == "info"


class TestFindingCreate:
    def test_create_minimal(self):
        f = Finding.create(
            title="Test Finding",
            description="A description",
            category="test",
            severity=FindingSeverity.MEDIUM,
            confidence=0.75,
            source="test_tool",
            raw_evidence={"key": "value"},
        )
        assert f.title == "Test Finding"
        assert f.severity == FindingSeverity.MEDIUM
        assert f.confidence == 0.75
        assert f.confidence_level == ConfidenceLevel.HIGH
        assert f.source == "test_tool"
        assert f.raw_evidence_hash.startswith("sha256:")
        assert f.is_citation_complete() is True
        assert isinstance(f.finding_id, str)
        assert len(f.finding_id) > 0

    def test_create_with_all_fields(self):
        f = Finding.create(
            title="Full Finding",
            description="Full description",
            category="cloud_exposure",
            severity=FindingSeverity.CRITICAL,
            confidence=0.95,
            source="aws_tool",
            raw_evidence={"bucket": "public-bucket"},
            affected_assets=["s3://bucket"],
            mitre_techniques=["T1525"],
            recommendation="Make bucket private",
            engagement_id="eng-001",
            phase="phase2",
        )
        assert f.confidence_level == ConfidenceLevel.CONFIRMED
        assert f.affected_assets == ["s3://bucket"]
        assert f.mitre_techniques == ["T1525"]
        assert f.recommendation == "Make bucket private"
        assert f.engagement_id == "eng-001"
        assert f.phase == "phase2"

    def test_create_low_confidence(self):
        f = Finding.create(
            title="Speculative",
            description="Maybe",
            category="test",
            severity=FindingSeverity.INFO,
            confidence=0.1,
            source="test",
            raw_evidence="hmm",
        )
        assert f.confidence_level == ConfidenceLevel.SPECULATIVE

    def test_create_zero_confidence(self):
        f = Finding.create(
            title="Zero",
            description="None",
            category="test",
            severity=FindingSeverity.INFO,
            confidence=0.0,
            source="test",
            raw_evidence="",
        )
        assert f.confidence_level == ConfidenceLevel.SPECULATIVE


class TestFindingValidation:
    def test_evidence_hash_auto(self):
        f = Finding.create(
            title="Hash Test",
            description="Testing hash",
            category="test",
            severity=FindingSeverity.LOW,
            confidence=0.5,
            source="test",
            raw_evidence={"data": "hello"},
        )
        # Re-validate (model_validator runs on create)
        f.validate_evidence_hash()
        assert f.raw_evidence_hash.startswith("sha256:")

    def test_evidence_hash_mismatch_raises(self):
        with pytest.raises(ValueError, match="Evidence hash mismatch"):
            Finding(
                title="Bad Hash",
                description="Desc",
                category="test",
                severity=FindingSeverity.LOW,
                confidence=0.5,
                confidence_level=ConfidenceLevel.MEDIUM,
                source="test",
                raw_evidence_hash="sha256:abc123",
                raw_evidence='{"different": "data"}',
            )

    def test_citation_complete(self):
        f = Finding.create(
            title="Cite",
            description="Desc",
            category="test",
            severity=FindingSeverity.INFO,
            confidence=0.8,
            source="src",
            raw_evidence="x",
        )
        assert f.is_citation_complete() is True


class TestFindingSerialization:
    def test_to_dict(self):
        f = Finding.create(
            title="Serialize",
            description="Desc",
            category="test",
            severity=FindingSeverity.HIGH,
            confidence=0.8,
            source="test",
            raw_evidence={"a": 1},
        )
        d = f.to_dict()
        assert d["title"] == "Serialize"
        assert d["severity"] == FindingSeverity.HIGH.value
        assert "timestamp" in d
        assert "finding_id" in d
        assert d["raw_evidence_hash"].startswith("sha256:")
