"""Tests for core/audit.py — hash-chained audit log."""
import json
from pathlib import Path

import pytest

from nexusrecon.core.audit import AuditLog


@pytest.fixture
def audit_log(tmp_path):
    return AuditLog(
        log_path=tmp_path / "audit.jsonl",
        campaign_id="test-campaign",
        scope_hash="sha256:abc123",
    )


class TestAuditLog:
    def test_init_writes_genesis(self, audit_log):
        path = Path(audit_log.log_path)
        assert path.exists()
        lines = path.read_text().strip().split("\n")
        assert len(lines) >= 1
        first = json.loads(lines[0])
        assert first["event_type"] == "audit_log_init"

    def test_log_tool_start(self, audit_log):
        h = audit_log.log_tool_start("subfinder", "T0", "acme.com", "subfinder -d acme.com")
        assert h.startswith("sha256:")

    def test_log_finding(self, audit_log):
        h = audit_log.log_finding("f-123", "Public S3 Bucket", "high", "aws_recon")
        assert h.startswith("sha256:")

    def test_chain_verification(self, audit_log):
        audit_log.log_tool_start("subfinder", "T0", "acme.com", "subfinder -d acme.com")
        audit_log.log_tool_result("subfinder", "acme.com", "sha256:xyz", 1500, 42)
        audit_log.log_finding("f-1", "Test", "high", "subfinder")
        assert audit_log.verify_chain() is True

    def test_chain_verification_after_tampering(self, audit_log, tmp_path):
        audit_log.log_tool_start("subfinder", "T0", "acme.com", "subfinder -d acme.com")
        path = Path(audit_log.log_path)
        # Tamper with the file
        lines = path.read_text().strip().split("\n")
        tampered = json.loads(lines[0])
        tampered["event_type"] = "tampered"
        lines[0] = json.dumps(tampered)
        path.write_text("\n".join(lines))

        assert audit_log.verify_chain() is False

    def test_seq_increments(self, audit_log):
        audit_log.log_tool_start("a", "T0", "x", "q")
        audit_log.log_tool_start("b", "T0", "y", "q")
        audit_log.log_tool_start("c", "T0", "z", "q")
        path = Path(audit_log.log_path)
        lines = path.read_text().strip().split("\n")
        seqs = [json.loads(l)["seq"] for l in lines[1:]]  # skip genesis
        assert seqs == [2, 3, 4]  # genesis is seq 1, tool calls start at 2
