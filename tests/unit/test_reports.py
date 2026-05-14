"""Tests for reports/engine.py — report generation."""
import json
import tempfile
from pathlib import Path
from datetime import datetime

from nexusrecon.reports.engine import ReportEngine


def _make_state(**overrides) -> dict:
    base = {
        "campaign_id": "test-campaign",
        "engagement_id": "eng-001",
        "scope_hash": "abc123",
        "seeds": ["example.com", "test.org"],
        "completed_phases": ["phase1", "phase2", "phase3", "phase4", "phase5", "phase6", "phase7", "phase8", "phase9"],
        "current_phase": "phase9",
        "findings": [
            {
                "finding_id": "f1",
                "title": "Public S3 Bucket",
                "description": "An S3 bucket is publicly accessible",
                "severity": "critical",
                "confidence": 0.95,
                "category": "cloud_exposure",
                "source": "aws_tool",
                "source_url": "https://console.aws.amazon.com/s3/buckets/test",
                "timestamp": "2025-01-01T00:00:00",
                "affected_assets": ["s3://test-bucket"],
                "mitre_techniques": ["T1525"],
                "recommendation": "Make the bucket private",
                "raw_evidence_hash": "sha256:abc",
            },
            {
                "finding_id": "f2",
                "title": "Exposed API Key",
                "description": "GitHub repo contains AWS API keys",
                "severity": "high",
                "confidence": 0.85,
                "category": "credential_leak",
                "source": "gitleaks",
                "timestamp": "2025-01-01T00:00:00",
                "affected_assets": ["github.com/test/repo"],
                "mitre_techniques": ["T1552"],
                "recommendation": "Rotate keys immediately",
                "raw_evidence_hash": "sha256:def",
            },
            {
                "finding_id": "f3",
                "title": "Open Admin Panel",
                "description": "Admin login page exposed",
                "severity": "medium",
                "confidence": 0.6,
                "category": "infrastructure",
                "source": "httpx",
                "timestamp": "2025-01-01T00:00:00",
                "affected_assets": ["admin.example.com"],
                "mitre_techniques": ["T1190"],
                "recommendation": "Restrict access",
                "raw_evidence_hash": "sha256:ghi",
            },
        ],
        "subdomain_intel": {
            "www.example.com": {"sources": ["crtsh"]},
            "api.example.com": {"sources": ["subfinder"]},
            "mail.example.com": {"sources": ["dns"]},
        },
        "email_intel": {
            "emails": {
                "ceo@example.com": {"source": "hunter", "position": "CEO", "department": "Executive"},
                "admin@example.com": {"source": "theharvester", "position": "IT Admin", "department": "IT"},
            },
            "format": {"most_likely_pattern": "first.last", "most_likely_confidence": 0.85},
        },
        "cloud_intel": {
            "azure/example.com": {
                "openid_config": {"tenant_id": "tenant-123", "issuer": "https://sts.windows.net/"},
                "user_realm": {"is_federated": True},
                "s3_buckets": [],
            },
        },
        "code_intel": {
            "github/example.com": {"data": {"leaks": [{"type": "aws_key"}]}},
        },
        "infra_intel": {
            "www.example.com": {
                "data": {"tech": [{"name": "nginx", "version": "1.20"}]},
            },
        },
        "vuln_intel": {
            "kev": {
                "data": {
                    "entries": [
                        {
                            "cveID": "CVE-2024-12345",
                            "vendorProject": "Test Corp",
                            "product": "Test Product",
                            "shortDescription": "A test vulnerability",
                            "dateAdded": "2025-01-15",
                        }
                    ]
                }
            },
        },
        "entity_graph": {
            "subdomains": ["www.example.com", "api.example.com"],
            "emails": ["ceo@example.com"],
        },
        "hypotheses": ["Check for more subdomains"],
        "confirmed_leads": ["Public S3 bucket is accessible", "AWS keys in GitHub"],
        "open_questions": ["Are there more leaked credentials?"],
        "llm_cost_usd": 0.05,
        "tool_cost_usd": 0.02,
        "step_count": 42,
        "errors": [],
        "agent_messages": [
            {"phase": "phase1", "agent": "passive_recon", "analysis": "Found subdomains", "timestamp": "2025-01-01T00:00:00"},
        ],
        "report_paths": {},
    }
    base.update(overrides)
    return base


class TestReportEngineInit:
    def test_init_creates_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "reports"
            engine = ReportEngine(
                campaign_id="test",
                engagement_id="eng",
                scope_hash="hash",
                output_dir=output,
            )
            assert output.exists()
            assert engine.campaign_id == "test"
            assert engine.engagement_id == "eng"
            assert engine.scope_hash == "hash"
            assert engine.report_paths == {}


class TestReportEngineGenerate:
    def test_generate_all_returns_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine(
                campaign_id="test-campaign",
                engagement_id="eng-001",
                scope_hash="abc123",
                output_dir=Path(tmp),
            )
            state = _make_state()
            paths = engine.generate_all(state)
            assert isinstance(paths, dict)
            assert len(paths) >= 10  # At least 10 report types

    def test_executive_summary_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._executive_summary(_make_state())
            content = Path(path).read_text()
            assert "Executive Summary" in content
            assert "Public S3 Bucket" in content
            assert "Exposed API Key" in content

    def test_full_report_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._full_report(_make_state())
            content = Path(path).read_text()
            assert "NexusRecon Engagement Report" in content
            assert "Public S3 Bucket" in content
            assert "Methodology" in content

    def test_asset_inventory_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._asset_inventory(_make_state())
            content = Path(path).read_text()
            assert "Asset Inventory" in content
            assert "www.example.com" in content
            assert "ceo@example.com" in content

    def test_phishing_package_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._phishing_package(_make_state())
            content = Path(path).read_text()
            assert "Phishing Target Package" in content
            assert "ceo@example.com" in content
            assert "first.last" in content

    def test_cloud_posture_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._cloud_posture(_make_state())
            content = Path(path).read_text()
            assert "Cloud & Identity Posture Brief" in content
            assert "Federated (ADFS)" in content

    def test_attack_surface_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._attack_surface(_make_state())
            content = Path(path).read_text()
            assert "Attack Surface Matrix" in content
            assert "Public S3 Bucket" in content

    def test_findings_json_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._findings_json(_make_state())
            data = json.loads(Path(path).read_text())
            assert "findings" in data
            assert len(data["findings"]) == 3

    def test_campaign_meta_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._campaign_meta(_make_state())
            data = json.loads(Path(path).read_text())
            assert data["campaign_id"] == "test"
            assert data["total_findings"] == 3

    def test_people_map_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._people_map(_make_state())
            content = Path(path).read_text()
            assert "People & Identity Map" in content
            assert "ceo@example.com" in content
            assert "Executive" in content

    def test_vuln_correlation_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._vuln_correlation(_make_state())
            content = Path(path).read_text()
            assert "Vulnerability Correlation Report" in content
            assert "CVE-2024-12345" in content

    def test_vendor_supply_chain_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._vendor_supply_chain(_make_state())
            content = Path(path).read_text()
            assert "Vendor & Supply Chain Report" in content
            assert "Microsoft 365" in content

    def test_jira_tracker_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._jira_tracker(_make_state())
            content = Path(path).read_text()
            assert "Summary" in content  # CSV header
            assert "Public S3 Bucket" in content

    def test_entity_graph_html_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._entity_graph_html(_make_state())
            content = Path(path).read_text()
            assert "<html" in content or "<!DOCTYPE" in content

    def test_pdf_report_fallback_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._pdf_report_fallback(_make_state())
            content = Path(path).read_text()
            assert "<html" in content or "<!DOCTYPE" in content
            assert "NexusRecon Report" in content

    def test_pptx_report_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            path = engine._pptx_report(_make_state())
            # If python-pptx is installed, path should exist
            if path:
                assert Path(path).exists()
                assert path.endswith(".pptx")

    def test_empty_state_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ReportEngine("test", "eng", "hash", Path(tmp))
            empty = _make_state(findings=[], subdomain_intel={}, email_intel={"emails": {}},
                                cloud_intel={}, code_intel={}, infra_intel={}, vuln_intel={})
            paths = engine.generate_all(empty)
            assert isinstance(paths, dict)
