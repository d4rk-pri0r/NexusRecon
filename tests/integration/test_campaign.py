"""Comprehensive end-to-end campaign integration test.

Tests the full pipeline:
  - Scope loading and preflight validation
  - LangGraph workflow execution
  - Report generation (all 16 types)
  - Entity graph roundtrip
  - Audit logging
  - State persistence and resume
"""
import json
import tempfile
from pathlib import Path

import pytest

from nexusrecon.core.audit import AuditLog
from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.core.scope import ScopeGuard, ScopeModel, preflight_check
from nexusrecon.graph.workflow import run_workflow
from nexusrecon.models.entities import EntityType, RelationshipType
from nexusrecon.reports.engine import ReportEngine

SCOPE_YAML = """engagement:
  client: E2ETestClient
  engagement_id: E2E-2026-001
  authorized_by: Test Authorizer
  authorization_date: "2026-01-01"
  signed_sow_hash: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
  start_date: "2026-01-01"
  end_date: "2027-12-31"
  engagement_type: red_team
scope:
  in_scope:
    domains:
      - e2e-testcorp.com
      - e2e-dev.com
    ip_ranges:
      - 10.0.0.0/24
      - 192.168.1.0/24
    email_domains:
      - e2e-testcorp.com
    cloud_tenants:
      aws_accounts:
        - "111111111111"
      azure_subscriptions:
        - "sub-aaaa-bbbb-cccc"
    github_orgs:
      - e2e-testorg
  out_of_scope:
    domains:
      - e2e-thirdparty.com
    third_parties:
      - Acme Corp
constraints:
  max_tier: T2
  stealth_profile: normal
  allow_breach_db_lookup: false
  allow_paid_apis: false
  max_llm_cost_usd: 50.0
"""


@pytest.fixture
def scope_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(SCOPE_YAML)
        path = f.name
    yield path
    Path(path).unlink(missing_ok=True)


# ── Full State Fixture ──────────────────────────────────────────────────────

@pytest.fixture
def full_state():
    return {
        "campaign_id": "NEXUS-E2E-FULL-001",
        "engagement_id": "E2E-2026-001",
        "scope_hash": "sha256:abc123def456",
        "seeds": ["e2e-testcorp.com", "e2e-dev.com"],
        "current_phase": "init",
        "completed_phases": [],
        "phase_results": {},
        "findings": [
            {
                "finding_id": "f-001", "title": "Public S3 Bucket",
                "description": "S3 bucket e2e-data is publicly readable",
                "severity": "critical", "confidence": 0.95,
                "source": "aws_recon", "category": "cloud_exposure",
                "affected_assets": ["e2e-data.s3.amazonaws.com"],
                "mitre_techniques": ["T1530"], "raw_evidence_hash": "sha256:abc",
                "timestamp": "2026-05-01T12:00:00Z",
            },
            {
                "finding_id": "f-002", "title": "Exposed Git Repository",
                "description": ".git directory exposed on dev portal",
                "severity": "high", "confidence": 0.88,
                "source": "gitleaks", "category": "code_leakage",
                "affected_assets": ["dev.e2e-testcorp.com"],
                "mitre_techniques": ["T1213"], "raw_evidence_hash": "sha256:def",
                "timestamp": "2026-05-01T13:00:00Z",
            },
            {
                "finding_id": "f-003", "title": "Valid Credentials in Public Repo",
                "description": "AWS keys found in public GitHub repo",
                "severity": "critical", "confidence": 0.99,
                "source": "trufflehog", "category": "secret_leak",
                "affected_assets": ["github.com/e2e-testorg/repo1"],
                "mitre_techniques": ["T1552"], "raw_evidence_hash": "sha256:ghi",
                "timestamp": "2026-05-01T14:00:00Z",
            },
            {
                "finding_id": "f-004", "title": "Open RDP Port",
                "description": "TCP 3389 exposed on infrastructure host",
                "severity": "high", "confidence": 0.75,
                "source": "shodan", "category": "infrastructure",
                "affected_assets": ["10.0.0.45"],
                "mitre_techniques": ["T1021"], "raw_evidence_hash": "sha256:jkl",
                "timestamp": "2026-05-01T15:00:00Z",
            },
        ],
        "domain_intel": {
            "e2e-testcorp.com": {
                "whois": {"registrar": "TestRegistrar", "created": "2020-01-01"},
                "dns": {"a": ["10.0.0.1"], "mx": ["mail.e2e-testcorp.com"]},
            },
        },
        "subdomain_intel": {
            "api.e2e-testcorp.com": {"sources": ["crtsh"]},
            "dev.e2e-testcorp.com": {"sources": ["crtsh", "subfinder"]},
            "admin.e2e-testcorp.com": {"sources": ["crtsh"]},
            "mail.e2e-testcorp.com": {"sources": ["dns"]},
        },
        "email_intel": {
            "emails": {
                "admin@e2e-testcorp.com": {"source": "hunter", "confidence": 0.9},
                "dev@e2e-testcorp.com": {"source": "hunter", "confidence": 0.7},
                "info@e2e-testcorp.com": {"source": "theharvester", "confidence": 0.5},
            },
            "formats": {"pattern": "first.last@e2e-testcorp.com"},
        },
        "identity_intel": {
            "employees": [
                {"name": "John Doe", "title": "CTO", "linkedin": "https://linkedin.com/in/johndoe"},
                {"name": "Jane Smith", "title": "DevOps Lead", "github": "janesmith"},
            ],
        },
        "cloud_intel": {
            "aws": {"accounts": ["111111111111"], "services": ["s3", "ec2", "iam"]},
            "azure": {"tenants": ["e2e-testcorp.onmicrosoft.com"]},
        },
        "code_intel": {
            "repos": [
                {"name": "e2e-testorg/repo1", "visibility": "public", "language": "Python"},
                {"name": "e2e-testorg/repo2", "visibility": "private", "language": "Go"},
            ],
            "secrets": [
                {"repo": "e2e-testorg/repo1", "type": "aws_key", "severity": "critical"},
            ],
        },
        "infra_intel": {
            "hosts": [
                {"ip": "10.0.0.1", "ports": [80, 443], "service": "nginx"},
                {"ip": "10.0.0.45", "ports": [3389], "service": "rdp"},
            ],
            "technologies": [{"name": "nginx", "version": "1.24", "confidence": "high"}],
        },
        "vuln_intel": {
            "software": [
                {"name": "nginx", "version": "1.24.0", "cves": ["CVE-2024-1234"]},
            ],
            "epss": {"CVE-2024-1234": {"score": 0.85, "percentile": 0.95}},
        },
        "pretext_intel": {
            "news": [
                {"title": "E2E TestCorp Acquires Startup", "date": "2026-04-15"},
            ],
            "jobs": [
                {"title": "Senior Security Engineer", "tech_stack": ["aws", "python", "k8s"]},
            ],
            "sec_filings": [
                {"type": "10-K", "filed": "2026-03-01", "highlights": ["cybersecurity investments"]},
            ],
        },
        "entity_graph": {},
        "hypotheses": [
            "Cloud misconfigurations indicate rushed AWS migration",
            "Exposed credentials suggest weak secrets management",
        ],
        "confirmed_leads": [
            "Public S3 bucket contains customer PII — prioritize containment",
            "Git credentials provide initial access path",
        ],
        "open_questions": [
            "Are there additional S3 buckets with similar misconfigurations?",
            "What is the blast radius of the exposed AWS keys?",
        ],
        "llm_cost_usd": 0.45,
        "tool_cost_usd": 12.30,
        "step_count": 47,
        "errors": [],
        "agent_messages": [
            {"phase": "phase1", "agent": "passive_recon",
             "analysis": "Identified 3 subdomains and WHOIS records.",
             "timestamp": "2026-05-01T12:00:00Z"},
            {"phase": "phase4", "agent": "correlation",
             "analysis": "Correlated cloud exposure with credential leaks.",
             "timestamp": "2026-05-01T16:00:00Z"},
        ],
        "report_paths": {},
    }


# ── E2E Report Generation ───────────────────────────────────────────────────

class TestE2EReportGeneration:
    """All 16 report types generate without error from a full state."""

    def test_all_reports_generate(self, tmp_path, full_state):
        engine = ReportEngine(
            campaign_id="NEXUS-E2E-FULL-001",
            engagement_id="E2E-2026-001",
            scope_hash="sha256:abc123def456",
            output_dir=tmp_path,
        )
        paths = engine.generate_all(full_state)

        expected_reports = [
            "executive_summary", "full_report", "asset_inventory",
            "phishing_package", "cloud_posture", "attack_surface",
            "findings_json", "campaign_meta", "people_map",
            "vuln_correlation", "vendor_supply_chain", "jira_tracker",
            "entity_graph_html", "pdf_report", "pptx_report",
        ]
        for name in expected_reports:
            assert name in paths, f"Missing report: {name}"
            assert Path(paths[name]).exists(), f"File not found: {paths[name]}"

    def test_executive_summary_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._executive_summary(full_state)
        content = Path(path).read_text()
        assert "Executive Summary" in content
        assert "Public S3 Bucket" in content
        assert "[CRITICAL]" in content

    def test_full_report_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._full_report(full_state)
        content = Path(path).read_text()
        assert "Engagement Report" in content
        assert "Public S3 Bucket" in content

    def test_findings_json_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._findings_json(full_state)
        data = json.loads(Path(path).read_text())
        assert len(data["findings"]) == 4
        assert data["findings"][0]["finding_id"] == "f-001"

    def test_asset_inventory_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._asset_inventory(full_state)
        content = Path(path).read_text()
        assert "e2e-testcorp.com" in content
        assert "api.e2e-testcorp.com" in content

    def test_campaign_meta_content(self, tmp_path, full_state):
        engine = ReportEngine("NEXUS-E2E-FULL-001", "E2E-2026-001", "sha256:abc123def456", tmp_path)
        path = engine._campaign_meta(full_state)
        data = json.loads(Path(path).read_text())
        assert data["campaign_id"] == "NEXUS-E2E-FULL-001"
        assert data["total_findings"] == 4

    def test_jira_tracker_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._jira_tracker(full_state)
        content = Path(path).read_text()
        assert "Public S3 Bucket" in content
        assert "Highest" in content

    def test_phishing_package_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._phishing_package(full_state)
        content = Path(path).read_text()
        assert "admin@e2e-testcorp.com" in content or "admin" in content.lower()

    def test_cloud_posture_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._cloud_posture(full_state)
        content = Path(path).read_text()
        assert "111111111111" in content or "aws" in content.lower()

    def test_vuln_correlation_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._vuln_correlation(full_state)
        content = Path(path).read_text()
        assert "Vulnerability Correlation" in content
        assert "Summary" in content

    def test_people_map_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._people_map(full_state)
        content = Path(path).read_text()
        assert "People & Identity" in content
        assert "admin@e2e-testcorp.com" in content

    def test_vendor_supply_chain_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._vendor_supply_chain(full_state)
        content = Path(path).read_text()
        assert "Vendor" in content or "Supply" in content or "Third" in content

    def test_attack_surface_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._attack_surface(full_state)
        content = Path(path).read_text()
        assert "Attack Surface" in content
        assert "Public S3 Bucket" in content

    def test_entity_graph_html_content(self, tmp_path, full_state):
        engine = ReportEngine("test", "E2E-2026-001", "h", tmp_path)
        path = engine._entity_graph_html(full_state)
        content = Path(path).read_text()
        assert "<!DOCTYPE html>" in content or "<html" in content


# ── E2E Scope and Enforcement ──────────────────────────────────────────────

class TestE2EScope:
    def test_scope_loading(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        assert model.engagement.client == "E2ETestClient"
        assert model.engagement.engagement_id == "E2E-2026-001"
        assert "sha256:" in model.scope_hash
        assert model.constraints.max_tier == "T2"

    def test_preflight_passes(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        warnings = preflight_check(model)
        errors = [w for w in warnings if w[0] == "ERROR"]
        assert len(errors) == 0

    def test_scope_guard_allows_in_scope(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        guard = ScopeGuard(model)
        # These should not raise OutOfScopeError
        guard.check_domain("e2e-testcorp.com")
        guard.check_domain("api.e2e-testcorp.com")

    def test_scope_guard_rejects_out_of_scope(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        guard = ScopeGuard(model)
        from nexusrecon.core.scope import OutOfScopeError
        with pytest.raises(OutOfScopeError):
            guard.check_domain("e2e-thirdparty.com")
        with pytest.raises(OutOfScopeError):
            guard.check_domain("malicious.com")

    def test_scope_guard_tier_enforcement(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        guard = ScopeGuard(model)
        guard.check_tier("T1", "tool1")
        guard.check_tier("T2", "tool2")
        from nexusrecon.core.scope import TierViolationError
        with pytest.raises(TierViolationError):
            guard.check_tier("T3", "tool3")

    def test_scope_guard_github_org_enforcement(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        guard = ScopeGuard(model)
        guard.check_github_org("e2e-testorg")
        from nexusrecon.core.scope import OutOfScopeError
        with pytest.raises(OutOfScopeError):
            guard.check_github_org("unknown-org")

    def test_scope_guard_aws_account_enforcement(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        guard = ScopeGuard(model)
        guard.check_aws_account("111111111111")
        from nexusrecon.core.scope import OutOfScopeError
        with pytest.raises(OutOfScopeError):
            guard.check_aws_account("999999999999")

    def test_scope_guard_ip_enforcement(self, scope_file):
        model = ScopeModel.from_yaml(scope_file)
        guard = ScopeGuard(model)
        guard.check_ip("10.0.0.5")
        from nexusrecon.core.scope import OutOfScopeError
        with pytest.raises(OutOfScopeError):
            guard.check_ip("1.2.3.4")


# ── E2E Audit Log ──────────────────────────────────────────────────────────

class TestE2EAuditLog:
    @staticmethod
    def _read_entries(path: Path):
        return [json.loads(line) for line in path.read_text().strip().split("\n") if line.strip()]

    @staticmethod
    def _read_data_entries(path: Path):
        return [e for e in TestE2EAuditLog._read_entries(path) if e.get("event_type") != "audit_log_init"]

    def test_audit_log_creation_and_integrity(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path, "test-campaign", "sha256:abc")
        audit.log_tool_start("crtsh", "T1", "example.com", "example.com")
        audit.log_tool_result("crtsh", "example.com", "abc", 1200, 5)
        audit.log_tool_error("hunter", "example.com", "API key missing")
        entries = self._read_data_entries(log_path)
        assert len(entries) == 3
        assert entries[0]["event_type"] == "tool_start"
        assert entries[0]["tool_name"] == "crtsh"
        assert entries[2]["event_type"] == "tool_error"
        assert entries[2]["error"] == "API key missing"

    def test_audit_log_chain_verification(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path, "test-campaign", "sha256:abc")
        for i in range(10):
            audit.log_tool_result(f"tool{i}", f"target{i}.com", "xyz", 500, 1)
        assert audit.verify_chain() is True

    def test_audit_log_tamper_detection(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLog(log_path, "test-campaign", "sha256:abc")
        audit.log_tool_result("crtsh", "example.com", "abc", 100, 3)
        audit.log_tool_result("hunter", "example.com", "def", 200, 1)
        # Tamper with the first data entry (skip genesis at line 0)
        lines = log_path.read_text().strip().split("\n")
        tampered = lines[1].replace("crtsh", "MODIFIED")
        lines[1] = tampered
        log_path.write_text("\n".join(lines))
        assert audit.verify_chain() is False

    def test_audit_log_empty(self, tmp_path):
        log_path = tmp_path / "empty.jsonl"
        log_path.write_text("")
        audit = AuditLog(log_path, "test-campaign", "sha256:abc")
        assert audit.verify_chain() is True
        assert self._read_data_entries(log_path) == []


# ── E2E Entity Graph ───────────────────────────────────────────────────────

class TestE2EEntityGraph:
    def test_entity_graph_build_and_query(self):
        g = EntityGraph("test", "E2E-2026-001")
        domain_id = g.add_domain("e2e-testcorp.com", source="whois")
        g.add_subdomain("api.e2e-testcorp.com", parent="e2e-testcorp.com", source="crtsh")
        ip_id = g.add_ip("10.0.0.1", source="dns")
        g.relate(domain_id, ip_id, RelationshipType.RESOLVES_TO)
        assert g.graph.number_of_nodes() == 3
        assert g.graph.number_of_edges() == 1

    def test_entity_graph_serialization(self):
        g = EntityGraph("test", "E2E-2026-001")
        g.add_domain("example.com", source="whois")
        data = g.to_dict()
        g2 = EntityGraph.from_dict(data)
        assert g2.graph.number_of_nodes() == 1

    def test_entity_graph_get_neighbors(self):
        g = EntityGraph("test", "E2E-2026-001")
        domain_id = g.add_domain("e2e-testcorp.com", source="whois")
        api_id = g.add_subdomain("api.e2e-testcorp.com", parent="e2e-testcorp.com", source="crtsh")
        dev_id = g.add_subdomain("dev.e2e-testcorp.com", parent="e2e-testcorp.com", source="crtsh")
        g.relate(domain_id, api_id, RelationshipType.HAS_SUBDOMAIN)
        g.relate(domain_id, dev_id, RelationshipType.HAS_SUBDOMAIN)
        g.add_domain("unrelated.com", source="whois")
        neighbors = g.get_neighbors(domain_id)
        assert len(neighbors) >= 2

    def test_entity_graph_find_path(self):
        g = EntityGraph("test", "E2E-2026-001")
        domain_id = g.add_domain("e2e-testcorp.com", source="whois")
        sub_id = g.add_subdomain("api.e2e-testcorp.com", parent="e2e-testcorp.com", source="crtsh")
        ip_id = g.add_ip("10.0.0.1", source="dns")
        g.relate(domain_id, sub_id, RelationshipType.HAS_SUBDOMAIN)
        g.relate(sub_id, ip_id, RelationshipType.RESOLVES_TO)
        path = g.find_path("e2e-testcorp.com", "10.0.0.1",
                           EntityType.DOMAIN, EntityType.IP_ADDRESS)
        assert path is not None
        assert len(path) >= 2


# ── E2E Workflow ───────────────────────────────────────────────────────────

class TestE2EWorkflow:
    @pytest.mark.asyncio
    async def test_workflow_execution_with_state(self):
        state = {
            "campaign_id": "NEXUS-E2E-WF-001",
            "engagement_id": "E2E-2026-001",
            "scope_hash": "sha256:abc",
            "seeds": ["e2e-testcorp.com"],
            "current_phase": "init",
            "completed_phases": [],
            "findings": [],
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "infra_intel": {},
            "domain_intel": {},
            "vuln_intel": {},
            "pretext_intel": {},
            "entity_graph": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "open_questions": [],
            "llm_cost_usd": 0.0,
            "tool_cost_usd": 0.0,
            "step_count": 0,
            "errors": [],
            "agent_messages": [],
            "report_paths": {},
        }
        result = await run_workflow(state)
        assert result is not None
        assert "completed_phases" in result
        assert len(result["completed_phases"]) > 0

    @pytest.mark.asyncio
    async def test_workflow_preserves_campaign_id(self):
        state = {
            "campaign_id": "NEXUS-E2E-WF-002",
            "engagement_id": "E2E-2026-001",
            "scope_hash": "sha256:def",
            "seeds": ["e2e-testcorp.com"],
            "current_phase": "init",
            "completed_phases": [],
            "findings": [],
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "infra_intel": {},
            "domain_intel": {},
            "vuln_intel": {},
            "pretext_intel": {},
            "entity_graph": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "open_questions": [],
            "llm_cost_usd": 0.0,
            "tool_cost_usd": 0.0,
            "step_count": 0,
            "errors": [],
            "agent_messages": [],
            "report_paths": {},
        }
        result = await run_workflow(state)
        assert result["campaign_id"] == "NEXUS-E2E-WF-002"

    @pytest.mark.asyncio
    async def test_workflow_resume_skip_completed(self):
        state = {
            "campaign_id": "NEXUS-E2E-WF-003",
            "engagement_id": "E2E-2026-001",
            "scope_hash": "sha256:ghi",
            "seeds": ["e2e-testcorp.com"],
            "current_phase": "phase3",
            "completed_phases": ["phase1", "phase2"],
            "findings": [],
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "infra_intel": {},
            "domain_intel": {},
            "vuln_intel": {},
            "pretext_intel": {},
            "entity_graph": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "open_questions": [],
            "llm_cost_usd": 0.0,
            "tool_cost_usd": 0.0,
            "step_count": 0,
            "errors": [],
            "agent_messages": [],
            "report_paths": {},
        }
        result = await run_workflow(state)
        completed = result.get("completed_phases", [])
        assert "phase1" in completed
        assert "phase2" in completed
        assert len(completed) >= 3
