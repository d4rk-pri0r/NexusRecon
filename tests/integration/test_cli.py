"""End-to-end CLI tests using Typer's CliRunner."""
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from nexusrecon.cli.main import app

runner = CliRunner()

SCOPE_YAML = """engagement:
  client: TestClient
  engagement_id: TEST-2026-E2E
  authorized_by: Test Authorizer
  authorization_date: "2026-01-01"
  signed_sow_hash: "sha256:abc123def456"
  start_date: "2026-01-01"
  end_date: "2027-03-01"
  engagement_type: red_team
scope:
  in_scope:
    domains:
      - testcorp.com
    ip_ranges:
      - 10.0.0.0/24
    email_domains:
      - testcorp.com
    cloud_tenants:
      aws_accounts:
        - "123456789012"
    github_orgs:
      - testcorp-org
  out_of_scope:
    domains:
      - eviltestcorp.com
constraints:
  max_tier: T1
  stealth_profile: normal
  allow_breach_db_lookup: true
  allow_paid_apis: false
  max_llm_cost_usd: 10.0
"""

INVALID_SCOPE_YAML = """engagement:
  client: BadScope
  engagement_id: BAD-01
  authorized_by: Nobody
  authorization_date: "2026-01-01"
  signed_sow_hash: "invalid-hash-format"
  start_date: "2026-01-01"
  end_date: "2026-03-01"
scope:
  in_scope:
    domains: []
constraints:
  max_tier: T5
  stealth_profile: ultra
"""


@pytest.fixture
def scope_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(SCOPE_YAML)
        path = f.name
    yield path
    Path(path).unlink(missing_ok=True)


@pytest.fixture
def invalid_scope_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(INVALID_SCOPE_YAML)
        path = f.name
    yield path
    Path(path).unlink(missing_ok=True)


class TestValidateCommand:
    def test_validate_valid_scope(self, scope_file):
        result = runner.invoke(app, ["validate", scope_file])
        assert result.exit_code == 0
        assert "TestClient" in result.stdout
        assert "TEST-2026-E2E" in result.stdout

    def test_validate_invalid_scope(self, invalid_scope_file):
        result = runner.invoke(app, ["validate", invalid_scope_file])
        assert result.exit_code == 1

    def test_validate_missing_file(self):
        result = runner.invoke(app, ["validate", "/nonexistent/scope.yaml"])
        assert result.exit_code == 1


class TestToolsCommand:
    def test_tools_list_displays_table(self):
        """The ``tools`` command renders the registered-tool inventory.

        The output format is the rich.Table title "NexusRecon Tools
        (N/M available)" plus a tabular body.  Match on the title prefix
        rather than a hard-coded "Registered" string, which was the
        wording in an earlier CLI revision.
        """
        result = runner.invoke(app, ["tools"])
        assert result.exit_code == 0
        assert "NexusRecon Tools" in result.stdout
        assert "available" in result.stdout

    def test_tools_check(self):
        result = runner.invoke(app, ["tools-check"])
        assert result.exit_code == 0


class TestConfigCommand:
    def test_config_display(self):
        result = runner.invoke(app, ["config"])
        assert result.exit_code == 0


class TestCampaignListCommand:
    def test_no_campaigns_when_empty(self):
        with patch("nexusrecon.cli.main.get_config") as mock_config:
            mock_cfg = mock_config.return_value
            mock_cfg.output_dir = "/nonexistent/output"
            result = runner.invoke(app, ["campaign-list"])
        assert result.exit_code == 0

    def test_campaign_list_with_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign_dir = Path(tmp) / "NEXUS-TEST-001"
            campaign_dir.mkdir()
            (campaign_dir / "state.json").write_text(json.dumps({
                "campaign_id": "NEXUS-TEST-001",
                "completed_phases": ["phase1", "phase2"],
                "engagement_id": "TEST-001",
                "findings": [],
                "errors": [],
            }))
            (campaign_dir / "scope_metadata.json").write_text(json.dumps({
                "engagement": {"client": "TestClient"},
                "constraints": {"max_tier": "T1"},
            }))
            with patch("nexusrecon.cli.main.get_config") as mock_config:
                mock_cfg = mock_config.return_value
                mock_cfg.output_dir = tmp
                result = runner.invoke(app, ["campaign-list"])
            assert result.exit_code == 0
            assert "NEXUS-TEST-001" in result.stdout


class TestExportCommand:
    def _setup_campaign(self, tmp: str, campaign_id: str, findings: list) -> Path:
        campaign_dir = Path(tmp) / campaign_id
        campaign_dir.mkdir()
        (campaign_dir / "state.json").write_text(
            json.dumps({"findings": findings, "campaign_id": campaign_id})
        )
        return campaign_dir

    def test_export_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._setup_campaign(tmp, "TEST-EXP-00", [])
            with patch("nexusrecon.cli.main.get_config") as mock_config:
                mock_cfg = mock_config.return_value
                mock_cfg.output_dir = tmp
                out_path = Path(tmp) / "out.json"
                result = runner.invoke(app, [
                    "export", "TEST-EXP-00", "--output", str(out_path)
                ])
            assert result.exit_code == 0

    def test_export_to_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._setup_campaign(tmp, "TEST-EXP-01", [
                {"finding_id": "f-1", "title": "Test Finding", "severity": "high"},
            ])
            with patch("nexusrecon.cli.main.get_config") as mock_config:
                mock_cfg = mock_config.return_value
                mock_cfg.output_dir = tmp
                out_path = Path(tmp) / "export.json"
                result = runner.invoke(app, [
                    "export", "TEST-EXP-01", "--output", str(out_path), "--format", "json"
                ])
            assert result.exit_code == 0
            assert out_path.exists()
            data = json.loads(out_path.read_text())
            assert len(data) == 1
            assert data[0]["title"] == "Test Finding"

    def test_export_to_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._setup_campaign(tmp, "TEST-EXP-02", [
                {"finding_id": "f-1", "title": "Test Finding", "severity": "high",
                 "description": "desc", "source": "test", "category": "web",
                 "affected_assets": ["example.com"], "confidence": 0.9,
                 "timestamp": "2026-01-01T00:00:00", "mitre_techniques": ["T1078"]},
            ])
            with patch("nexusrecon.cli.main.get_config") as mock_config:
                mock_cfg = mock_config.return_value
                mock_cfg.output_dir = tmp
                out_path = Path(tmp) / "export.csv"
                result = runner.invoke(app, [
                    "export", "TEST-EXP-02", "--output", str(out_path), "--format", "csv"
                ])
            assert result.exit_code == 0
            assert out_path.exists()
            content = out_path.read_text()
            assert "Title" in content
            assert "Test Finding" in content

    def test_export_stix2_default_filename_is_canonical(self):
        """`export --format stix2` with no --output must write
        stix2-bundle.json, the exact name `sign` auto-discovers. Previously it
        wrote findings_export.stix2 and the advertised export->sign happy path
        broke on defaults."""
        with tempfile.TemporaryDirectory() as tmp:
            campaign_dir = self._setup_campaign(tmp, "TEST-EXP-STIX", [])
            with patch("nexusrecon.cli.main.get_config") as mock_config:
                mock_cfg = mock_config.return_value
                mock_cfg.output_dir = tmp
                result = runner.invoke(app, [
                    "export", "TEST-EXP-STIX", "--format", "stix2"
                ])
            assert result.exit_code == 0, result.output
            assert (campaign_dir / "stix2-bundle.json").exists()
            # The legacy mismatched name is not what we write by default.
            assert not (campaign_dir / "findings_export.stix2").exists()
            bundle = json.loads((campaign_dir / "stix2-bundle.json").read_text())
            assert bundle["type"] == "bundle"

    def test_export_to_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._setup_campaign(tmp, "TEST-EXP-03", [
                {"finding_id": "f-1", "title": "Test Finding", "severity": "high"},
            ])
            with patch("nexusrecon.cli.main.get_config") as mock_config:
                mock_cfg = mock_config.return_value
                mock_cfg.output_dir = tmp
                out_path = Path(tmp) / "export.md"
                result = runner.invoke(app, [
                    "export", "TEST-EXP-03", "--output", str(out_path), "--format", "markdown"
                ])
            assert result.exit_code == 0
            assert out_path.exists()
            content = out_path.read_text()
            assert "Test Finding" in content


class TestDiffCommand:
    def test_diff_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            f1 = Path(tmp) / "a.json"
            f2 = Path(tmp) / "b.json"
            data = {"findings": [{"id": "1", "title": "test"}]}
            f1.write_text(json.dumps(data))
            f2.write_text(json.dumps(data))
            result = runner.invoke(app, ["diff", str(f1), str(f2)])
            assert result.exit_code == 0


class TestDryRun:
    def test_dry_run_valid(self, scope_file):
        result = runner.invoke(app, [
            "run", "--scope", scope_file, "--dry-run",
        ])
        assert result.exit_code == 0
