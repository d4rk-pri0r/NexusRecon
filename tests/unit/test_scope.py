"""Tests for core/scope.py — scope enforcement."""
from pathlib import Path
import pytest
from nexusrecon.models.scope import ScopeModel
from nexusrecon.core.scope import ScopeGuard, OutOfScopeError, TierViolationError, preflight_check


@pytest.fixture
def sample_scope(tmp_path):
    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text("""
engagement:
  client: "Test Corp"
  engagement_id: "TEST-2026-01"
  authorized_by: "Test Admin"
  authorization_date: "2026-01-01"
  signed_sow_hash: "sha256:abc123"
  start_date: "2026-01-01"
  end_date: "2026-12-31"

scope:
  in_scope:
    domains: ["acme.com", "acme-corp.io"]
    ip_ranges: ["203.0.113.0/24"]
    asns: ["AS64500"]
  out_of_scope:
    domains: ["legal.acme.com", "*.acquired-co.com"]

constraints:
  max_tier: "T1"
  stealth_profile: "high"
  max_llm_cost_usd: 50.0
""")
    return ScopeModel.from_yaml(str(scope_yaml))


class TestScopeModel:
    def test_load_from_yaml(self, sample_scope):
        assert sample_scope.engagement.client == "Test Corp"
        assert sample_scope.engagement.engagement_id == "TEST-2026-01"
        assert sample_scope.constraints.max_tier == "T1"
        assert sample_scope.scope_hash is not None
        assert sample_scope.scope_hash.startswith("sha256:")

    def test_tier_value(self, sample_scope):
        assert sample_scope.tier_value() == 1

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ScopeModel.from_yaml(str(tmp_path / "nonexistent.yaml"))


class TestScopeGuard:
    def test_allowed_domain(self, sample_scope):
        guard = ScopeGuard(sample_scope)
        guard.check_domain("acme.com")  # should not raise
        guard.check_domain("sub.acme.com")  # subdomain of in-scope domain

    def test_blocked_domain(self, sample_scope):
        guard = ScopeGuard(sample_scope)
        with pytest.raises(OutOfScopeError):
            guard.check_domain("legal.acme.com")

    def test_wildcard_blocked(self, sample_scope):
        guard = ScopeGuard(sample_scope)
        with pytest.raises(OutOfScopeError):
            guard.check_domain("foo.acquired-co.com")

    def test_out_of_scope_domain(self, sample_scope):
        guard = ScopeGuard(sample_scope)
        with pytest.raises(OutOfScopeError):
            guard.check_domain("random.com")

    def test_tier_check_allowed(self, sample_scope):
        guard = ScopeGuard(sample_scope)
        guard.check_tier("T0", "crtsh")
        guard.check_tier("T1", "dns")

    def test_tier_check_violation(self, sample_scope):
        guard = ScopeGuard(sample_scope)
        with pytest.raises(TierViolationError):
            guard.check_tier("T2", "httpx")

    def test_is_domain_in_scope(self, sample_scope):
        guard = ScopeGuard(sample_scope)
        assert guard.is_domain_in_scope("acme.com") is True
        assert guard.is_domain_in_scope("sub.acme.com") is True
        assert guard.is_domain_in_scope("random.com") is False


class TestPreflight:
    def test_no_errors(self, sample_scope):
        warnings = preflight_check(sample_scope)
        assert all(w[0] != "ERROR" for w in warnings)

    def test_invalid_sow_hash(self, tmp_path):
        scope_yaml = tmp_path / "scope.yaml"
        scope_yaml.write_text("""
engagement:
  client: "Test"
  engagement_id: "T-01"
  authorized_by: "Admin"
  authorization_date: "2026-01-01"
  signed_sow_hash: "invalid"
  start_date: "2026-01-01"
  end_date: "2026-12-31"
scope:
  in_scope:
    domains: ["test.com"]
constraints:
  max_tier: "T0"
""")
        from pydantic import ValidationError
        with pytest.raises(ValidationError, match="signed_sow_hash"):
            ScopeModel.from_yaml(str(scope_yaml))
