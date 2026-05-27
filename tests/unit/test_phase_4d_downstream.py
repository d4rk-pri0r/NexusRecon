"""Tests for Phase 4 PR D: downstream-consumer integrations.

PR D ships three purpose-built emitters under
``nexusrecon/export/downstream/``:

  - :class:`JiraTicketEmitter` — Findings → Jira REST API
    bodies, NDJSON.
  - :func:`emit_nuclei_targets` — EntityGraph → plain
    target list Nuclei consumes via ``-list``.
  - :func:`emit_cobaltstrike_profile_stub` — EntityGraph →
    Malleable C2 profile stub seeded with recon data.

Coverage
- JiraTicketEmitter: severity-to-priority mapping, summary
  truncation, label sanitisation, NDJSON write.
- Nuclei targets: URL entities pass through; bare hosts get
  scheme prefixes; min_confidence filter drops low-signal
  entities; ip_address entities included.
- Cobalt Strike stub: writes a parseable-shape profile
  (curly braces balanced, key blocks present); auto-fills
  sample target from the graph; includes subdomain-derived
  URIs.

What's NOT tested
- The TUI intent tab — deferred (sizable Textual integration
  scope; ships in a follow-up if community pull warrants).
- Live API calls — these emitters write files; we never
  call third-party APIs from PR D.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.export.downstream import (
    JiraIssue,
    JiraTicketEmitter,
    emit_cobaltstrike_profile_stub,
    emit_nuclei_targets,
)
from nexusrecon.export.downstream.jira import _sanitize_label


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _sample_findings() -> list[dict[str, Any]]:
    return [
        {
            "title": "Exposed admin panel",
            "severity": "high",
            "confidence": 0.92,
            "category": "Web Exposure",
            "source": "nuclei",
            "description": "Found /admin endpoint with default creds.",
            "affected_assets": ["api.acme.com"],
            "mitre_techniques": ["T1190"],
        },
        {
            "title": "Subdomain takeover candidate",
            "severity": "critical",
            "confidence": 0.85,
            "category": "Infrastructure",
            "source": "correlation",
            "description": "CNAME points to dangling S3 bucket.",
            "affected_assets": ["legacy.acme.com"],
        },
        {
            "title": "Leaked credential surfaced",
            "severity": "info",
            "confidence": 0.7,
            "category": "Identity",
            "source": "h8mail",
            "description": "Old breach data.",
        },
    ]


@pytest.fixture
def graph() -> EntityGraph:
    g = EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")
    g.add_domain("acme.com", source="scope", confidence=0.95)
    g.add_subdomain("api.acme.com", "acme.com", "subfinder", confidence=0.9)
    g.add_subdomain("admin.acme.com", "acme.com", "subfinder", confidence=0.85)
    g.add_ip("1.2.3.4", source="naabu", confidence=0.8)
    # Low-confidence — should be filtered by Nuclei emitter
    # default threshold.
    g.add_subdomain("legacy.acme.com", "acme.com", "subfinder", confidence=0.3)
    g.add_technology("nginx", source="httpx", confidence=0.9)
    return g


# ──────────────────────────────────────────────────────────────────────
# Jira emitter
# ──────────────────────────────────────────────────────────────────────


class TestJiraEmitter:
    def test_severity_to_priority_mapping(self):
        emitter = JiraTicketEmitter(project_key="SEC")
        issues = emitter.issues_from_findings(_sample_findings())
        priorities = [i.priority for i in issues]
        # high → High, critical → Highest, info → Lowest.
        assert priorities == ["High", "Highest", "Lowest"]

    def test_summary_truncation(self):
        emitter = JiraTicketEmitter(project_key="SEC")
        long_title = "x" * 500
        issues = emitter.issues_from_findings([
            {"title": long_title, "severity": "high"},
        ])
        assert len(issues[0].summary) == 255

    def test_label_sanitisation(self):
        emitter = JiraTicketEmitter(project_key="SEC")
        issues = emitter.issues_from_findings([
            {
                "title": "x", "severity": "high",
                "category": "Cloud Misconfig / S3!",
            },
        ])
        # "Cloud Misconfig / S3!" sanitises to "Cloud_Misconfig_S3".
        labels = issues[0].labels
        assert "nexusrecon" in labels
        assert any("Cloud_Misconfig" in l for l in labels)

    def test_label_sanitisation_helper(self):
        assert _sanitize_label("hello world!") == "hello_world"
        assert _sanitize_label("///") == "uncategorised"

    def test_to_jira_body_shape(self):
        issue = JiraIssue(
            summary="x", description="d",
            priority="High", labels=["a", "b"],
            project_key="SEC",
        )
        body = issue.to_jira_body()
        assert "fields" in body
        assert body["fields"]["project"]["key"] == "SEC"
        assert body["fields"]["priority"]["name"] == "High"
        assert body["fields"]["labels"] == ["a", "b"]

    def test_write_ndjson(self, tmp_path: Path):
        out = JiraTicketEmitter(project_key="SEC").write_ndjson(
            _sample_findings(), tmp_path / "tickets.ndjson",
        )
        assert out.exists()
        lines = out.read_text().splitlines()
        assert len(lines) == 3
        for line in lines:
            body = json.loads(line)
            assert "fields" in body
            assert body["fields"]["project"]["key"] == "SEC"

    def test_skips_non_dict_findings(self):
        emitter = JiraTicketEmitter(project_key="SEC")
        issues = emitter.issues_from_findings(
            [_sample_findings()[0], "not a dict", None],  # type: ignore[list-item]
        )
        assert len(issues) == 1

    def test_extra_fields_override(self):
        issue = JiraIssue(
            summary="x", description="d", priority="High",
            labels=[], project_key="SEC",
            extra_fields={"customfield_10001": "value"},
        )
        body = issue.to_jira_body()
        assert body["fields"]["customfield_10001"] == "value"


# ──────────────────────────────────────────────────────────────────────
# Nuclei target list
# ──────────────────────────────────────────────────────────────────────


class TestNucleiTargets:
    def test_basic_emission(self, graph: EntityGraph, tmp_path: Path):
        out, targets = emit_nuclei_targets(
            graph, tmp_path / "targets.txt",
        )
        body = out.read_text()
        # legacy.acme.com is below the 0.5 threshold; excluded.
        assert "legacy.acme.com" not in body
        # The high-confidence entities make it.
        assert "https://acme.com" in body
        assert "https://api.acme.com" in body
        assert "https://1.2.3.4" in body
        assert len(targets) >= 4

    def test_min_confidence_filter(self, graph: EntityGraph, tmp_path: Path):
        _, targets = emit_nuclei_targets(
            graph, tmp_path / "all.txt",
            min_confidence=0.0,
        )
        # With no threshold, legacy.acme.com gets included.
        assert any("legacy.acme.com" in t for t in targets)

    def test_multiple_schemes(self, graph: EntityGraph, tmp_path: Path):
        _, targets = emit_nuclei_targets(
            graph, tmp_path / "both.txt",
            schemes=["http", "https"],
        )
        # Each host appears with both schemes.
        assert "http://acme.com" in targets
        assert "https://acme.com" in targets

    def test_no_schemes_emits_bare_hosts(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        _, targets = emit_nuclei_targets(
            graph, tmp_path / "bare.txt",
            schemes=[],
        )
        assert "acme.com" in targets
        assert all("://" not in t for t in targets)

    def test_url_entity_passes_through(self, tmp_path: Path):
        g = EntityGraph(campaign_id="c", engagement_id="e")
        from nexusrecon.models.entities import URLEntity
        g.add_entity(URLEntity(
            value="https://api.acme.com/v1/users",
            sources=["httpx"], confidence=0.9,
        ))
        _, targets = emit_nuclei_targets(
            g, tmp_path / "urls.txt",
        )
        assert "https://api.acme.com/v1/users" in targets


# ──────────────────────────────────────────────────────────────────────
# Cobalt Strike profile stub
# ──────────────────────────────────────────────────────────────────────


class TestCobaltStrikeProfile:
    def test_writes_profile(self, graph: EntityGraph, tmp_path: Path):
        out = emit_cobaltstrike_profile_stub(
            graph, tmp_path / "profile.profile",
        )
        body = out.read_text()
        # The boilerplate.
        assert "Malleable C2" in body
        assert "http-get {" in body
        assert "http-post {" in body
        # User-agent candidates injected.
        assert "User-Agent" in body
        # Subdomain-derived URIs appear.
        assert "/api/status" in body or "/admin/status" in body

    def test_sample_target_explicit(self, graph: EntityGraph, tmp_path: Path):
        out = emit_cobaltstrike_profile_stub(
            graph, tmp_path / "p.profile",
            sample_target="explicit.example.com",
        )
        body = out.read_text()
        assert "explicit.example.com" in body

    def test_no_domain_uses_placeholder(self, tmp_path: Path):
        g = EntityGraph(campaign_id="c", engagement_id="e")
        out = emit_cobaltstrike_profile_stub(
            g, tmp_path / "empty.profile",
        )
        body = out.read_text()
        # Fallback placeholder when no domain entities exist.
        assert "example.com" in body

    def test_balanced_curly_braces(self, graph: EntityGraph, tmp_path: Path):
        out = emit_cobaltstrike_profile_stub(
            graph, tmp_path / "p.profile",
        )
        body = out.read_text()
        # Simple structural check — same number of opens and
        # closes. Operators load this file in Cobalt Strike;
        # malformed bracing is the most common authoring
        # mistake.
        assert body.count("{") == body.count("}")

    def test_review_warning_present(self, graph: EntityGraph, tmp_path: Path):
        out = emit_cobaltstrike_profile_stub(
            graph, tmp_path / "p.profile",
        )
        body = out.read_text()
        # The stub MUST tell operators to review before
        # deploying. This is a tradecraft safety net.
        assert "review" in body.lower() or "tune" in body.lower()
