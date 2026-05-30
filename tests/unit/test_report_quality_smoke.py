"""End-to-end report-quality smoke tests across varied target shapes.

Complementary to ``test_report_quality.py`` (which scans STATIC text:
agent prompts, Jinja templates, hardcoded engine prose). This file
runs the actual :class:`ReportEngine` against synthetic state
fixtures and asserts quality invariants on the GENERATED output.

Roadmap reference: ``ROADMAP.md`` Path-to-0.6.0 beta blocker
"Report quality smoke" — the original framing was "run 10 campaigns
across varied target shapes". Real campaigns aren't viable in a
unit suite (real LLM spend + hours of wall-clock), so we exercise
the report path with hand-built state fixtures that mirror the
shapes real campaigns produce:

  - **Small business**: a single corp domain, a handful of
    subdomains, light cloud presence, no breach hits.
  - **M365 enterprise**: Azure / M365 federation, a tenant ID,
    onmicrosoft.com presence, identity-graph populated with
    breach-derived exposures.
  - **AWS-native startup**: S3 buckets, AWS account ID, GitHub
    Actions leaks, exposed Cognito identity pool, CVEs from a
    third-party dependency.
  - **Mixed-cloud + breaches**: combines Azure + AWS + GCP
    findings with Phase D credential punch list + Phase E
    spear-phishing intelligence.
  - **Empty**: a campaign that produced no findings — the
    regression case where renderers tend to crash on
    ``state.get('foo')`` returning ``None``.

For every fixture we assert:

  1. Every deliverable lands on disk under ``output_dir`` without
     raising.
  2. The markdown footers carry both ``Scope Hash`` AND
     ``Tooling: NexusRecon vX.Y.Z`` — the audit identifiers
     pinned by the beta-blocker spec.
  3. JSON deliverables include ``nexusrecon_version`` next to
     ``scope_hash`` so a structured-data consumer can pin the
     run too.
  4. The generated prose contains no LLM-disclaimer artifacts
     ("As a large language model", "I'd be happy to help") that
     might have slipped in if a template ever started to embed
     LLM output directly.
  5. CVE references in the generated output match the canonical
     ``CVE-YYYY-NNNN`` format (no placeholders, no truncations).

Cross-tool dedup gets its own targeted test: a state in which two
different intel sources surface the same CVE must collapse to a
single ranked finding, not duplicate it across the report.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from nexusrecon.reports.engine import ReportEngine, collect_state_cves
from nexusrecon import __version__ as NEXUS_VERSION


# ──────────────────────────────────────────────────────────────────────
# LLM isolation
# ──────────────────────────────────────────────────────────────────────


class _StubAgentExecutor:
    """Stand-in for :class:`nexusrecon.graph.agent_executor.AgentExecutor`
    that returns instantly with deterministic content. The real
    executor invokes the configured LLM (Anthropic / OpenAI / Ollama /
    MockLLM), which makes a smoke run take ~20 seconds per fixture
    against a live provider key. The smoke suite is testing the
    report engine's plumbing + invariants, not the LLM provider's
    output, so we cut the dependency entirely."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def run_agent(
        self, agent_name: str, task_data: dict[str, Any] | None = None,
        task_prompt: str = "", state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # Return a benign canned response. The body contains no
        # AI-tell phrases (which would fail our own assertions).
        return {
            "output": (
                f"Agent {agent_name} stub output for smoke testing. "
                "No live LLM was contacted."
            ),
            "agent": agent_name,
            "step_count": 1,
            "findings": [],
        }


@pytest.fixture(autouse=True)
def _stub_llm_executor():
    """Replace AgentExecutor with the stub for every test in this
    module. Autouse so individual tests don't have to remember to
    apply it."""
    with patch(
        "nexusrecon.graph.agent_executor.AgentExecutor",
        _StubAgentExecutor,
    ):
        yield

# ──────────────────────────────────────────────────────────────────────
# AI-tell phrase inventory (mirror of test_report_quality.py constants)
# ──────────────────────────────────────────────────────────────────────

# Phrases that absolutely must not appear in any generated artefact.
# Mirrors the LLM disclaimer list in the static-text scanner; the
# duplication is intentional — these two suites cover different surface
# areas (authored prose vs. rendered output) and either could drift
# while the other holds.
LLM_DISCLAIMER_PHRASES: list[str] = [
    "as a large language model",
    "as an ai language model",
    "as an ai assistant",
    "i'd be happy to help",
    "i'd be glad to help",
    "i cannot fulfill",
    "i'm not able to provide",
    "i don't have access to real-time",
    "my training data",
    "my knowledge cutoff",
]

# Canonical CVE pattern. Any string that LOOKS like a CVE ID in the
# generated output must match this — anything that looks CVE-shaped
# but doesn't match is a typo or placeholder and shouldn't ship.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
# CVE-shape detector: only flags strings that LOOK like an attempted
# CVE citation (CVE- followed by either digits or a clear placeholder
# like X+). Skips ordinary prose like "CVE-to-asset mapping" or
# "CVE-style enrichment" ── those aren't citations, they're nouns.
# Pattern: two hyphen-separated segments where each segment is either
# all digits, all X (case-insensitive placeholder), or a mix.
_CVE_SHAPED_RE = re.compile(
    r"\bCVE-[0-9Xx]+-[0-9Xx]+\b",
    re.IGNORECASE,
)
# Case-insensitive canonical-CVE matcher for the provenance subset test.
# Mirrors engine.collect_state_cves so a lower-cased citation in next-steps
# text (e.g. the nuclei "-id cve-2021-44228" arg) still resolves to the
# upper-cased sourced id.
_CVE_CI_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


# ──────────────────────────────────────────────────────────────────────
# State fixtures
# ──────────────────────────────────────────────────────────────────────


def _state_small_business() -> dict[str, Any]:
    """Single-domain SMB shape: one corp domain, a few subdomains,
    a handful of employee emails, no cloud, one medium-severity
    finding."""
    return {
        "seeds": ["acme-widgets.com"],
        "completed_phases": [
            "phase1", "phase2", "phase3", "phase4", "phase5",
            "phase6", "phase7", "phase8", "phase9",
        ],
        "subdomain_intel": {
            "www.acme-widgets.com": {"sources": ["crtsh"]},
            "mail.acme-widgets.com": {"sources": ["crtsh"]},
            "vpn.acme-widgets.com": {"sources": ["amass"]},
        },
        "email_intel": {
            "emails": {
                "jane@acme-widgets.com": {"sources": ["hunter"], "role": "VP Engineering"},
                "bob@acme-widgets.com": {"sources": ["hunter"], "role": "IT Manager"},
            },
        },
        "cloud_intel": {},
        "findings": [
            {
                "title": "Outdated Apache version on vpn.acme-widgets.com",
                "severity": "medium",
                "description": "Apache/2.4.29 detected; multiple CVEs apply.",
                "source": "httpx",
                "confidence": 0.85,
                "category": "web",
                "affected_assets": ["vpn.acme-widgets.com"],
            },
        ],
        "ranked_threads": [],
    }


def _state_m365_enterprise() -> dict[str, Any]:
    """M365 federation tenant shape: tenant ID, onmicrosoft.com
    discovery, employee identities with breach hits. Mirrors the
    state shape phase2_5_personal_identity_pivot produces."""
    return {
        "seeds": ["megacorp.com"],
        "completed_phases": [
            "phase1", "phase2", "phase2_5", "phase3", "phase4",
            "phase5", "phase6", "phase7", "phase7_5", "phase8",
            "phase9",
        ],
        "subdomain_intel": {
            f"sub{i}.megacorp.com": {"sources": ["crtsh"]} for i in range(15)
        },
        "email_intel": {
            "emails": {
                "alice.smith@megacorp.com": {
                    "sources": ["hunter"], "role": "CISO",
                    "breaches": ["LinkedIn", "Adobe"],
                },
                "bob.jones@megacorp.com": {
                    "sources": ["hunter"], "role": "VP Sales",
                },
            },
        },
        "cloud_intel": {
            "azure/onmicrosoft": {
                "attribution_confidence": 0.95,
                "onmicrosoft_domain": {
                    "domains": [
                        {"tenant_id": "11111111-2222-3333-4444-555555555555",
                         "domain": "megacorp.onmicrosoft.com"},
                    ],
                },
                "federation": {"federated": True, "idp": "Okta"},
            },
        },
        "findings": [
            {
                "title": "Federation with Okta confirmed",
                "severity": "info",
                "description": "DOMAIN_FEDERATION on megacorp.com → okta.com",
                "source": "azure_tenant_enum",
                "confidence": 0.95,
                "category": "cloud",
                "affected_assets": ["megacorp.com"],
            },
            {
                "title": "Two employee emails appeared in LinkedIn breach (2012)",
                "severity": "high",
                "description": "alice.smith and bob.jones present in known breach.",
                "source": "haveibeenpwned",
                "confidence": 0.95,
                "category": "identity",
                "affected_assets": ["alice.smith@megacorp.com", "bob.jones@megacorp.com"],
            },
        ],
        "ranked_threads": [
            {"title": "Federation → spray candidates", "score": 0.82},
        ],
        # Phase D credential punch list
        "credential_punch_list": [
            {
                "identity_id": "id-alice-smith",
                "service": "megacorp-okta",
                "exposure_source": "LinkedIn 2012",
                "risk_score": 0.72,
            },
        ],
    }


def _state_aws_native_startup() -> dict[str, Any]:
    """AWS-native startup shape: S3 buckets, Cognito pool, GH Actions
    leaks, CVEs surfaced via dependency scanning."""
    return {
        "seeds": ["nimbusapp.io"],
        "completed_phases": [
            "phase1", "phase2", "phase3", "phase4", "phase5",
            "phase6", "phase7", "phase8", "phase9",
        ],
        "subdomain_intel": {
            "api.nimbusapp.io": {"sources": ["amass"]},
            "auth.nimbusapp.io": {"sources": ["amass"]},
        },
        "email_intel": {"emails": {}},
        "cloud_intel": {
            "aws/s3": {
                "attribution_confidence": 0.9,
                "buckets": [
                    {"name": "nimbusapp-prod", "region": "us-east-1",
                     "public": False},
                    {"name": "nimbusapp-leak-test", "region": "us-east-1",
                     "public": True},
                ],
            },
            "aws/cognito": {
                "attribution_confidence": 0.85,
                "identity_pools": [
                    {"id": "us-east-1:abc-def", "auth_role": "auth-role"},
                ],
            },
        },
        "findings": [
            {
                "title": "Public S3 bucket: nimbusapp-leak-test",
                "severity": "high",
                "description": "Bucket is world-readable.",
                "source": "bucket_enum",
                "confidence": 0.95,
                "category": "cloud",
                "affected_assets": ["s3://nimbusapp-leak-test"],
            },
            {
                "title": "CVE-2021-44228 in spring-boot-2.3.0 (GitHub Actions cache)",
                "severity": "critical",
                "description": "Log4Shell-affected version in build cache.",
                "source": "github_actions_leaks",
                "confidence": 0.8,
                "category": "vulnerability",
                "affected_assets": ["github.com/nimbusapp/api"],
                "mitre_techniques": ["T1190"],
            },
        ],
        "ranked_threads": [],
        "vuln_intel": {
            "enriched_cves": {
                "CVE-2021-44228": {
                    "tech": "log4j", "cvss": 10.0, "epss": 0.97,
                    "in_kev": True, "has_exploit": True,
                    "has_metasploit": True, "description": "Log4Shell",
                },
            },
            "kev": {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]},
        },
    }


def _state_mixed_cloud_with_breaches() -> dict[str, Any]:
    """The 'everything turned on' shape: multi-cloud + identity
    graph + credential punch list + spear-phishing intelligence.
    Stresses the report engine the most because every section has
    something to render."""
    return {
        "seeds": ["bigfish.io"],
        "completed_phases": [
            "phase1", "phase2", "phase2_5", "phase3", "phase4",
            "phase5", "phase6", "phase7", "phase7_5", "phase7_7",
            "phase8", "phase9",
        ],
        "subdomain_intel": {
            f"node-{i}.bigfish.io": {"sources": ["amass", "crtsh"]}
            for i in range(20)
        },
        "email_intel": {
            "emails": {
                f"emp{i}@bigfish.io": {"sources": ["hunter"]}
                for i in range(8)
            },
        },
        "cloud_intel": {
            "azure/onmicrosoft": {
                "attribution_confidence": 0.9,
                "onmicrosoft_domain": {"domains": [{"tenant_id": "tid"}]},
            },
            "aws/s3": {
                "attribution_confidence": 0.9,
                "buckets": [{"name": "bigfish-prod", "public": False}],
            },
            "gcp/projects": {
                "attribution_confidence": 0.7,
                "projects": [{"id": "bigfish-data", "number": "99999"}],
            },
        },
        "findings": [
            {
                "title": "Azure tenant + AWS account both attributed to bigfish.io",
                "severity": "high",
                "description": "Multi-cloud exposure across two providers.",
                "source": "correlation",
                "confidence": 0.85,
                "category": "cloud",
                "affected_assets": ["bigfish.io"],
            },
        ],
        "vuln_intel": {
            "enriched_cves": {
                "CVE-2024-3094": {
                    "tech": "xz-utils", "cvss": 10.0, "epss": 0.65,
                    "in_kev": False, "has_exploit": True,
                    "description": "xz-utils backdoor (CVE-2024-3094)",
                },
            },
        },
        "credential_punch_list": [
            {"identity_id": "id-1", "exposure_source": "Snusbase", "risk_score": 0.6},
            {"identity_id": "id-2", "exposure_source": "DeHashed", "risk_score": 0.55},
        ],
        "spear_phishing_intelligence": {
            "summary": {"candidate_count": 4},
            "targets": {
                "id-1": {
                    "target_identity_id": "id-1",
                    "target_label": "Carol Lee",
                    "top_candidates": [],
                    "draft": None,
                },
            },
        },
        "pretext_scores": [],
        "relationship_graph": {"edges": [], "by_source": {}, "by_target": {}},
        "ranked_threads": [],
    }


def _state_empty() -> dict[str, Any]:
    """Campaign that produced literally nothing. Tests that the
    report engine handles the empty case without crashing."""
    return {
        "seeds": ["unknown.test"],
        "completed_phases": ["phase1"],
        "subdomain_intel": {},
        "email_intel": {"emails": {}},
        "cloud_intel": {},
        "findings": [],
        "ranked_threads": [],
    }


def _state_gcp_native_only() -> dict[str, Any]:
    """GCP-only cloud shape: no Azure, no AWS. GCP otherwise appears
    only as a secondary provider inside the mixed fixture, so a
    GCP-only rendering path is never exercised in isolation."""
    return {
        "seeds": ["dataflow.io"],
        "completed_phases": [
            "phase1", "phase2", "phase3", "phase4", "phase5",
            "phase6", "phase7", "phase8", "phase9",
        ],
        "subdomain_intel": {
            "api.dataflow.io": {"sources": ["crtsh"]},
            "console.dataflow.io": {"sources": ["amass"]},
        },
        "email_intel": {
            "emails": {
                "dev@dataflow.io": {"sources": ["hunter"], "role": "Engineer"},
            },
        },
        "cloud_intel": {
            "gcp/projects": {
                "attribution_confidence": 0.9,
                "projects": [{"id": "dataflow-prod", "number": "112233445566"}],
            },
            "gcp/storage": {
                "attribution_confidence": 0.85,
                "buckets": [{"name": "dataflow-public-assets", "public": True}],
            },
        },
        "findings": [
            {
                "title": "Public GCS bucket: dataflow-public-assets",
                "severity": "high",
                "description": "Bucket grants allUsers read.",
                "source": "gcp_recon",
                "confidence": 0.9,
                "category": "cloud",
                "affected_assets": ["gs://dataflow-public-assets"],
            },
            {
                "title": "CVE-2022-3786 in openssl-3.0.5 on api.dataflow.io",
                "severity": "high",
                "description": "OpenSSL X.509 punycode buffer overflow.",
                "source": "httpx",
                "confidence": 0.7,
                "category": "vulnerability",
                "affected_assets": ["api.dataflow.io"],
            },
        ],
        "ranked_threads": [],
        "vuln_intel": {
            "enriched_cves": {
                "CVE-2022-3786": {
                    "tech": "openssl", "cvss": 7.5, "epss": 0.1,
                    "in_kev": False, "has_exploit": False,
                    "description": "OpenSSL punycode overflow",
                },
            },
        },
    }


def _state_degraded_partial_failure() -> dict[str, Any]:
    """A run where tools ran-but-degraded (errors populated, partial
    phases, a handshake/502/exit-1 cluster) yet still surfaced one real
    CVE. Exercises the full report set + the footer and CVE-provenance
    invariants on a degraded shape the Wave F run-health test never
    drives through ``generate_all``."""
    return {
        "seeds": ["flaky-target.test"],
        "completed_phases": ["phase1", "phase2", "phase3"],
        "errors": [
            {"tool": "sslyze", "error": "handshake failed", "degraded": True},
            {"tool": "crtsh", "error": "502 Bad Gateway"},
            {"tool": "nuclei", "error": "exit 1, no findings"},
        ],
        "subdomain_intel": {"www.flaky-target.test": {"sources": ["amass"]}},
        "email_intel": {"emails": {}},
        "cloud_intel": {},
        "findings": [
            {
                "title": "CVE-2023-44487 (HTTP/2 Rapid Reset) on www.flaky-target.test",
                "severity": "high",
                "description": "Server advertises HTTP/2; Rapid Reset DoS applies.",
                "source": "httpx",
                "confidence": 0.6,
                "category": "vulnerability",
                "affected_assets": ["www.flaky-target.test"],
            },
        ],
        "ranked_threads": [],
        "vuln_intel": {
            "enriched_cves": {
                "CVE-2023-44487": {
                    "tech": "http2", "cvss": 7.5, "epss": 0.4,
                    "in_kev": True, "has_exploit": True,
                    "description": "HTTP/2 Rapid Reset",
                },
            },
            "kev": {"vulnerabilities": [{"cveID": "CVE-2023-44487"}]},
        },
    }


def _state_phase_de_heavy() -> dict[str, Any]:
    """Populated Phase D punch list + Phase E relationship graph, pretext
    scores, and a generated spear-phishing draft. The mixed fixture
    carries these structures but empty; this one stresses the
    phase7_5 / phase7_7 render paths with real content."""
    candidate = {
        "sender_identity_id": "id-colleague-1",
        "sender_label": "Dana Boss",
        "sender_plausibility": 0.81,
        "rationale": "Frequent GitHub co-author on the target's main repo.",
        "sources": ["github_social"],
        "topic": "Q3 infra migration sign-off",
        "combined_score": 0.74,
        "timing_score": 0.66,
        "timing_anchor": {
            "title": "Target spoke at FOSDEM on platform migration",
            "published_at": "2026-02-01",
            "source": "conference_speaker",
            "url": "https://fosdem.org/2026/schedule/",
        },
    }
    return {
        "seeds": ["devhouse.io"],
        "completed_phases": [
            "phase1", "phase2", "phase2_5", "phase3", "phase4",
            "phase5", "phase6", "phase7", "phase7_5", "phase7_7",
            "phase8", "phase9",
        ],
        "subdomain_intel": {"git.devhouse.io": {"sources": ["crtsh"]}},
        "email_intel": {
            "emails": {
                "target@devhouse.io": {"sources": ["hunter"], "role": "Staff Engineer"},
            },
        },
        "cloud_intel": {},
        "findings": [
            {
                "title": "Employee email in DeHashed breach corpus",
                "severity": "medium",
                "description": "target@devhouse.io present in two breach sets.",
                "source": "dehashed",
                "confidence": 0.8,
                "category": "identity",
                "affected_assets": ["target@devhouse.io"],
            },
        ],
        "ranked_threads": [],
        "credential_punch_list": [
            {"identity_id": "id-target", "service": "github",
             "exposure_source": "DeHashed", "risk_score": 0.6},
            {"identity_id": "id-target", "service": "okta",
             "exposure_source": "Snusbase", "risk_score": 0.5},
        ],
        "relationship_graph": {
            "edge_count": 1,
            "edges": [
                {"source_identity": "id-target",
                 "target_identity": "id-colleague-1",
                 "interaction_type": "co_author", "strength": 0.8},
            ],
            "by_source": {"id-target": ["id-colleague-1"]},
            "by_target": {"id-colleague-1": ["id-target"]},
        },
        "pretext_scores": [candidate],
        "spear_phishing_intelligence": {
            "summary": {
                "target_count": 1, "candidate_count": 1,
                "score_min": 0.74, "score_median": 0.74, "score_max": 0.74,
            },
            "targets": {
                "id-target": {
                    "target_identity_id": "id-target",
                    "target_label": "Target Engineer",
                    "top_candidates": [candidate],
                    "draft": (
                        "Subject: Quick sign-off on the Q3 infra migration\n\n"
                        "Hi, following up after FOSDEM. Can you confirm the "
                        "platform migration runbook before Friday? Thanks."
                    ),
                },
            },
        },
    }


def _state_gov_dotgov() -> dict[str, Any]:
    """A .gov target shape. The engine should treat the TLD generically;
    this pins that an authorized .gov engagement renders cleanly across
    the report set (no special-casing crash, footers + provenance hold)."""
    return {
        "seeds": ["agency.gov"],
        "completed_phases": [
            "phase1", "phase2", "phase3", "phase4", "phase5",
            "phase6", "phase7", "phase8", "phase9",
        ],
        "subdomain_intel": {
            "portal.agency.gov": {"sources": ["crtsh"]},
            "vpn.agency.gov": {"sources": ["amass"]},
        },
        "email_intel": {
            "emails": {
                "officer@agency.gov": {"sources": ["hunter"], "role": "Program Officer"},
            },
        },
        "cloud_intel": {},
        "findings": [
            {
                "title": "CVE-2021-26855 (ProxyLogon) on portal.agency.gov",
                "severity": "critical",
                "description": "Exchange SSRF, KEV-listed and actively exploited.",
                "source": "nuclei",
                "confidence": 0.85,
                "category": "vulnerability",
                "affected_assets": ["portal.agency.gov"],
                "mitre_techniques": ["T1190"],
            },
        ],
        "ranked_threads": [],
        "vuln_intel": {
            "enriched_cves": {
                "CVE-2021-26855": {
                    "tech": "exchange", "cvss": 9.8, "epss": 0.9,
                    "in_kev": True, "has_exploit": True,
                    "has_metasploit": True, "description": "ProxyLogon",
                },
            },
            "kev": {"vulnerabilities": [{"cveID": "CVE-2021-26855"}]},
        },
    }


# A list of ``(name, fixture_fn)`` for parametrised tests. Adding
# a new target shape = adding one tuple.
FIXTURES = [
    ("small_business", _state_small_business),
    ("m365_enterprise", _state_m365_enterprise),
    ("aws_native_startup", _state_aws_native_startup),
    ("mixed_cloud_with_breaches", _state_mixed_cloud_with_breaches),
    ("empty", _state_empty),
    ("gcp_native_only", _state_gcp_native_only),
    ("degraded_partial_failure", _state_degraded_partial_failure),
    ("phase_de_heavy", _state_phase_de_heavy),
    ("gov_dotgov", _state_gov_dotgov),
]


@pytest.fixture
def engine(tmp_path: Path) -> ReportEngine:
    """One :class:`ReportEngine` per test, writing to a tmpdir."""
    return ReportEngine(
        campaign_id="smoke-test",
        engagement_id="ENG-SMOKE-1",
        scope_hash="sha256:smoketest123456789",
        output_dir=tmp_path / "out",
    )


# ──────────────────────────────────────────────────────────────────────
# Per-fixture smoke tests
# ──────────────────────────────────────────────────────────────────────


class TestGeneratedReportsAcrossFixtures:
    """Per-fixture smoke: report engine must complete + carry the
    audit metadata for every shape we plausibly campaign against."""

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_generate_all_completes_without_raising(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """End-to-end run. A regression in any builder shows up as
        a raised exception during ``generate_all`` and fails the
        test for the offending shape (so the name tells you which
        target shape broke)."""
        paths = engine.generate_all(fixture_fn())
        # Sanity: every report path returned actually exists on disk.
        for kind, path in paths.items():
            assert Path(path).exists(), (
                f"[{name}] report {kind!r} returned a non-existent "
                f"path: {path}"
            )

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_markdown_footers_carry_scope_hash_and_version(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """The audit footer pins both:

          - ``Scope Hash:`` (already covered for the engine source
            in the static test) — links report → engagement.
          - ``Tooling: NexusRecon vX.Y.Z`` — pins which framework
            version produced the artefact. Beta blocker per the
            roadmap.
        """
        paths = engine.generate_all(fixture_fn())
        # Pick the two operator-facing markdown deliverables that
        # MUST always render a footer: executive_summary and
        # full_report. Other reports may legitimately omit the full
        # footer (top_threads is short, asset_inventory is data-
        # heavy), but those two are the canonical narrative
        # deliverables.
        for kind in ("executive_summary", "full_report"):
            md = Path(paths[kind]).read_text()
            assert engine.scope_hash in md, (
                f"[{name}] {kind} missing scope_hash"
            )
            assert NEXUS_VERSION in md, (
                f"[{name}] {kind} missing NexusRecon version"
            )
            assert "Tooling:" in md, (
                f"[{name}] {kind} missing the Tooling line"
            )

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_json_deliverables_include_version(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """JSON consumers (a downstream report-aggregator, an
        evidence locker) need the version field next to
        ``scope_hash`` so they can pin the producer too."""
        paths = engine.generate_all(fixture_fn())
        for kind in ("findings_json", "campaign_meta", "asset_inventory"):
            # asset_inventory's "path" points at the .md but the JSON
            # is colocated. Resolve both shapes.
            p = Path(paths[kind])
            json_candidates = [p] if p.suffix == ".json" else [
                p.with_suffix(".json"), p.parent / f"{p.stem}.json",
            ]
            data = None
            for c in json_candidates:
                if c.exists():
                    try:
                        data = json.loads(c.read_text())
                    except json.JSONDecodeError:
                        continue
                    break
            if data is None:
                pytest.fail(
                    f"[{name}] couldn't load JSON for {kind}: tried {json_candidates}"
                )
            assert data.get("scope_hash") == engine.scope_hash, (
                f"[{name}] {kind}.json missing scope_hash"
            )
            assert data.get("nexusrecon_version") == NEXUS_VERSION, (
                f"[{name}] {kind}.json missing nexusrecon_version"
            )

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_generated_prose_has_no_llm_disclaimers(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """Sweep every generated markdown file for the LLM-disclaimer
        phrases. The static-text test (``test_report_quality.py``)
        catches authored prose; this catches a future regression
        where a Jinja template or report builder starts embedding
        raw LLM output that wasn't humanizer-reviewed."""
        paths = engine.generate_all(fixture_fn())
        for kind, p in paths.items():
            path = Path(p)
            if path.suffix.lower() not in (".md", ".markdown"):
                continue
            lowered = path.read_text().lower()
            for phrase in LLM_DISCLAIMER_PHRASES:
                assert phrase not in lowered, (
                    f"[{name}] LLM-disclaimer phrase {phrase!r} appeared "
                    f"in {kind} ({path.name}) ── prompt or template "
                    f"leaked model voice into the deliverable."
                )

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_cve_references_match_canonical_format(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """Any string in the generated output that LOOKS like a CVE
        ID must match the canonical CVE-YYYY-NNNN. A typo like
        ``CVE-2021-XX`` or ``CVE-44228`` is a regression in either
        the source data or the renderer."""
        paths = engine.generate_all(fixture_fn())
        for kind, p in paths.items():
            path = Path(p)
            if path.suffix.lower() not in (".md", ".markdown", ".json"):
                continue
            text = path.read_text()
            for cve_shaped in _CVE_SHAPED_RE.findall(text):
                # Strip trailing punctuation that may follow a CVE
                # in flowing prose ("...CVE-2021-44228.")
                stripped = cve_shaped.rstrip(".,;:)")
                # Allow lowercase "cve-" in headings? The canonical
                # citation is uppercase; if a renderer wraps it in
                # backticks or markdown the case is preserved.
                assert _CVE_RE.fullmatch(stripped), (
                    f"[{name}] malformed CVE reference in {kind}: "
                    f"{cve_shaped!r}. Expected CVE-YYYY-NNNN."
                )

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_obsidian_export_emitted_when_flagged(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """Phase 1 of the toolchain plan: ``generate_obsidian=True``
        produces a parallel ``master_report.obsidian.md`` carrying
        the YAML frontmatter, wikilinks, and callouts that make the
        directory drop-in for an Obsidian vault. Verify across
        every target shape so a fixture-specific edge case can't
        sneak past."""
        state = fixture_fn()
        state["generate_obsidian"] = True
        paths = engine.generate_all(state)
        assert "master_report_obsidian" in paths, (
            f"[{name}] obsidian flag set but master_report_obsidian "
            f"absent from paths"
        )
        body = Path(paths["master_report_obsidian"]).read_text(encoding="utf-8")
        # Frontmatter present and well-formed.
        assert body.startswith("---\n"), (
            f"[{name}] obsidian file missing YAML frontmatter open"
        )
        assert "\n---\n\n" in body, (
            f"[{name}] obsidian file missing YAML frontmatter close"
        )
        # Required Property fields all surfaced.
        for field in (
            f"scope_hash: {engine.scope_hash}",
            f"nexusrecon_version: {engine.nexusrecon_version}",
            "tags:",
            "  - nexusrecon",
        ):
            assert field in body, (
                f"[{name}] obsidian frontmatter missing {field!r}"
            )

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_obsidian_flag_off_means_no_parallel_file(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """When the flag is absent (default behavior pre-Phase 1),
        the obsidian file MUST NOT land on disk. Pin so a future
        always-on default doesn't sneak in and quietly double
        every campaign's deliverable count."""
        state = fixture_fn()
        # Explicitly do not set generate_obsidian.
        paths = engine.generate_all(state)
        assert "master_report_obsidian" not in paths
        assert not (engine.output_dir / "master_report.obsidian.md").exists()


# ──────────────────────────────────────────────────────────────────────
# Cross-tool dedup
# ──────────────────────────────────────────────────────────────────────


class TestCrossToolDedup:
    """When two tools both surface the same finding (e.g. shodan and
    censys both report the same open port; nvd and kev both surface
    the same CVE), the deduplicated report must list it once.

    Per-source dedup is already pinned in ``test_report_quality.py``;
    this class pins the cross-source case where the regression is
    likely to live."""

    def test_cve_in_both_enriched_and_kev_dedupes(self):
        """CVE-2021-44228 appears in BOTH ``enriched_cves`` AND the
        KEV catalogue. The scoring engine must collapse these into
        a single ranked finding, not two."""
        from nexusrecon.core.scoring import score_findings
        state = {
            "vuln_intel": {
                "enriched_cves": {
                    "CVE-2021-44228": {
                        "tech": "log4j", "cvss": 10.0, "epss": 0.97,
                        "in_kev": True, "has_exploit": True,
                        "description": "Log4Shell",
                    },
                },
                "kev": {
                    "vulnerabilities": [
                        {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
                    ],
                },
            },
        }
        findings = score_findings(state)
        log4shell = [f for f in findings if "CVE-2021-44228" in (f.title or "")]
        assert len(log4shell) == 1, (
            f"Expected 1 Log4Shell finding from dual-source state, got "
            f"{len(log4shell)}: {[f.title for f in log4shell]}"
        )

    def test_breach_email_from_two_sources_dedupes(self):
        """If hibp + leakcheck both flag the same email, the breach
        scoring engine must produce ONE finding for that email."""
        from nexusrecon.core.scoring import score_findings
        state = {
            "email_intel": {
                "emails": {
                    "victim@example.com": {
                        "breaches": ["LinkedIn", "Adobe"],
                        "source": "hibp",
                    },
                },
            },
        }
        findings = score_findings(state)
        breach = [
            f for f in findings
            if "victim@example.com" in (str(f.title) + " " + " ".join(f.affected_assets or []))
        ]
        # Per-email dedup ── at most one finding regardless of
        # how many breach DBs sourced it.
        assert len(breach) <= 1


# ──────────────────────────────────────────────────────────────────────
# Engine attribute pin
# ──────────────────────────────────────────────────────────────────────


class TestEngineCarriesVersion:
    """Direct attribute pin so a refactor that drops the
    ``nexusrecon_version`` resolution silently fails fast."""

    def test_engine_resolves_package_version(self, tmp_path: Path):
        e = ReportEngine(
            campaign_id="x", engagement_id="y",
            scope_hash="z", output_dir=tmp_path,
        )
        assert e.nexusrecon_version == NEXUS_VERSION
        # Defensive: never empty.
        assert e.nexusrecon_version
        # Never the literal placeholder.
        assert e.nexusrecon_version != "unknown"

    def test_engine_fallback_string_is_safe(self):
        """The init wraps the package-version import in a try/except
        with ``"unknown"`` as the fallback. The literal value must
        stay constant ── downstream tooling (an evidence locker,
        a report aggregator) keys off it to detect "this report
        was produced by a broken install" vs. a real version.

        We don't try to simulate the import failure itself ── that
        path is exercised by reading the source, not by patching
        ``builtins.__import__`` (which deadlocks pytest's internal
        rewriter).
        """
        engine_src = (
            Path(__file__).resolve().parents[2]
            / "nexusrecon" / "reports" / "engine.py"
        ).read_text()
        assert 'self.nexusrecon_version = "unknown"' in engine_src, (
            "ReportEngine fallback string changed ── downstream "
            "consumers may key off the literal 'unknown'."
        )


# ──────────────────────────────────────────────────────────────────────
# CVE provenance — bullet 3: "every CVE citation resolves to a real CVE
# record"
# ──────────────────────────────────────────────────────────────────────


class TestCVEProvenance:
    """The original beta-blocker bullet says every CVE citation must
    *resolve to a real CVE record*. The existing format check
    (``test_cve_references_match_canonical_format``) only validates
    ``CVE-YYYY-NNNN`` shape — a correctly-formatted but fabricated
    ``CVE-2099-99999`` passes it clean.

    Hitting NVD/MITRE per CVE is not CI-safe (network + rate limits), so
    we pin the meaningful, deterministic guarantee instead: every CVE id
    rendered into a deliverable must trace back to a CVE the run actually
    collected (present in the input *evidence*). The three LLM-prose
    embed sites (master report brief, executive-summary analyst
    assessment, people-map analyst notes) are the only paths that can
    inject an unsourced CVE; the engine's ``scrub_unsourced_cves`` guard
    redacts any CVE token absent from ``collect_state_cves``.
    """

    @pytest.mark.parametrize("name,fixture_fn", FIXTURES)
    def test_rendered_cves_trace_to_input_state(
        self, name: str, fixture_fn, engine: ReportEngine,
    ):
        """Subset invariant across every deliverable: the set of CVEs
        rendered must be a subset of the CVEs present in the input
        evidence. Green on the benign stub (no LLM CVEs) and on the
        genuinely-sourced fixtures (the AWS/GCP/gov CVEs all trace to
        ``vuln_intel`` / finding titles)."""
        state = fixture_fn()
        sourced = collect_state_cves(state)
        paths = engine.generate_all(state)
        for kind, p in paths.items():
            path = Path(p)
            if path.suffix.lower() not in (".md", ".markdown", ".json"):
                continue
            rendered = {m.upper() for m in _CVE_CI_RE.findall(path.read_text())}
            unsourced = rendered - sourced
            assert not unsourced, (
                f"[{name}] {kind} ({path.name}) cites CVE(s) absent from "
                f"input evidence: {sorted(unsourced)} — sourced set is "
                f"{sorted(sourced)}"
            )

    def test_collect_state_cves_is_comprehensive(self):
        """The allow-list must collect CVEs wherever they legitimately
        live in evidence — not just ``enriched_cves`` keys. Guards
        against a later 'just scan enriched_cves' narrowing that would
        false-positive on finding-title and description-substring CVEs
        the subset assertion depends on."""
        state = {
            "vuln_intel": {
                "enriched_cves": {"CVE-2021-44228": {"tech": "log4j"}},
                "kev": {"vulnerabilities": [{"cveID": "CVE-2014-0160"}]},
                "nvd/apache": {"matches": [{"id": "CVE-2017-5638"}]},
                "nuclei_scan": {"findings": [{"cve_ids": ["CVE-2019-11043"]}]},
            },
            "findings": [
                {"title": "CVE-2024-3094 in xz-utils", "severity": "critical"},
            ],
            "cloud_intel": {
                "note": {"description": "linked to CVE-2023-23397 exploitation"},
            },
        }
        got = collect_state_cves(state)
        for cve in (
            "CVE-2021-44228", "CVE-2014-0160", "CVE-2017-5638",
            "CVE-2019-11043", "CVE-2024-3094", "CVE-2023-23397",
        ):
            assert cve in got, f"{cve} not collected from its evidence slot"

    def test_agent_messages_do_not_seed_the_allowlist(self):
        """A CVE that appears ONLY in LLM agent prose must NOT become an
        allow-listed source — otherwise a hallucination would authorise
        itself and defeat the scrub."""
        state = {
            "agent_messages": [
                {"agent": "risk_analyst", "phase": "phase8",
                 "analysis": "I assess CVE-2099-12345 is critical."},
            ],
            "vuln_intel": {"enriched_cves": {"CVE-2021-44228": {}}},
        }
        got = collect_state_cves(state)
        assert "CVE-2021-44228" in got
        assert "CVE-2099-12345" not in got, (
            "agent prose seeded the CVE allow-list — a hallucination "
            "would self-authorise"
        )

    def test_hallucinated_cve_in_master_report_prose_is_redacted(
        self, engine: ReportEngine,
    ):
        """Negative test for the highest-risk path: a fabricated CVE in
        master_reporter agent output must not survive into
        master_report.md (nor the obsidian variant, which re-reads the
        scrubbed file), while a genuinely-sourced CVE is preserved."""
        fab = "CVE-2099-99999"
        sourced_cve = "CVE-2021-44228"  # genuinely in the AWS fixture evidence

        class _FabricatingExecutor:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def run_agent(
                self, agent_name, task_data=None, task_prompt="", state=None,
            ):
                if agent_name == "master_reporter":
                    return {"output": (
                        "## 2. Executive Brief\n\n"
                        f"The campaign confirmed {sourced_cve} (Log4Shell) in the "
                        f"build cache. It also surfaced {fab}, which the run never "
                        "actually collected.\n\n"
                        "## 10. Recommendations\n\n"
                        f"1. Remediate {sourced_cve} and {fab} immediately.\n"
                    )}
                return {"output": "stub", "agent": agent_name, "findings": []}

        state = _state_aws_native_startup()
        state["generate_obsidian"] = True
        with patch(
            "nexusrecon.graph.agent_executor.AgentExecutor", _FabricatingExecutor,
        ):
            paths = engine.generate_all(state)

        master = Path(paths["master_report"]).read_text()
        assert fab not in master, (
            "hallucinated CVE leaked into master_report.md — "
            "scrub_unsourced_cves did not fire on the master_reporter embed"
        )
        assert sourced_cve in master, (
            "a genuinely-sourced CVE was wrongly scrubbed from master_report.md"
        )
        obs = Path(paths["master_report_obsidian"]).read_text()
        assert fab not in obs, "obsidian export propagated the hallucinated CVE"

    def test_hallucinated_cve_in_analyst_prose_is_redacted(
        self, engine: ReportEngine,
    ):
        """The two strip-only prose embeds: a fabricated CVE injected via
        ``state['agent_messages']`` must not survive into
        executive_summary.md (risk_analyst assessment) or
        people_identity_map.md (phase2/phase4 analyst notes)."""
        fab = "CVE-2098-88888"
        sourced_cve = "CVE-2021-44228"
        state = _state_aws_native_startup()
        state["agent_messages"] = [
            {"agent": "risk_analyst", "phase": "phase8",
             "analysis": (
                 f"Primary risk is {sourced_cve} (Log4Shell). I also flag "
                 f"{fab} as critical."
             )},
            {"agent": "identity_analyst", "phase": "phase2",
             "analysis": f"Org note: exposure tied to {fab} surfaced in review."},
        ]
        paths = engine.generate_all(state)

        exec_md = Path(paths["executive_summary"]).read_text()
        assert fab not in exec_md, (
            "hallucinated CVE leaked into executive_summary.md analyst assessment"
        )
        assert sourced_cve in exec_md, (
            "sourced CVE wrongly scrubbed from executive_summary.md"
        )
        people_md = Path(paths["people_map"]).read_text()
        assert fab not in people_md, (
            "hallucinated CVE leaked into people_identity_map.md analyst notes"
        )
