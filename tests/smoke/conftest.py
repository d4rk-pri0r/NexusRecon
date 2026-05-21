"""Shared fixtures for the NexusRecon smoke test suite."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

# ── Minimal state skeleton ────────────────────────────────────────────────────

def _base_state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "campaign_id": "smoke-test",
        "engagement_id": "SMOKE-001",
        "scope_hash": "sha256:smoketest",
        "seeds": ["example.com"],
        "current_phase": "init",
        "completed_phases": [],
        "phase_results": {},
        "findings": [],
        "domain_intel": {},
        "subdomain_intel": {},
        "email_intel": {"emails": {}},
        "identity_intel": {},
        "cloud_intel": {},
        "code_intel": {},
        "infra_intel": {},
        "vuln_intel": {},
        "pretext_intel": {},
        "dark_intel": {},
        "breach_intel": {},
        "mobile_intel": {},
        "social_intel": {},
        "entity_graph": {},
        "hypotheses": [],
        "confirmed_leads": [],
        "open_questions": [],
        "harvested_credentials": [],
        "dynamic_dispatch_log": [],
        "ranked_threads": [],
        "llm_cost_usd": 0.0,
        "tool_cost_usd": 0.0,
        "step_count": 0,
        "errors": [],
        "agent_messages": [],
        "report_paths": {},
        "validate_credentials": False,
        "generate_phishing_drafts": False,
        "dispatch_mode": "off",
    }
    state.update(overrides)
    return state


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Temporary directory for report output."""
    out = tmp_path / "reports"
    out.mkdir()
    return out


@pytest.fixture
def mock_state_minimal() -> dict[str, Any]:
    """Bare-minimum CampaignGraphState useful for phase function calls."""
    return _base_state()


@pytest.fixture
def mock_state_rich() -> dict[str, Any]:
    """State pre-loaded with synthetic intel in every slot."""
    return _base_state(
        subdomain_intel={
            "mail.example.com": {"sources": ["crtsh"]},
            "vpn.example.com": {"sources": ["subfinder"]},
        },
        email_intel={
            "emails": {
                "admin@example.com": {"source": "theharvester", "position": "IT Admin"},
                "ceo@example.com": {"source": "hunter", "position": "CEO"},
            },
            "format": "first.last@example.com",
        },
        domain_intel={
            "dns": {"a": ["93.184.216.34"], "mx": ["mail.example.com"]},
            "whois": {"registrar": "Example Registrar", "org": "Example LLC"},
        },
        cloud_intel={
            "aws/example.com": {"public_buckets": [], "exposed_services": []},
        },
        vuln_intel={
            "enriched_cves": {
                "CVE-2021-44228": {
                    "cvss": 10.0,
                    "epss": 0.97,
                    "in_kev": True,
                    "has_metasploit": True,
                    "has_exploit": True,
                    "has_nuclei_template": True,
                    "tech": "Apache Log4j",
                    "description": "Remote code execution via JNDI injection.",
                    "affected_assets": ["vpn.example.com"],
                    "sources": ["nvd", "kev"],
                },
            },
        },
        infra_intel={
            "example.com": {
                "discovered_paths": [
                    {
                        "path": "/.env",
                        "status": 200,
                        "body": (
                            "AWS_ACCESS_KEY_ID=AKIATESTFAKEFAKEFAKE\n"
                            "AWS_SECRET_ACCESS_KEY=fakefakefakefakefakefakefakefake1234\n"
                            "DATABASE_URL=postgres://admin:password123@db.example.com/prod\n"
                        ),
                    },
                ],
            },
        },
        pretext_intel={
            "jobs": [{"title": "Senior DevOps Engineer", "team": "Infrastructure"}],
        },
    )
