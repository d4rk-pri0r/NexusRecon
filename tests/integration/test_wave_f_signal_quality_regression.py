"""F-C1: signal-quality regression fixture.

Locks in the combined Wave F-A + F-B behaviour against the failure modes of
the 2026-05-27 ginandjuice.shop run, so the report can never silently
regress to "36 findings, mostly noise, $0.00, looks complete".

The campaign output directory is gitignored, so this encodes the run's
shape as a fixed in-test fixture (noisy findings + a representative audit
log) rather than depending on a live re-scan. Each assertion maps to a
specific Wave F item.
"""
from __future__ import annotations

from pathlib import Path

from nexusrecon.core.run_health import summarize_run_health
from nexusrecon.core.scoring import score_findings_with_coverage
from nexusrecon.reports.engine import ReportEngine


def _noisy_findings():
    """The ginandjuice finding set: triple-counted facts, [POSSIBLE]
    speculation, absence-of-evidence notes, and one real weakness."""
    return [
        # Same SPF/DMARC fact, three phases, one reworded -> must dedup to 1.
        {"title": "Missing Email Security Controls (SPF/DMARC/DKIM)", "severity": "medium",
         "confidence": 0.95, "category": "email_security", "affected_assets": ["ginandjuice.shop"], "source": "dns"},
        {"title": "Missing Email Security Controls (SPF/DMARC/DKIM)", "severity": "medium",
         "confidence": 0.9, "category": "email security", "affected_assets": ["ginandjuice.shop"], "source": "dns2"},
        {"title": "Missing Email Security Controls (SPF/DMARC/DKIM) - Domain Spoofing Enabled",
         "severity": "medium", "confidence": 0.95, "category": "email_security",
         "affected_assets": ["ginandjuice.shop"], "source": "dns3"},
        # test subdomain x2 -> dedup to 1.
        {"title": "Subdomain Discovered - test.ginandjuice.shop", "severity": "low", "confidence": 0.85,
         "category": "subdomain", "affected_assets": ["test.ginandjuice.shop"], "source": "vt"},
        {"title": "Subdomain Discovered - test.ginandjuice.shop", "severity": "low", "confidence": 0.75,
         "category": "subdomain", "affected_assets": ["test.ginandjuice.shop"], "source": "subfinder"},
        # absence-of-evidence -> coverage, not ranked.
        {"title": "No MX Records - Email Handling Unknown", "severity": "info", "confidence": 0.85, "category": "email"},
        {"title": "No Code or Secret Leakage Detected", "severity": "info", "confidence": 0.85, "category": "code"},
        {"title": "Clean Reputation - No Malicious Indicators", "severity": "info", "confidence": 0.95, "category": "reputation"},
        # conf-0.2 [POSSIBLE] speculation -> coverage.
        {"title": "[POSSIBLE] AWS Infrastructure - No Public Assets Discovered", "severity": "info",
         "confidence": 0.2, "category": "cloud_infrastructure"},
        {"title": "[POSSIBLE] GCP Infrastructure - No Public Assets Discovered", "severity": "info",
         "confidence": 0.2, "category": "cloud_infrastructure"},
    ]


def _audit_entries():
    """A representative slice of the run's audit log."""
    return [
        {"event_type": "tool_result", "tool_name": "dns", "success": True, "result_count": 7, "degraded": False},
        # sslyze ran, returned no TLS data -> degraded (silent failure), NOT a clean negative.
        {"event_type": "tool_result", "tool_name": "sslyze", "success": True, "result_count": 0,
         "degraded": True, "degraded_reason": "TLS scan returned no protocols and no certificate"},
        {"event_type": "tool_error", "tool_name": "crtsh", "error": "crt.sh returned 502"},
        {"event_type": "policy_skipped", "tool_name": "dehashed", "reason": "breach-DB lookups disabled"},
        {"event_type": "simulation", "expected_new_nodes": 48},
        {"event_type": "simulation", "expected_new_nodes": 50},
        {"event_type": "phase_end", "phase_name": "phase1", "entities_count": 0},
    ]


def _state():
    return {
        "findings": _noisy_findings(),
        "preflight": {"buckets": {
            "missing_binary": {"theharvester": "binary not on PATH"},
            "missing_key": {}, "policy": {"dehashed": "breach disabled", "shodan": "paid disabled"},
            "over_tier": {}, "active": {}, "stubbed": {},
        }},
        # cloud probes ran but found nothing -> must NOT be claimed as detected.
        "cloud_intel": {"aws/ginandjuice.shop": {}, "gcp/ginandjuice.shop": {}},
        "code_intel": {"github_recon/x": {"leaks": []}, "gitleaks/x": {}},
        "email_intel": {"emails": {
            "carlos@ginandjuice.shop": {"position": "Employee"},
            "abcfoo@ginandjuice.shop": {"position": "Unknown"},  # junk probe identity
        }},
        "harvested_credentials": [],
        # An agent assessment that leaked the machine protocol marker.
        "agent_messages": [{
            "agent": "risk_analyst", "phase": "phase8",
            "analysis": 'The surface is moderate.\n\nFINDINGS_JSON:[{"title":"x","severity":"low"}]\n\nStart with email.',
        }],
        "subdomain_intel": {}, "infra_intel": {}, "domain_intel": {},
    }


def _engine(tmp_path):
    return ReportEngine("nr-regression", "none", "sha256:0", tmp_path)


class TestSignalQualityRegression:
    def test_findings_deduped_and_partitioned(self):
        """F-B1/B2/B3: 10 noisy items -> a handful of real findings + coverage,
        with no duplicate fact in the ranked list."""
        kept, coverage = score_findings_with_coverage(_state())
        titles = [k.title.lower() for k in kept]
        # SPF/DMARC appears once, not three times.
        assert sum("email security controls" in t for t in titles) == 1
        # test subdomain appears once.
        assert sum("subdomain discovered" in t for t in titles) == 1
        # absence + speculation are quarantined in coverage.
        assert any("clean reputation" in c.title.lower() for c in coverage)
        assert any(c.title.lower().startswith("[possible]") for c in coverage)
        assert all(not k.title.lower().startswith("[possible]") for k in kept)

    def test_no_findings_json_in_any_report(self, tmp_path):
        """F-B6: the FINDINGS_JSON protocol marker never reaches a deliverable."""
        eng = _engine(tmp_path)
        state = _state()
        state["ranked_threads"] = [k.to_dict() for k in score_findings_with_coverage(state)[0][:10]]
        state["coverage_items"] = [c.to_dict() for c in score_findings_with_coverage(state)[1]]
        produced = [
            eng._top_threads_to_pull(state),
            eng._executive_summary(state),
            eng._full_report(state),
        ]
        for p in produced:
            assert "FINDINGS_JSON" not in Path(p).read_text()

    def test_coverage_appendix_present_in_top_threads(self, tmp_path):
        """F-B1: the 'what we checked' appendix exists so dead ends don't pad
        the ranked list."""
        eng = _engine(tmp_path)
        state = _state()
        kept, coverage = score_findings_with_coverage(state)
        state["ranked_threads"] = [k.to_dict() for k in kept[:10]]
        state["coverage_items"] = [c.to_dict() for c in coverage]
        body = Path(eng._top_threads_to_pull(state)).read_text()
        assert "Coverage / What We Checked" in body

    def test_no_presence_claim_from_zero_result_tools(self, tmp_path):
        """F-B4: AWS/GCP probes returned nothing, so the vendor report must
        not list them as detected; empty code sources omitted."""
        eng = _engine(tmp_path)
        body = Path(eng._vendor_supply_chain(_state())).read_text()
        assert "AWS" not in body
        assert "Google Cloud" not in body
        assert "Code & Package Sources" not in body

    def test_empty_credentials_no_false_alarm(self, tmp_path):
        """F-B8."""
        eng = _engine(tmp_path)
        body = Path(eng._harvested_credentials(_state())).read_text()
        assert "contains real credentials" not in body

    def test_junk_identity_excluded_from_phishing(self, tmp_path):
        """F-B5: the junk probe address never gets a pretext bundle."""
        eng = _engine(tmp_path)
        body = Path(eng._phishing_package(_state())).read_text()
        assert "carlos@ginandjuice.shop" in body
        assert "abcfoo@ginandjuice.shop" not in body

    def test_run_health_tells_the_truth(self):
        """F-A5/A7: degraded tool is not counted as a clean negative; the
        failed capability is named; the node forecast vs 0 is flagged."""
        h = summarize_run_health(
            _audit_entries(),
            {"dns": "dns", "sslyze": "web", "crtsh": "certificate"},
        )
        # sslyze degraded -> in degraded, not productive/empty_ok.
        assert any(d["tool"] == "sslyze" for d in h.degraded)
        assert h.productive == 1  # only dns produced data
        # web + certificate attempted, no usable data -> degraded capabilities.
        caps = {c["capability"] for c in h.degraded_capabilities}
        assert "web" in caps and "certificate" in caps
        # simulator forecast 98 nodes, run produced 0 -> flagged.
        assert h.predicted_new_nodes == 98
        assert h.node_estimate_note is not None
        # zero entities despite a productive tool.
        assert h.zero_entities is True
