"""Wave F-B tests: reporting value and noise reduction.

Built from the 2026-05-27 ginandjuice.shop run, where 36 "findings" were
mostly the same few facts counted 2-3x, absence-of-evidence notes, and
conf-0.2 speculation. These tests pin the dedup (F-B2), the findings-vs-
coverage split (F-B1), and the confidence floor (F-B3).
"""
from __future__ import annotations

from nexusrecon.core.scoring import score_findings, score_findings_with_coverage


def _f(title, *, severity="medium", confidence=0.8, category="general", assets=None, source="agent"):
    return {
        "title": title, "severity": severity, "confidence": confidence,
        "category": category, "affected_assets": assets or [], "source": source,
    }


# ── F-B2: dedup ──────────────────────────────────────────────────────────────


class TestDedup:
    def test_reworded_same_fact_merges(self):
        # Three SPF/DMARC findings, one with a trailing qualifier, same asset.
        state = {"findings": [
            _f("Missing Email Security Controls (SPF/DMARC/DKIM)", confidence=0.95,
               category="email_security", assets=["acme.com"], source="dns"),
            _f("Missing Email Security Controls (SPF/DMARC/DKIM)", confidence=0.9,
               category="email security", assets=["acme.com"], source="dns2"),
            _f("Missing Email Security Controls (SPF/DMARC/DKIM) - Domain Spoofing Enabled",
               confidence=0.95, category="email_security", assets=["acme.com"], source="dns3"),
        ]}
        kept, _ = score_findings_with_coverage(state)
        spf = [k for k in kept if "email security controls" in k.title.lower()]
        assert len(spf) == 1
        # sources unioned across the merged group
        assert set(spf[0].sources) >= {"dns", "dns2", "dns3"}
        assert spf[0].confidence == 0.95  # highest retained

    def test_distinct_subdomains_not_merged(self):
        # Same title stem, DIFFERENT primary asset -> must stay separate.
        state = {"findings": [
            _f("Subdomain Discovered - test.acme.com", severity="low",
               category="subdomain", assets=["test.acme.com"]),
            _f("Subdomain Discovered - admin.acme.com", severity="low",
               category="subdomain", assets=["admin.acme.com"]),
        ]}
        kept, _ = score_findings_with_coverage(state)
        subs = [k for k in kept if "subdomain discovered" in k.title.lower()]
        assert len(subs) == 2

    def test_same_subdomain_dupes_merge(self):
        state = {"findings": [
            _f("Subdomain Discovered - test.acme.com", severity="low", confidence=0.85,
               category="subdomain", assets=["test.acme.com"], source="vt"),
            _f("Subdomain Discovered - test.acme.com", severity="low", confidence=0.75,
               category="subdomain", assets=["test.acme.com"], source="subfinder"),
        ]}
        kept, _ = score_findings_with_coverage(state)
        subs = [k for k in kept if "subdomain discovered" in k.title.lower()]
        assert len(subs) == 1
        assert set(subs[0].sources) >= {"vt", "subfinder"}


# ── F-B1: findings vs. non-findings ──────────────────────────────────────────


class TestNonFindingSplit:
    def test_absence_notes_routed_to_coverage(self):
        state = {"findings": [
            _f("No MX Records - Email Handling Unknown", severity="info", confidence=0.85, category="email"),
            _f("No Code or Secret Leakage Detected", severity="info", confidence=0.85, category="code"),
            _f("Clean Reputation - No Malicious Indicators", severity="info", confidence=0.95, category="reputation"),
            _f("Limited Email Intelligence - Small Sample Size", severity="info", confidence=0.8,
               category="reconnaissance_gap"),
        ]}
        kept, coverage = score_findings_with_coverage(state)
        assert kept == []
        assert len(coverage) == 4

    def test_real_info_weakness_stays_a_finding(self):
        # An informational weakness is not an absence note; it stays ranked.
        state = {"findings": [
            _f("DNSSEC Not Configured - DNS Spoofing Risk", severity="info", confidence=0.85, category="dns"),
        ]}
        kept, coverage = score_findings_with_coverage(state)
        assert len(kept) == 1
        assert coverage == []


# ── F-B3: confidence floor / speculation ─────────────────────────────────────


class TestConfidenceFloor:
    def test_possible_prefix_routed_to_coverage(self):
        state = {"findings": [
            _f("[POSSIBLE] AWS Infrastructure - No Public Assets Discovered",
               severity="info", confidence=0.4, category="cloud_infrastructure"),
        ]}
        kept, coverage = score_findings_with_coverage(state)
        assert kept == []
        assert len(coverage) == 1

    def test_below_floor_confidence_routed_to_coverage(self):
        state = {"findings": [
            _f("Multi-Cloud Presence Indicators", severity="info", confidence=0.2, category="cloud"),
        ]}
        kept, coverage = score_findings_with_coverage(state)
        assert kept == []
        assert len(coverage) == 1

    def test_high_confidence_finding_kept(self):
        state = {"findings": [
            _f("Public S3 bucket exposed", severity="high", confidence=0.9, category="cloud", assets=["s3://x"]),
        ]}
        kept, coverage = score_findings_with_coverage(state)
        assert len(kept) == 1
        assert coverage == []


# ── back-compat ──────────────────────────────────────────────────────────────


class TestBackCompat:
    def test_empty_state(self):
        assert score_findings({}) == []
        assert score_findings_with_coverage({}) == ([], [])

    def test_score_findings_returns_only_kept(self):
        state = {"findings": [
            _f("Real finding", severity="high", confidence=0.9, assets=["acme.com"]),
            _f("Clean Reputation - No Malicious Indicators", severity="info", confidence=0.95, category="reputation"),
        ]}
        ranked = score_findings(state)
        titles = [r.title for r in ranked]
        assert "Real finding" in titles
        assert "Clean Reputation - No Malicious Indicators" not in titles


# ── F-B6: strip machine scaffolding from human reports ───────────────────────


class TestStripScaffolding:
    def test_removes_findings_json_block(self):
        from nexusrecon.reports.engine import strip_agent_scaffolding
        text = 'Intro prose.\n\nFINDINGS_JSON:[{"severity":"low","title":"x"}]\n\nClosing prose.'
        out = strip_agent_scaffolding(text)
        assert "FINDINGS_JSON" not in out
        assert "[" not in out  # the JSON array is gone
        assert "Intro prose." in out
        assert "Closing prose." in out

    def test_plain_prose_untouched(self):
        from nexusrecon.reports.engine import strip_agent_scaffolding
        text = "Just an assessment with no machine markers."
        assert strip_agent_scaffolding(text) == text

    def test_empty(self):
        from nexusrecon.reports.engine import strip_agent_scaffolding
        assert strip_agent_scaffolding("") == ""


# ── F-B4: presence from results, not from the fact a tool ran ────────────────


class TestPresenceFromResults:
    def test_provider_evidence_helper(self):
        from nexusrecon.reports.engine import _provider_has_evidence
        assert _provider_has_evidence({}) is False
        assert _provider_has_evidence({"s3_buckets": []}) is False
        assert _provider_has_evidence({"tenant_id": "unknown"}) is False
        assert _provider_has_evidence({"user_realm": {"is_federated": False}}) is True
        assert _provider_has_evidence({"s3_buckets": [{"name": "b"}]}) is True

    def test_code_source_evidence_helper(self):
        from nexusrecon.reports.engine import _code_source_has_evidence
        assert _code_source_has_evidence({"leaks": []}) is False
        assert _code_source_has_evidence({}) is False
        assert _code_source_has_evidence({"leaks": [{"rule": "aws"}]}) is True

    def _engine(self, tmp_path):
        from nexusrecon.reports.engine import ReportEngine
        return ReportEngine("nr-test", "eng", "sha256:0", tmp_path)

    def test_vendor_report_omits_empty_providers_and_code(self, tmp_path):
        eng = self._engine(tmp_path)
        state = {
            "cloud_intel": {
                "aws/acme.com": {},                                   # ran, nothing
                "gcp/acme.com": {},                                   # ran, nothing
                "azure/acme.com": {"user_realm": {"is_federated": False}},  # real signal
            },
            "code_intel": {
                "github_recon/acme.com": {"leaks": []},               # ran, nothing
                "gitleaks/acme.com": {},
            },
            "subdomain_intel": {}, "infra_intel": {},
        }
        path = eng._vendor_supply_chain(state)
        body = open(path).read()
        assert "Microsoft 365 / Azure" in body          # has evidence
        assert "AWS" not in body                          # empty -> not "detected"
        assert "Google Cloud" not in body
        assert "Code & Package Sources" not in body       # no code source had evidence

    def test_cloud_posture_skips_empty_subsections(self, tmp_path):
        eng = self._engine(tmp_path)
        state = {"cloud_intel": {
            "aws/acme.com": {"s3_buckets": []},
            "gcp/acme.com": {},
            "azure/acme.com": {"user_realm": {"is_federated": False}},
        }}
        body = open(eng._cloud_posture(state)).read()
        assert "Federation: Managed" in body
        assert "S3 Buckets Found: 0" not in body
        assert "Tenant ID: unknown" not in body
        assert "## aws/acme.com" not in body              # empty subsection omitted


# ── F-B8: empty deliverables ─────────────────────────────────────────────────


class TestEmptyDeliverables:
    def test_empty_harvested_credentials_has_no_scary_header(self, tmp_path):
        from nexusrecon.reports.engine import ReportEngine
        eng = ReportEngine("nr-test", "eng", "sha256:0", tmp_path)
        body = open(eng._harvested_credentials({"harvested_credentials": []})).read()
        assert "contains real credentials" not in body
        assert "No credentials were harvested" in body


# ── F-B5: identity input hygiene ─────────────────────────────────────────────


class TestIdentityHygiene:
    def test_junk_caught_real_names_safe(self):
        from nexusrecon.core.identity_hygiene import is_probable_test_identity as junk
        for e in ["abcfoo@x.com", "foobar@x.com", "test@x.com", "noreply@x.com",
                  "asdf@x.com", "xxxx@x.com", "abc@x.com"]:
            assert junk(e) is True, e
        for e in ["carlos@x.com", "barbara@x.com", "testa@x.com", "foster@x.com",
                  "j.smith@x.com", "alice.smith@x.com", "barber@x.com"]:
            assert junk(e) is False, e

    def test_filter_splits_real_and_dropped(self):
        from nexusrecon.core.identity_hygiene import filter_test_identities
        real, dropped = filter_test_identities(["carlos@x.com", "abcfoo@x.com"])
        assert real == ["carlos@x.com"]
        assert dropped == ["abcfoo@x.com"]

    def test_email_format_drops_junk_before_pattern(self):
        import asyncio
        from nexusrecon.tools.identity.email_format_tool import EmailFormatTool
        tool = EmailFormatTool()
        # carlos = flast-ish 'first'; abcfoo would distort the distribution.
        res = asyncio.run(tool.run("x.com", emails=["carlos@x.com", "abcfoo@x.com"]))
        assert res.data["total_emails"] == 1
        assert "abcfoo@x.com" in res.data["dropped_test_identities"]

    def test_phishing_package_skips_test_identity(self, tmp_path):
        from nexusrecon.reports.engine import ReportEngine
        eng = ReportEngine("nr-test", "eng", "sha256:0", tmp_path)
        state = {"email_intel": {"emails": {
            "carlos@acme.com": {"position": "Engineer"},
            "abcfoo@acme.com": {"position": "Unknown"},
        }}}
        body = open(eng._phishing_package(state)).read()
        assert "carlos@acme.com" in body
        assert "abcfoo@acme.com" not in body


# ── F-B7: recommendations respect availability ───────────────────────────────


class TestRecommendationHygiene:
    def _preflight(self):
        return {"buckets": {
            "missing_binary": {"theharvester": "binary 'theHarvester' not on PATH"},
            "missing_key": {},
            "policy": {"dehashed": "breach-DB lookups disabled", "shodan": "paid APIs disabled"},
            "over_tier": {},
            "active": {}, "stubbed": {},
        }}

    def test_unavailable_map_from_preflight(self):
        from nexusrecon.core.scoring import unavailable_tools_from_preflight
        u = unavailable_tools_from_preflight(self._preflight())
        assert u["theharvester"] == "not installed"
        assert u["dehashed"] == "disabled by engagement policy"
        assert u["shodan"] == "disabled by engagement policy"

    def test_steps_referencing_unavailable_tools_annotated(self):
        from nexusrecon.core.scoring import annotate_next_steps, unavailable_tools_from_preflight
        u = unavailable_tools_from_preflight(self._preflight())
        steps = [
            "Query DeHashed/IntelX for the 2 email addresses",
            "Use theHarvester to expand the email list",
            "Run amass with brute-force mode",  # amass is available -> untouched
        ]
        out = annotate_next_steps(steps, u)
        assert "unavailable this run" in out[0]
        assert "unavailable this run" in out[1]
        assert out[2] == "Run amass with brute-force mode"

    def test_no_preflight_is_noop(self):
        from nexusrecon.core.scoring import annotate_next_steps, unavailable_tools_from_preflight
        u = unavailable_tools_from_preflight(None)
        steps = ["Query DeHashed"]
        assert annotate_next_steps(steps, u) == steps
