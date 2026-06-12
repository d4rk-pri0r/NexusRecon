"""ROADMAP item 6: MockLLM findings are marked unmistakably in reports, the
evidence hash is honestly labeled when self-reported, and the evidence auditor
no longer overclaims legal defensibility."""
from nexusrecon.agents.evidence_auditor import (
    AUDITOR_BACKSTORY,
    AUDITOR_GOAL,
    AUDITOR_ROLE,
)
from nexusrecon.reports.engine import (
    _MOCK_FINDING_MARKER,
    finding_display_title,
    finding_evidence_hash_label,
    finding_is_mock,
)


class TestMockFindingMarking:
    def test_finding_is_mock_via_analysis_engine(self):
        assert finding_is_mock({"analysis_engine": "mock"})
        assert not finding_is_mock({"analysis_engine": "live"})

    def test_finding_is_mock_via_legacy_source(self):
        # robust marker is analysis_engine, but pre-marker findings carried
        # source == 'mock_llm' and must still be caught
        assert finding_is_mock({"source": "mock_llm"})
        assert not finding_is_mock({"source": "crtsh"})

    def test_display_title_marks_mock(self):
        out = finding_display_title(
            {"title": "Recon data collected", "analysis_engine": "mock"}
        )
        assert out.startswith(_MOCK_FINDING_MARKER)
        assert "Recon data collected" in out

    def test_display_title_unchanged_for_live(self):
        out = finding_display_title(
            {"title": "Exposed .git directory", "analysis_engine": "live"}
        )
        assert out == "Exposed .git directory"
        assert "MOCK" not in out

    def test_display_title_idempotent(self):
        once = finding_display_title({"title": "x", "analysis_engine": "mock"})
        twice = finding_display_title({"title": once, "analysis_engine": "mock"})
        assert twice == once  # an already-marked title is not double-prefixed

    def test_marker_has_no_em_dash(self):
        # honesty-cleanup guidance: em-dashes read as an AI tell in delivered prose
        assert "—" not in _MOCK_FINDING_MARKER


class TestEvidenceHashHonesty:
    def test_self_reported_hash_labeled(self):
        label = finding_evidence_hash_label(
            {"raw_evidence_hash": "sha256:abc", "evidence_provenance": "self_reported"}
        )
        assert "sha256:abc" in label
        assert "not independent evidence" in label

    def test_tool_evidence_hash_plain(self):
        label = finding_evidence_hash_label(
            {"raw_evidence_hash": "sha256:def", "evidence_provenance": "tool_evidence"}
        )
        assert label == "sha256:def"


class TestEvidenceAuditorClaimReframed:
    def test_no_legal_defensibility_overclaim(self):
        blob = (AUDITOR_ROLE + AUDITOR_GOAL + AUDITOR_BACKSTORY).lower()
        assert "legal defensibility" not in blob
        assert "defensible in a legal context" not in blob

    def test_completeness_framing_present(self):
        blob = (AUDITOR_ROLE + AUDITOR_GOAL + AUDITOR_BACKSTORY).lower()
        assert "completeness" in blob
        assert "self-reported" in blob
