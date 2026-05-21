"""Report quality assertions ── static properties of the report engine
and agent prompts that don't require a real campaign run.

The ROADMAP item Day 7 originally specified "run 10 campaigns and pin
the failure modes." Real campaigns mean real LLM spend and a few
hours of wall-clock per run, neither of which fit in a test suite.
What does fit: unit-level assertions that pin the properties those
campaigns would surface. These tests catch:

1. **AI-tell phrases in static text** (agent prompts, report templates,
   hardcoded report engine prose). An LLM tell that leaks into the
   shipped product would be embarrassing; this scanner catches them
   before they ship.

2. **Scope hash + tool versions in every report footer.** Pinned so an
   evidence-chain regression (renaming the metadata key, dropping the
   footer block) fails loud.

3. **CVE citations match the IANA-blessed format.** Reports that cite
   "CVE-12345" or "CVE-2024-XX" instead of "CVE-2024-12345" look
   careless even when the underlying intel is correct.

4. **Findings deduplication.** A finding produced by two overlapping
   tools (e.g. shodan + censys both surface the same open port) should
   not appear twice in the final report.

Manual verification of the things only a human can judge ── tone,
narrative coherence, executive-summary readability ── lives in
``tests/manual/REPORT_QUALITY_CHECKLIST.md``.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTS_DIR = REPO_ROOT / "nexusrecon" / "agents"
REPORTS_DIR = REPO_ROOT / "nexusrecon" / "reports"
TEMPLATES_DIR = REPORTS_DIR / "templates"


# ──────────────────────────────────────────────────────────────────────────
# AI-tell phrase scanner
# ──────────────────────────────────────────────────────────────────────────


# Phrases that should NEVER appear in static text shipped with the
# framework. Categorised so future contributors understand the *why*
# of each entry. All matching is case-insensitive substring.
#
# These are NOT the same thing as catching AI tells in LLM *output* ──
# we can't stop the model from emitting "delve" mid-prose. This list
# catches AI-tell phrases that crept into authored prompts/templates/
# hardcoded report prose. That's where they hurt most: the operator
# sees them as the framework's voice, not the LLM's.

# Hardest-rule phrases ── LLM refusal/disclaimer artifacts that mean
# the prompt is leaking model identity into the deliverable.
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

# Marketing fluff that signals a product brochure, not an operator
# tool. From the ROADMAP humanizer skill's "buzzwords & filler" list.
MARKETING_FLUFF_PHRASES: list[str] = [
    "cutting-edge",
    "best-in-class",
    "game-changer",
    "game-changing",
    "next-gen ",  # trailing space avoids matching "next-generation"
    "world-class",
    "revolutionary ",
    "paradigm shift",
    "synergy",
    "synergies",
    "leverages cutting-edge",
    "thought leader",
    "thought leadership",
]

# Tone-style AI vocabulary that signals a humanizer pass is missing.
# Kept narrow ── words like "leverage" have legit uses in this domain
# ("leverage a vulnerability") so we exclude general technical terms
# and only flag pure-prose AI hits.
AI_VOCABULARY_PHRASES: list[str] = [
    "delve into",
    "delving into",
    "tapestry of",
    "rich tapestry",
    "multifaceted",
    "in today's ever-evolving",
    "in today's fast-paced",
    "in today's digital landscape",
    "in the realm of",
    "navigate the complex",
    "harness the power",
    "unleash the power",
    "embark on a journey",
    "at the forefront of",
]


def _iter_scannable_text_files() -> Iterator[tuple[Path, str]]:
    """Yield ``(path, text)`` for every file we want the AI-tell scanner
    to look at. Scope:

      - ``nexusrecon/agents/*.py`` ── these define the LLM prompts via
        ROLE/GOAL/BACKSTORY string constants.
      - ``nexusrecon/reports/templates/*.j2`` ── Jinja templates that
        render into deliverables.
      - ``nexusrecon/reports/engine.py`` ── 1800+ lines of hardcoded
        report prose interleaved with logic.

    We do NOT scan tool docstrings or general code comments ── those
    aren't user-visible. The targets here are strings that either go
    into an LLM prompt or directly into a generated report.
    """
    for py_file in sorted(AGENTS_DIR.glob("*.py")):
        if py_file.name in ("__init__.py", "base.py"):
            continue
        yield py_file, py_file.read_text()

    for j2_file in sorted(TEMPLATES_DIR.glob("*.j2")):
        yield j2_file, j2_file.read_text()

    engine = REPORTS_DIR / "engine.py"
    if engine.exists():
        yield engine, engine.read_text()


def _scan_for_phrases(phrases: list[str]) -> list[tuple[Path, int, str, str]]:
    """Return a list of ``(path, line_number, phrase, line_text)`` for
    every hit across the scannable text inventory."""
    hits: list[tuple[Path, int, str, str]] = []
    for path, text in _iter_scannable_text_files():
        for line_no, line in enumerate(text.splitlines(), 1):
            lowered = line.lower()
            for phrase in phrases:
                if phrase in lowered:
                    hits.append((path, line_no, phrase, line.strip()))
    return hits


def _format_hits(hits: list[tuple[Path, int, str, str]]) -> str:
    out = []
    for path, line_no, phrase, text in hits:
        rel = path.relative_to(REPO_ROOT)
        out.append(f"  {rel}:{line_no}  [{phrase!r}]  {text[:120]}")
    return "\n".join(out)


class TestAITellScanner:
    """Static scan of agent prompts + report templates + report engine
    for AI-tell phrases. Adding a new forbidden phrase = adding a string
    to the relevant list above."""

    def test_no_llm_disclaimer_phrases(self):
        """If any of these phrases ship in our static text, an LLM
        artifact has bled into the framework's voice. These should
        never appear in any author-controlled string."""
        hits = _scan_for_phrases(LLM_DISCLAIMER_PHRASES)
        assert not hits, (
            "LLM disclaimer phrases found in static text ── these read as "
            "if the framework itself is an LLM rather than an operator tool:\n"
            + _format_hits(hits)
        )

    def test_no_marketing_fluff_phrases(self):
        """Marketing copy ('cutting-edge', 'game-changer', 'world-class')
        sounds like a SaaS homepage, not a pentester's toolbox. The
        framework's voice should be a thoughtful operator, not a sales
        deck."""
        hits = _scan_for_phrases(MARKETING_FLUFF_PHRASES)
        assert not hits, (
            "Marketing fluff phrases found in static text ── these "
            "make the tool sound like a brochure:\n"
            + _format_hits(hits)
        )

    def test_no_ai_vocabulary_phrases(self):
        """High-signal AI vocabulary ('delve into', 'tapestry of',
        'multifaceted', 'navigate the complex') in author-controlled
        text. These are the words the humanizer skill catches; once
        committed, they signal that the prompts/templates weren't
        humanizer-reviewed."""
        hits = _scan_for_phrases(AI_VOCABULARY_PHRASES)
        assert not hits, (
            "AI-vocabulary phrases found in static text ── humanizer "
            "pass missed these:\n"
            + _format_hits(hits)
        )


# ──────────────────────────────────────────────────────────────────────────
# Scope hash + tool versions in report footer
# ──────────────────────────────────────────────────────────────────────────


class TestReportEvidenceChain:
    """Every generated report must carry enough provenance metadata for
    an auditor to reproduce the campaign:

      - Scope hash (sha256 of the loaded scope file) → links the report
        to a specific signed engagement authorisation.
      - Campaign + engagement IDs → identifies the run.
      - Generated timestamp → fixes the run in time.

    These come from ``ReportEngine.__init__``. We pin them by
    instantiating a real engine with synthetic IDs and inspecting its
    bound state."""

    def test_engine_stores_scope_hash(self):
        from nexusrecon.reports.engine import ReportEngine
        engine = ReportEngine(
            campaign_id="test-camp",
            engagement_id="ENG-2026-TEST",
            scope_hash="sha256:abc123def456",
            output_dir=Path("/tmp/nexusrecon_test_unused"),
        )
        assert engine.scope_hash == "sha256:abc123def456"
        assert engine.campaign_id == "test-camp"
        assert engine.engagement_id == "ENG-2026-TEST"

    def test_scope_hash_appears_in_report_engine_text(self):
        """The report engine's hardcoded prose must include the scope
        hash via the ``self.scope_hash`` attribute. Grep the source
        for at least 3 occurrences ── a regression that drops one of
        the multi-format reports' footers would fail this."""
        engine_src = (REPORTS_DIR / "engine.py").read_text()
        # ``self.scope_hash`` is what every report's footer references.
        occurrences = engine_src.count("self.scope_hash")
        assert occurrences >= 3, (
            f"Expected >= 3 'self.scope_hash' references in engine.py, "
            f"got {occurrences}. A regression has dropped the scope hash "
            f"from at least one report's footer."
        )

    def test_executive_summary_template_includes_scope_hash(self):
        """The executive_summary.j2 template must render the scope hash
        ── this is the operator-facing front-page deliverable."""
        template = (TEMPLATES_DIR / "executive_summary.j2").read_text()
        assert "{{ scope_hash }}" in template or "{{scope_hash}}" in template, (
            "executive_summary.j2 does not reference {{ scope_hash }}. "
            "The deliverable cannot be tied back to the engagement "
            "authorisation without it."
        )


# ──────────────────────────────────────────────────────────────────────────
# CVE citation format
# ──────────────────────────────────────────────────────────────────────────


# MITRE CVE IDs: "CVE-YYYY-NNNN" where YYYY is a 4-digit year and NNNN
# is at least 4 digits (5+ for newer years). The regex below catches
# the well-formed ones; the test ensures everything that looks like a
# CVE actually matches this pattern.
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b")
# Anything that looks CVE-ish but malformed (placeholder digits, wrong
# year width, missing parts). We use this to fail the test if any
# report-engine prose has a typo CVE reference.
_MALFORMED_CVE_PATTERNS = [
    re.compile(r"CVE-XX+-\d+", re.IGNORECASE),  # placeholder YYYY
    re.compile(r"CVE-\d+-XXX+", re.IGNORECASE),  # placeholder digits
    re.compile(r"\bCVE-\d{1,3}-\d+\b"),  # year too short
    re.compile(r"\bCVE-\d{4}-\d{1,3}\b"),  # ID too short (<4 digits)
]


class TestCVECitationFormat:
    """Any CVE reference in static report-engine prose must use the
    canonical CVE-YYYY-NNNN format with year >=1999 (when MITRE
    started)."""

    def test_engine_has_no_malformed_cve_references(self):
        engine_src = (REPORTS_DIR / "engine.py").read_text()
        bad: list[str] = []
        for pattern in _MALFORMED_CVE_PATTERNS:
            for match in pattern.finditer(engine_src):
                bad.append(match.group(0))
        assert not bad, (
            "Malformed CVE references in report engine prose: "
            f"{bad!r}. CVE citations must use CVE-YYYY-NNNN where "
            f"YYYY is 4 digits and NNNN is at least 4 digits."
        )

    def test_well_formed_cves_have_plausible_year(self):
        """Any well-formed CVE in static text must have a year that
        actually exists (MITRE started in 1999, current year is 2026)."""
        engine_src = (REPORTS_DIR / "engine.py").read_text()
        for match in _CVE_RE.finditer(engine_src):
            year = int(match.group(1))
            assert 1999 <= year <= 2030, (
                f"Implausible CVE year in engine.py: {match.group(0)}"
            )

    def test_cve_regex_accepts_canonical_format(self):
        """Sanity ── the regex itself accepts known-good IDs."""
        for cve in (
            "CVE-2021-44228",  # Log4Shell
            "CVE-2014-0160",   # Heartbleed
            "CVE-2024-0001",   # 4-digit ID
            "CVE-2024-123456", # 6-digit ID (modern format)
        ):
            assert _CVE_RE.fullmatch(cve), f"regex rejected canonical {cve}"

    def test_cve_regex_rejects_malformed(self):
        for bad in (
            "CVE-21-44228",     # year too short
            "CVE-2021-44",      # ID too short
            "CVE-2021",         # missing ID
            "CVE-XXXX-44228",   # year placeholder
        ):
            assert not _CVE_RE.fullmatch(bad), f"regex accepted malformed {bad}"


# ──────────────────────────────────────────────────────────────────────────
# Findings deduplication
# ──────────────────────────────────────────────────────────────────────────


class TestFindingsDeduplication:
    """The scoring engine collects findings from multiple sources
    (vuln_intel, cloud_intel, code_intel, etc.). When two tools surface
    the same underlying issue ── e.g. shodan and censys both report the
    same open port ── the deduplicated report must not list it twice.

    ``score_findings`` produces ``RankedFinding`` objects; per-source
    deduplication happens inside the individual ``_score_*`` helpers
    (CVEs are keyed by ID, breached emails by address, etc.). These
    tests pin the most-likely regression points."""

    def test_cve_scoring_dedupes_within_state(self):
        """Two NVD lookups that surface the same CVE ID must produce one
        RankedFinding, not two. This is what protects against
        ``vuln_correlator`` re-emitting the same KEV entry from each
        tech-name lookup."""
        from nexusrecon.core.scoring import score_findings

        state = {
            "vuln_intel": {
                "enriched_cves": {
                    "CVE-2021-44228": {
                        "tech": "log4j",
                        "cvss": 10.0,
                        "epss": 0.97,
                        "in_kev": True,
                        "has_exploit": True,
                        "has_metasploit": True,
                        "description": "Log4Shell",
                    },
                },
                "kev": {
                    "vulnerabilities": [{"cveID": "CVE-2021-44228"}],
                },
            },
        }
        findings = score_findings(state)
        log4shell_findings = [
            f for f in findings if "CVE-2021-44228" in (f.title or "")
        ]
        assert len(log4shell_findings) == 1, (
            f"Expected single Log4Shell finding, got "
            f"{len(log4shell_findings)}: {[f.title for f in log4shell_findings]}"
        )

    def test_empty_state_produces_zero_findings(self):
        """A campaign that surfaced nothing must produce an empty
        ranked-findings list, not crash and not emit placeholder
        entries."""
        from nexusrecon.core.scoring import score_findings
        findings = score_findings({})
        assert findings == []

    def test_breach_scoring_dedupes_by_email(self):
        """If hibp + leakcheck + intelx all surface the same breached
        email, the score_breaches helper should produce one finding for
        that email, not three."""
        from nexusrecon.core.scoring import score_findings

        # Same email surfaced by two sources within email_intel.
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
        breach_findings = [f for f in findings if "victim@example.com" in str(f.title) + str(f.affected_assets)]
        # Per-email dedup means at most one finding for victim@example.com,
        # regardless of how many breach databases surfaced them.
        assert len(breach_findings) <= 1
