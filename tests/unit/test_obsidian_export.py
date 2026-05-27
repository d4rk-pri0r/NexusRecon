"""Tests for the Obsidian-flavored master-report export.

Pure-function tests on :mod:`nexusrecon.reports.obsidian_export`.
End-to-end coverage (the file actually lands on disk when the
flag is set) lives in ``test_report_quality_smoke.py``; this
file pins the transform contracts in isolation.
"""
from __future__ import annotations

import re

import pytest

from nexusrecon.reports.obsidian_export import (
    build_obsidian_master,
    render_frontmatter,
    rewrite_local_links_to_wikilinks,
    upgrade_severity_blockquotes,
)


# ──────────────────────────────────────────────────────────────────────
# Frontmatter
# ──────────────────────────────────────────────────────────────────────


class TestFrontmatter:
    """The YAML frontmatter is what makes the file usable as an
    Obsidian Property surface — it shows up in the file's
    Properties panel and is queryable via Dataview. Every field
    enumerated here is part of the operator-facing contract."""

    def test_block_delimited_by_triple_dash(self):
        out = render_frontmatter(
            {"seeds": ["acme.com"], "campaign_id": "c1",
             "engagement_id": "e1", "generated": "2026-01-01T00:00:00"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert out.startswith("---\n")
        # Closing fence followed by a blank line so the caller can
        # append body content directly.
        assert "\n---\n\n" in out

    @pytest.mark.parametrize(
        "field",
        [
            "campaign_id: c1",
            "engagement_id: e1",
            "target: acme.com",
            "generated: 2026-01-01T00:00:00",
            "scope_hash: sha256:abc",
            "nexusrecon_version: 0.6.0",
        ],
    )
    def test_contains_required_field(self, field: str):
        out = render_frontmatter(
            {"seeds": ["acme.com"], "campaign_id": "c1",
             "engagement_id": "e1", "generated": "2026-01-01T00:00:00"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert field in out, f"missing required field: {field!r}"

    def test_tags_block_lists_three_canonical_tags(self):
        """tags: list is what makes the campaign discoverable in
        Graph View under the right cluster. Operators key off
        these three; adding more is fine, removing is not."""
        out = render_frontmatter(
            {"seeds": ["acme.com"], "campaign_id": "c1",
             "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert "tags:" in out
        for tag in ("- nexusrecon", "- recon", "- redteam"):
            assert tag in out, f"missing canonical tag: {tag!r}"

    def test_missing_seeds_falls_back_to_unknown(self):
        """A campaign somehow lacking seeds shouldn't crash the
        renderer ── it should produce a frontmatter with an
        explicit ``unknown`` so the operator notices the gap."""
        out = render_frontmatter(
            {"campaign_id": "c1", "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert "target: unknown" in out

    def test_missing_campaign_id_falls_back_to_unknown(self):
        out = render_frontmatter(
            {"seeds": ["acme.com"], "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert "campaign_id: unknown" in out
        assert "engagement_id: unknown" in out


# ──────────────────────────────────────────────────────────────────────
# Wikilink rewrite
# ──────────────────────────────────────────────────────────────────────


class TestWikilinks:
    """Local cross-references between deliverables become Obsidian
    wikilinks so Graph View draws the campaign's deliverables as
    a connected component. External URLs and other-path links
    must NOT be rewritten ── breaking external links is louder
    than breaking wikilinks."""

    def test_local_md_link_becomes_wikilink(self):
        md = "See the [Asset Inventory](asset_inventory.md) for more."
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[asset_inventory|Asset Inventory]]" in out
        assert "[Asset Inventory](asset_inventory.md)" not in out

    def test_local_json_link_becomes_wikilink(self):
        md = "Raw findings: [findings](findings.json)."
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[findings|findings]]" in out

    def test_local_html_link_becomes_wikilink(self):
        """``entity_graph.html`` is a NexusRecon deliverable;
        Obsidian opens .html files via its file:// handler."""
        md = "[Entity graph](entity_graph.html)"
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[entity_graph|Entity graph]]" in out

    def test_local_csv_link_becomes_wikilink(self):
        md = "[Maltego CSV](maltego_export.csv)"
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[maltego_export|Maltego CSV]]" in out

    def test_external_https_link_preserved(self):
        md = "See [MITRE ATT&CK](https://attack.mitre.org/)."
        out = rewrite_local_links_to_wikilinks(md)
        assert "[MITRE ATT&CK](https://attack.mitre.org/)" in out
        assert "[[" not in out

    def test_external_http_link_preserved(self):
        md = "[Insecure example](http://example.com/x.md)"
        out = rewrite_local_links_to_wikilinks(md)
        assert "[Insecure example](http://example.com/x.md)" in out
        assert "[[" not in out

    def test_pathed_link_not_rewritten(self):
        """A link with a path separator (``../foo.md`` or
        ``subdir/bar.md``) points outside the vault root or to a
        subdir we don't manage. Leave it as-is."""
        md = "[Other](../other_campaign/report.md)"
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[other" not in out

    def test_label_preserves_inline_formatting(self):
        """Some labels include inline markdown (backticks for
        filenames). The wikilink pipe syntax keeps them so
        Obsidian renders the formatting in the visible label."""
        md = "[`asset_inventory.md`](asset_inventory.md)"
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[asset_inventory|`asset_inventory.md`]]" in out

    def test_multiple_links_in_one_paragraph(self):
        md = (
            "See [Top Threads](top_threads.md) and "
            "[Findings](findings.json) and [MITRE](https://attack.mitre.org/)."
        )
        out = rewrite_local_links_to_wikilinks(md)
        assert "[[top_threads|Top Threads]]" in out
        assert "[[findings|Findings]]" in out
        # External preserved.
        assert "[MITRE](https://attack.mitre.org/)" in out


# ──────────────────────────────────────────────────────────────────────
# Severity callouts
# ──────────────────────────────────────────────────────────────────────


class TestSeverityCallouts:
    """Bare ``> **CRITICAL**: …`` blockquotes lose their colored
    treatment in Obsidian's renderer. The callout syntax restores
    severity at a glance via Obsidian's built-in callout types."""

    @pytest.mark.parametrize(
        "severity,callout",
        [
            ("CRITICAL", "danger"),
            ("HIGH", "warning"),
            ("MEDIUM", "note"),
            ("LOW", "info"),
        ],
    )
    def test_severity_becomes_callout(self, severity: str, callout: str):
        md = f"> **{severity}**: log4shell active on vpn.acme.com"
        out = upgrade_severity_blockquotes(md)
        assert f"> [!{callout}] {severity}" in out
        assert "> log4shell active on vpn.acme.com" in out

    def test_severity_without_colon(self):
        """Some authors omit the colon — ``> **HIGH** something``.
        Pin both shapes so a renderer change doesn't drop one."""
        md = "> **HIGH** exposed Cognito identity pool"
        out = upgrade_severity_blockquotes(md)
        assert "> [!warning] HIGH" in out
        assert "> exposed Cognito identity pool" in out

    def test_severity_with_period(self):
        md = "> **MEDIUM**. outdated apache version"
        out = upgrade_severity_blockquotes(md)
        assert "> [!note] MEDIUM" in out

    def test_severity_with_no_following_text(self):
        """Just the severity marker on its own — still becomes a
        callout header, no body line."""
        md = "> **CRITICAL**"
        out = upgrade_severity_blockquotes(md)
        assert "> [!danger] CRITICAL" in out
        assert "> log4shell" not in out  # nothing else got pulled in

    def test_unrelated_blockquote_left_alone(self):
        md = "> A general engagement note that doesn't carry severity."
        out = upgrade_severity_blockquotes(md)
        assert out == md

    def test_unknown_severity_left_alone(self):
        """If an author invents a new severity (``URGENT``) the
        transform leaves the blockquote alone rather than picking
        an arbitrary callout type."""
        md = "> **URGENT**: act now"
        out = upgrade_severity_blockquotes(md)
        assert out == md
        assert "[!" not in out

    def test_multi_paragraph_blockquote_only_first_line_rewritten(self):
        """Severity markers are only meaningful on the leading
        line of a blockquote. Continuations stay raw quoted
        text. Verify the regex only matches the first line."""
        md = (
            "> **HIGH**: exposed Cognito pool\n"
            "> Additional context spanning a second line."
        )
        out = upgrade_severity_blockquotes(md)
        assert "> [!warning] HIGH" in out
        # The continuation line is unchanged.
        assert "> Additional context spanning a second line." in out


# ──────────────────────────────────────────────────────────────────────
# Composition
# ──────────────────────────────────────────────────────────────────────


class TestBuildObsidianMaster:
    """The composition function ties the three transforms
    together in the right order. Frontmatter must precede body;
    wikilinks must replace links before frontmatter so the YAML
    delimiters aren't mistaken for content; callouts run on the
    body."""

    def test_frontmatter_precedes_body(self):
        standard = "# Master Report\n\n[Asset Inventory](asset_inventory.md)"
        out = build_obsidian_master(
            standard_md=standard,
            state={"seeds": ["acme.com"], "campaign_id": "c1",
                   "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert out.startswith("---\n")
        idx_body = out.index("# Master Report")
        idx_fm_close = out.index("\n---\n\n")
        assert idx_fm_close < idx_body, (
            "frontmatter close must precede body content"
        )

    def test_wikilink_present_in_composed_output(self):
        standard = "[Asset Inventory](asset_inventory.md)"
        out = build_obsidian_master(
            standard_md=standard,
            state={"seeds": ["acme.com"], "campaign_id": "c1",
                   "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert "[[asset_inventory|Asset Inventory]]" in out

    def test_severity_callout_in_composed_output(self):
        standard = "> **CRITICAL**: rce on vpn.acme.com"
        out = build_obsidian_master(
            standard_md=standard,
            state={"seeds": ["acme.com"], "campaign_id": "c1",
                   "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert "> [!danger] CRITICAL" in out

    def test_external_link_survives_composition(self):
        standard = "See [MITRE](https://attack.mitre.org/)."
        out = build_obsidian_master(
            standard_md=standard,
            state={"seeds": ["acme.com"], "campaign_id": "c1",
                   "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert "[MITRE](https://attack.mitre.org/)" in out
        # No accidental wikilink rewrite.
        assert "[[" + "attack.mitre" not in out

    def test_empty_body_still_produces_frontmatter(self):
        """An edge case: an empty master report still gets a
        frontmatter block. Operators dropping the directory into
        a vault should always see Properties."""
        out = build_obsidian_master(
            standard_md="",
            state={"seeds": ["acme.com"], "campaign_id": "c1",
                   "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:abc",
            nexusrecon_version="0.6.0",
        )
        assert out.startswith("---\n")
        assert out.endswith("---\n\n")

    def test_frontmatter_contains_engine_passed_values(self):
        """Composition forwards scope_hash + nexusrecon_version
        from the engine into the YAML block. Pin the round-trip."""
        out = build_obsidian_master(
            standard_md="# body",
            state={"seeds": ["acme.com"], "campaign_id": "c1",
                   "engagement_id": "e1", "generated": "now"},
            scope_hash="sha256:DEADBEEF",
            nexusrecon_version="9.9.9",
        )
        # Splice out just the YAML block to assert on it.
        m = re.match(r"---\n(.*?)\n---\n", out, re.DOTALL)
        assert m, "no frontmatter found"
        body = m.group(1)
        assert "scope_hash: sha256:DEADBEEF" in body
        assert "nexusrecon_version: 9.9.9" in body
