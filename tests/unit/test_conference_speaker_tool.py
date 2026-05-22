"""Tests for nexusrecon.tools.identity.conference_speaker_tool (E7).

Covers:
  - Empty target fail-fast.
  - Site list resolution: explicit objects > string filter > defaults.
  - FOSDEM parser extracts talks where target appears in title/speakers.
  - Soft 404 → conference returns empty without aborting the crawl.
  - Aggregation: talks_found, unique_speakers, unique_co_speakers counts.
  - Adapter extract_edges_from_conference_speaker:
      * emits bidirectional co-speaker edges from talks where target
        appears
      * skips talks where target is NOT a speaker
      * self-loops dropped
      * materialize_unknown semantics
      * uses INTERACTION_WEIGHTS["co-speaker"] = 0.95
      * year → ISO-8601 last_observed
  - Registration + empty trigger hints.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    derive_identity_id,
)
from nexusrecon.core.relationship_graph import INTERACTION_WEIGHTS
from nexusrecon.tools.pretext.conference_speaker_tool import (
    SITE_REGISTRY,
    ConferenceSite,
    ConferenceSpeakerTool,
    _parse_fosdem,
    _resolve_sites,
    _year_to_iso,
    extract_edges_from_conference_speaker,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _resp(status_code: int = 200, text: str = ""):
    resp = MagicMock()
    resp.is_success = (200 <= status_code < 300)
    resp.status_code = status_code
    resp.text = text
    return resp


# ──────────────────────────────────────────────────────────────────────
# Site list resolution
# ──────────────────────────────────────────────────────────────────────


class TestResolveSites:
    def test_default_full_registry(self):
        out = _resolve_sites(None)
        assert len(out) == len(SITE_REGISTRY)
        assert out == list(SITE_REGISTRY)

    def test_string_filter_matches_subset(self):
        out = _resolve_sites(["DEFCON", "FOSDEM"])
        names = [s.name for s in out]
        assert names == ["DEFCON", "FOSDEM"]

    def test_string_filter_case_insensitive(self):
        out = _resolve_sites(["defcon"])
        assert len(out) == 1
        assert out[0].name == "DEFCON"

    def test_string_filter_unknown_returns_empty(self):
        out = _resolve_sites(["NotAConference"])
        assert out == []

    def test_conference_site_objects_passed_through(self):
        custom = ConferenceSite(
            name="MyConf", archive_url="https://x", parser=lambda h, t: [],
        )
        out = _resolve_sites([custom])
        assert out == [custom]


# ──────────────────────────────────────────────────────────────────────
# _year_to_iso
# ──────────────────────────────────────────────────────────────────────


class TestYearToIso:
    def test_int_year(self):
        assert _year_to_iso(2024) == "2024-01-01T00:00:00+00:00"

    def test_string_year(self):
        assert _year_to_iso("2024") == "2024-01-01T00:00:00+00:00"

    def test_none(self):
        assert _year_to_iso(None) is None

    def test_invalid(self):
        assert _year_to_iso("not-a-year") is None
        assert _year_to_iso([]) is None

    def test_out_of_range(self):
        assert _year_to_iso(1800) is None
        assert _year_to_iso(2200) is None


# ──────────────────────────────────────────────────────────────────────
# FOSDEM parser
# ──────────────────────────────────────────────────────────────────────


class TestParseFosdem:
    def test_target_in_title(self):
        html = '''
        <h4 class="event"><a href="/2024/schedule/event/network_security/">Network Security Best Practices</a></h4>
        <a href="/2024/schedule/speaker/jane_doe/">Jane Doe</a>
        '''
        talks = _parse_fosdem(html, "Network Security")
        assert len(talks) == 1
        assert "Network Security" in talks[0]["title"]
        assert "Jane Doe" in talks[0]["speakers"]

    def test_target_in_speaker_list(self):
        html = '''
        <h4 class="event"><a href="/2024/schedule/event/x/">Some Talk</a></h4>
        <a href="/2024/schedule/speaker/alice_smith/">Alice Smith</a>
        <a href="/2024/schedule/speaker/bob_jones/">Bob Jones</a>
        '''
        talks = _parse_fosdem(html, "Alice Smith")
        assert len(talks) == 1
        assert set(talks[0]["speakers"]) == {"Alice Smith", "Bob Jones"}

    def test_no_match_returns_empty(self):
        html = '''
        <h4 class="event"><a href="/x/">Unrelated</a></h4>
        <a href="/foo/speaker/eve/">Eve</a>
        '''
        assert _parse_fosdem(html, "Alice") == []

    def test_empty_html(self):
        assert _parse_fosdem("", "anyone") == []


# ──────────────────────────────────────────────────────────────────────
# Tool: input + behaviour
# ──────────────────────────────────────────────────────────────────────


class TestConferenceSpeakerTool:
    @pytest.mark.asyncio
    async def test_empty_target(self):
        tool = ConferenceSpeakerTool()
        result = await tool.run("")
        assert not result.success
        assert "empty target" in result.error

    @pytest.mark.asyncio
    async def test_all_sites_404_returns_success_with_empty(self):
        # Every conference site 404s. Tool should still succeed with
        # empty talks (404 is in soft_failure_codes).
        tool = ConferenceSpeakerTool()
        mock_client = AsyncMock()
        mock_client.get.return_value = _resp(404)
        with patch(
            "nexusrecon.tools.pretext.conference_speaker_tool.httpx.AsyncClient",
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run("Alice Doe", sites=["DEFCON", "FOSDEM"])
        assert result.success
        assert result.data["talks"] == []
        assert result.data["summary"]["talks_found"] == 0
        assert result.data["conferences_probed"] == ["DEFCON", "FOSDEM"]

    @pytest.mark.asyncio
    async def test_aggregation_across_sites(self):
        # FOSDEM returns a talk where Alice appears; DEFCON returns 404.
        tool = ConferenceSpeakerTool()
        fosdem_html = '''
        <h4 class="event"><a href="/2024/event/x/">Cloud Native Auth</a></h4>
        <a href="/2024/speaker/alice_doe/">Alice Doe</a>
        <a href="/2024/speaker/bob_smith/">Bob Smith</a>
        '''

        async def _get(url, params=None):
            if "fosdem" in url:
                return _resp(200, fosdem_html)
            return _resp(404)

        mock_client = AsyncMock()
        mock_client.get.side_effect = _get
        with patch(
            "nexusrecon.tools.pretext.conference_speaker_tool.httpx.AsyncClient",
        ) as cls:
            cls.return_value.__aenter__.return_value = mock_client
            result = await tool.run(
                "Alice Doe", sites=["DEFCON", "FOSDEM"],
            )
        assert result.success
        d = result.data
        assert d["summary"]["talks_found"] == 1
        assert d["summary"]["unique_speakers"] == 2
        assert d["summary"]["unique_co_speakers"] == 1  # excludes Alice
        assert d["summary"]["conferences_with_hits"] == 1
        assert d["talks"][0]["conference"] == "FOSDEM"
        assert "Bob Smith" in d["talks"][0]["speakers"]


# ──────────────────────────────────────────────────────────────────────
# Adapter
# ──────────────────────────────────────────────────────────────────────


def _name_identity(name: str) -> Identity:
    ident = Identifier(
        value=name,
        identifier_type=IdentifierType.REAL_NAME,
        source="test",
        confidence=0.9,
    )
    return Identity(
        identity_id=derive_identity_id([ident]),
        primary_label=name,
        identifiers=[ident],
    )


class TestExtractEdgesFromConferenceSpeaker:
    def _setup(self) -> tuple[IdentityGraph, str]:
        graph = IdentityGraph()
        alice = _name_identity("Alice Doe")
        graph.add_identity(alice)
        return graph, alice.identity_id

    def test_bidirectional_co_speaker_edges(self):
        graph, alice_id = self._setup()
        bob = _name_identity("Bob Smith")
        graph.add_identity(bob)
        raw = {
            "target": "Alice Doe",
            "talks": [{
                "conference": "FOSDEM",
                "year": 2024,
                "title": "Cloud Native Auth",
                "url": "https://x",
                "speakers": ["Alice Doe", "Bob Smith"],
                "track": None,
            }],
        }
        edges = extract_edges_from_conference_speaker(raw, alice_id, graph)
        # 2 edges: alice→bob, bob→alice
        assert len(edges) == 2
        for _, e in edges:
            assert e.interaction_type == "co-speaker"
            assert e.strength == pytest.approx(INTERACTION_WEIGHTS["co-speaker"])
            assert e.last_observed == "2024-01-01T00:00:00+00:00"
            assert "conference_speaker" in e.sources
            assert "conf:FOSDEM" in e.sources

    def test_target_not_in_speakers_yields_no_edges(self):
        graph, alice_id = self._setup()
        raw = {
            "target": "Alice Doe",
            "talks": [{
                "conference": "FOSDEM", "year": 2024,
                "title": "Other Talk",
                "speakers": ["Bob", "Carol"],  # No Alice
            }],
        }
        edges = extract_edges_from_conference_speaker(raw, alice_id, graph)
        # Adapter only emits edges where the crawled target is a speaker
        assert edges == []

    def test_self_loop_filtered(self):
        graph, alice_id = self._setup()
        raw = {
            "target": "Alice Doe",
            "talks": [{
                "conference": "FOSDEM", "year": 2024,
                "title": "Solo Talk",
                "speakers": ["Alice Doe"],  # only herself
            }],
        }
        edges = extract_edges_from_conference_speaker(raw, alice_id, graph)
        assert edges == []

    def test_materializes_unknown_speakers(self):
        graph, alice_id = self._setup()
        raw = {
            "target": "Alice Doe",
            "talks": [{
                "conference": "FOSDEM", "year": 2024,
                "title": "x",
                "speakers": ["Alice Doe", "Stranger Person"],
            }],
        }
        edges = extract_edges_from_conference_speaker(raw, alice_id, graph)
        assert len(edges) == 2
        stranger = graph.by_identifier("Stranger Person")
        assert stranger is not None

    def test_skip_unknown_when_flag_off(self):
        graph, alice_id = self._setup()
        raw = {
            "target": "Alice Doe",
            "talks": [{
                "conference": "FOSDEM", "year": 2024,
                "title": "x",
                "speakers": ["Alice Doe", "Stranger Person"],
            }],
        }
        edges = extract_edges_from_conference_speaker(
            raw, alice_id, graph, materialize_unknown=False,
        )
        assert edges == []

    def test_case_insensitive_target_match(self):
        # Adapter lowercases for the speaker-membership check.
        graph, alice_id = self._setup()
        bob = _name_identity("Bob")
        graph.add_identity(bob)
        raw = {
            "target": "Alice Doe",
            "talks": [{
                "conference": "DEFCON", "year": 2024,
                "title": "x",
                "speakers": ["alice doe", "Bob"],  # case-mismatched alice
            }],
        }
        edges = extract_edges_from_conference_speaker(raw, alice_id, graph)
        # Should still emit edges (alice case-insensitive matches)
        assert len(edges) == 2

    def test_multiple_talks_aggregate_edges(self):
        graph, alice_id = self._setup()
        raw = {
            "target": "Alice Doe",
            "talks": [
                {"conference": "FOSDEM", "year": 2024, "title": "T1",
                 "speakers": ["Alice Doe", "Bob"]},
                {"conference": "DEFCON", "year": 2023, "title": "T2",
                 "speakers": ["Alice Doe", "Carol"]},
            ],
        }
        edges = extract_edges_from_conference_speaker(raw, alice_id, graph)
        # 2 edges per talk × 2 talks = 4
        assert len(edges) == 4


# ──────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────


class TestRegistration:
    def test_tool_registered(self):
        from nexusrecon.tools.registry import get_registry
        assert get_registry().get("conference_speaker") is not None

    def test_no_required_keys(self):
        tool = ConferenceSpeakerTool()
        assert tool.requires_keys == []

    def test_empty_dynamic_trigger_hints(self):
        tool = ConferenceSpeakerTool()
        assert tool.dynamic_trigger_hints == []

    def test_soft_failure_codes_includes_404(self):
        tool = ConferenceSpeakerTool()
        assert 404 in tool.soft_failure_codes

    def test_default_registry_has_expected_conferences(self):
        names = {s.name for s in SITE_REGISTRY}
        assert {"DEFCON", "BSides", "RSA", "KubeCon", "FOSDEM",
                "BlackHat", "Strange Loop", "USENIX"} <= names
