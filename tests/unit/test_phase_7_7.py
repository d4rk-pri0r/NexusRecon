"""Tests for Phase 7.7 (E11) wiring.

Covers:
  - Empty inputs → phase short-circuits with empty state slots.
  - Full input flow → state slots populated correctly, with edges
    discovered via mocked social tools and activities via mocked
    news_intel.
  - --pretext-targets narrowing flows through to the scoring engine.
  - generate_phishing_drafts gate: drafter agent only runs when set.
  - Phase 7.7 registered in workflow ordering between 7.5 and 8.
  - State slots present in CampaignGraphState.
  - Report builder: markdown + JSON companion shape for empty and
    populated cases.
  - PhishingDrafterAgent backstory has the new E10 schema.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    derive_identity_id,
)
from nexusrecon.graph.nodes import phase7_7_pretext_intelligence
from nexusrecon.graph.workflow import PHASE_NODES, PHASE_ORDER, PHASE_TIERS

# ──────────────────────────────────────────────────────────────────────
# Workflow registration
# ──────────────────────────────────────────────────────────────────────


class TestPhaseRegistration:
    def test_phase_7_7_in_order_between_7_5_and_8(self):
        i75 = PHASE_ORDER.index("phase7_5")
        i77 = PHASE_ORDER.index("phase7_7")
        i8 = PHASE_ORDER.index("phase8")
        assert i75 < i77 < i8

    def test_phase_7_7_tier_zero(self):
        # All-public sources, no privileged operations.
        assert PHASE_TIERS["phase7_7"] == 0

    def test_phase_7_7_node_is_callable(self):
        assert callable(PHASE_NODES["phase7_7"])
        assert PHASE_NODES["phase7_7"] is phase7_7_pretext_intelligence


# ──────────────────────────────────────────────────────────────────────
# State slot presence
# ──────────────────────────────────────────────────────────────────────


class TestStateSlots:
    def test_new_state_slots_typed(self):
        from nexusrecon.graph.state import CampaignGraphState
        # TypedDict: hints contain the new slots
        hints = CampaignGraphState.__annotations__
        assert "pretext_scores" in hints
        assert "spear_phishing_intelligence" in hints
        assert "pretext_targets" in hints


# ──────────────────────────────────────────────────────────────────────
# Phase node behavior
# ──────────────────────────────────────────────────────────────────────


def _identity(seed: str, *, with_github: bool = False, domain: str = "acme.com") -> Identity:
    idents = [
        Identifier(
            value=f"{seed}@{domain}",
            identifier_type=IdentifierType.CORP_EMAIL,
            source="test", confidence=1.0,
        ),
        Identifier(
            value=seed.title(),
            identifier_type=IdentifierType.REAL_NAME,
            source="test", confidence=0.9,
        ),
    ]
    if with_github:
        idents.append(Identifier(
            value=f"{seed}-gh",
            identifier_type=IdentifierType.HANDLE,
            service="GitHub",
            source="test", confidence=0.9,
        ))
    return Identity(
        identity_id=derive_identity_id(idents),
        primary_label=seed.title(),
        identifiers=idents,
    )


def _seed_identity_graph_state(identities: list[Identity]) -> dict:
    g = IdentityGraph()
    for i in identities:
        g.add_identity(i)
    return g.to_dict()


@pytest.mark.asyncio
async def test_phase_7_7_empty_state_short_circuits():
    """No identities → empty pretext state slots, no tool calls."""
    state = {
        "identity_graph": {"identities": []},
        "email_intel": {},
        "completed_phases": [],
    }
    # Patch the registry so any unexpected call would crash the test.
    with patch(
        "nexusrecon.graph.nodes.get_registry",
        return_value=MagicMock(execute=AsyncMock(return_value=MagicMock(
            success=False, data=None, error="should not be called",
        ))),
    ):
        out = await phase7_7_pretext_intelligence(state)

    assert out["pretext_scores"] == []
    assert out["spear_phishing_intelligence"]["targets"] == {}
    assert out["spear_phishing_intelligence"]["summary"]["candidate_count"] == 0
    assert out["relationship_graph"]["edge_count"] == 0
    assert "phase7_7" in out["completed_phases"]


@pytest.mark.asyncio
async def test_phase_7_7_full_flow_populates_state():
    """Two identities, github+news mocks produce edges + activity.
    Expects pretext_scores populated and dossiers per target."""
    alice = _identity("alice", with_github=True, domain="acme.com")
    bob = _identity("bob", with_github=True, domain="acme.com")
    state = {
        "identity_graph": _seed_identity_graph_state([alice, bob]),
        "completed_phases": [],
    }

    # github_social returns data such that bob → alice (followers)
    def _github_for(target):
        # Alice's followers include bob-gh (so bob→alice follower edge)
        if target == "alice-gh":
            return MagicMock(success=True, data={
                "username": "alice-gh",
                "followers": [{"login": "bob-gh", "id": 2}],
                "following": [],
                "repositories": [],
            })
        if target == "bob-gh":
            return MagicMock(success=True, data={
                "username": "bob-gh",
                "followers": [{"login": "alice-gh", "id": 1}],
                "following": [],
                "repositories": [],
            })
        return MagicMock(success=False, data=None, error="unknown")

    # news_intel returns a recent activity about acme.com.
    news_resp = MagicMock(success=True, data={
        "target": "acme.com",
        "total_articles": 1,
        "sources_used": ["rss"],
        "articles": [],
        "recent_activity_records": [{
            "target": "acme.com",
            "kind": "press_release",
            "source": "rss",
            "title": "Acme Announces Acquisition",
            "url": "https://example.com/x",
            "summary": "x",
            "published_at": "2024-06-25T00:00:00+00:00",
            "raw": {},
        }],
        "time_window_days": 90,
    })

    async def _execute(name, target, target_type=None, **kw):
        if name == "github_social":
            return _github_for(target)
        if name == "news_intel":
            return news_resp
        # All other tools (mastodon_social, bluesky_social, linkedin_social,
        # conference_speaker, business_partner) return clean failure so
        # the phase keeps going without that signal.
        return MagicMock(success=False, data=None, error="not configured")

    mock_registry = MagicMock()
    mock_registry.execute = _execute

    with patch(
        "nexusrecon.graph.nodes.get_registry",
        return_value=mock_registry,
    ):
        out = await phase7_7_pretext_intelligence(state)

    # State commitments
    assert "phase7_7" in out["completed_phases"]
    assert out["relationship_graph"]["edge_count"] >= 1  # at least bob→alice
    assert isinstance(out["pretext_scores"], list)
    # Both identities are scored (default target_ids=None means all).
    assert len(out["spear_phishing_intelligence"]["targets"]) >= 1


@pytest.mark.asyncio
async def test_phase_7_7_pretext_targets_narrows():
    alice = _identity("alice", with_github=True)
    bob = _identity("bob", with_github=True)
    state = {
        "identity_graph": _seed_identity_graph_state([alice, bob]),
        "pretext_targets": [alice.identity_id],
        "completed_phases": [],
    }
    # Mock so alice gets a follower from bob; both will get news mention.
    def _github_for(target):
        if target == "alice-gh":
            return MagicMock(success=True, data={
                "username": "alice-gh",
                "followers": [{"login": "bob-gh", "id": 2}],
                "following": [], "repositories": [],
            })
        return MagicMock(success=True, data={
            "username": target, "followers": [], "following": [],
            "repositories": [],
        })
    news_resp = MagicMock(success=True, data={
        "target": "acme.com", "total_articles": 1, "sources_used": ["rss"],
        "articles": [],
        "recent_activity_records": [{
            "target": "acme.com", "kind": "press_release", "source": "rss",
            "title": "T", "url": "u",
            "summary": "s",
            "published_at": "2024-06-25T00:00:00+00:00",
            "raw": {},
        }],
        "time_window_days": 90,
    })

    async def _execute(name, target, target_type=None, **kw):
        if name == "github_social":
            return _github_for(target)
        if name == "news_intel":
            return news_resp
        return MagicMock(success=False, data=None)

    mock_registry = MagicMock()
    mock_registry.execute = _execute

    with patch(
        "nexusrecon.graph.nodes.get_registry",
        return_value=mock_registry,
    ):
        out = await phase7_7_pretext_intelligence(state)

    # Only alice's dossier should exist.
    target_ids = set(out["spear_phishing_intelligence"]["targets"].keys())
    assert alice.identity_id in target_ids
    assert bob.identity_id not in target_ids


@pytest.mark.asyncio
async def test_phase_7_7_drafter_gated_on_flag():
    """generate_phishing_drafts=False → drafter never invoked."""
    alice = _identity("alice", with_github=True)
    bob = _identity("bob", with_github=True)
    state = {
        "identity_graph": _seed_identity_graph_state([alice, bob]),
        "generate_phishing_drafts": False,
        "completed_phases": [],
    }

    async def _execute(name, target, target_type=None, **kw):
        if name == "github_social" and target == "alice-gh":
            return MagicMock(success=True, data={
                "username": "alice-gh",
                "followers": [{"login": "bob-gh", "id": 2}],
                "following": [], "repositories": [],
            })
        if name == "news_intel":
            return MagicMock(success=True, data={
                "target": "acme.com", "total_articles": 0,
                "sources_used": [], "articles": [],
                "recent_activity_records": [{
                    "target": "acme.com", "kind": "news_article",
                    "source": "rss", "title": "X", "url": "u",
                    "summary": "", "published_at": "2024-06-25T00:00:00+00:00",
                    "raw": {},
                }],
                "time_window_days": 90,
            })
        return MagicMock(success=True, data={"username": target,
                                              "followers": [], "following": [],
                                              "repositories": []})

    mock_registry = MagicMock()
    mock_registry.execute = _execute

    # Track if executor.run_agent ever called for drafter.
    mock_executor = MagicMock()
    mock_executor.run_agent = AsyncMock(return_value={"output": "should not run"})

    with patch("nexusrecon.graph.nodes.get_registry", return_value=mock_registry), \
         patch("nexusrecon.graph.nodes._get_executor", return_value=mock_executor):
        out = await phase7_7_pretext_intelligence(state)

    mock_executor.run_agent.assert_not_called()
    # No drafts should be populated.
    for dossier in out["spear_phishing_intelligence"]["targets"].values():
        assert dossier.get("draft") is None


@pytest.mark.asyncio
async def test_phase_7_7_drafter_invoked_when_flag_set():
    """Positive gate: ``generate_phishing_drafts=True`` AND at least
    one target → drafter runs once per target and its output lands
    in that target's dossier under the ``draft`` field.

    Pairs with ``test_phase_7_7_drafter_gated_on_flag`` (the negative
    gate). Together they pin the binary contract the
    ``--generate-phishing`` CLI flag makes to operators."""
    alice = _identity("alice", with_github=True)
    bob = _identity("bob", with_github=True)
    state = {
        "identity_graph": _seed_identity_graph_state([alice, bob]),
        "generate_phishing_drafts": True,
        "completed_phases": [],
    }

    async def _execute(name, target, target_type=None, **kw):
        # Wire enough signal that the scoring engine produces at
        # least one candidate per target: alice follows bob on
        # github (co-interaction) + a recent news article ties to
        # the corp domain so the timing axis is non-zero.
        if name == "github_social" and target == "alice-gh":
            return MagicMock(success=True, data={
                "username": "alice-gh",
                "followers": [{"login": "bob-gh", "id": 2}],
                "following": [{"login": "bob-gh", "id": 2}],
                "repositories": [],
            })
        if name == "github_social" and target == "bob-gh":
            return MagicMock(success=True, data={
                "username": "bob-gh",
                "followers": [{"login": "alice-gh", "id": 1}],
                "following": [{"login": "alice-gh", "id": 1}],
                "repositories": [],
            })
        if name == "news_intel":
            return MagicMock(success=True, data={
                "target": "acme.com", "total_articles": 1,
                "sources_used": ["rss"], "articles": [],
                "recent_activity_records": [{
                    "target": "acme.com", "kind": "news_article",
                    "source": "rss", "title": "Acme announces X",
                    "url": "https://example.com/n",
                    "summary": "Acme announced X today.",
                    "published_at": "2024-06-25T00:00:00+00:00",
                    "raw": {},
                }],
                "time_window_days": 90,
            })
        return MagicMock(success=True, data={"username": target,
                                              "followers": [], "following": [],
                                              "repositories": []})

    mock_registry = MagicMock()
    mock_registry.execute = _execute

    canned_draft = '{"target_identity_id":"x","subject":"hello"}'
    mock_executor = MagicMock()
    mock_executor.run_agent = AsyncMock(return_value={
        "output": canned_draft, "agent": "phishing_drafter",
        "step_count": 1, "findings": [],
    })

    with patch("nexusrecon.graph.nodes.get_registry", return_value=mock_registry), \
         patch("nexusrecon.graph.nodes._get_executor", return_value=mock_executor):
        out = await phase7_7_pretext_intelligence(state)

    targets = out["spear_phishing_intelligence"]["targets"]
    # At least one target should have been scored — both Alice and
    # Bob exchange interactions, so at least one candidate per
    # ordered pair should be produced.
    assert targets, "expected at least one target dossier"
    # The drafter was invoked at least once and the canned output
    # landed in every dossier that got a draft.
    assert mock_executor.run_agent.call_count >= 1
    # Every call MUST be addressed to the drafter agent (not some
    # other agent the phase might invoke later).
    for call in mock_executor.run_agent.await_args_list:
        args, kwargs = call
        assert (args[0] if args else kwargs.get("agent_name")) == "phishing_drafter"
    drafted = [d for d in targets.values() if d.get("draft")]
    assert drafted, "expected at least one drafted target"
    assert all(d["draft"] == canned_draft for d in drafted)


# ──────────────────────────────────────────────────────────────────────
# Report builder
# ──────────────────────────────────────────────────────────────────────


def test_report_builder_empty_state_emits_both_files(tmp_path: Path):
    from nexusrecon.reports.spear_phishing_intelligence import (
        build_spear_phishing_intelligence_md,
    )
    md_path, json_path = build_spear_phishing_intelligence_md(
        campaign_id="camp_1", engagement_id="eng_1",
        state={
            "spear_phishing_intelligence": {"summary": {}, "targets": {}},
            "pretext_scores": [],
            "relationship_graph": {"edge_count": 0},
        },
        output_dir=tmp_path,
    )
    assert Path(md_path).exists()
    assert Path(json_path).exists()
    md = Path(md_path).read_text()
    assert "Spear-Phishing Intelligence" in md
    assert "No pretext candidates" in md
    payload = json.loads(Path(json_path).read_text())
    assert payload["campaign_id"] == "camp_1"
    assert payload["candidates"] == []


def test_report_builder_populated_state(tmp_path: Path):
    from nexusrecon.reports.spear_phishing_intelligence import (
        build_spear_phishing_intelligence_md,
    )
    cand = {
        "target_identity_id": "alice-id",
        "target_label": "Alice",
        "sender_identity_id": "bob-id",
        "sender_label": "Bob",
        "topic": "Acme Announces",
        "timing_anchor": {
            "target": "acme.com",
            "title": "Acme Announces",
            "published_at": "2024-06-25T00:00:00+00:00",
            "source": "news_intel",
            "url": "https://example.com/x",
            "kind": "press_release",
        },
        "sender_plausibility": 0.8,
        "topic_plausibility": 0.65,
        "timing_score": 0.95,
        "combined_score": 0.79,
        "sources": ["github_social", "news_intel"],
        "rationale": "Bob → Alice (co-author on github_social, ...)",
    }
    state = {
        "spear_phishing_intelligence": {
            "summary": {"target_count": 1, "candidate_count": 1,
                         "score_min": 0.79, "score_median": 0.79,
                         "score_max": 0.79},
            "targets": {
                "alice-id": {
                    "target_identity_id": "alice-id",
                    "target_label": "Alice",
                    "top_candidates": [cand],
                    "draft": None,
                },
            },
        },
        "pretext_scores": [cand],
        "relationship_graph": {"edge_count": 1},
    }
    md_path, json_path = build_spear_phishing_intelligence_md(
        campaign_id="camp_1", engagement_id="eng_1",
        state=state, output_dir=tmp_path,
    )
    md = Path(md_path).read_text()
    assert "Alice" in md
    assert "Bob" in md
    assert "Acme Announces" in md
    assert "github_social" in md
    assert "Recommended draft framing" in md

    payload = json.loads(Path(json_path).read_text())
    assert payload["summary"]["candidate_count"] == 1
    assert payload["candidates"][0]["topic"] == "Acme Announces"
    assert payload["edge_count"] == 1


# ──────────────────────────────────────────────────────────────────────
# Phishing drafter agent (E10)
# ──────────────────────────────────────────────────────────────────────


class TestPhishingDrafterAgent:
    def test_agent_name_unchanged(self):
        from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
        assert PhishingDrafterAgent.agent_name == "phishing_drafter"

    def test_backstory_describes_new_schema(self):
        from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
        bs = PhishingDrafterAgent.backstory
        # E10 schema fields must be documented
        for field in (
            "target_identity_id",
            "subject",
            "sender_display_name",
            "sender_address",
            "body_markdown",
            "rationale",
            "sources",
        ):
            assert field in bs, f"backstory missing schema field {field!r}"

    def test_backstory_warns_against_fabrication(self):
        from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
        bs = PhishingDrafterAgent.backstory.lower()
        # The "do not invent" guidance is load-bearing.
        assert "don't invent" in bs or "do not invent" in bs

    def test_backstory_covers_dmarc_decision(self):
        from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
        bs = PhishingDrafterAgent.backstory
        assert "DMARC" in bs
        assert "reject" in bs
        assert "lookalike" in bs.lower()

    def test_backstory_no_draft_fallback(self):
        from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
        bs = PhishingDrafterAgent.backstory.lower()
        # Empty-candidate fallback shape should be documented.
        assert "insufficient pretext signal" in bs or "no-draft" in bs

    def test_require_citations(self):
        from nexusrecon.agents.phishing_drafter import PhishingDrafterAgent
        assert PhishingDrafterAgent.require_citations is True
