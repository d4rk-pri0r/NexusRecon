"""Tests for Phase 3 PR B: contribution SDK.

PR B ships three pieces under ``nexusrecon/sdk/``:

  - **Prompt versioning** — process-wide registry mapping
    ``name`` → ``(version, content_hash, body)``. Detects
    silent hot-edits of deployed prompts.
  - **Citation guardrails** — ``validate_citations(text,
    graph)`` extracts ``[[citation]]`` markers from agent
    output + verifies each against the live graph; returns
    a structured :class:`CitationReport`.
  - **Agent scaffolder** — ``nexusrecon agent new`` CLI +
    the underlying ``scaffold_agent(ScaffoldInputs)``
    function. Writes a Python module + manifest entry (new
    pack OR appending to existing).

Coverage
- ``register_prompt`` is idempotent for same body, raises on
  silent hot-edits, accepts deliberate version bumps,
  rejects bad version strings.
- ``compute_prompt_hash`` is stable + deterministic.
- ``extract_citations`` handles inline markers,
  deduplicates, preserves order.
- ``validate_citations`` resolves by entity_id, by value,
  reports missing as ``error``, type-mismatches as
  ``warning``, claims-without-citations as ``info``.
- Scaffolder: ``validate_inputs`` catches bad slugs / empty
  fields. End-to-end scaffold produces a parseable manifest
  (validated through Pydantic) + an importable agent module.
- Scaffolder refuses to clobber existing files / append a
  duplicate registry_name.
- Generated agent loads under the pack loader.
"""
from __future__ import annotations

import importlib
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.sdk import (
    CitationReport,
    PromptVersionMismatch,
    compute_prompt_hash,
    get_prompt_record,
    register_prompt,
    validate_citations,
)
from nexusrecon.sdk.agent_scaffolder import (
    ScaffoldInputs,
    _agent_class_name,
    scaffold_agent,
    validate_inputs,
)
from nexusrecon.sdk.citation_guard import extract_citations
from nexusrecon.sdk.prompt_versioning import _reset_prompt_registry


@pytest.fixture(autouse=True)
def _isolate_prompt_registry():
    _reset_prompt_registry()
    yield
    _reset_prompt_registry()


# ──────────────────────────────────────────────────────────────────────
# Prompt versioning
# ──────────────────────────────────────────────────────────────────────


class TestPromptVersioning:
    def test_register_then_lookup(self):
        record = register_prompt("p", "1.0.0", "body")
        assert get_prompt_record("p") is record
        assert record.content_hash.startswith("sha256:")

    def test_idempotent_same_body(self):
        r1 = register_prompt("p", "1.0.0", "body")
        r2 = register_prompt("p", "1.0.0", "body")
        assert r1 is r2

    def test_raises_on_silent_hot_edit(self):
        register_prompt("p", "1.0.0", "old body")
        with pytest.raises(PromptVersionMismatch):
            register_prompt("p", "1.0.0", "new body")

    def test_version_bump_accepted(self):
        register_prompt("p", "1.0.0", "old body")
        r2 = register_prompt("p", "1.1.0", "new body")
        assert r2.version == "1.1.0"

    def test_bad_version_rejected(self):
        with pytest.raises(ValueError):
            register_prompt("p", "alpha", "body")

    def test_expected_hash_safety_net(self):
        body = "the body"
        h = compute_prompt_hash(body)
        # Correct hash → succeeds.
        register_prompt("p", "1.0.0", body, expected_hash=h)
        # Wrong hash → raises.
        with pytest.raises(PromptVersionMismatch):
            register_prompt(
                "p2", "1.0.0", body, expected_hash="sha256:wrong",
            )

    def test_hash_stable(self):
        assert compute_prompt_hash("x") == compute_prompt_hash("x")
        assert compute_prompt_hash("x") != compute_prompt_hash("y")

    def test_to_dict_excludes_body(self):
        record = register_prompt("p", "1.0.0", "secret body")
        d = record.to_dict()
        assert "body" not in d
        assert d["content_hash"] == record.content_hash


# ──────────────────────────────────────────────────────────────────────
# Citation extraction
# ──────────────────────────────────────────────────────────────────────


class TestExtractCitations:
    def test_extracts_inline_markers(self):
        text = "Found [[ent-1]] which resolves to [[ip-2]]."
        assert extract_citations(text) == ["ent-1", "ip-2"]

    def test_deduplicates_preserving_order(self):
        text = "Found [[a]], then [[b]], then [[a]] again."
        assert extract_citations(text) == ["a", "b"]

    def test_empty_text(self):
        assert extract_citations("") == []
        assert extract_citations(None) == []  # type: ignore[arg-type]

    def test_no_citations(self):
        assert extract_citations("plain text without markers") == []


# ──────────────────────────────────────────────────────────────────────
# Citation validation
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def graph() -> EntityGraph:
    g = EntityGraph(campaign_id="cmp", engagement_id="eng")
    g.add_domain("acme.com", source="scope")
    g.add_subdomain(
        "api.acme.com", "acme.com", "subfinder", confidence=0.8,
    )
    return g


class TestValidateCitations:
    def test_valid_citation_by_value(self, graph: EntityGraph):
        text = "We found [[acme.com]] and [[api.acme.com]]."
        report = validate_citations(text, graph)
        assert report.cited_count == 2
        assert report.verified_count == 2
        assert report.has_errors is False

    def test_missing_citation_is_error(self, graph: EntityGraph):
        text = "Found [[ghost.example]] in the data."
        report = validate_citations(text, graph)
        assert report.has_errors is True
        assert report.severity_counts["error"] == 1

    def test_type_mismatch_is_warning(self, graph: EntityGraph):
        text = "Found [[acme.com]]."
        report = validate_citations(
            text, graph,
            expected_types={"acme.com": "subdomain"},
        )
        # acme.com is a domain in the graph, not subdomain.
        assert report.severity_counts["warning"] == 1
        assert report.severity_counts["error"] == 0

    def test_claims_without_citations_is_info(self, graph: EntityGraph):
        text = "We found a thing. We discovered another."
        report = validate_citations(text, graph)
        assert report.cited_count == 0
        assert report.severity_counts["info"] == 1

    def test_empty_response_no_violations(self, graph: EntityGraph):
        report = validate_citations("", graph)
        assert report.severity_counts == {"error": 0, "warning": 0, "info": 0}

    def test_explicit_citations_override_extraction(self, graph: EntityGraph):
        text = "Plain text without markers but logic says we cited acme.com"
        report = validate_citations(
            text, graph, explicit_citations=["acme.com"],
        )
        assert report.cited_count == 1
        assert report.verified_count == 1

    def test_report_to_dict_shape(self, graph: EntityGraph):
        report = validate_citations(
            "[[acme.com]] and [[ghost]]", graph,
        )
        d = report.to_dict()
        for key in ("agent_name", "cited_count", "verified_count",
                    "severity_counts", "violations"):
            assert key in d


# ──────────────────────────────────────────────────────────────────────
# Agent scaffolder — validate_inputs
# ──────────────────────────────────────────────────────────────────────


class TestValidateInputs:
    def test_good_inputs_pass(self, tmp_path: Path):
        inputs = ScaffoldInputs(
            agent_name="my_agent",
            role="A test agent",
            goal="Test things",
            backstory="A backstory",
            pack_target=tmp_path,
            is_new_pack=True,
            pack_name="my-pack",
        )
        validate_inputs(inputs)  # no exception

    def test_bad_slug_rejected(self, tmp_path: Path):
        inputs = ScaffoldInputs(
            agent_name="My-Bad-Slug",
            role="x", goal="x", backstory="x",
            pack_target=tmp_path, is_new_pack=True,
            pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="snake_case"):
            validate_inputs(inputs)

    def test_empty_role_rejected(self, tmp_path: Path):
        inputs = ScaffoldInputs(
            agent_name="my_agent",
            role="", goal="x", backstory="x",
            pack_target=tmp_path, is_new_pack=True,
            pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="role"):
            validate_inputs(inputs)

    def test_new_pack_requires_name(self, tmp_path: Path):
        inputs = ScaffoldInputs(
            agent_name="my_agent", role="x", goal="x",
            backstory="x", pack_target=tmp_path,
            is_new_pack=True, pack_name="",
        )
        with pytest.raises(ValueError, match="pack_name"):
            validate_inputs(inputs)


# ──────────────────────────────────────────────────────────────────────
# Agent scaffolder — end-to-end
# ──────────────────────────────────────────────────────────────────────


class TestScaffoldAgentNewPack:
    def test_creates_pack_with_manifest_and_module(self, tmp_path: Path):
        pack_dir = tmp_path / "my-pack"
        inputs = ScaffoldInputs(
            agent_name="my_agent",
            role="A test agent",
            goal="Test things",
            backstory="A neutral backstory.",
            pack_target=pack_dir,
            is_new_pack=True,
            pack_name="my-pack",
        )
        result = scaffold_agent(inputs)
        assert result.agent_module_path.exists()
        assert result.manifest_path.exists()
        assert result.is_new_pack is True
        # Manifest is parseable through the loader.
        from nexusrecon.packs import parse_manifest
        manifest = parse_manifest(result.manifest_path)
        assert manifest.name == "my-pack"
        assert len(manifest.contributes.agents) == 1
        assert manifest.contributes.agents[0].registry_name == "my_agent"

    def test_module_has_prompt_registration(self, tmp_path: Path):
        pack_dir = tmp_path / "my-pack"
        inputs = ScaffoldInputs(
            agent_name="my_agent",
            role="A test agent",
            goal="Test things",
            backstory="Backstory.",
            pack_target=pack_dir,
            is_new_pack=True,
            pack_name="my-pack",
        )
        result = scaffold_agent(inputs)
        body = result.agent_module_path.read_text()
        assert "register_prompt" in body
        assert "validate_citations" in body
        cls_name = _agent_class_name("my_agent")
        assert f"class {cls_name}" in body

    def test_test_file_generated(self, tmp_path: Path):
        pack_dir = tmp_path / "my-pack"
        inputs = ScaffoldInputs(
            agent_name="my_agent",
            role="A test agent",
            goal="Test things",
            backstory="Backstory.",
            pack_target=pack_dir,
            is_new_pack=True,
            pack_name="my-pack",
        )
        result = scaffold_agent(inputs)
        assert result.test_path is not None
        body = result.test_path.read_text()
        assert "test_agent_imports" in body

    def test_refuses_to_clobber_existing_module(self, tmp_path: Path):
        pack_dir = tmp_path / "my-pack"
        inputs = ScaffoldInputs(
            agent_name="my_agent",
            role="x", goal="x", backstory="x",
            pack_target=pack_dir, is_new_pack=True,
            pack_name="my-pack",
        )
        scaffold_agent(inputs)
        # Second call → FileExistsError.
        with pytest.raises(FileExistsError):
            scaffold_agent(inputs)

    def test_generated_module_is_importable(self, tmp_path: Path):
        """End-to-end: scaffold a fresh pack and confirm the
        Python module it produced is importable + the agent
        class instantiates."""
        pack_dir = tmp_path / "my-pack"
        inputs = ScaffoldInputs(
            agent_name="my_test_agent",
            role="A test agent",
            goal="Test things",
            backstory="Backstory.",
            pack_target=pack_dir,
            is_new_pack=True,
            pack_name="my-pack",
        )
        scaffold_agent(inputs)
        # Make the pack dir importable.
        sys.path.insert(0, str(pack_dir))
        try:
            module = importlib.import_module("my_test_agent")
            cls = getattr(module, _agent_class_name("my_test_agent"))
            agent = cls()
            assert agent.agent_name == "my_test_agent"
            # Citation review runs on an empty graph.
            empty_graph = EntityGraph(
                campaign_id="c", engagement_id="e",
            )
            report = agent.review_citations(
                "We found something but cited nothing.",
                empty_graph,
            )
            assert report["agent_name"] == "my_test_agent"
            assert report["severity_counts"]["info"] >= 1
        finally:
            sys.path.remove(str(pack_dir))
            # Drop cached module so other tests don't get
            # cross-contamination.
            for key in list(sys.modules):
                if key in ("my_test_agent",) or key.startswith("my_test_agent."):
                    del sys.modules[key]


# ──────────────────────────────────────────────────────────────────────
# Agent scaffolder — existing pack
# ──────────────────────────────────────────────────────────────────────


class TestScaffoldAgentExistingPack:
    def test_appends_to_existing_manifest(self, tmp_path: Path):
        pack_dir = tmp_path / "existing-pack"
        pack_dir.mkdir()
        manifest_body = {
            "name": "existing-pack",
            "version": "1.0.0",
            "contributes": {
                "agents": [
                    {
                        "module": "first_agent",
                        "class_name": "FirstAgent",
                        "registry_name": "first_agent",
                    },
                ],
            },
        }
        (pack_dir / "manifest.yaml").write_text(
            yaml.safe_dump(manifest_body),
        )
        (pack_dir / "first_agent.py").write_text("")

        inputs = ScaffoldInputs(
            agent_name="second_agent",
            role="x", goal="x", backstory="x",
            pack_target=pack_dir,
            is_new_pack=False,
        )
        scaffold_agent(inputs)

        from nexusrecon.packs import parse_manifest
        manifest = parse_manifest(pack_dir / "manifest.yaml")
        names = {a.registry_name for a in manifest.contributes.agents}
        assert names == {"first_agent", "second_agent"}

    def test_refuses_duplicate_registry_name(self, tmp_path: Path):
        pack_dir = tmp_path / "existing-pack"
        pack_dir.mkdir()
        (pack_dir / "manifest.yaml").write_text(yaml.safe_dump({
            "name": "existing-pack",
            "version": "1.0.0",
            "contributes": {
                "agents": [
                    {
                        "module": "my_agent",
                        "class_name": "MyAgent",
                        "registry_name": "my_agent",
                    },
                ],
            },
        }))
        inputs = ScaffoldInputs(
            agent_name="my_agent",  # collision
            role="x", goal="x", backstory="x",
            pack_target=pack_dir, is_new_pack=False,
        )
        with pytest.raises(ValueError, match="registry_name"):
            scaffold_agent(inputs)

    def test_missing_manifest_in_existing_mode(self, tmp_path: Path):
        pack_dir = tmp_path / "empty-dir"
        pack_dir.mkdir()
        inputs = ScaffoldInputs(
            agent_name="my_agent",
            role="x", goal="x", backstory="x",
            pack_target=pack_dir, is_new_pack=False,
        )
        with pytest.raises(FileNotFoundError):
            scaffold_agent(inputs)
