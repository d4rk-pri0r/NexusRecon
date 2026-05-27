"""Tests for Phase 3 PR A: recon pack format + loader.

PR A ships the ``nexusrecon/packs/`` package. Packs are
directories under ``~/.nexusrecon/packs/`` containing a
``manifest.yaml``; the loader discovers them, parses + validates
the manifest, imports declared modules, and registers their
contributions (tools, agents, dispatch policies, report
templates, custom entity / relationship types).

Failure mode is skip + warn per the architecture decisions:
broken packs land in the registry tagged ``failed`` with the
error preserved for ``packs list`` — campaigns never abort
on pack failures.

Coverage
- Manifest parsing + validation: required fields, name +
  version patterns, schema_version major check.
- Manifest hash: ``compute_manifest_hash`` is stable across
  serialisations + symmetric (recomputing the hash on the
  loaded manifest matches what the pack author would
  compute).
- Discovery: only directories with ``manifest.yaml`` are
  picked up; sorted output for determinism.
- Custom-type extension registry: registration is
  idempotent, collisions with built-ins are rejected, value
  re-use across names is rejected.
- Loader: end-to-end through a fixture pack with all five
  contribution kinds.
- Loader failure isolation: a pack with one broken
  contribution still loads the rest; a pack with a broken
  manifest goes into ``failed`` state without raising.
- Audit log: every load attempt produces an
  ``agent_action`` entry.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from nexusrecon.packs import (
    PackLoadStatus,
    compute_manifest_hash,
    discover_packs,
    is_known_entity_type,
    is_known_relationship_type,
    load_packs,
    parse_manifest,
    register_entity_type,
    register_relationship_type,
)
from nexusrecon.packs.manifest import PackManifest
from nexusrecon.packs.registry import (
    custom_entity_types,
    custom_relationship_types,
    get_pack_registry,
    reset_pack_registry,
)


@pytest.fixture(autouse=True)
def _isolate_pack_state():
    """Each test starts with a clean PackRegistry + clean
    custom-type registries. Without this the
    register_entity_type tests would interfere with each
    other (and with anything else in the suite that touches
    the entity-type extension)."""
    reset_pack_registry()
    yield
    reset_pack_registry()


# ──────────────────────────────────────────────────────────────────────
# Manifest schema + parsing
# ──────────────────────────────────────────────────────────────────────


def _write_manifest(directory: Path, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / "manifest.yaml"
    manifest_path.write_text(textwrap.dedent(body), encoding="utf-8")
    return manifest_path


class TestManifestParsing:
    def test_minimal_manifest_parses(self, tmp_path: Path):
        path = _write_manifest(tmp_path / "pk", """
            name: my-pack
            version: 1.0.0
        """)
        manifest = parse_manifest(path)
        assert manifest.name == "my-pack"
        assert manifest.version == "1.0.0"
        assert manifest.contributes.total() == 0

    def test_bad_name_rejected(self, tmp_path: Path):
        path = _write_manifest(tmp_path / "pk", """
            name: BAD_PACK
            version: 1.0.0
        """)
        with pytest.raises(ValueError):
            parse_manifest(path)

    def test_bad_version_rejected(self, tmp_path: Path):
        path = _write_manifest(tmp_path / "pk", """
            name: pk
            version: alpha
        """)
        with pytest.raises(ValueError):
            parse_manifest(path)

    def test_unknown_schema_version_rejected(self, tmp_path: Path):
        path = _write_manifest(tmp_path / "pk", """
            name: pk
            version: 1.0.0
            schema_version: 99
        """)
        with pytest.raises(ValueError, match="schema_version"):
            parse_manifest(path)

    def test_malformed_yaml_raises_value_error(self, tmp_path: Path):
        path = _write_manifest(tmp_path / "pk", """
            name: pk
            version: 1.0.0
            contributes: [this is not a mapping
        """)
        with pytest.raises(ValueError):
            parse_manifest(path)

    def test_entity_type_name_must_be_upper_snake(self, tmp_path: Path):
        path = _write_manifest(tmp_path / "pk", """
            name: pk
            version: 1.0.0
            contributes:
              entity_types:
                - name: business_partner
                  value: business_partner
        """)
        with pytest.raises(ValueError, match="UPPER_SNAKE"):
            parse_manifest(path)


# ──────────────────────────────────────────────────────────────────────
# Manifest hash
# ──────────────────────────────────────────────────────────────────────


class TestManifestHash:
    def test_hash_is_stable(self):
        m = PackManifest(name="pk", version="1.0.0")
        assert compute_manifest_hash(m) == compute_manifest_hash(m)

    def test_hash_excludes_self(self):
        """Setting ``manifest_hash`` doesn't change the
        computed hash — that's what makes the field
        injectable by the author before publishing."""
        m1 = PackManifest(name="pk", version="1.0.0")
        m2 = PackManifest(
            name="pk", version="1.0.0",
            manifest_hash="sha256:wrong",
        )
        assert compute_manifest_hash(m1) == compute_manifest_hash(m2)

    def test_hash_changes_with_content(self):
        m1 = PackManifest(name="pk-a", version="1.0.0")
        m2 = PackManifest(name="pk-b", version="1.0.0")
        assert compute_manifest_hash(m1) != compute_manifest_hash(m2)


# ──────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────


class TestDiscovery:
    def test_finds_directories_with_manifest(self, tmp_path: Path):
        _write_manifest(tmp_path / "pack-a", """
            name: pack-a
            version: 1.0.0
        """)
        _write_manifest(tmp_path / "pack-b", """
            name: pack-b
            version: 1.0.0
        """)
        # A directory WITHOUT manifest.yaml is ignored.
        (tmp_path / "not-a-pack").mkdir()

        found = discover_packs(tmp_path)
        assert len(found) == 2
        assert {p.name for p in found} == {"pack-a", "pack-b"}

    def test_missing_pack_dir_returns_empty(self, tmp_path: Path):
        assert discover_packs(tmp_path / "nope") == []

    def test_files_ignored(self, tmp_path: Path):
        (tmp_path / "stray.yaml").write_text("name: x")
        assert discover_packs(tmp_path) == []

    def test_deterministic_order(self, tmp_path: Path):
        # Create packs in non-alphabetical order so we can
        # confirm the loader sorts.
        for name in ("z-pack", "a-pack", "m-pack"):
            _write_manifest(tmp_path / name, f"""
                name: {name}
                version: 1.0.0
            """)
        found = [p.name for p in discover_packs(tmp_path)]
        assert found == ["a-pack", "m-pack", "z-pack"]


# ──────────────────────────────────────────────────────────────────────
# Custom-type extension registry
# ──────────────────────────────────────────────────────────────────────


class TestExtensionRegistry:
    def test_register_entity_type_idempotent(self):
        register_entity_type("BUSINESS_PARTNER", "business_partner")
        register_entity_type("BUSINESS_PARTNER", "business_partner")
        assert custom_entity_types() == {
            "BUSINESS_PARTNER": "business_partner",
        }

    def test_conflict_on_name_with_different_value(self):
        register_entity_type("BUSINESS_PARTNER", "business_partner")
        with pytest.raises(ValueError, match="already registered"):
            register_entity_type("BUSINESS_PARTNER", "other")

    def test_built_in_value_collision_rejected(self):
        with pytest.raises(ValueError, match="built-in"):
            register_entity_type("MY_DOMAIN", "domain")

    def test_cross_name_value_collision_rejected(self):
        register_entity_type("ALPHA", "shared_value")
        with pytest.raises(ValueError, match="already used"):
            register_entity_type("BRAVO", "shared_value")

    def test_is_known_entity_type_built_in_and_custom(self):
        register_entity_type("BUSINESS_PARTNER", "business_partner")
        assert is_known_entity_type("domain")          # built-in
        assert is_known_entity_type("business_partner")  # custom
        assert not is_known_entity_type("nonsense")

    def test_relationship_registry_works_symmetrically(self):
        register_relationship_type("SUPPLY_CHAINS_TO", "supply_chains_to")
        assert custom_relationship_types() == {
            "SUPPLY_CHAINS_TO": "supply_chains_to",
        }
        assert is_known_relationship_type("supply_chains_to")
        assert is_known_relationship_type("resolves_to")  # built-in


# ──────────────────────────────────────────────────────────────────────
# End-to-end pack loading
# ──────────────────────────────────────────────────────────────────────


def _build_full_pack(root: Path) -> Path:
    """Build a fixture pack with every contribution kind.
    Returns the pack directory."""
    pack = root / "full-pack"
    pack.mkdir(parents=True)

    # tools module
    (pack / "my_tools.py").write_text(textwrap.dedent("""
        # A tool that doesn't actually register (we just need
        # the import to succeed for the loader's purposes).
        TOOL_NAME = "fake-tool"
    """).strip())

    # agents module
    (pack / "my_agents.py").write_text(textwrap.dedent("""
        class FakeAgent:
            name = "fake-agent"
    """).strip())

    # policy module
    (pack / "my_policies.py").write_text(textwrap.dedent("""
        from dataclasses import dataclass, field
        from nexusrecon.strategy.policy import LitePolicy

        @dataclass
        class CustomPolicy(LitePolicy):
            name: str = "custom_pack_policy"
            max_per_cycle: int = 7
            max_total: int = 40
            eligible_phases: frozenset[str] = field(
                default_factory=lambda: frozenset({"phase1", "phase4"}),
            )
    """).strip())

    # manifest
    _write_manifest(pack, """
        name: full-pack
        version: 1.0.0
        schema_version: 1
        description: Fixture pack covering every contribution kind.
        author: tests
        license: MIT
        contributes:
          tools:
            - module: my_tools
              class_name: FakeTool
          agents:
            - module: my_agents
              class_name: FakeAgent
              registry_name: fake_agent
          policies:
            - module: my_policies
              class_name: CustomPolicy
              name: custom_pack_policy
          entity_types:
            - name: BUSINESS_PARTNER
              value: business_partner
          relationship_types:
            - name: SUPPLY_CHAINS_TO
              value: supply_chains_to
    """)
    return pack


class TestEndToEndLoad:
    def test_full_pack_loads_all_contributions(self, tmp_path: Path):
        _build_full_pack(tmp_path)
        results = load_packs(tmp_path)
        assert len(results) == 1
        r = results[0]
        assert r.status == PackLoadStatus.LOADED
        assert r.contributions_loaded["tools"] == 1
        assert r.contributions_loaded["agents"] == 1
        assert r.contributions_loaded["policies"] == 1
        assert r.contributions_loaded["entity_types"] == 1
        assert r.contributions_loaded["relationship_types"] == 1

        # Agent landed in AGENT_REGISTRY.
        from nexusrecon.graph.agent_executor import AGENT_REGISTRY
        assert "fake_agent" in AGENT_REGISTRY
        # Policy resolvable by name.
        from nexusrecon.strategy.policy import get_policy
        policy = get_policy("custom_pack_policy")
        assert policy.max_per_cycle == 7
        # Custom type registered.
        assert is_known_entity_type("business_partner")
        assert is_known_relationship_type("supply_chains_to")

    def test_registry_records_loaded_pack(self, tmp_path: Path):
        _build_full_pack(tmp_path)
        load_packs(tmp_path)
        registry = get_pack_registry()
        entry = registry.get("full-pack")
        assert entry is not None
        assert entry.status == "loaded"
        assert entry.contributions_summary["tools"] == 1

    def test_broken_manifest_recorded_as_failed(self, tmp_path: Path):
        broken = tmp_path / "broken-pack"
        broken.mkdir()
        (broken / "manifest.yaml").write_text(
            "name: BAD_NAME\nversion: 1.0.0\n",
        )
        results = load_packs(tmp_path)
        assert len(results) == 1
        assert results[0].status == PackLoadStatus.FAILED
        assert "manifest parse failed" in results[0].error.lower() or \
               "manifest parse failed" in results[0].error
        # Campaign-launch path doesn't raise.

    def test_one_broken_contribution_doesnt_fail_whole_pack(
        self, tmp_path: Path,
    ):
        """Pack with two tool contributions, one bad. The
        loader should record the failure as a warning + still
        finish with status=loaded for the rest."""
        pack = tmp_path / "partial-pack"
        pack.mkdir()
        (pack / "ok_tool.py").write_text("X = 1")
        _write_manifest(pack, """
            name: partial-pack
            version: 1.0.0
            contributes:
              tools:
                - module: ok_tool
                - module: nonexistent_module
        """)
        results = load_packs(tmp_path)
        assert results[0].status == PackLoadStatus.LOADED
        assert results[0].contributions_loaded["tools"] == 1
        # The broken contribution is recorded as a warning.
        assert any(
            "nonexistent_module" in w for w in results[0].warnings
        )


# ──────────────────────────────────────────────────────────────────────
# Audit log
# ──────────────────────────────────────────────────────────────────────


class TestAuditLogging:
    def test_load_writes_audit_entries(self, tmp_path: Path):
        _build_full_pack(tmp_path)
        audit = MagicMock()
        load_packs(tmp_path, audit_log=audit)
        audit.log_agent_action.assert_called_once()
        kw = audit.log_agent_action.call_args.kwargs
        assert kw["action"] == "pack_load"
        assert kw["agent"].startswith("pack:")
        assert "full-pack" in kw["agent"]

    def test_audit_records_failures_too(self, tmp_path: Path):
        broken = tmp_path / "broken"
        broken.mkdir()
        (broken / "manifest.yaml").write_text("name: BAD\n")
        audit = MagicMock()
        load_packs(tmp_path, audit_log=audit)
        # Even failed packs write an audit entry — operators
        # need the trail.
        audit.log_agent_action.assert_called_once()
