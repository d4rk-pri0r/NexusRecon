"""Tests for PR C2: tool + policy scaffolders.

PR C2 adds two scaffolders under ``nexusrecon/sdk/``,
parallel to ``agent_scaffolder`` from PR B:

  - ``tool_scaffolder.scaffold_tool(ToolScaffoldInputs)``
  - ``policy_scaffolder.scaffold_policy(PolicyScaffoldInputs)``

Each writes a Python module + manifest entry (new pack OR
appending to existing) + smoke test, mirroring the agent
scaffolder shape.

Coverage
- ``validate_tool_inputs`` catches bad slugs, empty fields,
  unknown categories / tiers, empty target_types, missing
  pack name on new-pack mode.
- ``validate_policy_inputs`` catches bad slugs, negative caps,
  inverted caps, unknown phases.
- ``scaffold_tool`` end-to-end: parseable manifest +
  importable module + @register_tool decorator applied.
- ``scaffold_policy`` end-to-end: parseable manifest +
  importable module + policy class instantiable + caps
  preserved.
- Each scaffolder refuses to clobber existing files +
  refuses duplicate manifest entries on append.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
import yaml

from nexusrecon.sdk.policy_scaffolder import (
    PolicyScaffoldInputs,
    _policy_class_name,
    scaffold_policy,
    validate_policy_inputs,
)
from nexusrecon.sdk.tool_scaffolder import (
    ToolScaffoldInputs,
    _tool_class_name,
    scaffold_tool,
    validate_tool_inputs,
)


# ──────────────────────────────────────────────────────────────────────
# Tool scaffolder — validation
# ──────────────────────────────────────────────────────────────────────


class TestValidateToolInputs:
    def test_good_inputs_pass(self, tmp_path: Path):
        inputs = ToolScaffoldInputs(
            tool_name="my_tool", description="A tool",
            category="subdomain", tier="T0",
            target_types=["domain"],
            pack_target=tmp_path, is_new_pack=True,
            pack_name="my-pack",
        )
        validate_tool_inputs(inputs)

    def test_bad_slug_rejected(self, tmp_path: Path):
        inputs = ToolScaffoldInputs(
            tool_name="Bad-Slug", description="x",
            category="subdomain", tier="T0",
            target_types=["domain"], pack_target=tmp_path,
            is_new_pack=True, pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="snake_case"):
            validate_tool_inputs(inputs)

    def test_empty_description_rejected(self, tmp_path: Path):
        inputs = ToolScaffoldInputs(
            tool_name="my_tool", description="",
            category="subdomain", tier="T0",
            target_types=["domain"], pack_target=tmp_path,
            is_new_pack=True, pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="description"):
            validate_tool_inputs(inputs)

    def test_unknown_category_rejected(self, tmp_path: Path):
        inputs = ToolScaffoldInputs(
            tool_name="my_tool", description="x",
            category="cosmic_rays", tier="T0",
            target_types=["domain"], pack_target=tmp_path,
            is_new_pack=True, pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="category"):
            validate_tool_inputs(inputs)

    def test_unknown_tier_rejected(self, tmp_path: Path):
        inputs = ToolScaffoldInputs(
            tool_name="my_tool", description="x",
            category="subdomain", tier="T9",
            target_types=["domain"], pack_target=tmp_path,
            is_new_pack=True, pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="tier"):
            validate_tool_inputs(inputs)

    def test_empty_target_types_rejected(self, tmp_path: Path):
        inputs = ToolScaffoldInputs(
            tool_name="my_tool", description="x",
            category="subdomain", tier="T0",
            target_types=[], pack_target=tmp_path,
            is_new_pack=True, pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="target_types"):
            validate_tool_inputs(inputs)


# ──────────────────────────────────────────────────────────────────────
# Tool scaffolder — end-to-end
# ──────────────────────────────────────────────────────────────────────


class TestScaffoldTool:
    def test_creates_new_pack(self, tmp_path: Path):
        pack_dir = tmp_path / "tools-pack"
        inputs = ToolScaffoldInputs(
            tool_name="my_tool",
            description="A test tool",
            category="subdomain", tier="T0",
            target_types=["domain", "subdomain"],
            cost_per_run_usd=0.05,
            pack_target=pack_dir,
            is_new_pack=True, pack_name="tools-pack",
        )
        result = scaffold_tool(inputs)
        assert result.tool_module_path.exists()
        assert result.manifest_path.exists()
        body = result.tool_module_path.read_text()
        assert "@register_tool" in body
        assert "class MyToolTool" in body
        assert "Category.SUBDOMAIN" in body
        assert "Tier.T0" in body

    def test_refuses_to_clobber(self, tmp_path: Path):
        pack_dir = tmp_path / "tools-pack"
        inputs = ToolScaffoldInputs(
            tool_name="my_tool", description="x",
            category="subdomain", tier="T0",
            target_types=["domain"], pack_target=pack_dir,
            is_new_pack=True, pack_name="tools-pack",
        )
        scaffold_tool(inputs)
        with pytest.raises(FileExistsError):
            scaffold_tool(inputs)

    def test_appends_to_existing_pack(self, tmp_path: Path):
        pack_dir = tmp_path / "existing"
        pack_dir.mkdir()
        (pack_dir / "manifest.yaml").write_text(yaml.safe_dump({
            "name": "existing", "version": "1.0.0",
            "contributes": {"tools": [
                {"module": "first_tool", "class_name": "FirstTool"},
            ]},
        }))
        (pack_dir / "first_tool.py").write_text("")
        inputs = ToolScaffoldInputs(
            tool_name="second_tool", description="x",
            category="email", tier="T1",
            target_types=["email"], pack_target=pack_dir,
            is_new_pack=False,
        )
        scaffold_tool(inputs)
        from nexusrecon.packs import parse_manifest
        manifest = parse_manifest(pack_dir / "manifest.yaml")
        modules = {t.module for t in manifest.contributes.tools}
        assert modules == {"first_tool", "second_tool"}

    def test_refuses_duplicate_module_on_append(self, tmp_path: Path):
        pack_dir = tmp_path / "existing"
        pack_dir.mkdir()
        (pack_dir / "manifest.yaml").write_text(yaml.safe_dump({
            "name": "existing", "version": "1.0.0",
            "contributes": {"tools": [
                {"module": "dup", "class_name": "DupTool"},
            ]},
        }))
        inputs = ToolScaffoldInputs(
            tool_name="dup", description="x",
            category="subdomain", tier="T0",
            target_types=["domain"], pack_target=pack_dir,
            is_new_pack=False,
        )
        with pytest.raises(ValueError, match="module"):
            scaffold_tool(inputs)


# ──────────────────────────────────────────────────────────────────────
# Policy scaffolder — validation
# ──────────────────────────────────────────────────────────────────────


class TestValidatePolicyInputs:
    def test_good_inputs_pass(self, tmp_path: Path):
        inputs = PolicyScaffoldInputs(
            policy_name="my_policy", description="x",
            max_per_cycle=5, max_total=30,
            eligible_phases=["phase1", "phase4"],
            pack_target=tmp_path, is_new_pack=True,
            pack_name="my-pack",
        )
        validate_policy_inputs(inputs)

    def test_inverted_caps_rejected(self, tmp_path: Path):
        inputs = PolicyScaffoldInputs(
            policy_name="my_policy", description="x",
            max_per_cycle=50, max_total=5,
            pack_target=tmp_path, is_new_pack=True,
            pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="exceed"):
            validate_policy_inputs(inputs)

    def test_negative_cap_rejected(self, tmp_path: Path):
        inputs = PolicyScaffoldInputs(
            policy_name="my_policy", description="x",
            max_per_cycle=-1, max_total=5,
            pack_target=tmp_path, is_new_pack=True,
            pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="non-negative"):
            validate_policy_inputs(inputs)

    def test_unknown_phase_rejected(self, tmp_path: Path):
        inputs = PolicyScaffoldInputs(
            policy_name="my_policy", description="x",
            max_per_cycle=5, max_total=30,
            eligible_phases=["phase999"],
            pack_target=tmp_path, is_new_pack=True,
            pack_name="my-pack",
        )
        with pytest.raises(ValueError, match="phases"):
            validate_policy_inputs(inputs)


# ──────────────────────────────────────────────────────────────────────
# Policy scaffolder — end-to-end
# ──────────────────────────────────────────────────────────────────────


class TestScaffoldPolicy:
    def test_creates_new_pack(self, tmp_path: Path):
        pack_dir = tmp_path / "policy-pack"
        inputs = PolicyScaffoldInputs(
            policy_name="my_policy",
            description="An aggressive corp policy",
            max_per_cycle=10, max_total=50,
            eligible_phases=["phase1", "phase4", "phase7"],
            pack_target=pack_dir, is_new_pack=True,
            pack_name="policy-pack",
        )
        result = scaffold_policy(inputs)
        assert result.policy_module_path.exists()
        body = result.policy_module_path.read_text()
        assert "class MyPolicyPolicy" in body
        assert "DispatchPolicy" in body
        assert "max_per_cycle: int = 10" in body

    def test_generated_policy_is_importable(self, tmp_path: Path):
        pack_dir = tmp_path / "policy-pack-imp"
        inputs = PolicyScaffoldInputs(
            policy_name="importable_policy",
            description="Test", max_per_cycle=7, max_total=25,
            eligible_phases=["phase1"],
            pack_target=pack_dir, is_new_pack=True,
            pack_name="policy-pack-imp",
        )
        scaffold_policy(inputs)
        sys.path.insert(0, str(pack_dir))
        try:
            mod = importlib.import_module("importable_policy")
            cls = getattr(mod, _policy_class_name("importable_policy"))
            policy = cls()
            assert policy.name == "importable_policy"
            assert policy.max_per_cycle == 7
            assert policy.max_total == 25
            assert policy.should_dispatch_for_phase("phase1") is True
            assert policy.should_dispatch_for_phase("phase2") is False
        finally:
            sys.path.remove(str(pack_dir))
            sys.modules.pop("importable_policy", None)

    def test_empty_eligible_phases_means_all_phases(self, tmp_path: Path):
        pack_dir = tmp_path / "all-phases-pack"
        inputs = PolicyScaffoldInputs(
            policy_name="every_phase",
            description="Dispatch after every phase",
            max_per_cycle=5, max_total=50,
            eligible_phases=[],
            pack_target=pack_dir, is_new_pack=True,
            pack_name="all-phases-pack",
        )
        scaffold_policy(inputs)
        sys.path.insert(0, str(pack_dir))
        try:
            mod = importlib.import_module("every_phase")
            cls = getattr(mod, _policy_class_name("every_phase"))
            policy = cls()
            assert policy.should_dispatch_for_phase("phase1") is True
            assert policy.should_dispatch_for_phase("phase9") is True
        finally:
            sys.path.remove(str(pack_dir))
            sys.modules.pop("every_phase", None)

    def test_refuses_duplicate_policy_name_on_append(self, tmp_path: Path):
        pack_dir = tmp_path / "existing"
        pack_dir.mkdir()
        (pack_dir / "manifest.yaml").write_text(yaml.safe_dump({
            "name": "existing", "version": "1.0.0",
            "contributes": {"policies": [
                {"module": "dup_policy", "class_name": "DupPolicy",
                 "name": "dup_policy"},
            ]},
        }))
        inputs = PolicyScaffoldInputs(
            policy_name="dup_policy", description="x",
            max_per_cycle=5, max_total=30,
            pack_target=pack_dir, is_new_pack=False,
        )
        with pytest.raises(ValueError, match="name"):
            scaffold_policy(inputs)
