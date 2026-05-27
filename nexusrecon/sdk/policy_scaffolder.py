"""Dispatch-policy scaffolder — `nexusrecon policy new`.

Generates a :class:`DispatchPolicy` subclass with the
operator-chosen eligible_phases + caps. Smaller than the
tool / agent scaffolders because :class:`DispatchPolicy`
itself is smaller; the same shape patterns still apply for
maintainability.
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from nexusrecon.packs.manifest import (
    CURRENT_SCHEMA_VERSION,
    PackManifest,
    parse_manifest,
)

log = structlog.get_logger(__name__)


_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

CANONICAL_PHASES = (
    "phase1", "phase2", "phase2_5", "phase3", "phase4", "phase5",
    "phase6", "phase7", "phase7_5", "phase7_7", "phase8", "phase9",
)


@dataclass
class PolicyScaffoldInputs:
    policy_name: str
    """snake_case identifier — becomes the operator-facing
    name (selectable via ``--dispatch-mode <name>``)."""
    description: str
    max_per_cycle: int = 5
    max_total: int = 30
    eligible_phases: list[str] = field(default_factory=list)
    """Empty list means "every phase" — same semantics as
    :class:`FullPolicy`."""
    pack_target: Path = field(default_factory=lambda: Path("."))
    is_new_pack: bool = False
    pack_name: str = ""


def validate_policy_inputs(inputs: PolicyScaffoldInputs) -> None:
    if not _NAME_PATTERN.fullmatch(inputs.policy_name):
        raise ValueError(
            f"policy_name {inputs.policy_name!r} must be snake_case"
        )
    if not inputs.description.strip():
        raise ValueError("description must not be empty")
    if inputs.max_per_cycle < 0 or inputs.max_total < 0:
        raise ValueError("caps must be non-negative")
    if inputs.max_per_cycle > inputs.max_total:
        raise ValueError(
            f"max_per_cycle ({inputs.max_per_cycle}) cannot exceed "
            f"max_total ({inputs.max_total})"
        )
    invalid = [
        p for p in inputs.eligible_phases
        if p not in CANONICAL_PHASES
    ]
    if invalid:
        raise ValueError(
            f"unknown phases in eligible_phases: {invalid}; "
            f"canonical: {list(CANONICAL_PHASES)}"
        )
    if inputs.is_new_pack and not inputs.pack_name:
        raise ValueError(
            "new pack requested but pack_name was empty"
        )


def _policy_class_name(slug: str) -> str:
    return "".join(p.capitalize() for p in slug.split("_")) + "Policy"


def _policy_module_body(inputs: PolicyScaffoldInputs) -> str:
    cls = _policy_class_name(inputs.policy_name)
    phases_init = (
        "frozenset()"
        if not inputs.eligible_phases
        else f"frozenset({set(inputs.eligible_phases)!r})"
    )
    if not inputs.eligible_phases:
        # Empty = match every phase, like FullPolicy.
        method_body = "        return True"
    else:
        method_body = "        return phase in self.eligible_phases"
    return textwrap.dedent(f'''
        """Auto-generated dispatch policy — {inputs.policy_name}.

        Created by ``nexusrecon policy new``. Selectable via
        ``--dispatch-mode {inputs.policy_name}`` once the
        pack is loaded."""
        from __future__ import annotations

        from dataclasses import dataclass, field

        from nexusrecon.strategy.policy import DispatchPolicy


        @dataclass
        class {cls}(DispatchPolicy):
            """{inputs.description.strip()}"""

            name: str = "{inputs.policy_name}"
            max_per_cycle: int = {inputs.max_per_cycle}
            max_total: int = {inputs.max_total}
            eligible_phases: frozenset[str] = field(
                default_factory=lambda: {phases_init},
            )

            def should_dispatch_for_phase(self, phase: str) -> bool:
        {method_body}
    ''').strip() + "\n"


def _policy_test_body(inputs: PolicyScaffoldInputs) -> str:
    cls = _policy_class_name(inputs.policy_name)
    module_name = inputs.policy_name
    if not inputs.eligible_phases:
        sample_phase = "phase1"
        expected = True
    else:
        sample_phase = inputs.eligible_phases[0]
        expected = True
    return textwrap.dedent(f'''
        """Smoke test for the generated {inputs.policy_name}
        policy."""
        from __future__ import annotations


        def test_policy_caps():
            from {module_name} import {cls}
            p = {cls}()
            assert p.name == "{inputs.policy_name}"
            assert p.max_per_cycle == {inputs.max_per_cycle}
            assert p.max_total == {inputs.max_total}


        def test_dispatch_eligibility():
            from {module_name} import {cls}
            p = {cls}()
            assert p.should_dispatch_for_phase("{sample_phase}") is {expected}
    ''').strip() + "\n"


def _manifest_dict_for_new_pack(inputs: PolicyScaffoldInputs) -> dict[str, Any]:
    cls = _policy_class_name(inputs.policy_name)
    return {
        "name": inputs.pack_name,
        "version": "0.1.0",
        "schema_version": CURRENT_SCHEMA_VERSION,
        "description": (
            f"Generated by `nexusrecon policy new`. Ships the "
            f"{inputs.policy_name} dispatch policy."
        ),
        "contributes": {
            "policies": [
                {
                    "module": inputs.policy_name,
                    "class_name": cls,
                    "name": inputs.policy_name,
                },
            ],
        },
    }


def _append_policy_to_existing_manifest(
    manifest_path: Path, inputs: PolicyScaffoldInputs,
) -> None:
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(
            f"existing manifest at {manifest_path} is not a mapping"
        )
    contributes = raw.setdefault("contributes", {})
    policies = contributes.setdefault("policies", [])
    for entry in policies:
        if (
            isinstance(entry, dict)
            and entry.get("name") == inputs.policy_name
        ):
            raise ValueError(
                f"manifest already declares a policy with "
                f"name={inputs.policy_name!r}"
            )
    policies.append({
        "module": inputs.policy_name,
        "class_name": _policy_class_name(inputs.policy_name),
        "name": inputs.policy_name,
    })
    manifest_path.write_text(
        yaml.safe_dump(raw, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


@dataclass
class PolicyScaffoldResult:
    policy_module_path: Path
    manifest_path: Path
    test_path: Path | None
    is_new_pack: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_module_path": str(self.policy_module_path),
            "manifest_path": str(self.manifest_path),
            "test_path": str(self.test_path) if self.test_path else "",
            "is_new_pack": self.is_new_pack,
        }


def scaffold_policy(inputs: PolicyScaffoldInputs) -> PolicyScaffoldResult:
    validate_policy_inputs(inputs)
    pack_dir = inputs.pack_target
    pack_dir.mkdir(parents=True, exist_ok=True)

    policy_path = pack_dir / f"{inputs.policy_name}.py"
    if policy_path.exists():
        raise FileExistsError(
            f"{policy_path} already exists; refusing to overwrite.",
        )
    policy_path.write_text(_policy_module_body(inputs), encoding="utf-8")

    tests_dir = pack_dir / "tests"
    test_path: Path | None = None
    try:
        tests_dir.mkdir(exist_ok=True)
        test_path = tests_dir / f"test_{inputs.policy_name}.py"
        if not test_path.exists():
            test_path.write_text(
                _policy_test_body(inputs), encoding="utf-8",
            )
    except Exception as exc:
        log.debug("Policy test scaffolding skipped", error=str(exc))
        test_path = None

    manifest_path = pack_dir / "manifest.yaml"
    if inputs.is_new_pack:
        if manifest_path.exists():
            raise FileExistsError(
                f"{manifest_path} already exists; pass "
                f"--pack <existing-dir> instead.",
            )
        body = _manifest_dict_for_new_pack(inputs)
        PackManifest(**body)
        manifest_path.write_text(
            yaml.safe_dump(body, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
    else:
        if not manifest_path.exists():
            raise FileNotFoundError(
                f"no manifest at {manifest_path}; did you mean "
                f"--pack new?"
            )
        parse_manifest(manifest_path)
        _append_policy_to_existing_manifest(manifest_path, inputs)
        parse_manifest(manifest_path)

    return PolicyScaffoldResult(
        policy_module_path=policy_path,
        manifest_path=manifest_path,
        test_path=test_path,
        is_new_pack=inputs.is_new_pack,
    )
