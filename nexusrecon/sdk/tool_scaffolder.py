"""Tool scaffolder — `nexusrecon tool new`.

Same shape as :mod:`nexusrecon.sdk.agent_scaffolder`. The
generated module subclasses :class:`OSINTTool` and registers
itself via ``@register_tool``. Interactive capability picker
gathers the operator's choices for category, target types,
tier, and cost.

Why a separate module instead of generalising
agent_scaffolder
- Tools and agents differ enough at the file level
  (decorator registration vs. ``AGENT_REGISTRY`` binding,
  ``run`` method signature with ``ToolResult``) that
  conditional template logic would be uglier than two
  focused files.
- A future "things-in-common-here" refactor is cheap when
  there are three scaffolders, not two.
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


# ──────────────────────────────────────────────────────────────────────
# Inputs
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ToolScaffoldInputs:
    """Inputs for tool scaffolding. Mirrors
    :class:`AgentScaffoldInputs` shape."""

    tool_name: str
    """snake_case identifier."""

    description: str
    category: str  # one of Category enum values
    tier: str  # "T0" | "T1" | "T2" | "T3"
    target_types: list[str] = field(default_factory=list)
    """e.g. ["domain", "ip", "url"]."""
    cost_per_run_usd: float = 0.0
    pack_target: Path = field(default_factory=lambda: Path("."))
    is_new_pack: bool = False
    pack_name: str = ""


def validate_tool_inputs(inputs: ToolScaffoldInputs) -> None:
    """Raise ``ValueError`` on any rule violation."""
    if not _NAME_PATTERN.fullmatch(inputs.tool_name):
        raise ValueError(
            f"tool_name {inputs.tool_name!r} must be snake_case "
            f"(lower + underscore + digits, starting with a letter)"
        )
    if not inputs.description.strip():
        raise ValueError("description must not be empty")
    # Late-validate category against the real enum so a typo
    # surfaces immediately.
    from nexusrecon.tools.base import Category, Tier
    valid_categories = {c.value for c in Category}
    if inputs.category not in valid_categories:
        raise ValueError(
            f"category {inputs.category!r} not in {sorted(valid_categories)}"
        )
    if inputs.tier not in {t.value for t in Tier}:
        raise ValueError(
            f"tier {inputs.tier!r} not in {sorted(t.value for t in Tier)}"
        )
    if not inputs.target_types:
        raise ValueError("target_types must not be empty")
    if inputs.is_new_pack and not inputs.pack_name:
        raise ValueError(
            "new pack requested but pack_name was empty"
        )


# ──────────────────────────────────────────────────────────────────────
# Templates
# ──────────────────────────────────────────────────────────────────────


def _tool_class_name(slug: str) -> str:
    """``my_cool_tool`` → ``MyCoolTool``."""
    return "".join(p.capitalize() for p in slug.split("_")) + "Tool"


def _tool_module_body(inputs: ToolScaffoldInputs) -> str:
    cls = _tool_class_name(inputs.tool_name)
    targets_repr = repr(inputs.target_types)
    return textwrap.dedent(f'''
        """Auto-generated tool — {inputs.tool_name}.

        Created by ``nexusrecon tool new``. Implement
        :meth:`run` to actually call your data source; the
        boilerplate around scope, caching, and rate limiting
        is handled by the registry."""
        from __future__ import annotations

        from typing import Any

        from nexusrecon.tools.base import (
            Category,
            OSINTTool,
            Tier,
            ToolResult,
        )
        from nexusrecon.tools.registry import register_tool


        @register_tool
        class {cls}(OSINTTool):
            """{inputs.description.strip()}"""

            name: str = "{inputs.tool_name}"
            tier: Tier = Tier.{inputs.tier}
            category: Category = Category.{inputs.category.upper()}
            cost_per_run_usd: float = {inputs.cost_per_run_usd}
            target_types: list[str] = {targets_repr}
            description: str = """{inputs.description.strip()}"""

            async def run(
                self, target: str, **kwargs: Any,
            ) -> ToolResult:
                """Replace this stub with your real call. The
                return value should be a :class:`ToolResult`
                carrying parsed data + provenance markers."""
                return ToolResult(
                    success=False,
                    tool_name=self.name,
                    target=target,
                    data={{}},
                    error=(
                        "{inputs.tool_name}.run() is a stub — "
                        "implement it before invoking."
                    ),
                )
    ''').strip() + "\n"


def _tool_test_body(inputs: ToolScaffoldInputs) -> str:
    cls = _tool_class_name(inputs.tool_name)
    module_name = inputs.tool_name
    return textwrap.dedent(f'''
        """Smoke test for the generated {inputs.tool_name}
        tool. Doesn't run the network call — just checks the
        registry wiring + the stub behavior."""
        from __future__ import annotations

        import pytest


        def test_tool_class_imports():
            from {module_name} import {cls}
            t = {cls}()
            assert t.name == "{inputs.tool_name}"
            assert t.category.value == "{inputs.category}"


        @pytest.mark.asyncio
        async def test_stub_returns_error_until_implemented():
            from {module_name} import {cls}
            t = {cls}()
            result = await t.run("example.com")
            assert result.success is False
            assert "stub" in (result.error or "").lower()
    ''').strip() + "\n"


def _manifest_dict_for_new_pack(inputs: ToolScaffoldInputs) -> dict[str, Any]:
    cls = _tool_class_name(inputs.tool_name)
    return {
        "name": inputs.pack_name,
        "version": "0.1.0",
        "schema_version": CURRENT_SCHEMA_VERSION,
        "description": (
            f"Generated by `nexusrecon tool new`. "
            f"Ships the {inputs.tool_name} tool."
        ),
        "contributes": {
            "tools": [
                {
                    "module": inputs.tool_name,
                    "class_name": cls,
                },
            ],
        },
    }


def _append_tool_to_existing_manifest(
    manifest_path: Path, inputs: ToolScaffoldInputs,
) -> None:
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(
            f"existing manifest at {manifest_path} is not a mapping"
        )
    contributes = raw.setdefault("contributes", {})
    tools = contributes.setdefault("tools", [])
    for entry in tools:
        if (
            isinstance(entry, dict)
            and entry.get("module") == inputs.tool_name
        ):
            raise ValueError(
                f"manifest already declares a tool with "
                f"module={inputs.tool_name!r}; pick a "
                f"different slug or remove the existing one."
            )
    tools.append({
        "module": inputs.tool_name,
        "class_name": _tool_class_name(inputs.tool_name),
    })
    manifest_path.write_text(
        yaml.safe_dump(raw, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


# ──────────────────────────────────────────────────────────────────────
# Result
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ToolScaffoldResult:
    tool_module_path: Path
    manifest_path: Path
    test_path: Path | None
    is_new_pack: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_module_path": str(self.tool_module_path),
            "manifest_path": str(self.manifest_path),
            "test_path": str(self.test_path) if self.test_path else "",
            "is_new_pack": self.is_new_pack,
        }


def scaffold_tool(inputs: ToolScaffoldInputs) -> ToolScaffoldResult:
    """Write tool module + (if new pack) the manifest. Pre-
    condition: ``validate_tool_inputs`` has passed."""
    validate_tool_inputs(inputs)
    pack_dir = inputs.pack_target
    pack_dir.mkdir(parents=True, exist_ok=True)

    tool_path = pack_dir / f"{inputs.tool_name}.py"
    if tool_path.exists():
        raise FileExistsError(
            f"{tool_path} already exists; refusing to overwrite.",
        )
    tool_path.write_text(_tool_module_body(inputs), encoding="utf-8")

    tests_dir = pack_dir / "tests"
    test_path: Path | None = None
    try:
        tests_dir.mkdir(exist_ok=True)
        test_path = tests_dir / f"test_{inputs.tool_name}.py"
        if not test_path.exists():
            test_path.write_text(
                _tool_test_body(inputs), encoding="utf-8",
            )
    except Exception as exc:
        log.debug("Tool test scaffolding skipped", error=str(exc))
        test_path = None

    manifest_path = pack_dir / "manifest.yaml"
    if inputs.is_new_pack:
        if manifest_path.exists():
            raise FileExistsError(
                f"{manifest_path} already exists; pass "
                f"--pack <existing-dir> instead.",
            )
        body = _manifest_dict_for_new_pack(inputs)
        PackManifest(**body)  # parse-check before writing
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
        _append_tool_to_existing_manifest(manifest_path, inputs)
        parse_manifest(manifest_path)

    return ToolScaffoldResult(
        tool_module_path=tool_path,
        manifest_path=manifest_path,
        test_path=test_path,
        is_new_pack=inputs.is_new_pack,
    )
