"""Agent scaffolder — `nexusrecon agent new` machinery.

What it does
- Interactive (or flag-driven) prompts gather the new agent's
  identity: name, role, goal, backstory, target pack.
- Writes a Python file that subclasses
  :class:`~nexusrecon.agents.base.BaseNexusAgent`, with the
  prompt registered via :func:`register_prompt` and citation
  validation hooked into the response path.
- Writes a smoke-test file using the same pattern as the
  bundled agent tests.
- Either creates a fresh pack (manifest + agent module +
  test) or appends to an existing pack's manifest.

Why no cookiecutter dependency
- Cookiecutter is a fine tool but adds a transitive Jinja
  dep we don't otherwise need + a global config dir +
  template inheritance machinery. The templates here are
  inlined Python multi-line strings — easy to edit, no
  dependency, and the operator's view of "what got
  generated" is the same Python file they'd write by hand.

UX
- Interactive Rich prompts (operator-friendly) with flag
  bypass (``--name`` / ``--role`` / ``--pack`` / ``--goal``
  / ``--backstory``) so scripted use works too.
- Existing-pack mode: ``--pack <path>`` adds the agent to
  that pack's manifest.
- New-pack mode: ``--pack new`` (or omit) creates a fresh
  pack directory with a fresh manifest.
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
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
class ScaffoldInputs:
    """Everything the scaffolder needs to write files.

    Constructed either from CLI flags directly or by the
    interactive walk-through (which fills missing values with
    Rich prompts). The split keeps the actual file-writing
    logic test-friendly: tests build a fully-populated
    ``ScaffoldInputs`` and call :func:`scaffold_agent`
    without going through the Rich prompts."""

    agent_name: str
    """snake_case identifier — becomes the AGENT_REGISTRY
    key + the Python class slug. Must match
    ``^[a-z][a-z0-9_]*$``."""

    role: str
    goal: str
    backstory: str
    pack_target: Path
    """Where the agent module lives. For ``--pack new`` this
    is a fresh dir under the pack root; for ``--pack <path>``
    it's the existing pack's root."""

    is_new_pack: bool
    pack_name: str = ""
    """Only meaningful when ``is_new_pack=True``. The slug
    used for the new pack's ``manifest.yaml``."""


# ──────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────


def validate_inputs(inputs: ScaffoldInputs) -> None:
    """Sanity-check what we're about to write. Raises
    ``ValueError`` on any rule violation; the CLI catches +
    surfaces."""
    if not _NAME_PATTERN.fullmatch(inputs.agent_name):
        raise ValueError(
            f"agent_name {inputs.agent_name!r} must be "
            f"snake_case (lower + underscore + digits, "
            f"starting with a letter)"
        )
    if not inputs.role.strip():
        raise ValueError("role must not be empty")
    if not inputs.goal.strip():
        raise ValueError("goal must not be empty")
    if inputs.is_new_pack and not inputs.pack_name:
        raise ValueError(
            "new pack requested but pack_name was empty"
        )


# ──────────────────────────────────────────────────────────────────────
# Templates
# ──────────────────────────────────────────────────────────────────────


def _agent_class_name(agent_slug: str) -> str:
    """Convert ``my_pack_agent`` → ``MyPackAgent``."""
    return "".join(p.capitalize() for p in agent_slug.split("_")) + "Agent"


def _agent_module_body(inputs: ScaffoldInputs) -> str:
    """Render the generated agent module. The body weaves
    :class:`BaseNexusAgent` together with
    :func:`register_prompt` and :func:`validate_citations`."""
    cls = _agent_class_name(inputs.agent_name)
    prompt_name = f"{inputs.pack_name or 'pack'}.{inputs.agent_name}"
    return textwrap.dedent(f'''
        """Auto-generated agent — {inputs.agent_name}.

        Created by ``nexusrecon agent new``. Edit the prompt
        body + role / goal / backstory below to match the
        capability you want this agent to add. The boilerplate
        wires up:

        - :func:`register_prompt` so the prompt is versioned in
          the audit chain.
        - :func:`validate_citations` so claims that don't cite
          real graph entities surface as violations.
        """
        from __future__ import annotations

        from typing import Any

        from nexusrecon.agents.base import BaseNexusAgent
        from nexusrecon.sdk.citation_guard import validate_citations
        from nexusrecon.sdk.prompt_versioning import register_prompt


        AGENT_PROMPT_VERSION = "1.0.0"
        AGENT_PROMPT_NAME = "{prompt_name}"

        AGENT_SYSTEM_PROMPT = """\
        {inputs.backstory.strip()}

        Always cite the graph entities you reference using
        ``[[entity_id]]`` syntax. Findings without citations
        will be flagged.
        """

        register_prompt(
            AGENT_PROMPT_NAME,
            AGENT_PROMPT_VERSION,
            AGENT_SYSTEM_PROMPT,
        )


        class {cls}(BaseNexusAgent):
            """{inputs.role.strip()}"""

            agent_name = "{inputs.agent_name}"
            role = """{inputs.role.strip()}"""
            goal = """{inputs.goal.strip()}"""
            backstory = AGENT_SYSTEM_PROMPT
            max_steps = 15
            max_tokens = 4096

            def review_citations(
                self,
                response: str,
                graph: Any,
            ) -> dict[str, Any]:
                """Validate citations in ``response`` against
                ``graph``. Returns the report as a dict — the
                campaign executor lifts violations into
                ``state["citation_violations"]``."""
                report = validate_citations(
                    response,
                    graph,
                    agent_name=self.agent_name,
                )
                return report.to_dict()
    ''').strip() + "\n"


def _agent_test_body(inputs: ScaffoldInputs) -> str:
    """Tiny smoke test so the contributor sees a working
    invocation immediately. Avoids depending on a real LLM
    by exercising the citation guardrail only."""
    cls = _agent_class_name(inputs.agent_name)
    module_name = inputs.agent_name
    return textwrap.dedent(f'''
        """Smoke test for the generated {inputs.agent_name}
        agent. Doesn't call an LLM — just checks the citation
        guardrail wiring."""
        from __future__ import annotations


        def test_agent_imports():
            from {module_name} import {cls}
            agent = {cls}()
            assert agent.agent_name == "{inputs.agent_name}"
            assert agent.role
            assert agent.backstory


        def test_citation_guardrail_runs_on_empty_graph():
            from nexusrecon.core.entity_graph import EntityGraph
            from {module_name} import {cls}

            graph = EntityGraph(
                campaign_id="cmp-test",
                engagement_id="eng-test",
            )
            agent = {cls}()
            report = agent.review_citations(
                "We found something but cited nothing.",
                graph,
            )
            assert report["agent_name"] == "{inputs.agent_name}"
            # The "found" verb without citations triggers the
            # info-level finding even with no graph entities.
            assert report["severity_counts"]["info"] >= 1
    ''').strip() + "\n"


def _manifest_dict_for_new_pack(inputs: ScaffoldInputs) -> dict[str, Any]:
    """Manifest body for a freshly-scaffolded pack."""
    cls = _agent_class_name(inputs.agent_name)
    return {
        "name": inputs.pack_name,
        "version": "0.1.0",
        "schema_version": CURRENT_SCHEMA_VERSION,
        "description": (
            f"Generated by `nexusrecon agent new`. "
            f"Ships the {inputs.agent_name} agent."
        ),
        "author": "",
        "license": "",
        "contributes": {
            "agents": [
                {
                    "module": inputs.agent_name,
                    "class_name": cls,
                    "registry_name": inputs.agent_name,
                },
            ],
        },
    }


def _append_agent_to_existing_manifest(
    manifest_path: Path,
    inputs: ScaffoldInputs,
) -> None:
    """Read an existing pack's manifest, add the new agent's
    contribution entry, write it back. Refuses to clobber an
    existing entry with the same ``registry_name`` — the
    operator should bump the version + pick a fresh slug
    instead."""
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(
            f"existing manifest at {manifest_path} is not a mapping"
        )
    contributes = raw.setdefault("contributes", {})
    agents = contributes.setdefault("agents", [])
    cls = _agent_class_name(inputs.agent_name)
    for entry in agents:
        if (
            isinstance(entry, dict)
            and entry.get("registry_name") == inputs.agent_name
        ):
            raise ValueError(
                f"manifest already declares an agent with "
                f"registry_name={inputs.agent_name!r}; pick a "
                f"different slug or bump the existing one."
            )
    agents.append({
        "module": inputs.agent_name,
        "class_name": cls,
        "registry_name": inputs.agent_name,
    })
    manifest_path.write_text(
        yaml.safe_dump(raw, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )


# ──────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ScaffoldResult:
    """Files written + the path to the new agent module
    (handy for the CLI to print)."""

    agent_module_path: Path
    manifest_path: Path
    test_path: Path | None
    is_new_pack: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_module_path": str(self.agent_module_path),
            "manifest_path": str(self.manifest_path),
            "test_path": str(self.test_path) if self.test_path else "",
            "is_new_pack": self.is_new_pack,
        }


def scaffold_agent(inputs: ScaffoldInputs) -> ScaffoldResult:
    """Write the agent + (if new pack) the manifest.

    Pre-conditions: ``validate_inputs`` has passed. The caller
    is responsible for that — the CLI runs it in the prompt
    layer so error messages can be Rich-formatted; tests
    invoke validate directly + raise.
    """
    validate_inputs(inputs)

    pack_dir = inputs.pack_target
    pack_dir.mkdir(parents=True, exist_ok=True)

    # Agent module file
    agent_path = pack_dir / f"{inputs.agent_name}.py"
    if agent_path.exists():
        raise FileExistsError(
            f"{agent_path} already exists; refusing to "
            f"overwrite. Delete it first or pick a different "
            f"slug."
        )
    agent_path.write_text(_agent_module_body(inputs), encoding="utf-8")

    # Test file — best effort, optional
    tests_dir = pack_dir / "tests"
    test_path: Path | None = None
    try:
        tests_dir.mkdir(exist_ok=True)
        test_path = tests_dir / f"test_{inputs.agent_name}.py"
        if not test_path.exists():
            test_path.write_text(
                _agent_test_body(inputs),
                encoding="utf-8",
            )
    except Exception as exc:
        log.debug("Test scaffolding skipped", error=str(exc))
        test_path = None

    # Manifest
    manifest_path = pack_dir / "manifest.yaml"
    if inputs.is_new_pack:
        if manifest_path.exists():
            raise FileExistsError(
                f"{manifest_path} already exists; if you "
                f"meant to extend it, pass --pack <its dir>."
            )
        body = _manifest_dict_for_new_pack(inputs)
        # Validate the body parses through Pydantic before
        # writing — surfaces errors immediately rather than
        # on the next `packs list`.
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
        # Sanity-check the existing manifest is parseable before
        # we touch it.
        parse_manifest(manifest_path)
        _append_agent_to_existing_manifest(manifest_path, inputs)
        # Re-parse to confirm we left it valid.
        parse_manifest(manifest_path)

    return ScaffoldResult(
        agent_module_path=agent_path,
        manifest_path=manifest_path,
        test_path=test_path,
        is_new_pack=inputs.is_new_pack,
    )
