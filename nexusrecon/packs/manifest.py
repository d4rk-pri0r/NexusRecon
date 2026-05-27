"""Manifest schema + parsing.

A recon pack's ``manifest.yaml`` declares its identity (name,
version, license), its dependencies on the NexusRecon core,
and its contributions. The :class:`PackManifest` Pydantic
model is the authoritative shape — both the loader and the
``nexusrecon packs validate`` CLI use it.

Example::

    name: corp-red-team
    version: 1.0.0
    schema_version: 1
    description: Aggressive corporate red-team pack.
    author: operator-x
    license: MIT
    manifest_hash: sha256:abc123...
    dependencies:
      nexusrecon: ">=0.6.0"
    contributes:
      tools:
        - module: corp_tools.my_tool
      agents:
        - module: corp_agents.exec_analyst
          class_name: ExecAnalystAgent
          registry_name: exec_analyst
      policies:
        - module: corp_policies
          class_name: CorpRedTeamPolicy
          name: corp_red_team
      report_templates:
        - name: executive_pretext
          path: templates/exec_pretext.md.j2
      entity_types:
        - name: BUSINESS_PARTNER
          value: business_partner
      relationship_types:
        - name: SUPPLY_CHAINS_TO
          value: supply_chains_to

Validation rules
- ``name`` must be a non-empty kebab-case slug. (Used as the
  directory name; we don't want surprises from paths with
  spaces or uppercase.)
- ``version`` must parse as a SemVer-ish triple, even if we
  don't yet enforce ordering against ``dependencies``.
- ``schema_version`` is 1 today. Future schema changes bump
  the major; the loader refuses unknown majors so old packs
  don't silently miss new fields.
- Each contribution carries the minimum metadata the loader
  needs (module path; optional ``class_name`` for agents and
  policies; ``name`` for things looked up by a string key).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, Field, field_validator

log = structlog.get_logger(__name__)


#: Current manifest schema major. Loaders refuse unknown
#: majors so old packs miss new fields LOUDLY rather than
#: silently. Bump this when the manifest shape changes in a
#: way old loaders can't handle (e.g. renaming a required
#: field).
CURRENT_SCHEMA_VERSION: int = 1


# ──────────────────────────────────────────────────────────────────────
# Per-contribution sub-models
# ──────────────────────────────────────────────────────────────────────


class ToolContribution(BaseModel):
    """A tool contribution.

    The pack's tool module imports ``@register_tool`` and
    decorates one or more :class:`OSINTTool` subclasses. The
    loader's job is just to ensure the module gets imported
    so the decorator runs; ``class_name`` is informational
    (surfaced in ``packs list`` output) and not used to look
    up the tool.
    """

    module: str = Field(..., description="Importable module path")
    class_name: str | None = Field(
        None, description="Class name (informational)",
    )


class AgentContribution(BaseModel):
    """An agent contribution.

    Unlike tools (which auto-register via decorator), agents
    are bound into :data:`AGENT_REGISTRY` by name. The loader
    imports the module, fetches ``class_name``, and writes
    ``AGENT_REGISTRY[registry_name] = class``.
    """

    module: str
    class_name: str
    registry_name: str = Field(
        ..., description="Key in AGENT_REGISTRY",
    )


class PolicyContribution(BaseModel):
    """A dispatch-policy contribution.

    Loader imports the module, fetches ``class_name``, calls
    :func:`register_policy(name, class_)`. Policies are then
    selectable via ``--dispatch-mode <name>``.
    """

    module: str
    class_name: str
    name: str = Field(..., description="Operator-facing name")


class ReportTemplateContribution(BaseModel):
    """A report-section template contribution.

    Templates are looked up by name when the report engine
    builds a section. ``path`` is relative to the pack's
    directory."""

    name: str
    path: str


class EntityTypeContribution(BaseModel):
    """A custom entity type added to the runtime extension
    registry.

    ``name`` is the canonical identifier (UPPER_SNAKE for
    consistency with the built-in StrEnum); ``value`` is the
    lowercase string stored on graph nodes. The loader
    enforces a naming pattern + collision-checks against
    built-ins."""

    name: str
    value: str

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", v):
            raise ValueError(
                "entity_type name must be UPPER_SNAKE_CASE",
            )
        return v

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", v):
            raise ValueError(
                "entity_type value must be lower_snake_case",
            )
        return v


class RelationshipTypeContribution(BaseModel):
    """A custom relationship type. Same shape and rules as
    :class:`EntityTypeContribution`."""

    name: str
    value: str

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", v):
            raise ValueError(
                "relationship_type name must be UPPER_SNAKE_CASE",
            )
        return v

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", v):
            raise ValueError(
                "relationship_type value must be lower_snake_case",
            )
        return v


# ──────────────────────────────────────────────────────────────────────
# Contributions container
# ──────────────────────────────────────────────────────────────────────


class PackContribution(BaseModel):
    """What a pack adds to a campaign. Every field is optional
    so minimal packs (e.g. ``tools`` only) don't need empty
    list boilerplate."""

    tools: list[ToolContribution] = Field(default_factory=list)
    agents: list[AgentContribution] = Field(default_factory=list)
    policies: list[PolicyContribution] = Field(default_factory=list)
    report_templates: list[ReportTemplateContribution] = Field(
        default_factory=list,
    )
    entity_types: list[EntityTypeContribution] = Field(
        default_factory=list,
    )
    relationship_types: list[RelationshipTypeContribution] = Field(
        default_factory=list,
    )

    def total(self) -> int:
        """Count of contributions across every category."""
        return (
            len(self.tools)
            + len(self.agents)
            + len(self.policies)
            + len(self.report_templates)
            + len(self.entity_types)
            + len(self.relationship_types)
        )


# ──────────────────────────────────────────────────────────────────────
# Top-level manifest
# ──────────────────────────────────────────────────────────────────────


_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$")


class PackManifest(BaseModel):
    """The whole ``manifest.yaml``. Constructed by
    :func:`parse_manifest`; consumed by :func:`load_packs`."""

    name: str = Field(..., description="Kebab-case pack identifier")
    version: str = Field(..., description="SemVer-ish triple")
    schema_version: int = Field(
        default=CURRENT_SCHEMA_VERSION,
        description="Manifest schema major version",
    )
    description: str = ""
    author: str = ""
    license: str = ""
    homepage: str = ""
    manifest_hash: str = Field(
        default="",
        description=(
            "SHA-256 of the canonical manifest body. Loader "
            "warns on mismatch but does not gate loading."
        ),
    )
    dependencies: dict[str, str] = Field(
        default_factory=dict,
        description="Min versions for nexusrecon + python packages",
    )
    contributes: PackContribution = Field(
        default_factory=PackContribution,
    )

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not _NAME_PATTERN.fullmatch(v):
            raise ValueError(
                "pack name must be kebab-case (lowercase + digits + hyphens, "
                "2-64 chars, starting with a letter)"
            )
        return v

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if not _VERSION_PATTERN.fullmatch(v):
            raise ValueError(
                "version must look like SemVer (e.g. 1.0.0 or 1.0.0-rc.1)"
            )
        return v


# ──────────────────────────────────────────────────────────────────────
# Parsing + hashing
# ──────────────────────────────────────────────────────────────────────


def parse_manifest(manifest_path: Path) -> PackManifest:
    """Load + validate a manifest YAML file.

    Raises ``ValueError`` (with the validation error chain) on
    any failure: missing file, malformed YAML, schema
    mismatch, or unknown schema_version major."""
    if not manifest_path.exists():
        raise ValueError(f"manifest not found: {manifest_path}")
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"malformed YAML in {manifest_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(
            f"manifest must be a YAML mapping (got {type(raw).__name__})",
        )

    manifest = PackManifest(**raw)

    if manifest.schema_version != CURRENT_SCHEMA_VERSION:
        # Future-proofing: if a newer pack ships schema_version
        # 2 and we're a 1-only loader, refuse rather than risk
        # silently dropping new contributions.
        raise ValueError(
            f"unsupported manifest schema_version "
            f"{manifest.schema_version}; this build understands "
            f"{CURRENT_SCHEMA_VERSION}"
        )

    return manifest


def compute_manifest_hash(manifest: PackManifest) -> str:
    """Compute the canonical manifest hash.

    Strategy: serialise the manifest to JSON with sorted keys
    + the ``manifest_hash`` field removed, hash with SHA-256.
    This means a pack author can compute the hash by stripping
    that one field; recomputation by the loader is symmetric.
    """
    body = manifest.model_dump(exclude={"manifest_hash"})
    canonical = json.dumps(body, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
