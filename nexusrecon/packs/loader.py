"""Pack discovery + loader.

The loader's job is to walk the pack directory, parse each
manifest, and turn its declared contributions into runtime
state: imported modules (tool decorators auto-fire), agent
registry entries, dispatch-policy registrations, custom-type
runtime registrations, and report-template registrations.

Failure isolation
- Per the architecture decisions: skip + warn on failure.
- Every step is wrapped in its own try/except. A broken
  manifest, a missing module, an import error, a collision in
  the extension registry — none of these abort the campaign;
  they land in ``PackRegistry`` as a ``failed`` entry with
  the error string preserved for ``packs list``.
- Successful loads + every failure write to the audit log
  via :meth:`AuditLog.log_agent_action` (or are queued for
  later when the audit log isn't yet bound — tests + early
  startup).

sys.path management
- The pack's directory is prepended to ``sys.path`` so its
  modules (declared as plain Python paths in the manifest)
  resolve. We don't try to be clever with editable installs
  or namespace packages — packs are just directories.
- We DO NOT remove the directory from sys.path after loading.
  That would break delayed imports inside the pack's code.
"""
from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import structlog

from nexusrecon.packs.manifest import (
    PackManifest,
    compute_manifest_hash,
    parse_manifest,
)
from nexusrecon.packs.registry import (
    PackRegistryEntry,
    get_pack_registry,
    register_entity_type,
    register_relationship_type,
)

log = structlog.get_logger(__name__)


DEFAULT_PACK_DIR_ENV = "NEXUSRECON_PACK_DIR"
DEFAULT_PACK_DIR = "~/.nexusrecon/packs"


class PackLoadStatus(StrEnum):
    """The status a pack ends up with after a load attempt."""
    LOADED = "loaded"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class PackLoadResult:
    """What :func:`load_packs` returns per attempted pack.
    Mirrors :class:`PackRegistryEntry` but carries the full
    manifest object so callers can inspect (e.g. for ``packs
    list --json`` output)."""

    pack_dir: Path
    status: PackLoadStatus
    manifest: PackManifest | None = None
    contributions_loaded: dict[str, int] = field(default_factory=dict)
    error: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_dir": str(self.pack_dir),
            "status": self.status.value,
            "name": self.manifest.name if self.manifest else "",
            "version": self.manifest.version if self.manifest else "",
            "contributions_loaded": dict(self.contributions_loaded),
            "error": self.error,
            "warnings": list(self.warnings),
        }


# ──────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────


def _resolve_pack_dir(explicit: Path | str | None = None) -> Path:
    """Resolve the pack directory. Precedence:
    1. Explicit argument (tests + CLI override).
    2. ``NEXUSRECON_PACK_DIR`` env var.
    3. ``~/.nexusrecon/packs``.
    """
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    env_val = os.environ.get(DEFAULT_PACK_DIR_ENV)
    if env_val:
        return Path(env_val).expanduser().resolve()
    return Path(DEFAULT_PACK_DIR).expanduser().resolve()


def discover_packs(pack_dir: Path | str | None = None) -> list[Path]:
    """Find pack directories under ``pack_dir``. A directory
    counts as a candidate when it contains ``manifest.yaml``
    at its top level. Returns sorted absolute paths so
    ``load_packs`` produces deterministic ordering."""
    base = _resolve_pack_dir(pack_dir)
    if not base.exists():
        return []
    candidates: list[Path] = []
    for entry in sorted(base.iterdir()):
        if not entry.is_dir():
            continue
        if (entry / "manifest.yaml").exists():
            candidates.append(entry)
    return candidates


# ──────────────────────────────────────────────────────────────────────
# Loading
# ──────────────────────────────────────────────────────────────────────


def load_packs(
    pack_dir: Path | str | None = None,
    *,
    audit_log: Any | None = None,
) -> list[PackLoadResult]:
    """Discover + load every pack under ``pack_dir``.

    Returns one :class:`PackLoadResult` per candidate. The
    :class:`PackRegistry` singleton is updated in-place so
    later consumers (CLI, audit log, TUI) can read pack state
    without threading it through every call site."""
    results: list[PackLoadResult] = []
    registry = get_pack_registry()

    for pack_path in discover_packs(pack_dir):
        result = _load_one(pack_path)
        results.append(result)
        registry.add(PackRegistryEntry(
            name=result.manifest.name if result.manifest else pack_path.name,
            version=result.manifest.version if result.manifest else "",
            path=str(pack_path),
            status=result.status.value,
            contributions_summary=dict(result.contributions_loaded),
            error=result.error,
        ))
        # Audit-log every attempt — successes + failures.
        # Operators want the trail to show what was tried, not
        # just what worked.
        if audit_log is not None:
            try:
                audit_log.log_agent_action(
                    agent=f"pack:{result.manifest.name if result.manifest else pack_path.name}",
                    action="pack_load",
                    details=result.to_dict(),
                )
            except Exception as exc:
                log.debug("Pack audit log write failed", error=str(exc))

    return results


def _load_one(pack_path: Path) -> PackLoadResult:
    """Load a single pack directory. All failures are caught
    + returned as a ``failed`` result; the function never
    raises so the outer ``load_packs`` walk continues."""
    result = PackLoadResult(
        pack_dir=pack_path,
        status=PackLoadStatus.LOADED,
    )

    # ── Parse manifest ───────────────────────────────────────
    manifest_path = pack_path / "manifest.yaml"
    try:
        manifest = parse_manifest(manifest_path)
    except Exception as exc:
        result.status = PackLoadStatus.FAILED
        result.error = f"manifest parse failed: {exc}"
        log.warning("Pack manifest parse failed",
                    pack=pack_path.name, error=str(exc))
        return result
    result.manifest = manifest

    # ── Verify manifest hash (warning only) ──────────────────
    if manifest.manifest_hash:
        actual = compute_manifest_hash(manifest)
        if actual != manifest.manifest_hash:
            result.warnings.append(
                f"manifest_hash mismatch: declared "
                f"{manifest.manifest_hash}, computed {actual}"
            )
            log.warning(
                "Pack manifest hash mismatch — trust by inspection",
                pack=manifest.name,
                declared=manifest.manifest_hash,
                computed=actual,
            )

    # ── Make pack dir importable ─────────────────────────────
    pack_str = str(pack_path)
    if pack_str not in sys.path:
        sys.path.insert(0, pack_str)

    # ── Load each contribution category ──────────────────────
    counts = {
        "tools": _load_tools(manifest, result),
        "agents": _load_agents(manifest, result),
        "policies": _load_policies(manifest, result),
        "report_templates": _load_report_templates(
            manifest, pack_path, result,
        ),
        "entity_types": _load_entity_types(manifest, result),
        "relationship_types": _load_relationship_types(
            manifest, result,
        ),
    }
    result.contributions_loaded = counts

    # If ALL categories failed and nothing loaded, mark the
    # whole pack failed.
    if (
        result.warnings  # any warning about hash mismatch is fine
        and sum(counts.values()) == 0
        and manifest.contributes.total() > 0
    ):
        # The pack declared contributions but loaded none.
        result.status = PackLoadStatus.FAILED
        result.error = (
            "manifest declared contributions but none loaded "
            "(check warnings)"
        )

    return result


# ──────────────────────────────────────────────────────────────────────
# Per-category loaders
# ──────────────────────────────────────────────────────────────────────


def _load_tools(manifest: PackManifest, result: PackLoadResult) -> int:
    """Import each tool module so its ``@register_tool``
    decorators fire. We don't try to grab the class — the
    registry side-effects are the source of truth."""
    n = 0
    for tool in manifest.contributes.tools:
        try:
            importlib.import_module(tool.module)
            n += 1
        except Exception as exc:
            result.warnings.append(
                f"tool {tool.module}: {exc}",
            )
            log.warning("Pack tool import failed",
                        pack=manifest.name, module=tool.module,
                        error=str(exc))
    return n


def _load_agents(manifest: PackManifest, result: PackLoadResult) -> int:
    """Import each agent's module + bind its class into
    AGENT_REGISTRY by ``registry_name``."""
    if not manifest.contributes.agents:
        return 0
    try:
        from nexusrecon.graph.agent_executor import AGENT_REGISTRY
    except Exception as exc:
        result.warnings.append(f"AGENT_REGISTRY unavailable: {exc}")
        return 0

    n = 0
    for agent in manifest.contributes.agents:
        try:
            module = importlib.import_module(agent.module)
            cls = getattr(module, agent.class_name)
            AGENT_REGISTRY[agent.registry_name] = cls
            n += 1
        except Exception as exc:
            result.warnings.append(
                f"agent {agent.module}.{agent.class_name}: {exc}",
            )
            log.warning("Pack agent import failed",
                        pack=manifest.name,
                        module=agent.module,
                        class_name=agent.class_name,
                        error=str(exc))
    return n


def _load_policies(manifest: PackManifest, result: PackLoadResult) -> int:
    """Import each policy module + register the class via
    :func:`register_policy`."""
    if not manifest.contributes.policies:
        return 0
    try:
        from nexusrecon.strategy.policy import register_policy
    except Exception as exc:
        result.warnings.append(f"register_policy unavailable: {exc}")
        return 0

    n = 0
    for policy in manifest.contributes.policies:
        try:
            module = importlib.import_module(policy.module)
            cls = getattr(module, policy.class_name)
            register_policy(policy.name, cls)
            n += 1
        except Exception as exc:
            result.warnings.append(
                f"policy {policy.module}.{policy.class_name}: {exc}",
            )
            log.warning("Pack policy import failed",
                        pack=manifest.name, module=policy.module,
                        error=str(exc))
    return n


def _load_report_templates(
    manifest: PackManifest,
    pack_path: Path,
    result: PackLoadResult,
) -> int:
    """Register report templates. v1 simply records ``name ->
    absolute path``; the report engine reads from this dict
    when rendering. If the engine isn't available (older
    builds) we skip with a warning."""
    if not manifest.contributes.report_templates:
        return 0
    try:
        from nexusrecon.report.template_registry import (
            register_template,
        )
    except Exception:
        # Future-proofing: the report engine may not yet have
        # a template_registry module. Record + skip cleanly.
        for tmpl in manifest.contributes.report_templates:
            result.warnings.append(
                f"report_template {tmpl.name}: registry unavailable"
            )
        return 0

    n = 0
    for tmpl in manifest.contributes.report_templates:
        try:
            tmpl_path = (pack_path / tmpl.path).resolve()
            if not tmpl_path.exists():
                raise FileNotFoundError(
                    f"template file not found: {tmpl_path}",
                )
            register_template(tmpl.name, tmpl_path)
            n += 1
        except Exception as exc:
            result.warnings.append(
                f"report_template {tmpl.name}: {exc}",
            )
            log.warning("Pack template registration failed",
                        pack=manifest.name, template=tmpl.name,
                        error=str(exc))
    return n


def _load_entity_types(
    manifest: PackManifest, result: PackLoadResult,
) -> int:
    n = 0
    for et in manifest.contributes.entity_types:
        try:
            register_entity_type(et.name, et.value)
            n += 1
        except Exception as exc:
            result.warnings.append(
                f"entity_type {et.name}: {exc}",
            )
            log.warning("Pack entity_type registration failed",
                        pack=manifest.name, name=et.name,
                        value=et.value, error=str(exc))
    return n


def _load_relationship_types(
    manifest: PackManifest, result: PackLoadResult,
) -> int:
    n = 0
    for rt in manifest.contributes.relationship_types:
        try:
            register_relationship_type(rt.name, rt.value)
            n += 1
        except Exception as exc:
            result.warnings.append(
                f"relationship_type {rt.name}: {exc}",
            )
            log.warning("Pack relationship_type registration failed",
                        pack=manifest.name, name=rt.name,
                        value=rt.value, error=str(exc))
    return n
