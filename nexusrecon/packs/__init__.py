"""Recon Pack format — Phase 3 PR A.

A **recon pack** is a portable bundle of contributions —
tools, agents, dispatch policies, report templates, custom
entity / relationship types — distributed as a directory with
a ``manifest.yaml`` at its root. Packs let community
contributors extend NexusRecon without forking the core
codebase, in the same spirit that Metasploit modules let
operators ship aggressive new capabilities without rebuilding
Metasploit itself.

Lifecycle
- Packs live under ``~/.nexusrecon/packs/<pack-name>/``.
- :func:`discover_packs` walks that directory and finds
  candidates (anything with a ``manifest.yaml``).
- :func:`load_packs` parses each manifest, validates it,
  imports the declared modules, and registers their
  contributions.
- Each successful load writes a hash-chained
  ``pack_loaded`` audit entry; failures emit a ``warning``
  but never abort the campaign (operators can re-enable
  strict behavior in a future PR).

What a pack can contribute (v1)
- ``tools`` — :class:`OSINTTool` subclasses auto-registered
  via the existing ``@register_tool`` decorator. Pack just
  imports the module; the decorator does the work.
- ``agents`` — :class:`BaseNexusAgent` subclasses registered
  in :data:`AGENT_REGISTRY`. Pack passes the class name so
  the loader knows which symbol to bind.
- ``policies`` — :class:`DispatchPolicy` subclasses
  registered via :func:`register_policy`.
- ``report_templates`` — Jinja / Markdown templates
  registered with the report engine (lookup by name).
- ``entity_types`` / ``relationship_types`` — string values
  added to the runtime extension registry so a pack's tools
  can return entities the core schema doesn't ship with.

Trust model (PR A: minimal)
- Each manifest carries an optional ``manifest_hash``: a
  SHA-256 of the canonical manifest body (everything except
  the hash field). The loader recomputes it and warns on
  mismatch; it does NOT gate loading. Per the architecture
  decisions: unsigned + manifest hash, trust by inspection.
- A future PR may layer optional Ed25519 signing on top.

What's deliberately NOT here
- Marketplace registry / version resolution — local dirs only
  in v1, with ``git`` URLs as a follow-up.
- Strict-mode failure handling — every failure is currently
  skip+warn.
- Hot reload — packs are loaded once at startup; restart
  required.
"""
from nexusrecon.packs.loader import (
    PackLoadResult,
    PackLoadStatus,
    discover_packs,
    load_packs,
)
from nexusrecon.packs.manifest import (
    PackContribution,
    PackManifest,
    compute_manifest_hash,
    parse_manifest,
)
from nexusrecon.packs.registry import (
    PackRegistry,
    get_pack_registry,
    is_known_entity_type,
    is_known_relationship_type,
    register_entity_type,
    register_relationship_type,
)

__all__ = [
    "PackContribution",
    "PackLoadResult",
    "PackLoadStatus",
    "PackManifest",
    "PackRegistry",
    "compute_manifest_hash",
    "discover_packs",
    "get_pack_registry",
    "is_known_entity_type",
    "is_known_relationship_type",
    "load_packs",
    "parse_manifest",
    "register_entity_type",
    "register_relationship_type",
]
