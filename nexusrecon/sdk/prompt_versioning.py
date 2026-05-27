"""Prompt versioning — every agent prompt is registered with
a version + content hash so the audit chain survives prompt
edits.

The problem
- An operator runs a campaign, generates findings, archives
  the audit log. Three weeks later they (or the platform
  developer) hot-patch a prompt to fix a bug. Now the
  archived findings' provenance points to a prompt that
  no longer matches what the archive claims produced them.
  The audit chain is technically intact (no entries were
  rewritten), but the *meaning* of those entries has
  silently drifted.

The fix
- Treat prompts as versioned data. Each agent decorates its
  prompt with ``register_prompt(name, version, body)`` (or
  the decorator equivalent). The SDK computes a SHA-256 of
  the body and stores ``{name, version, content_hash}`` in
  a process-wide registry.
- The audit-log writer (``log_agent_action`` in
  :class:`AuditLog`) can pull the prompt fingerprint into
  every agent's action entry so reviewers can later check
  "was the prompt at version 1.2.0 with hash ABC when this
  finding was produced?" against today's deployed version.

Sequencing
- This module is stateless aside from the registry dict;
  importing it from a pack just adds entries.
- :func:`PromptVersionMismatch` is raised when a caller
  declares an expected version but the registered body
  hashes differently — defensive guard for plugin
  developers who hand-edit a deployed prompt without
  bumping the version string.

Storage shape
- The registry is in-process. Persisting it across runs
  is a future concern: the audit log already carries the
  hash + version per agent action, so the canonical record
  IS the audit log; the registry is just a lookup index for
  the current process.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)


_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$")


# ──────────────────────────────────────────────────────────────────────
# Errors
# ──────────────────────────────────────────────────────────────────────


class PromptVersionMismatch(ValueError):
    """Raised when ``register_prompt`` is called with an
    expected hash that doesn't match the body. Intended for
    plugin authors who pin a hash explicitly in their code so
    the build breaks on a sneaky in-place edit."""


# ──────────────────────────────────────────────────────────────────────
# Records
# ──────────────────────────────────────────────────────────────────────


@dataclass
class PromptRecord:
    """One registered prompt's identity.

    ``name`` is operator-facing (e.g.
    ``"corp_pack.exec_pretext_drafter"``). ``version`` is a
    SemVer-ish triple so the audit trail can compare across
    releases. ``content_hash`` is the SHA-256 of the body —
    if two runs claim the same name+version but different
    hashes, the prompt was hot-patched."""

    name: str
    version: str
    content_hash: str
    body: str
    registered_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "content_hash": self.content_hash,
            "registered_at": self.registered_at,
            # ``body`` deliberately excluded — prompts can be
            # large + sometimes carry proprietary phrasing.
            # The hash is the audit-safe identifier.
        }


_PROMPT_REGISTRY: dict[str, PromptRecord] = {}


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────


def compute_prompt_hash(body: str) -> str:
    """SHA-256 of the prompt body, prefixed ``sha256:`` to
    match the audit-log hash format."""
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def register_prompt(
    name: str,
    version: str,
    body: str,
    *,
    expected_hash: str | None = None,
) -> PromptRecord:
    """Register a prompt with the process-wide registry.

    ``expected_hash`` is an optional safety net: pin the hash
    you expect the body to produce, and a hot-edit that
    changed the body without bumping ``version`` raises
    :class:`PromptVersionMismatch`. Strongly recommended for
    plugin authors who keep their prompts in a separate file
    that's easier to edit casually.

    Returns the :class:`PromptRecord`. Re-registering the
    same ``(name, version, body)`` is idempotent. Re-
    registering the same ``(name, version)`` with a different
    body raises — that's the case the operator wants to know
    about. Bumping ``version`` is the supported path for
    deliberate edits.
    """
    if not _VERSION_PATTERN.fullmatch(version):
        raise ValueError(
            f"version {version!r} must be SemVer-ish "
            f"(e.g. 1.0.0 or 1.2.3-rc.1)"
        )

    content_hash = compute_prompt_hash(body)
    if expected_hash and expected_hash != content_hash:
        raise PromptVersionMismatch(
            f"prompt {name!r} body hashes to {content_hash} "
            f"but expected {expected_hash}. Bump the version "
            f"string if the change was intentional."
        )

    existing = _PROMPT_REGISTRY.get(name)
    if existing is not None and existing.version == version:
        if existing.content_hash != content_hash:
            raise PromptVersionMismatch(
                f"prompt {name!r}@{version} already registered "
                f"with hash {existing.content_hash}; new body "
                f"hashes to {content_hash}. Bump the version."
            )
        # Same body — idempotent re-registration.
        return existing

    record = PromptRecord(
        name=name,
        version=version,
        content_hash=content_hash,
        body=body,
        registered_at=datetime.now(UTC).isoformat(),
    )
    _PROMPT_REGISTRY[name] = record
    log.debug("Registered prompt", name=name, version=version,
              hash=content_hash[:24])
    return record


def get_prompt_record(name: str) -> PromptRecord | None:
    """Return the currently-registered :class:`PromptRecord`
    for ``name``, or ``None`` if no prompt by that name has
    been registered yet."""
    return _PROMPT_REGISTRY.get(name)


def list_registered_prompts() -> list[PromptRecord]:
    """Snapshot of the registry. Sorted by name for
    deterministic CLI output."""
    return sorted(_PROMPT_REGISTRY.values(), key=lambda r: r.name)


def _reset_prompt_registry() -> None:
    """Tear down for tests. Not part of the public API."""
    _PROMPT_REGISTRY.clear()
