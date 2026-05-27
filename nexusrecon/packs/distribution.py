"""Git-based pack distribution — `nexusrecon packs install`.

Distribution model (per the architecture decisions)
- Local dirs + git URLs. PR C1 adds the git URL handler.
- Shallow clone (``--depth 1``) into the pack directory.
  Refspec is the default branch; explicit tags or branches
  can be requested via ``gh:foo/bar@v1.2.0`` syntax.
- No lockfile, no resolved-version pinning. Trust by
  inspection + manifest_hash is the v1 trust model;
  reproducible installs are a future concern.

URL shorthand grammar
- ``gh:owner/repo`` → ``https://github.com/owner/repo.git``
- ``gh:owner/repo@ref`` → ditto, checkout ``ref`` after clone.
- ``https://…/foo.git`` / ``git@…`` are passed through verbatim
  for self-hosted GitLabs, gitea, etc.

Failure mode
- Same skip+warn philosophy as the loader. Failed clones
  leave the destination directory empty (we clean up
  on partial clone) + return a non-success result. The CLI
  surfaces the error string.

Why not pull a dep like ``dulwich`` or ``GitPython``?
- ``git`` is universally installed where ``nexusrecon`` runs.
- Subprocess + small wrapper has zero transitive surface.
- We DO NOT trust pack contents (skip+warn loader), so
  trying to sandbox the clone is theatre. Operators inspect
  before activating.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from nexusrecon.packs.loader import _resolve_pack_dir
from nexusrecon.packs.manifest import parse_manifest

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# URL handling
# ──────────────────────────────────────────────────────────────────────


_GH_SHORTHAND = re.compile(
    r"^gh:(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+)(?:@(?P<ref>[\w./-]+))?$"
)


@dataclass
class ParsedURL:
    """Result of :func:`parse_url` — the components needed by
    :func:`clone_pack`."""

    url: str
    """Resolved clone URL (https:// or git@)."""
    ref: str | None
    """Tag / branch / commit to check out after clone, or
    ``None`` for default branch."""
    inferred_name: str
    """Best guess at the pack's directory name. The actual
    pack name comes from the cloned manifest — this is just
    the temporary destination slug."""


def parse_url(spec: str) -> ParsedURL:
    """Resolve a user-supplied URL spec.

    Accepts ``gh:owner/repo[@ref]`` shorthand and any
    git-compatible URL otherwise. Raises ``ValueError`` on
    obviously malformed input so the CLI can render a useful
    error before invoking subprocess."""
    spec = spec.strip()
    if not spec:
        raise ValueError("empty URL")
    m = _GH_SHORTHAND.fullmatch(spec)
    if m:
        return ParsedURL(
            url=f"https://github.com/{m.group('owner')}/{m.group('repo')}.git",
            ref=m.group("ref"),
            inferred_name=m.group("repo"),
        )
    # Generic URL — extract the trailing path segment as the
    # candidate directory name. Strip ``.git`` if present.
    if "://" not in spec and not spec.startswith("git@"):
        raise ValueError(
            f"unrecognised URL spec {spec!r}; use "
            f"gh:owner/repo or a full git URL"
        )
    # Split off optional ``@ref`` suffix only when it's a tag-
    # looking token (digits/dots/letters) — avoids tripping on
    # ``user@host`` in SSH URLs.
    ref: str | None = None
    if "@" in spec and not spec.startswith("git@"):
        # Heuristic: the LAST ``@`` followed by a SemVer/branch-
        # looking token at the end.
        candidate_url, candidate_ref = spec.rsplit("@", 1)
        if re.fullmatch(r"[\w./-]+", candidate_ref):
            spec = candidate_url
            ref = candidate_ref
    tail = spec.rstrip("/").rsplit("/", 1)[-1]
    inferred_name = tail.removesuffix(".git") or "pack"
    return ParsedURL(url=spec, ref=ref, inferred_name=inferred_name)


# ──────────────────────────────────────────────────────────────────────
# Install / uninstall / update
# ──────────────────────────────────────────────────────────────────────


@dataclass
class InstallResult:
    """One ``install`` / ``update`` outcome."""

    success: bool
    pack_path: Path
    pack_name: str
    """Name from the cloned manifest. ``""`` when the install
    failed before parsing reached the manifest."""
    version: str
    ref: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "pack_path": str(self.pack_path),
            "pack_name": self.pack_name,
            "version": self.version,
            "ref": self.ref,
            "error": self.error,
        }


def install_pack(
    url_spec: str,
    *,
    pack_root: Path | str | None = None,
    runner: Any = subprocess.run,
) -> InstallResult:
    """Shallow-clone the pack at ``url_spec`` into the pack
    root. Returns an :class:`InstallResult`.

    ``runner`` is injectable for tests — defaults to
    :func:`subprocess.run`. Tests pass a fake that records
    the command + writes a manifest into the target dir."""
    try:
        parsed = parse_url(url_spec)
    except ValueError as exc:
        return InstallResult(
            success=False, pack_path=Path("."),
            pack_name="", version="", ref="",
            error=f"bad URL: {exc}",
        )

    root = _resolve_pack_dir(pack_root)
    root.mkdir(parents=True, exist_ok=True)
    dest = root / parsed.inferred_name

    if dest.exists():
        return InstallResult(
            success=False, pack_path=dest,
            pack_name="", version="", ref=parsed.ref or "",
            error=(
                f"destination {dest} already exists; uninstall "
                f"or update instead of re-installing."
            ),
        )

    # Build the clone command. Shallow + single-branch keeps
    # the working copy small.
    cmd = [
        "git", "clone", "--depth", "1", "--single-branch",
    ]
    if parsed.ref:
        cmd.extend(["--branch", parsed.ref])
    cmd.extend([parsed.url, str(dest)])

    log.debug("Cloning pack", url=parsed.url, ref=parsed.ref, dest=str(dest))
    try:
        result = runner(
            cmd, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return InstallResult(
            success=False, pack_path=dest,
            pack_name="", version="", ref=parsed.ref or "",
            error=(
                "git binary not found in PATH; install git or "
                "drop the pack directory manually."
            ),
        )
    except Exception as exc:
        return InstallResult(
            success=False, pack_path=dest,
            pack_name="", version="", ref=parsed.ref or "",
            error=f"clone failed: {exc}",
        )

    if result.returncode != 0:
        # Clean up the half-cloned dir so we leave the pack
        # root tidy.
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        return InstallResult(
            success=False, pack_path=dest,
            pack_name="", version="", ref=parsed.ref or "",
            error=(result.stderr or result.stdout or "git exit nonzero").strip(),
        )

    # Parse the cloned manifest to surface the real name +
    # version. If parsing fails the install is still considered
    # successful but flagged in the error field — the operator
    # can then decide whether to uninstall.
    manifest_path = dest / "manifest.yaml"
    if not manifest_path.exists():
        return InstallResult(
            success=True, pack_path=dest,
            pack_name=parsed.inferred_name,
            version="", ref=parsed.ref or "",
            error=(
                f"clone OK but no manifest.yaml at root — "
                f"this directory is NOT a recon pack."
            ),
        )
    try:
        manifest = parse_manifest(manifest_path)
        return InstallResult(
            success=True, pack_path=dest,
            pack_name=manifest.name, version=manifest.version,
            ref=parsed.ref or "",
        )
    except Exception as exc:
        return InstallResult(
            success=True, pack_path=dest,
            pack_name=parsed.inferred_name,
            version="", ref=parsed.ref or "",
            error=f"manifest parse failed: {exc}",
        )


def uninstall_pack(
    name_or_path: str,
    *,
    pack_root: Path | str | None = None,
) -> bool:
    """Remove a pack from disk. ``name_or_path`` is either
    the pack directory name (relative to pack root) or an
    absolute path. Returns ``True`` on successful removal,
    ``False`` if nothing was there to remove."""
    root = _resolve_pack_dir(pack_root)
    candidate = Path(name_or_path).expanduser()
    if not candidate.is_absolute():
        candidate = root / name_or_path
    if not candidate.exists():
        return False
    # Refuse to uninstall something OUTSIDE the pack root.
    # Operators shouldn't be `rm -rf`ing arbitrary paths via
    # this command.
    candidate_resolved = candidate.resolve()
    root_resolved = root.resolve()
    if root_resolved not in candidate_resolved.parents \
            and candidate_resolved != root_resolved:
        log.warning("Refusing to uninstall outside pack root",
                    candidate=str(candidate), root=str(root))
        return False
    shutil.rmtree(candidate_resolved)
    return True


def update_pack(
    name_or_path: str,
    *,
    pack_root: Path | str | None = None,
    runner: Any = subprocess.run,
) -> InstallResult:
    """Pull the latest from the pack's origin remote. Uses
    ``git fetch + reset --hard`` so a local edit doesn't
    block the update (operators who edit installed packs
    should fork the repo instead)."""
    root = _resolve_pack_dir(pack_root)
    candidate = Path(name_or_path).expanduser()
    if not candidate.is_absolute():
        candidate = root / name_or_path
    if not (candidate / ".git").exists():
        return InstallResult(
            success=False, pack_path=candidate,
            pack_name=name_or_path, version="", ref="",
            error=(
                f"{candidate} is not a git-cloned pack "
                f"(no .git directory)."
            ),
        )
    try:
        # Detect current branch so we know what to reset to.
        branch_result = runner(
            ["git", "-C", str(candidate), "rev-parse",
             "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=False,
        )
        branch = (branch_result.stdout or "").strip() or "HEAD"

        fetch_result = runner(
            ["git", "-C", str(candidate), "fetch", "--depth", "1",
             "origin", branch],
            capture_output=True, text=True, check=False,
        )
        if fetch_result.returncode != 0:
            return InstallResult(
                success=False, pack_path=candidate,
                pack_name=name_or_path, version="", ref=branch,
                error=(fetch_result.stderr or "fetch failed").strip(),
            )

        reset_result = runner(
            ["git", "-C", str(candidate), "reset", "--hard",
             "FETCH_HEAD"],
            capture_output=True, text=True, check=False,
        )
        if reset_result.returncode != 0:
            return InstallResult(
                success=False, pack_path=candidate,
                pack_name=name_or_path, version="", ref=branch,
                error=(reset_result.stderr or "reset failed").strip(),
            )
    except FileNotFoundError:
        return InstallResult(
            success=False, pack_path=candidate,
            pack_name=name_or_path, version="", ref="",
            error="git binary not found in PATH",
        )
    except Exception as exc:
        return InstallResult(
            success=False, pack_path=candidate,
            pack_name=name_or_path, version="", ref="",
            error=str(exc),
        )

    manifest_path = candidate / "manifest.yaml"
    if not manifest_path.exists():
        return InstallResult(
            success=True, pack_path=candidate,
            pack_name=name_or_path, version="", ref=branch,
        )
    try:
        manifest = parse_manifest(manifest_path)
        return InstallResult(
            success=True, pack_path=candidate,
            pack_name=manifest.name, version=manifest.version,
            ref=branch,
        )
    except Exception as exc:
        return InstallResult(
            success=True, pack_path=candidate,
            pack_name=name_or_path, version="", ref=branch,
            error=f"manifest parse failed after update: {exc}",
        )
