"""Safe read / write for `.env` that preserves comments and ordering.

`python-dotenv` reads `.env` files just fine but its writers tend to
rewrite the whole file, dropping comments and re-ordering keys. For an
operator-editable config screen we want the inverse — the file the user
sees in `$EDITOR` after the TUI edits it should look like the one they
hand-edited yesterday plus the one line that changed.

This module:
  * Parses `.env` into an ordered list of (key, value, raw_line) tuples
    plus the comment / blank lines preserved verbatim at their original
    positions.
  * Provides `set_value(key, value)` that updates the key in-place if it
    exists, otherwise appends to the end. Comments and surrounding
    structure are untouched.
  * Provides `delete_value(key)` for "clear this key" semantics — we
    REMOVE the line entirely rather than leaving `KEY=` empty, because
    an empty env var defeats `.env` precedence (B33).
  * Writes back atomically (tempfile + rename) so a crash mid-write
    can't truncate the file.
  * Never echoes secret values to logs.

The schema lives in `config_schema.py` — this module only deals with
text I/O.
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class _EnvLine:
    """One line from `.env`. Either a key-value assignment, a comment, or
    a blank. Keeping the original raw text lets us write back without
    re-formatting unrelated lines."""
    raw: str               # the line exactly as it appeared (no trailing \n)
    key: Optional[str]     # KEY for assignments, None for comments/blanks
    value: Optional[str]   # value for assignments (unquoted), else None


class EnvFile:
    """Edit a `.env` file while preserving its structure."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lines: List[_EnvLine] = []
        self._load()

    def _load(self) -> None:
        self._lines = []
        if not self.path.exists():
            return
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            self._lines.append(self._parse_line(raw))

    @staticmethod
    def _parse_line(raw: str) -> _EnvLine:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            return _EnvLine(raw=raw, key=None, value=None)
        if "=" not in stripped:
            # Malformed; preserve as-is so user can fix it
            return _EnvLine(raw=raw, key=None, value=None)
        k, _, v = stripped.partition("=")
        k = k.strip()
        v = v.strip()
        # Strip surrounding quotes so the in-memory value is plain text;
        # we re-quote on write only if the value contains shell-meaningful chars.
        if (v.startswith('"') and v.endswith('"')) or (
            v.startswith("'") and v.endswith("'")
        ):
            v = v[1:-1]
        return _EnvLine(raw=raw, key=k, value=v)

    def get(self, key: str) -> Optional[str]:
        """Return the current value for ``key``, or ``None`` if absent.

        Treats present-but-empty values as ``None`` so callers can
        distinguish "configured" from "empty placeholder" the same way
        the runtime config singleton does (B13/B33)."""
        for ln in self._lines:
            if ln.key == key:
                return ln.value if ln.value else None
        return None

    def all_keys(self) -> List[str]:
        return [ln.key for ln in self._lines if ln.key is not None]

    def is_set(self, key: str) -> bool:
        """True if the key exists in .env with a non-empty value."""
        v = self.get(key)
        return v is not None and v != ""

    def set_value(self, key: str, value: str) -> None:
        """Set or update ``key`` to ``value``. Appends if missing.

        Empty / whitespace-only values are treated as "clear this key"
        and remove the line entirely (avoids the B33 empty-shadow trap)."""
        cleaned = (value or "").strip()
        if not cleaned:
            self.delete_value(key)
            return
        new_raw = self._render_assignment(key, cleaned)
        for i, ln in enumerate(self._lines):
            if ln.key == key:
                self._lines[i] = _EnvLine(raw=new_raw, key=key, value=cleaned)
                return
        # Not found: append (with a leading blank if the file doesn't end blank)
        if self._lines and self._lines[-1].raw.strip():
            self._lines.append(_EnvLine(raw="", key=None, value=None))
        self._lines.append(_EnvLine(raw=new_raw, key=key, value=cleaned))

    def delete_value(self, key: str) -> bool:
        """Remove ``key``'s assignment line entirely. Returns True if a
        line was removed."""
        for i, ln in enumerate(self._lines):
            if ln.key == key:
                self._lines.pop(i)
                return True
        return False

    @staticmethod
    def _render_assignment(key: str, value: str) -> str:
        """Quote the value only if it contains characters that would be
        misinterpreted by the shell or pydantic-settings parser."""
        needs_quote = any(c in value for c in [" ", "#", "$", '"', "'", "\\"])
        if needs_quote:
            # Use single quotes when possible (no escaping), else double-quoted with escapes
            if "'" not in value:
                return f"{key}='{value}'"
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'{key}="{escaped}"'
        return f"{key}={value}"

    def write(self) -> None:
        """Atomic write: render to a tempfile in the same directory,
        fsync, then rename over the original. Either the change is
        complete or .env is untouched — no partial writes."""
        body = "\n".join(ln.raw for ln in self._lines)
        if not body.endswith("\n"):
            body += "\n"
        # Same-directory tempfile so rename is atomic on the same filesystem
        fd, tmp_path = tempfile.mkstemp(
            prefix=".env.", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
            # Lock down permissions so the file isn't world-readable.
            # If someone has chmod'd it more permissively on purpose,
            # we respect their choice and only tighten it on first write.
            try:
                cur_mode = self.path.stat().st_mode & 0o777
                if cur_mode > 0o600:
                    os.chmod(self.path, 0o600)
            except OSError:
                pass
        except Exception:
            if Path(tmp_path).exists():
                try:
                    Path(tmp_path).unlink()
                except OSError:
                    pass
            raise

    def as_dict(self) -> Dict[str, str]:
        """Snapshot of all key/value pairs (non-empty only)."""
        return {
            ln.key: ln.value
            for ln in self._lines
            if ln.key is not None and ln.value
        }


def mask_value(value: Optional[str], visible_tail: int = 4) -> str:
    """Return a masked display string for a sensitive value.

    Shows length + last ``visible_tail`` chars so the operator can
    visually confirm "yes, that's the one ending in ...xyz9" without
    exposing the bulk of the secret.
    """
    if value is None or value == "":
        return "(not set)"
    n = len(value)
    if n <= visible_tail:
        return f"({n}c) {'*' * n}"
    return f"({n}c) {'*' * (n - visible_tail)}{value[-visible_tail:]}"
