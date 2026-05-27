"""Marketplace index — discoverability for community packs.

The index
- A JSON document listing packs that have opted into
  discovery. v1 schema::

    {
      "schema_version": 1,
      "generated_at": "2026-05-27T...",
      "packs": [
        {
          "name": "corp-red-team",
          "summary": "Corporate red team pack",
          "url": "gh:operator-x/corp-red-team",
          "latest_version": "1.0.0",
          "categories": ["red-team", "corp"],
          "license": "MIT"
        },
        ...
      ]
    }

- Hosted at a URL the operator configures. Default points to
  a placeholder — the actual hosting / curation is a Phase 4
  concern. Operators can override via
  ``NEXUSRECON_MARKETPLACE_URL``.

What we ship in PR C1
- Local + remote index loading.
- Simple substring + category search.
- ``nexusrecon packs search <term>`` CLI command.
- NO automatic install on search match — the operator pipes
  the chosen pack URL into ``packs install``. Two-step is
  the right default for security review.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


DEFAULT_MARKETPLACE_URL_ENV = "NEXUSRECON_MARKETPLACE_URL"
DEFAULT_MARKETPLACE_URL = (
    # Placeholder. Eventually points at a GitHub-hosted JSON
    # that the community curates. Setting the env var
    # overrides — operators behind firewalls can point at an
    # internal mirror.
    ""
)
CURRENT_MARKETPLACE_SCHEMA: int = 1


# ──────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────


@dataclass
class MarketplaceEntry:
    """One pack in the marketplace index."""

    name: str
    summary: str
    url: str
    latest_version: str
    categories: list[str]
    license: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "url": self.url,
            "latest_version": self.latest_version,
            "categories": list(self.categories),
            "license": self.license,
        }


@dataclass
class Marketplace:
    """A loaded marketplace index."""

    schema_version: int
    generated_at: str
    entries: list[MarketplaceEntry]
    source: str
    """Where this index came from. Either a URL or a path."""

    def search(
        self,
        query: str = "",
        *,
        category: str | None = None,
    ) -> list[MarketplaceEntry]:
        """Substring + category match. ``query`` matches name
        or summary case-insensitively; ``category`` is exact
        match on the entry's categories list."""
        q = query.lower().strip()
        results: list[MarketplaceEntry] = []
        for entry in self.entries:
            if q and (
                q not in entry.name.lower()
                and q not in entry.summary.lower()
            ):
                continue
            if category and category not in entry.categories:
                continue
            results.append(entry)
        return results


# ──────────────────────────────────────────────────────────────────────
# Loading
# ──────────────────────────────────────────────────────────────────────


def resolve_marketplace_url() -> str:
    """Read the configured marketplace URL. Empty string means
    "no marketplace configured" — the CLI shows a helpful
    error rather than trying to fetch."""
    return os.environ.get(
        DEFAULT_MARKETPLACE_URL_ENV,
        DEFAULT_MARKETPLACE_URL,
    )


def load_marketplace(
    source: str | Path,
    *,
    timeout: float = 10.0,
) -> Marketplace:
    """Load an index from a URL or local path.

    Raises ``ValueError`` on any parse / schema / fetch
    failure with a useful message. The CLI catches +
    surfaces; tests assert specific errors."""
    if isinstance(source, Path) or (
        isinstance(source, str)
        and not source.startswith(("http://", "https://"))
    ):
        path = Path(source).expanduser()
        if not path.exists():
            raise ValueError(f"marketplace index not found: {path}")
        body = path.read_text(encoding="utf-8")
        source_str = str(path)
    else:
        try:
            with urllib.request.urlopen(source, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise ValueError(
                f"could not fetch marketplace from {source}: {exc}"
            ) from exc
        source_str = str(source)

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"marketplace index from {source_str} is not valid JSON: {exc}"
        ) from exc

    return _parse(data, source_str)


def _parse(data: Any, source: str) -> Marketplace:
    if not isinstance(data, dict):
        raise ValueError(
            "marketplace root must be a JSON object",
        )
    schema = int(data.get("schema_version", 0))
    if schema != CURRENT_MARKETPLACE_SCHEMA:
        # Future-proofing: same posture as the pack manifest
        # — refuse unknown majors loudly so old clients fail
        # rather than silently missing fields.
        raise ValueError(
            f"unsupported marketplace schema_version {schema}; "
            f"this build understands {CURRENT_MARKETPLACE_SCHEMA}"
        )
    raw_entries = data.get("packs", [])
    if not isinstance(raw_entries, list):
        raise ValueError("'packs' must be a JSON array")

    entries: list[MarketplaceEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            continue
        try:
            entries.append(MarketplaceEntry(
                name=str(raw["name"]),
                summary=str(raw.get("summary", "")),
                url=str(raw["url"]),
                latest_version=str(raw.get("latest_version", "")),
                categories=[
                    str(c) for c in (raw.get("categories") or [])
                ],
                license=str(raw.get("license", "")),
            ))
        except KeyError as exc:
            log.warning(
                "Marketplace entry missing required field",
                missing=str(exc), entry=raw,
            )
            continue

    return Marketplace(
        schema_version=schema,
        generated_at=str(data.get("generated_at", "")),
        entries=entries,
        source=source,
    )
