"""Sample responses for mocking external data sources in tool tests.

Each tool category gets a subdirectory under ``tests/fixtures/``; each
JSON file inside is one canonical response shape — happy path, empty
result, error envelope, etc. — copied from the provider's public API
documentation (or, for HTML-scraping tools, from a one-time snapshot
of a real response).

The naming convention is:

    tests/fixtures/<tool_name>/<scenario>.json
    tests/fixtures/<tool_name>/<scenario>.html

Tests load fixtures via :func:`load_fixture` / :func:`load_text_fixture`
rather than embedding response shapes inline. Two reasons:

1. **Readability** — the test code stays focused on the assertions; the
   sample data lives where it can be reviewed alongside the provider's
   docs.
2. **Reuse** — the same fixture seeds the mock test (``tests/integration/``)
   and the live opt-in test (``tests/live/``) when the latter wants to
   assert "the provider still returns approximately this shape".
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_FIXTURES_DIR = Path(__file__).parent


def load_fixture(rel_path: str) -> Any:
    """Read and parse a JSON fixture under ``tests/fixtures/``.

    ``rel_path`` is relative to the fixtures directory, e.g.
    ``"shodan/host_search.json"``. Raises ``FileNotFoundError`` if the
    fixture is missing — the test will then fail loudly rather than
    silently mocking with an empty response.
    """
    path = _FIXTURES_DIR / rel_path
    return json.loads(path.read_text(encoding="utf-8"))


def load_text_fixture(rel_path: str) -> str:
    """Read a non-JSON fixture (HTML, plain text, CSV, …) verbatim."""
    path = _FIXTURES_DIR / rel_path
    return path.read_text(encoding="utf-8")


def fixture_path(rel_path: str) -> Path:
    """Return the absolute path to a fixture without reading it.

    Useful for binary fixtures (synthetic APKs, screenshot PNGs, …)
    where the test passes the path to a library function rather than
    loading the bytes itself.
    """
    return _FIXTURES_DIR / rel_path
