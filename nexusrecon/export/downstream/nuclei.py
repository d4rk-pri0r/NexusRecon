"""Nuclei target list emitter.

Nuclei consumes a plain-text list of targets via ``-list``::

    nuclei -list nexusrecon-targets.txt -t cves/ -severity high

This emitter walks an :class:`EntityGraph` and pulls out
URLs, domains, subdomains, and IP addresses — the four
entity types Nuclei knows how to probe. Operators feed the
output straight into ``-list``.

What gets included
- All ``url`` entities (full URLs).
- All ``domain`` + ``subdomain`` entities, optionally
  upgraded to ``https://`` schemes when the operator wants
  a URL-style list.
- All ``ip_address`` entities (with optional ``https://``
  schemes too).

Filtering
- ``min_confidence`` skips entities below the threshold
  (default 0.5). Stops Nuclei from chasing low-signal
  noise.
- ``schemes`` controls whether plain hosts get a scheme
  prefix added (default ``["https"]``).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def emit_nuclei_targets(
    graph: Any,
    out_path: Path | str,
    *,
    min_confidence: float = 0.5,
    schemes: list[str] | None = None,
) -> tuple[Path, list[str]]:
    """Write a Nuclei-consumable target list. Returns the
    output path + the list of targets written (handy for
    the CLI to print "N targets → <path>").

    ``schemes`` controls how bare hosts are rendered:
    ``["https"]`` (default) emits ``https://<host>``;
    ``["http", "https"]`` emits both schemes for each host;
    ``[]`` emits the bare host string only.
    """
    schemes = schemes if schemes is not None else ["https"]
    targets: list[str] = []
    seen: set[str] = set()

    for _, data in graph.graph.nodes(data=True):
        entity_type = data.get("entity_type")
        confidence = float(data.get("confidence", 0.0))
        if confidence < min_confidence:
            continue
        value = str(data.get("value") or "")
        if not value:
            continue

        if entity_type == "url":
            # URLs go in verbatim — they already carry a
            # scheme.
            if value not in seen:
                targets.append(value)
                seen.add(value)
            continue

        if entity_type in ("domain", "subdomain", "ip_address"):
            if not schemes:
                if value not in seen:
                    targets.append(value)
                    seen.add(value)
            else:
                for scheme in schemes:
                    rendered = f"{scheme}://{value}"
                    if rendered not in seen:
                        targets.append(rendered)
                        seen.add(rendered)

    out = Path(out_path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(targets) + ("\n" if targets else ""),
                   encoding="utf-8")
    return out, targets
