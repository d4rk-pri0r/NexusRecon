"""Burp Suite bidirectional XML handoff — first-party pack.

This module ships two capabilities:

1. **Import**: parse Burp Suite's site map XML export
   (``Target → Site map → Save as → XML``) and turn each
   ``<item>`` into structured entities the Living Graph can
   ingest. Exposed both as a plain Python function and as a
   :class:`BurpXmlImporter` OSINTTool the registry can
   dispatch via ``--tool burp_xml_importer --target
   path/to/burp.xml``.

2. **Export**: render the campaign's in-scope domains as a
   Burp-importable XML document the operator can paste into
   Burp's Target → Scope → Import. Plain Python function;
   no tool wrapper because exports are operator-driven, not
   dispatcher-driven.

Why first-party
- The Recon Pack format (PR A) + scaffolders (PR B/C2)
  said *anyone* can ship a pack. We need to dogfood the
  format with something real, and Burp is the canonical
  example operators ask about — bidirectional handoff
  closes the loop between OSINT recon and active testing.
- This pack is in-tree (``packs/burp/``) so it's always
  available, but it uses the *same* loader path as community
  packs. If the loader breaks for community packs, it breaks
  for Burp too — operators will notice immediately.

Implementation notes
- stdlib ``xml.etree.ElementTree``. Burp's XML is simple
  enough that we don't need lxml.
- Tolerant of partial / malformed items: skips entries that
  can't be parsed, never raises on a single bad element.
- Import dedupes by ``(host, port, path)`` so a 10,000-item
  Burp export with repeated requests doesn't multiply graph
  nodes.
"""
from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nexusrecon.tools.base import (
    Category,
    OSINTTool,
    Tier,
    ToolResult,
)
from nexusrecon.tools.registry import register_tool


# ──────────────────────────────────────────────────────────────────────
# Parsed structures
# ──────────────────────────────────────────────────────────────────────


@dataclass
class BurpSitemapItem:
    """One ``<item>`` from Burp's site map XML, mapped into
    the fields NexusRecon cares about. Burp's full schema is
    much richer (request/response bodies, cookies, headers);
    we keep only the parts that turn into graph entities."""

    url: str
    host: str
    port: int
    protocol: str
    method: str
    path: str
    status: int | None
    mime_type: str
    ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "mime_type": self.mime_type,
            "ip": self.ip,
        }


@dataclass
class BurpImportReport:
    """Aggregate result of a parse_burp_sitemap call."""

    items: list[BurpSitemapItem] = field(default_factory=list)
    """Successfully-parsed items, dedup'd by (host, port, path)."""
    skipped: int = 0
    """Items that couldn't be parsed (logged at debug)."""
    distinct_hosts: list[str] = field(default_factory=list)
    distinct_subdomains: list[str] = field(default_factory=list)
    distinct_ips: list[str] = field(default_factory=list)
    distinct_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_count": len(self.items),
            "skipped": self.skipped,
            "distinct_hosts": list(self.distinct_hosts),
            "distinct_subdomains": list(self.distinct_subdomains),
            "distinct_ips": list(self.distinct_ips),
            "distinct_urls": list(self.distinct_urls),
        }


# ──────────────────────────────────────────────────────────────────────
# Parsing
# ──────────────────────────────────────────────────────────────────────


def parse_burp_sitemap(xml_text: str) -> BurpImportReport:
    """Parse a Burp Suite site map XML body into a
    :class:`BurpImportReport`.

    Resilient: a single malformed ``<item>`` doesn't sink the
    whole parse. Items are deduplicated by
    ``(host.lower(), port, path)`` — same URL hit by
    different methods/responses still collapses to one
    graph-significant entry."""
    report = BurpImportReport()
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Whole document unparseable; return empty report so
        # callers see (0 items, 0 skipped) — distinguishable
        # from "parsed 0 items".
        return report

    seen: set[tuple[str, int, str]] = set()
    host_set: set[str] = set()
    ip_set: set[str] = set()
    url_set: set[str] = set()

    items = root.findall("item")
    for elem in items:
        try:
            item = _parse_item(elem)
        except Exception:
            report.skipped += 1
            continue
        if item is None:
            report.skipped += 1
            continue

        key = (item.host.lower(), item.port, item.path)
        if key in seen:
            continue
        seen.add(key)
        report.items.append(item)
        host_set.add(item.host)
        if item.ip:
            ip_set.add(item.ip)
        url_set.add(item.url)

    report.distinct_hosts = sorted(host_set)
    report.distinct_subdomains = sorted(
        h for h in host_set if h.count(".") >= 2
    )
    report.distinct_ips = sorted(ip_set)
    report.distinct_urls = sorted(url_set)
    return report


def _parse_item(elem: ET.Element) -> BurpSitemapItem | None:
    """Pull the fields we care about out of a single
    ``<item>``. Returns ``None`` if the item lacks the
    minimum (host + url)."""
    url = _text(elem, "url")
    host_elem = elem.find("host")
    host = (host_elem.text or "").strip() if host_elem is not None else ""
    if not host or not url:
        return None
    ip = (
        host_elem.get("ip")
        if host_elem is not None and host_elem.get("ip")
        else None
    )
    port_str = _text(elem, "port") or "0"
    try:
        port = int(port_str)
    except ValueError:
        port = 0
    protocol = _text(elem, "protocol") or "http"
    method = _text(elem, "method") or "GET"
    path = _text(elem, "path") or "/"
    status_str = _text(elem, "status")
    status: int | None
    if status_str:
        try:
            status = int(status_str)
        except ValueError:
            status = None
    else:
        status = None
    mime_type = _text(elem, "mimetype") or ""
    return BurpSitemapItem(
        url=url, host=host, port=port, protocol=protocol,
        method=method, path=path, status=status,
        mime_type=mime_type, ip=ip,
    )


def _text(elem: ET.Element, tag: str) -> str:
    child = elem.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


# ──────────────────────────────────────────────────────────────────────
# Export
# ──────────────────────────────────────────────────────────────────────


def render_scope_to_burp_xml(
    in_scope_domains: list[str],
    *,
    out_of_scope_domains: list[str] | None = None,
    include_subdomains: bool = True,
) -> str:
    """Render an in-scope / out-of-scope domain list as a Burp
    Suite scope XML document.

    Burp expects scope entries as regex-like prefix matchers.
    We emit one ``<include>`` (or ``<exclude>``) entry per
    domain with the ``^https?://([^/]+\\.)?<domain>(/.*)?$``
    pattern — matches the bare domain + subdomains when
    ``include_subdomains=True`` (the common operator default).

    Operators paste the result into Burp via Target → Scope
    → Configure → Import. The format is documented in Burp's
    user docs."""
    out_of_scope_domains = out_of_scope_domains or []
    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<scope>',
        '  <include>',
    ]
    for domain in in_scope_domains:
        lines.append(_scope_rule_xml(domain, include_subdomains))
    lines.append('  </include>')
    if out_of_scope_domains:
        lines.append('  <exclude>')
        for domain in out_of_scope_domains:
            lines.append(_scope_rule_xml(domain, include_subdomains))
        lines.append('  </exclude>')
    lines.append('</scope>')
    return "\n".join(lines) + "\n"


def _scope_rule_xml(domain: str, include_subdomains: bool) -> str:
    """Single ``<rule>`` element. Burp's regex flavor escapes
    dots; we do the same. Bare host (no ``http://``) so the
    same rule applies across both protocols when the operator
    chooses."""
    escaped = domain.replace(".", r"\.")
    sub_prefix = r"([^/]+\.)?" if include_subdomains else ""
    pattern = f"^https?://{sub_prefix}{escaped}(/.*)?$"
    return (
        f'    <rule enabled="true">'
        f'<host>{pattern}</host>'
        f'</rule>'
    )


def export_campaign_scope_to_burp(
    state: dict[str, Any],
    output_path: Path | str,
    *,
    include_subdomains: bool = True,
) -> Path:
    """Convenience wrapper: extract in-scope domains from
    campaign state, write a Burp scope XML at ``output_path``.

    Returns the resolved output path so callers can print
    "wrote N entries to <path>"."""
    in_scope = list(state.get("seeds") or [])
    # Campaign state usually carries the scope-yaml domain
    # list at ``scope.in_scope.domains``; fall back to seeds.
    scope_obj = state.get("scope")
    if isinstance(scope_obj, dict):
        nested = (scope_obj.get("in_scope") or {}).get("domains") or []
        if nested:
            in_scope = list(nested)
    out_of_scope: list[str] = []
    if isinstance(scope_obj, dict):
        out_of_scope = list(
            (scope_obj.get("out_of_scope") or {}).get("domains") or []
        )
    body = render_scope_to_burp_xml(
        in_scope,
        out_of_scope_domains=out_of_scope,
        include_subdomains=include_subdomains,
    )
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# ──────────────────────────────────────────────────────────────────────
# Tool wrapper for import
# ──────────────────────────────────────────────────────────────────────


@register_tool
class BurpXmlImporter(OSINTTool):
    """OSINTTool wrapper for the Burp import path. ``target``
    is the path to a Burp site map XML file."""

    name: str = "burp_xml_importer"
    tier: Tier = Tier.T0  # purely a file read; no network
    category: Category = Category.WEB
    cost_per_run_usd: float = 0.0
    target_types: list[str] = ["file"]
    description: str = (
        "Imports a Burp Suite site map XML export into the "
        "Living Graph. Dedupes by (host, port, path)."
    )

    async def run(
        self, target: str, **kwargs: Any,
    ) -> ToolResult:
        start = time.time()
        path = Path(target).expanduser()
        if not path.exists():
            return ToolResult(
                success=False, source=self.name,
                error=f"file not found: {target}",
                runtime_ms=int((time.time() - start) * 1000),
            )
        try:
            xml_text = path.read_text(encoding="utf-8")
        except Exception as exc:
            return ToolResult(
                success=False, source=self.name,
                error=f"could not read {target}: {exc}",
                runtime_ms=int((time.time() - start) * 1000),
            )
        report = parse_burp_sitemap(xml_text)
        runtime_ms = int((time.time() - start) * 1000)
        return ToolResult(
            success=True, source=self.name,
            data=report.to_dict(),
            runtime_ms=runtime_ms,
            result_count=len(report.items),
            metadata={"items": [i.to_dict() for i in report.items]},
        )
