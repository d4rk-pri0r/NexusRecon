"""Business-partner / vendor / customer intelligence (Phase E6).

Aggregator. Calls existing single-source tools where they already
exist (rather than duplicating them) and adds new signal-extraction
logic for sources that don't yet have a dedicated tool:

  - **Crunchbase** — funding rounds + leadership + acquisitions.
    Calls the existing ``crunchbase`` tool via the registry so
    operators that already configured ``CRUNCHBASE_API_KEY`` reuse
    one credential surface.
  - **BuiltWith** — tech-stack vendor inference. Requires
    ``BUILTWITH_API_KEY`` (fail-fast when absent ── same pattern as
    DeHashed). Surfaces the SaaS / infrastructure vendors a target
    domain runs on.
  - **DNS TXT vendor inference** — parses SPF includes + MX hosts
    for known vendor markers (``include:_spf.google.com`` →
    Google Workspace, ``include:spf.protection.outlook.com`` →
    Microsoft 365, ``include:mail.zendesk.com`` → Zendesk, etc.).
    Pure DNS, no API key. Surfaces vendors the target authorises
    to send email on their behalf, which is a strong signal of
    business relationship.
  - **Press-release scraping** — best-effort HTML fetch of the
    target's press / news page. Stops short of a full crawl ── we
    pull the first page only to bound wall-clock.

Output is **org-to-org** relationships, not human-to-human. The
:func:`extract_org_edges_from_business_partner` adapter materialises
corporate-identity stubs (``service="Org"``) and emits edges between
them. E9 later combines these with the human-to-human edges from
E2-E5 to build the full plausibility picture.

Dispatcher safety: empty ``dynamic_trigger_hints``.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
import structlog

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    RelationshipEdge,
    derive_identity_id,
)
from nexusrecon.core.relationship_graph import INTERACTION_WEIGHTS
from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import BaseHTTPTool, Category, Tier, ToolResult
from nexusrecon.tools.registry import get_registry, register_tool

log = structlog.get_logger(__name__)

#: Per-target hard caps.
DEFAULT_TIMEOUT_SEC = 15.0
DEFAULT_MAX_PRESS_LINKS = 20
DEFAULT_BUILTWITH_LIMIT = 50

# Known vendor markers in SPF / MX records. Maps a substring marker
# → ``(vendor_name, kind)``. Kind hints what kind of relationship
# the marker implies, which feeds the edge interaction_type.
_VENDOR_MARKERS: dict[str, tuple[str, str]] = {
    # Email senders (SPF includes)
    "_spf.google.com":                    ("Google Workspace", "email_provider"),
    "spf.protection.outlook.com":         ("Microsoft 365", "email_provider"),
    "amazonses.com":                      ("Amazon SES", "email_provider"),
    "_spf.mailgun.org":                   ("Mailgun", "email_provider"),
    "spf.sendgrid.net":                   ("SendGrid", "email_provider"),
    "spf.mandrillapp.com":                ("Mandrill", "email_provider"),
    "_spf.salesforce.com":                ("Salesforce", "saas_vendor"),
    "include.mailcontrol.com":            ("Forcepoint Email Security", "security_vendor"),
    "mailcheckin.com":                    ("Mimecast", "security_vendor"),
    "mail.zendesk.com":                   ("Zendesk", "support_vendor"),
    "_spf.intercom.io":                   ("Intercom", "support_vendor"),
    "mail.zoho.com":                      ("Zoho", "saas_vendor"),
    "_spf.helpscout.net":                 ("Help Scout", "support_vendor"),
    "mktomail.com":                       ("Marketo", "marketing_vendor"),
    "mailcheck.com":                      ("Pardot", "marketing_vendor"),
    "_spf.createsend.com":                ("Campaign Monitor", "marketing_vendor"),
    "_spf.hubspotemail.net":              ("HubSpot", "marketing_vendor"),
    "_spf.constantcontact.com":           ("Constant Contact", "marketing_vendor"),
    "_spf.mailchimp.com":                 ("Mailchimp", "marketing_vendor"),
    # MX hosts (sometimes appear in MX records rather than SPF)
    "google.com":                         ("Google Workspace", "email_provider"),
    "outlook.com":                        ("Microsoft 365", "email_provider"),
    "mail.protection.outlook.com":        ("Microsoft 365", "email_provider"),
    "messagingengine.com":                ("Fastmail", "email_provider"),
}


@register_tool
class BusinessPartnerTool(BaseHTTPTool):
    name = "business_partner"
    provider_label = "Business Partner Aggregator"
    tier = Tier.T0
    category = Category.PRETEXT
    # NOTE: ``requires_keys`` only blocks execution when ALL listed
    # secrets are missing. The aggregator can still run with partial
    # signal (e.g., DNS TXT only) when neither paid key is set, so
    # we don't set this. Per-source fail-fast happens inside run().
    requires_keys: list[str] = []
    description = (
        "Business-partner / vendor / customer org-to-org "
        "intelligence aggregator. Combines Crunchbase (funding / "
        "leadership), BuiltWith (tech stack), DNS TXT vendor "
        "inference (SPF / MX), and press-release scraping. Feeds "
        "Phase E relationship graph at the org level."
    )
    target_types = ["domain"]
    dynamic_trigger_hints: list[str] = []

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        domain = (target or "").strip().lower()
        if not domain:
            return ToolResult(
                success=False, source=self.name,
                error="business_partner: empty domain",
            )

        include_crunchbase = bool(kwargs.get("include_crunchbase", True))
        include_builtwith = bool(kwargs.get("include_builtwith", True))
        include_dns = bool(kwargs.get("include_dns_vendor_inference", True))
        include_press = bool(kwargs.get("include_press_scrape", True))
        max_press = int(kwargs.get("max_press_links", DEFAULT_MAX_PRESS_LINKS))

        sources_used: list[str] = []
        errors: list[str] = []
        crunchbase: dict[str, Any] = {}
        builtwith: dict[str, Any] = {}
        dns_vendors: list[dict[str, Any]] = []
        press_links: list[dict[str, Any]] = []

        # ── Crunchbase via the existing tool ─────────────────────
        if include_crunchbase:
            try:
                cb_result = await get_registry().execute(
                    "crunchbase", domain, target_type="domain",
                )
                if cb_result.success:
                    crunchbase = dict(cb_result.data or {})
                    sources_used.append("crunchbase")
                else:
                    errors.append(f"crunchbase: {cb_result.error}")
            except Exception as exc:
                errors.append(f"crunchbase: {exc}")

        # ── BuiltWith API ────────────────────────────────────────
        if include_builtwith:
            bw_key = self.config.get_secret("builtwith_api_key")
            if not bw_key:
                errors.append(
                    "builtwith: BUILTWITH_API_KEY required for "
                    "tech-stack inference"
                )
            else:
                try:
                    builtwith = await self._fetch_builtwith(
                        domain, bw_key,
                    )
                    if builtwith:
                        sources_used.append("builtwith")
                except Exception as exc:
                    errors.append(f"builtwith: {exc}")

        # ── DNS TXT + MX vendor inference ────────────────────────
        if include_dns:
            try:
                dns_vendors = await self._infer_dns_vendors(domain)
                if dns_vendors:
                    sources_used.append("dns_vendor_inference")
            except Exception as exc:
                errors.append(f"dns_vendor_inference: {exc}")

        # ── Press-release page scrape ────────────────────────────
        if include_press:
            try:
                press_links = await self._scrape_press_page(
                    domain, max_links=max_press,
                )
                if press_links:
                    sources_used.append("press_scrape")
            except Exception as exc:
                errors.append(f"press_scrape: {exc}")

        # If nothing succeeded AND there are errors, surface a
        # failure so the operator knows the aggregator couldn't
        # find a thing. Otherwise we return success with the
        # partial signal.
        if not sources_used:
            return ToolResult(
                success=False, source=self.name,
                error=(
                    f"business_partner: all sources failed: "
                    f"{'; '.join(errors) or 'no signal'}"
                ),
            )

        data = {
            "target": domain,
            "sources_used": sources_used,
            "errors": errors,
            "crunchbase": crunchbase,
            "builtwith": builtwith,
            "dns_vendors": dns_vendors,
            "press_links": press_links,
            "summary": {
                "vendor_count": len(dns_vendors) + (
                    len(builtwith.get("technologies") or [])
                    if isinstance(builtwith.get("technologies"), list) else 0
                ),
                "press_link_count": len(press_links),
                "leadership_count": (
                    len(crunchbase.get("leadership") or [])
                    if isinstance(crunchbase.get("leadership"), list) else 0
                ),
            },
        }

        return ToolResult(
            success=True, source=self.name, data=data,
            result_count=(
                len(dns_vendors) + len(press_links)
                + len(crunchbase.get("leadership") or [])
                + (
                    len(builtwith.get("technologies") or [])
                    if isinstance(builtwith.get("technologies"), list) else 0
                )
            ),
        )

    # ── BuiltWith ────────────────────────────────────────────────

    async def _fetch_builtwith(
        self, domain: str, api_key: str,
    ) -> dict[str, Any]:
        """Fetch BuiltWith's domain-level tech stack.

        BuiltWith's free tier (FreeAPI v1) returns a summarised list
        of technologies; the paid Domain API v17 returns deeper
        history. We hit the v17 endpoint which honors the key.
        """
        url = "https://api.builtwith.com/v17/api.json"
        try:
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT_SEC,
                headers={"User-Agent": random_ua()},
                **self._proxy_kwargs(),
            ) as client:
                resp = await client.get(
                    url,
                    params={"KEY": api_key, "LOOKUP": domain},
                )
                fail = self.classify_response(resp, "builtwith")
                if fail is not None:
                    raise RuntimeError(fail.error)
                raw = resp.json()
        except Exception as exc:
            raise RuntimeError(f"builtwith fetch failed: {exc}") from exc

        # The v17 response wraps results under "Results"[0]["Result"]["Paths"]
        # → each "Path" has "Technologies"[]. We flatten + dedup.
        techs: dict[str, dict[str, Any]] = {}
        results = raw.get("Results") or []
        if isinstance(results, list) and results:
            first = results[0] if isinstance(results[0], dict) else {}
            result_block = first.get("Result") or {}
            for path in (result_block.get("Paths") or []):
                if not isinstance(path, dict):
                    continue
                for tech in (path.get("Technologies") or []):
                    if not isinstance(tech, dict):
                        continue
                    name = tech.get("Name")
                    if not name or name in techs:
                        continue
                    techs[name] = {
                        "name": name,
                        "category": tech.get("Tag") or tech.get("Categories"),
                        "first_detected": tech.get("FirstDetected"),
                        "last_detected": tech.get("LastDetected"),
                    }

        return {
            "domain": domain,
            "technologies": list(techs.values())[:DEFAULT_BUILTWITH_LIMIT],
            "raw_meta": {
                "result_count": len(results),
                "errors": raw.get("Errors") or [],
            },
        }

    # ── DNS vendor inference ─────────────────────────────────────

    async def _infer_dns_vendors(self, domain: str) -> list[dict[str, Any]]:
        """Parse TXT (SPF) + MX records for known vendor markers.

        Uses ``dnspython`` (already a project dep). Soft-fails on
        DNS errors ── returns an empty list rather than raising.
        """
        try:
            import dns.resolver  # noqa: PLC0415
        except ImportError:
            return []

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 8.0

        found: dict[str, dict[str, Any]] = {}

        def _scan(text: str, record_type: str) -> None:
            for marker, (vendor, kind) in _VENDOR_MARKERS.items():
                if marker.lower() in text.lower():
                    if vendor not in found:
                        found[vendor] = {
                            "vendor": vendor,
                            "kind": kind,
                            "evidence": [],
                        }
                    if record_type not in found[vendor]["evidence"]:
                        found[vendor]["evidence"].append(record_type)

        # TXT (for SPF)
        try:
            txt_answers = await asyncio.to_thread(
                lambda: list(resolver.resolve(domain, "TXT")),
            )
            for r in txt_answers:
                raw = b"".join(getattr(r, "strings", [])).decode(
                    "utf-8", errors="replace",
                ) if hasattr(r, "strings") else str(r)
                _scan(raw, "TXT/SPF")
        except Exception:
            pass

        # MX
        try:
            mx_answers = await asyncio.to_thread(
                lambda: list(resolver.resolve(domain, "MX")),
            )
            for r in mx_answers:
                _scan(str(getattr(r, "exchange", r)), "MX")
        except Exception:
            pass

        return list(found.values())

    # ── Press-release scrape (best-effort) ───────────────────────

    async def _scrape_press_page(
        self, domain: str, *, max_links: int,
    ) -> list[dict[str, Any]]:
        """Fetch ``/press`` or ``/news`` and extract a few headline
        links. Best-effort ── if both paths 404 / time out, returns
        an empty list."""
        for path in ("/press", "/news", "/blog", "/press-releases"):
            url = f"https://{domain}{path}"
            try:
                async with httpx.AsyncClient(
                    timeout=DEFAULT_TIMEOUT_SEC,
                    headers={"User-Agent": random_ua()},
                    follow_redirects=True,
                    **self._proxy_kwargs(),
                ) as client:
                    resp = await client.get(url)
                    if not resp.is_success:
                        continue
                    return _extract_press_links(
                        resp.text, base_url=url, max_links=max_links,
                    )
            except Exception as exc:
                log.debug("business_partner press scrape failed",
                          url=url, error=str(exc))
                continue
        return []


# ──────────────────────────────────────────────────────────────────────
# HTML link extractor (no BeautifulSoup; minimal regex)
# ──────────────────────────────────────────────────────────────────────


_ANCHOR_RE = re.compile(
    r'<a\b[^>]*?\bhref=["\'](?P<href>[^"\']+)["\'][^>]*>(?P<text>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _extract_press_links(
    html_text: str, *, base_url: str, max_links: int,
) -> list[dict[str, Any]]:
    """Pull anchor tags out of an HTML page, lightly normalised.

    Filters anchors with empty text, anchors pointing to fragment-
    only URLs, and obvious navigation chrome ("Home", "About", etc.).
    Returns at most ``max_links`` distinct entries.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    skip_words = {
        "home", "about", "contact", "subscribe", "search", "menu",
        "skip to content", "skip to main content",
    }
    for m in _ANCHOR_RE.finditer(html_text):
        href = m.group("href").strip()
        text = _TAG_RE.sub("", m.group("text") or "").strip()
        if not href or href.startswith("#") or href.startswith("mailto:"):
            continue
        if not text or text.lower() in skip_words:
            continue
        if href in seen:
            continue
        seen.add(href)
        # Make relative URLs absolute against the base.
        if href.startswith("/"):
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            href = f"{parsed.scheme}://{parsed.netloc}{href}"
        out.append({
            "title": text[:200],
            "url": href,
        })
        if len(out) >= max_links:
            break
    return out


# ──────────────────────────────────────────────────────────────────────
# Edge-extraction adapter (org-to-org)
# ──────────────────────────────────────────────────────────────────────


def _resolve_org(
    identity_graph: IdentityGraph,
    org_name: str,
    *,
    materialize_unknown: bool = True,
) -> str | None:
    """Map an org name to an identity_id. Stub identities for unknown
    orgs carry service="Org" so they're distinguishable from human
    identities in reports.
    """
    if not org_name:
        return None
    existing = identity_graph.by_identifier(org_name)
    if existing is not None:
        return existing.identity_id
    if not materialize_unknown:
        return None
    ident = Identifier(
        value=org_name,
        identifier_type=IdentifierType.OTHER,
        service="Org",
        source="business_partner",
        confidence=0.7,
    )
    ident_id = derive_identity_id([ident])
    if ident_id in identity_graph:
        return ident_id
    stub = Identity(
        identity_id=ident_id,
        primary_label=org_name,
        identifiers=[ident],
        metadata={
            "discovered_via": "business_partner",
            "entity_type": "org",
        },
    )
    identity_graph.add_identity(stub)
    return ident_id


def extract_org_edges_from_business_partner(
    raw_data: dict[str, Any],
    target_org_identity_id: str,
    identity_graph: IdentityGraph,
    *,
    materialize_unknown: bool = True,
) -> list[tuple[str, RelationshipEdge]]:
    """Convert ``BusinessPartnerTool`` raw data into ORG-to-ORG edges.

    Direction conventions (all outbound from target org):

      - DNS vendors → ``target_org → vendor`` (interaction_type
        ``"collaborator"`` because the org explicitly authorises the
        vendor to act on its behalf).
      - BuiltWith technologies that map to known vendors → same as
        above.
      - Crunchbase "investors" (if surfaced) → ``investor →
        target_org`` (interaction_type ``"endorser"``).

    Press-release links don't yield org edges directly (they're
    content, not relationships); E8 RecentActivity captures them.
    """
    edges: list[tuple[str, RelationshipEdge]] = []

    # ── DNS vendors ──
    for vendor in (raw_data.get("dns_vendors") or []):
        name = vendor.get("vendor")
        if not name:
            continue
        v_id = _resolve_org(
            identity_graph, name,
            materialize_unknown=materialize_unknown,
        )
        if not v_id or v_id == target_org_identity_id:
            continue
        edges.append((target_org_identity_id, RelationshipEdge(
            target_identity_id=v_id,
            interaction_type="collaborator",
            strength=INTERACTION_WEIGHTS.get("collaborator", 0.85),
            last_observed=None,
            sources=["business_partner:dns"],
        )))

    # ── BuiltWith techs (only those that map to vendor names) ──
    bw = raw_data.get("builtwith") or {}
    for tech in (bw.get("technologies") or []):
        name = tech.get("name")
        if not name:
            continue
        v_id = _resolve_org(
            identity_graph, name,
            materialize_unknown=materialize_unknown,
        )
        if not v_id or v_id == target_org_identity_id:
            continue
        edges.append((target_org_identity_id, RelationshipEdge(
            target_identity_id=v_id,
            interaction_type="collaborator",
            strength=INTERACTION_WEIGHTS.get("collaborator", 0.85) * 0.7,
            last_observed=tech.get("last_detected"),
            sources=["business_partner:builtwith"],
        )))

    # ── Crunchbase investors (when present) ──
    cb = raw_data.get("crunchbase") or {}
    for inv in (cb.get("investors") or []):
        name = inv.get("name") if isinstance(inv, dict) else inv
        if not name:
            continue
        i_id = _resolve_org(
            identity_graph, name,
            materialize_unknown=materialize_unknown,
        )
        if not i_id or i_id == target_org_identity_id:
            continue
        edges.append((i_id, RelationshipEdge(
            target_identity_id=target_org_identity_id,
            interaction_type="endorser",
            strength=INTERACTION_WEIGHTS.get("endorser", 0.7),
            last_observed=None,
            sources=["business_partner:crunchbase"],
        )))

    return edges
