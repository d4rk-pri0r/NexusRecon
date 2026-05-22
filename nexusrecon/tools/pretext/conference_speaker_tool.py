"""Conference speaker + co-speaker intelligence (Phase E7).

Crawls a hardcoded list of well-known conferences for talks featuring
a given target name / org and extracts the co-speaker graph. Co-
speaker relationships are a particularly strong pretext signal ──
two people who shared a stage at DEFCON last year have plausible
reason to email each other about "follow-up from the talk".

Architectural posture (locked-in 2026-05-21):

  - **Hardcoded site list ships by default.** Predictable behaviour,
    no LLM cost on the default path, easy to test. The default set
    targets infosec / SRE / OSS communities where the operator is
    most likely to find pretext-relevant signal:
        DEFCON, BSides, RSA, KubeCon, FOSDEM, BlackHat,
        Strange Loop, USENIX.
  - **LLM expansion is opt-in.** When
    ``state["dispatch_mode"] == "full"`` Phase E11 may suggest
    additional sites; this tool itself never calls the dispatcher.
  - **Empty ``dynamic_trigger_hints``.** Tool runs only when E11
    explicitly invokes it. No auto-fire from the dispatcher.

Site-specific parsing reality:

  Most conference sites are heavily JS-rendered and lack a public
  schedule API. Reliable scraping requires per-site reverse-
  engineering that's brittle (HTML changes when the site is
  redesigned for the next year). This module ships with the data
  shape + parser interface locked in but the parser implementations
  return best-effort signal only. Operators that need full talk-
  level data should plug in conference-specific exports (CFP-time
  JSON dumps, schedule.json endpoints).

  The parser interface (:class:`ConferenceSite`) is designed to be
  swappable per-site without touching the aggregator ── operators
  can drop in better parsers as conferences evolve.

Shape contract (``ToolResult.data``):

    {
        "target": str,                  # the name / org searched
        "conferences_probed": [str],
        "talks": [
            {
                "conference": "DEFCON",
                "year": 2024,
                "title": "...",
                "url": "...",
                "speakers": ["Alice Doe", "Bob Smith"],
                "track": "Main Track",
            }, ...
        ],
        "summary": {
            "talks_found": int,
            "unique_speakers": int,
            "unique_co_speakers": int,  # excludes target
            "conferences_with_hits": int,
        },
    }

Adapter: :func:`extract_edges_from_conference_speaker` emits
co-speaker edges (bidirectional, INTERACTION_WEIGHTS["co-speaker"]
== 0.95).
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass
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
from nexusrecon.tools.registry import register_tool

log = structlog.get_logger(__name__)

DEFAULT_TIMEOUT_SEC = 15.0
DEFAULT_MAX_TALKS_PER_CONF = 20


# ──────────────────────────────────────────────────────────────────────
# Site registry
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ConferenceSite:
    """One conference's scrape definition.

    Attributes:
        name: Human-readable conference name (used in reports + edge
            sources).
        archive_url: A URL the parser should fetch. Templated with
            ``{target}`` when the conference supports search; static
            otherwise.
        parser: Callable ``(html_text, target) -> list[talk_dict]``.
            See :func:`_parse_generic` for the default that returns
            an empty list. Override per-site for richer extraction.
        supports_query: When True, ``{target}`` in ``archive_url``
            is URL-encoded and substituted before the fetch. When
            False, the parser does the filtering client-side.
    """

    name: str
    archive_url: str
    parser: Callable[[str, str], list[dict[str, Any]]]
    supports_query: bool = False


def _parse_generic(html_text: str, target: str) -> list[dict[str, Any]]:
    """Default parser ── returns no talks.

    Conference HTML varies wildly; the safe default is "best-effort
    empty" so the tool always returns a clean structure even when no
    site-specific parser has been wired up. Operators add real
    parsers for conferences they care about by extending
    :data:`SITE_REGISTRY`.
    """
    return []


def _parse_fosdem(html_text: str, target: str) -> list[dict[str, Any]]:
    """FOSDEM's schedule pages list speakers in ``<li>`` tags inside
    a ``speakers`` ``<ul>``. This parser is *best-effort* and
    matches the historical schedule layout; the live site may have
    drifted.
    """
    talks: list[dict[str, Any]] = []
    target_lower = target.lower()
    # Each event has an <h4 class="event"><a href="...">Talk title</a></h4>
    # followed by a speakers block.
    for m in re.finditer(
        r'<h4 class="event"[^>]*>\s*<a href="(?P<url>[^"]+)"[^>]*>'
        r'(?P<title>[^<]+)</a>',
        html_text, re.IGNORECASE,
    ):
        title = (m.group("title") or "").strip()
        # Look ahead for a speakers block within ~500 chars.
        tail = html_text[m.end():m.end() + 1500]
        speakers = []
        for sm in re.finditer(
            r'<a[^>]*href="/[^"]*/speaker/[^"]*"[^>]*>([^<]+)</a>',
            tail, re.IGNORECASE,
        ):
            name = sm.group(1).strip()
            if name and name not in speakers:
                speakers.append(name)
        # Only include if the target appears in title or speaker list.
        relevant = (
            target_lower in title.lower()
            or any(target_lower in s.lower() for s in speakers)
        )
        if not relevant:
            continue
        talks.append({
            "title": title,
            "url": m.group("url"),
            "speakers": speakers,
            "track": None,
        })
    return talks


#: Hardcoded default conference list. Keep ordering deterministic
#: (tests can assert against it). Operators override / extend via
#: the ``sites`` kwarg on :meth:`ConferenceSpeakerTool.run`.
SITE_REGISTRY: tuple[ConferenceSite, ...] = (
    ConferenceSite(
        name="DEFCON",
        archive_url="https://defcon.org/html/links/dc-archives.html",
        parser=_parse_generic,
    ),
    ConferenceSite(
        name="BSides",
        archive_url="https://bsides.org",
        parser=_parse_generic,
    ),
    ConferenceSite(
        name="RSA",
        archive_url="https://www.rsaconference.com/usa/agenda",
        parser=_parse_generic,
    ),
    ConferenceSite(
        name="KubeCon",
        archive_url="https://kccncna.io",
        parser=_parse_generic,
    ),
    ConferenceSite(
        name="FOSDEM",
        archive_url="https://fosdem.org/2025/schedule/",
        parser=_parse_fosdem,
    ),
    ConferenceSite(
        name="BlackHat",
        archive_url="https://www.blackhat.com/us-24/briefings/schedule/",
        parser=_parse_generic,
    ),
    ConferenceSite(
        name="Strange Loop",
        archive_url="https://www.thestrangeloop.com/sessions.html",
        parser=_parse_generic,
    ),
    ConferenceSite(
        name="USENIX",
        archive_url="https://www.usenix.org/conferences",
        parser=_parse_generic,
    ),
)


# ──────────────────────────────────────────────────────────────────────
# Tool
# ──────────────────────────────────────────────────────────────────────


@register_tool
class ConferenceSpeakerTool(BaseHTTPTool):
    name = "conference_speaker"
    provider_label = "Conference Speakers"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys: list[str] = []
    description = (
        "Conference talk + co-speaker discovery across the major "
        "infosec / OSS conferences (DEFCON, BSides, RSA, KubeCon, "
        "FOSDEM, BlackHat, Strange Loop, USENIX). Co-speaker edges "
        "feed Phase E relationship graph + pretext scoring."
    )
    target_types = ["username", "handle", "identity", "name"]
    dynamic_trigger_hints: list[str] = []

    # Conference sites often serve 404 for missing pages (e.g. last
    # year's URL after a redesign). Treat 404 as soft so a single
    # dead URL doesn't abort the whole crawl.
    soft_failure_codes: tuple[int, ...] = (404,)

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        target_clean = (target or "").strip()
        if not target_clean:
            return ToolResult(
                success=False, source=self.name,
                error="conference_speaker: empty target",
            )

        sites_override = kwargs.get("sites")
        sites = _resolve_sites(sites_override)
        max_per_conf = int(kwargs.get(
            "max_talks_per_conference", DEFAULT_MAX_TALKS_PER_CONF,
        ))

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml",
            "User-Agent": random_ua(),
        }

        async def _probe(site: ConferenceSite) -> tuple[ConferenceSite, list[dict[str, Any]]]:
            url = site.archive_url
            if site.supports_query and "{target}" in url:
                from urllib.parse import quote
                url = url.replace("{target}", quote(target_clean))
            try:
                async with httpx.AsyncClient(
                    headers=headers,
                    timeout=DEFAULT_TIMEOUT_SEC,
                    follow_redirects=True,
                    **self._proxy_kwargs(),
                ) as client:
                    resp = await client.get(url)
                    fail = self.classify_response(resp, site.name)
                    if fail is not None:
                        # 404 in soft list → treat as "no hits" rather than
                        # propagating up. Other classify failures (401/403/
                        # 429/5xx) we just log and continue.
                        return site, []
                    talks = site.parser(resp.text, target_clean)
                    return site, talks[:max_per_conf]
            except Exception as exc:
                log.debug(
                    "conference_speaker probe failed",
                    site=site.name, error=str(exc),
                )
                return site, []

        probes = await asyncio.gather(
            *(_probe(s) for s in sites),
            return_exceptions=True,
        )

        all_talks: list[dict[str, Any]] = []
        conferences_probed: list[str] = []
        conferences_with_hits: list[str] = []
        for entry in probes:
            if isinstance(entry, BaseException):
                continue
            site, talks = entry
            conferences_probed.append(site.name)
            if not talks:
                continue
            conferences_with_hits.append(site.name)
            for talk in talks:
                all_talks.append({
                    "conference": site.name,
                    "year": talk.get("year"),
                    "title": talk.get("title"),
                    "url": talk.get("url"),
                    "speakers": list(talk.get("speakers") or []),
                    "track": talk.get("track"),
                })

        unique_speakers: set[str] = set()
        unique_co_speakers: set[str] = set()
        target_lower = target_clean.lower()
        for t in all_talks:
            for s in t["speakers"]:
                if not s:
                    continue
                unique_speakers.add(s)
                if s.lower() != target_lower:
                    unique_co_speakers.add(s)

        data = {
            "target": target_clean,
            "conferences_probed": conferences_probed,
            "talks": all_talks,
            "summary": {
                "talks_found": len(all_talks),
                "unique_speakers": len(unique_speakers),
                "unique_co_speakers": len(unique_co_speakers),
                "conferences_with_hits": len(conferences_with_hits),
            },
        }

        return ToolResult(
            success=True, source=self.name, data=data,
            result_count=len(all_talks),
        )


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _resolve_sites(override: Any) -> list[ConferenceSite]:
    """Build the probe list.

    When ``override`` is a list of :class:`ConferenceSite`, use it
    directly. When a list of strings, filter the default registry
    by name. Otherwise return the full default registry.
    """
    if override is None:
        return list(SITE_REGISTRY)
    if isinstance(override, (list, tuple)):
        if all(isinstance(o, ConferenceSite) for o in override):
            return list(override)
        if all(isinstance(o, str) for o in override):
            wanted = {s.lower() for s in override}
            return [s for s in SITE_REGISTRY if s.name.lower() in wanted]
    return list(SITE_REGISTRY)


# ──────────────────────────────────────────────────────────────────────
# Edge-extraction adapter
# ──────────────────────────────────────────────────────────────────────


def _resolve_speaker(
    identity_graph: IdentityGraph,
    name: str,
    *,
    materialize_unknown: bool = True,
) -> str | None:
    """Map a speaker name to an identity_id. Stub identities for
    unknown speakers carry IdentifierType.REAL_NAME."""
    if not name:
        return None
    existing = identity_graph.by_identifier(name)
    if existing is not None:
        return existing.identity_id
    if not materialize_unknown:
        return None
    ident = Identifier(
        value=name,
        identifier_type=IdentifierType.REAL_NAME,
        source="conference_speaker",
        confidence=0.7,
    )
    ident_id = derive_identity_id([ident])
    if ident_id in identity_graph:
        return ident_id
    stub = Identity(
        identity_id=ident_id,
        primary_label=name,
        identifiers=[ident],
        metadata={"discovered_via": "conference_speaker"},
    )
    identity_graph.add_identity(stub)
    return ident_id


def extract_edges_from_conference_speaker(
    raw_data: dict[str, Any],
    crawled_identity_id: str,
    identity_graph: IdentityGraph,
    *,
    materialize_unknown: bool = True,
) -> list[tuple[str, RelationshipEdge]]:
    """Convert ``ConferenceSpeakerTool`` raw data into co-speaker
    edges.

    Direction conventions:

      - For each talk in which the crawled identity (matched by
        name) appears: every OTHER speaker becomes a bidirectional
        ``co-speaker`` edge (crawled ↔ each other speaker).
      - Self-loops dropped.

    Strength is :data:`~nexusrecon.core.relationship_graph.INTERACTION_WEIGHTS`
    ``["co-speaker"]`` (0.95 ── strongest tier).
    """
    edges: list[tuple[str, RelationshipEdge]] = []
    target_lower = (raw_data.get("target") or "").lower()
    weight = INTERACTION_WEIGHTS.get("co-speaker", 0.95)

    for talk in (raw_data.get("talks") or []):
        speakers = talk.get("speakers") or []
        # Only emit edges from talks the crawled identity is actually
        # in ── otherwise we'd emit edges between random co-speakers
        # of unrelated talks the crawled user wasn't part of.
        if not any(s and s.lower() == target_lower for s in speakers):
            continue
        # Use the talk URL as a year-ish marker if present; some
        # conferences embed year in the URL slug.
        last_obs = _year_to_iso(talk.get("year"))

        for other_name in speakers:
            if not other_name or other_name.lower() == target_lower:
                continue
            other_id = _resolve_speaker(
                identity_graph, other_name,
                materialize_unknown=materialize_unknown,
            )
            if not other_id or other_id == crawled_identity_id:
                continue
            sources = ["conference_speaker"]
            if talk.get("conference"):
                sources.append(f"conf:{talk['conference']}")
            edges.append((crawled_identity_id, RelationshipEdge(
                target_identity_id=other_id,
                interaction_type="co-speaker",
                strength=weight,
                last_observed=last_obs,
                sources=sources,
            )))
            edges.append((other_id, RelationshipEdge(
                target_identity_id=crawled_identity_id,
                interaction_type="co-speaker",
                strength=weight,
                last_observed=last_obs,
                sources=list(sources),
            )))

    return edges


def _year_to_iso(year: Any) -> str | None:
    """Convert a year integer / string to ``YYYY-01-01T00:00:00Z``.

    Used as a coarse ``last_observed`` for co-speaker edges when the
    parser only surfaces a year. None → None.
    """
    if year is None:
        return None
    try:
        y = int(year)
    except (TypeError, ValueError):
        return None
    if y < 1990 or y > 2100:
        return None
    return f"{y}-01-01T00:00:00+00:00"
