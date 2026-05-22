"""Wikipedia/Wikidata — structured org intelligence from public encyclopedic sources."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class WikipediaTool(OSINTTool):
    name = "wikipedia"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys = []
    description = "Wikipedia/Wikidata org intelligence — founding date, leadership, HQ, subsidiaries, industry"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        company = target.split(".")[0].replace("-", " ")

        try:
            async with httpx.AsyncClient(
                headers={
                    "Accept": "application/json",
                    "User-Agent": "NexusRecon OSINT Platform/1.0 (authorized engagement)",
                },
                timeout=15.0,
            ) as client:
                # Step 1 — Wikidata entity search
                search_resp = await client.get(
                    "https://www.wikidata.org/w/api.php",
                    params={
                        "action": "wbsearchentities",
                        "search": company,
                        "language": "en",
                        "type": "item",
                        "limit": 3,
                        "format": "json",
                    },
                )
                if search_resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"Wikidata search returned {search_resp.status_code}")

                results = search_resp.json().get("search", [])
                if not results:
                    return ToolResult(success=True, source=self.name, data={"target": target, "found": False}, result_count=0)

                qid = results[0]["id"]
                label = results[0].get("label", company)
                description = results[0].get("description", "")

                # Step 2 — Wikipedia summary
                wiki_resp = await client.get(
                    f"https://en.wikipedia.org/api/rest_v1/page/summary/{label.replace(' ', '_')}",
                )
                wiki_summary = ""
                wiki_url = ""
                if wiki_resp.status_code == 200:
                    wiki_data = wiki_resp.json()
                    wiki_summary = wiki_data.get("extract", "")[:500]
                    wiki_url = wiki_data.get("content_urls", {}).get("desktop", {}).get("page", "")

                # Step 3 — Wikidata structured properties
                entity_resp = await client.get(
                    f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json",
                )
                claims: dict[str, Any] = {}
                if entity_resp.status_code == 200:
                    entity = entity_resp.json().get("entities", {}).get(qid, {})
                    claims = entity.get("claims", {})

                def _claim_value(prop: str) -> str | None:
                    snaks = claims.get(prop, [{}])
                    if not snaks:
                        return None
                    mv = snaks[0].get("mainsnak", {}).get("datavalue", {}).get("value")
                    if isinstance(mv, dict):
                        return mv.get("text") or mv.get("time") or str(mv)
                    return str(mv) if mv else None

                def _claim_values(prop: str, limit: int = 5) -> list[str]:
                    vals = []
                    for snak in claims.get(prop, [])[:limit]:
                        mv = snak.get("mainsnak", {}).get("datavalue", {}).get("value")
                        if isinstance(mv, dict):
                            v = mv.get("text") or mv.get("id")
                        else:
                            v = str(mv) if mv else None
                        if v:
                            vals.append(v)
                    return vals

                data: dict[str, Any] = {
                    "target": target,
                    "found": True,
                    "wikidata_id": qid,
                    "name": label,
                    "description": description,
                    "summary": wiki_summary,
                    "wikipedia_url": wiki_url,
                    # P571 = inception/founding date, P18 = image, P159 = HQ location,
                    # P112 = founded by, P169 = CEO, P452 = industry, P355 = subsidiaries
                    "founded": _claim_value("P571"),
                    "headquarters": _claim_value("P159"),
                    "industry": _claim_values("P452"),
                    "ceo": _claim_value("P169"),
                    "founded_by": _claim_values("P112"),
                    "subsidiaries": _claim_values("P355"),
                    "number_of_employees": _claim_value("P1082"),
                    "official_website": _claim_value("P856"),
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=1)
