"""Crunchbase — funding rounds, leadership, acquisitions, and company intelligence."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class CrunchbaseTool(OSINTTool):
    name = "crunchbase"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys = ["crunchbase_api_key"]
    description = "Crunchbase org intelligence — funding history, leadership, acquisitions, investors"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("crunchbase_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="CRUNCHBASE_API_KEY not set")

        # Derive a permalink candidate from the domain stem
        permalink = target.split(".")[0].lower().replace(" ", "-")

        try:
            async with httpx.AsyncClient(
                base_url="https://api.crunchbase.com/api/v4",
                headers={
                    "Accept": "application/json",
                    "User-Agent": random_ua(),
                },
                timeout=20.0,
            ) as client:
                # Fetch org entity with key cards
                resp = await client.get(
                    f"/entities/organizations/{permalink}",
                    params={
                        "user_key": key,
                        "card_ids": "founders,leadership,funding_rounds,acquisitions",
                    },
                )

                if resp.status_code == 404:
                    # Try autocomplete to find the right permalink
                    ac = await client.get(
                        "/autocompletes",
                        params={"query": permalink, "collection_ids": "organizations", "user_key": key, "limit": 3},
                    )
                    if ac.status_code == 200:
                        items = ac.json().get("entities", [])
                        if items:
                            permalink = items[0].get("identifier", {}).get("permalink", permalink)
                            resp = await client.get(
                                f"/entities/organizations/{permalink}",
                                params={"user_key": key, "card_ids": "founders,leadership,funding_rounds"},
                            )

                if resp.status_code in (401, 403):
                    return ToolResult(success=False, source=self.name, error="Invalid Crunchbase API key")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"Crunchbase returned {resp.status_code}")

                raw = resp.json()
                props = raw.get("properties", {})
                cards = raw.get("cards", {})

                def _people(card_key: str) -> list[dict[str, str]]:
                    return [
                        {
                            "name": p.get("person_identifier", {}).get("value"),
                            "title": p.get("title"),
                            "started_on": p.get("started_on"),
                        }
                        for p in cards.get(card_key, [])[:20]
                        if p.get("person_identifier", {}).get("value")
                    ]

                funding_rounds = [
                    {
                        "announced": r.get("announced_on"),
                        "series": r.get("funding_type"),
                        "amount_usd": r.get("money_raised", {}).get("value_usd"),
                        "investors": [i.get("value") for i in r.get("lead_investor_identifiers", [])],
                    }
                    for r in cards.get("funding_rounds", [])[:10]
                ]

                data: dict[str, Any] = {
                    "name": props.get("identifier", {}).get("value"),
                    "permalink": permalink,
                    "domain": props.get("website", {}).get("value"),
                    "description": props.get("short_description"),
                    "founded_on": props.get("founded_on"),
                    "employee_count": props.get("num_employees_enum"),
                    "total_funding_usd": props.get("total_funding_usd"),
                    "ipo_status": props.get("ipo_status"),
                    "headquarters": props.get("location_identifiers", [{}])[0].get("value") if props.get("location_identifiers") else None,
                    "founders": _people("founders"),
                    "leadership": _people("leadership"),
                    "funding_rounds": funding_rounds,
                    "acquisitions": [
                        a.get("acquiree_identifier", {}).get("value")
                        for a in cards.get("acquisitions", [])[:10]
                    ],
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        people_count = len(data["founders"]) + len(data["leadership"])
        return ToolResult(success=True, source=self.name, data=data, result_count=people_count)
