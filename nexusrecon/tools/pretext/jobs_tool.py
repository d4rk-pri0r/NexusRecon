"""Job posting tech stack mining tool."""
from __future__ import annotations

import re
from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

ADZUNA_API = "https://api.adzuna.com/v1/api/jobs"

TECH_KEYWORDS = [
    "python", "java", "javascript", "typescript", "golang", "rust", "ruby",
    "react", "angular", "vue", "node", "django", "flask", "spring",
    "aws", "azure", "gcp", "kubernetes", "docker", "terraform",
    "postgresql", "mysql", "mongodb", "redis", "elasticsearch",
    "machine learning", "data science", "devops", "sre", "security",
]


@register_tool
class JobsTool(OSINTTool):
    name = "jobs_intel"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys = []
    description = "Job posting tech stack mining from Adzuna API + web fallback"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        results: list[dict[str, Any]] = []
        sources_used: list[str] = []

        # Adzuna API (requires API key)
        adzuna_key = self.config.get_secret("adzuna_api_key")
        adzuna_id = self.config.get_secret("adzuna_app_id")
        if adzuna_key and adzuna_id:
            adzuna_results = await self._fetch_adzuna(target, adzuna_id, adzuna_key)
            results.extend(adzuna_results)
            sources_used.append("adzuna")

        # Web scrape fallback — try Google Jobs
        web_results = await self._scrape_google_jobs(target)
        results.extend(web_results)
        if web_results:
            sources_used.append("google_jobs")

        # Extract tech stack across all job postings
        tech_stack: dict[str, int] = {}
        for job in results:
            text = f"{job.get('title', '')} {job.get('description', '')}".lower()
            for kw in TECH_KEYWORDS:
                if kw in text:
                    tech_stack[kw] = tech_stack.get(kw, 0) + 1

        return ToolResult(
            success=True, source=self.name,
            data={
                "target": target,
                "total_jobs": len(results),
                "sources_used": sources_used,
                "jobs": results[:30],
                "tech_stack": dict(sorted(tech_stack.items(), key=lambda x: -x[1])),
                "top_technologies": [k for k, v in sorted(tech_stack.items(), key=lambda x: -x[1])[:10]],
            },
            result_count=len(results),
        )

    async def _fetch_adzuna(self, target: str, app_id: str, api_key: str) -> list[dict[str, Any]]:
        """Query Adzuna API for job postings related to the target."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{ADZUNA_API}/us/search/1",
                    params={
                        "app_id": app_id,
                        "app_key": api_key,
                        "what": target,
                        "content_type": "application/json",
                        "results_per_page": 20,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [
                        {
                            "title": j.get("title", ""),
                            "company": j.get("company", {}).get("display_name", ""),
                            "location": j.get("location", {}).get("display_name", ""),
                            "description": (j.get("description") or "")[:500],
                            "url": j.get("redirect_url", ""),
                            "salary_min": j.get("salary_min"),
                            "salary_max": j.get("salary_max"),
                            "category": j.get("category", {}).get("label", ""),
                            "source": "adzuna",
                        }
                        for j in data.get("results", [])
                    ]
        except Exception:
            pass
        return []

    async def _scrape_google_jobs(self, target: str) -> list[dict[str, Any]]:
        """Scrape Google Jobs for postings mentioning the target company/domain."""
        jobs: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                resp = await client.get(
                    "https://www.google.com/search",
                    params={"q": f"{target} jobs hiring", "ibp": "htl;jobs"},
                    headers={"User-Agent": random_ua()},
                )
                if resp.status_code == 200:
                    # Extract job titles from Google Jobs results
                    titles = re.findall(r'<div[^>]*class="[^"]*jobTitle[^"]*"[^>]*>(.*?)</div>', resp.text, re.DOTALL)
                    companies = re.findall(r'<div[^>]*class="[^"]*companyName[^"]*"[^>]*>(.*?)</div>', resp.text, re.DOTALL)
                    for i, title in enumerate(titles[:20]):
                        jobs.append({
                            "title": re.sub(r"<[^>]+>", "", title).strip(),
                            "company": re.sub(r"<[^>]+>", "", companies[i]).strip() if i < len(companies) else "",
                            "description": "",
                            "source": "google_jobs",
                        })
        except Exception:
            pass
        return jobs
