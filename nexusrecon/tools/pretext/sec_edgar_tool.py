"""SEC EDGAR filings parsing tool."""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

EDGAR_SEARCH_URL = "https://efts.sec.gov/LATEST/search-index"
EDGAR_CIK_LOOKUP = "https://www.sec.gov/cgi-bin/browse-edgar"

FILING_TYPES = [
    "10-K", "10-Q", "8-K", "S-1", "DEF 14A", "20-F", "6-K",
]

TECH_KEYWORDS = [
    "cybersecurity", "data breach", "ransomware", "security incident",
    "cloud infrastructure", "artificial intelligence", "machine learning",
    "zero trust", "encryption", "vulnerability", "patent",
    "information security", "privacy", "gdpr", "ccpa", "soc 2",
    "acquisition", "merger", "strategic partnership",
]


@register_tool
class SECEdgarTool(OSINTTool):
    name = "sec_edgar"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys = []
    description = "SEC filings (10-K, 10-Q, 8-K) parsing for tech disclosures"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        company_name = kwargs.get("company_name") or self._domain_to_company(target)
        filings: List[Dict[str, Any]] = []
        tech_mentions: Dict[str, int] = {}

        # Search SEC EDGAR full-text index
        search_results = await self._search_edgar(company_name)
        for filing in search_results:
            # Fetch detailed filing content for tech keyword analysis
            if filing.get("url"):
                content = await self._fetch_filing_text(filing["url"])
                if content:
                    filing["content_preview"] = content[:1000]
                    for kw in TECH_KEYWORDS:
                        count = len(re.findall(re.escape(kw), content, re.IGNORECASE))
                        if count > 0:
                            tech_mentions[kw] = tech_mentions.get(kw, 0) + count
            filings.append(filing)

        return ToolResult(
            success=True, source=self.name,
            data={
                "target": target,
                "company_name": company_name,
                "total_filings": len(filings),
                "filings": filings[:20],
                "relevant_tech_mentions": dict(sorted(tech_mentions.items(), key=lambda x: -x[1])),
            },
            result_count=len(filings),
        )

    async def _search_edgar(self, company: str) -> List[Dict[str, Any]]:
        """Search SEC EDGAR full-text index for filings mentioning the company."""
        results: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                for filing_type in FILING_TYPES[:3]:
                    resp = await client.get(
                        EDGAR_SEARCH_URL,
                        params={
                            "q": f'"{company}" AND formType:"{filing_type}"',
                            "start": 0,
                            "count": 10,
                        },
                        headers={
                            "User-Agent": "NexusRecon/1.0 (mailto:research@example.com)",
                            "Accept": "application/json",
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for hit in data.get("hits", {}).get("hits", []):
                            source = hit.get("_source", {})
                            results.append({
                                "filing_type": source.get("formType", filing_type),
                                "company": source.get("companyName", ""),
                                "cik": source.get("cik", ""),
                                "filed_at": source.get("filedAt", ""),
                                "description": (source.get("description") or "")[:300],
                                "url": source.get("fileUrl", ""),
                            })
        except Exception:
            pass
        return results

    async def _fetch_filing_text(self, url: str) -> Optional[str]:
        """Fetch filing text for keyword analysis."""
        if not url.startswith("http"):
            url = f"https://www.sec.gov{url}" if url.startswith("/") else url
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={
                    "User-Agent": "NexusRecon/1.0 (mailto:research@example.com)",
                })
                if resp.status_code == 200:
                    text = resp.text
                    # Strip HTML tags
                    text = re.sub(r"<[^>]+>", " ", text)
                    text = re.sub(r"\s+", " ", text).strip()
                    return text[:10000]
        except Exception:
            pass
        return None

    @staticmethod
    def _domain_to_company(domain: str) -> str:
        """Extract company name from domain."""
        name = domain.split(".")[0]
        # Remove common prefixes
        for prefix in ["www", "app", "api", "mail", "login", "portal"]:
            if name == prefix and "." in domain:
                name = domain.split(".")[1]
        # Capitalize
        name = name.replace("-", " ").replace("_", " ")
        return " ".join(word.capitalize() for word in name.split())
