"""GitHub org member enumeration — employees, contributors, and public profiles."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GitHubOrgMembersTool(OSINTTool):
    name = "github_org_members"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys = ["github_token"]
    description = "GitHub org member enumeration — names, emails, and public profiles for pretexting"
    target_types = ["domain", "username"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        token = self.config.get_secret("github_token")
        if not token:
            return ToolResult(success=False, source=self.name, error="GITHUB_TOKEN not set")

        target_type = kwargs.get("target_type", "domain")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        }

        try:
            async with httpx.AsyncClient(
                base_url="https://api.github.com",
                headers=headers,
                timeout=20.0,
            ) as client:
                # If target is a domain, first find the org handle
                org_names: List[str] = []
                if target_type == "username":
                    org_names = [target]
                else:
                    # Derive company name from domain and search for it as a GitHub org
                    company = target.split(".")[0]
                    search_resp = await client.get(
                        "/search/users",
                        params={"q": f"{company} type:org", "per_page": 5},
                    )
                    if search_resp.status_code == 200:
                        for item in search_resp.json().get("items", []):
                            org_names.append(item["login"])
                    # Also try the domain stem directly as an org handle
                    if company not in org_names:
                        org_names.insert(0, company)

                all_members: List[Dict[str, Any]] = []
                orgs_enumerated: List[str] = []

                for org in org_names[:3]:
                    members_resp = await client.get(
                        f"/orgs/{org}/members",
                        params={"per_page": 100},
                    )
                    if members_resp.status_code != 200:
                        continue

                    orgs_enumerated.append(org)
                    members = members_resp.json()

                    # Fetch extended profile for up to 30 members in parallel
                    async def _get_profile(login: str) -> Dict[str, Any]:
                        r = await client.get(f"/users/{login}")
                        if r.status_code == 200:
                            u = r.json()
                            return {
                                "login": u.get("login"),
                                "name": u.get("name"),
                                "email": u.get("email"),
                                "company": u.get("company"),
                                "location": u.get("location"),
                                "bio": u.get("bio"),
                                "blog": u.get("blog"),
                                "public_repos": u.get("public_repos"),
                                "followers": u.get("followers"),
                                "profile_url": u.get("html_url"),
                                "avatar_url": u.get("avatar_url"),
                            }
                        return {"login": login}

                    profiles = await asyncio.gather(
                        *(_get_profile(m["login"]) for m in members[:30]),
                        return_exceptions=True,
                    )
                    for p in profiles:
                        if isinstance(p, dict):
                            all_members.append(p)

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        emails = [m["email"] for m in all_members if m.get("email")]
        data: Dict[str, Any] = {
            "target": target,
            "orgs_found": orgs_enumerated,
            "member_count": len(all_members),
            "members": all_members,
            "emails_found": emails,
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(all_members))
