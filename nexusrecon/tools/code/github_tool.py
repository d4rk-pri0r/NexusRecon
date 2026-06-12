"""
GitHub reconnaissance tool.

Implements:
  - Organization enumeration (repos, members, forks)
  - Code search for secrets, endpoints, config files
  - Dork-based discovery (curated dork list)
  - User enumeration (if username provided)

Tier: T0 (GitHub API only, passive)
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

GITHUB_CODE_DORKS = [
    "aws_access_key_id",
    "aws_secret_access_key",
    "api_key",
    "api_secret",
    "access_token",
    "auth_token",
    "client_secret",
    "connection_string",
    "database_url",
    "db_password",
    "password",
    "secret_key",
    "private_key",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "jdbc:",
    "mysql://",
    "postgres://",
    "redis://",
    "mongodb://",
    "mongodb+srv://",
    "slack_token",
    "slack_webhook",
    "github_token",
    "npm_token",
    "docker_password",
    "heroku_api_key",
    "mailgun_api_key",
    "sendgrid_api_key",
    "twilio_auth_token",
    "stripe_secret_key",
    "firebase_database_url",
    "google_oauth_secret",
    "okta_client_token",
    "salesforce_password",
    "internal.",
    "dev.",
    "staging.",
    "admin.",
    "s3.amazonaws.com",
    "blob.core.windows.net",
]


@register_tool
class GitHubTool(OSINTTool):
    name = "github_recon"
    tier = Tier.T0
    category = Category.CODE
    requires_keys = ["github_token"]
    description = "GitHub org/user enumeration, code search, and dork scanning"
    target_types = ["domain", "github_org", "github_user"]
    dynamic_trigger_hints = ["github repository found", "github org discovered"]

    def __init__(self) -> None:
        super().__init__()
        self._http: httpx.AsyncClient | None = None
        # Status codes seen this run, so assess_result can distinguish a
        # throttled/unauthorized scan (401/403/429) from a genuine empty.
        self._status_codes: list[int] = []

    async def _get_client(self, token: str) -> httpx.AsyncClient:
        if self._http is None:
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "NexusRecon/1.0",
            }
            self._http = httpx.AsyncClient(
                base_url="https://api.github.com",
                headers=headers,
                timeout=10.0,
                http2=True,
            )
        return self._http

    async def _close(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    async def _get(self, client: httpx.AsyncClient, url: str, **kwargs: Any) -> httpx.Response:
        """GET wrapper that records each response status so assess_result can
        detect the auth / rate-limit failures (401/403/429) that this tool's
        per-endpoint handlers otherwise swallow into empty org/repo/secret
        results (the documented "quiet rate-limit-driven empty results")."""
        resp = await client.get(url, **kwargs)
        self._status_codes.append(resp.status_code)
        return resp

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        # The tool declares ``requires_keys = ["github_token"]`` but a
        # previous revision wrote ``token = self.config.get_secret(...)
        # or ""`` in ``_get_client``, falling back to an empty string
        # token. GitHub treats an empty ``Authorization: token`` header
        # as unauthenticated, which caps the rate at 60 req/hr — far
        # too low for the 20-dork scan in ``_search_secrets``. The
        # operator saw quiet rate-limit-driven empty results instead
        # of a clear "set GITHUB_TOKEN" error.
        # Reset unconditionally on every run() path, before the token check,
        # so a reused tool instance never carries a prior run's status codes.
        self._status_codes = []
        token = self.config.get_secret("github_token")
        if not token:
            return ToolResult(
                success=False, source=self.name,
                error="GITHUB_TOKEN not set",
            )

        results: dict[str, Any] = {}
        try:
            client = await self._get_client(token)

            # Determine target type
            target_type = kwargs.get("target_type", "domain")

            if target_type in ("github_org", "domain"):
                # Try as org name
                results["org"] = await self._get_org(client, target)
                results["org_repos"] = await self._get_org_repos(client, target)

                # Search for domain in code
                results["domain_in_code"] = await self._search_code(client, target)

                # Search with dorks
                results["secret_searches"] = await self._search_secrets(client, target)

            elif target_type == "github_user":
                results["user"] = await self._get_user(client, target)
                results["user_repos"] = await self._get_user_repos(client, target)

            await self._close()
            # Flag whether any endpoint hit an auth / rate-limit failure so
            # assess_result can mark a throttled scan degraded. 404 (target is
            # not an org/user) is deliberately excluded: it is a legitimate
            # negative, not a failure.
            results["_status_degraded"] = any(
                s in (401, 403, 429) for s in self._status_codes
            )
            repo_count = len(results.get("org_repos", {}).get("repos", []))
            return ToolResult(
                success=True, source=self.name, data=results,
                result_count=repo_count,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # GitHub's REST/search endpoints return 401 (bad/expired token), 403
        # (rate limit or insufficient scope), or 429 on failure; this tool used
        # to swallow those into empty org/repo/secret results, so a throttled
        # run looked identical to "nothing on GitHub". A 404 (target is not an
        # org/user) is a legitimate negative and is deliberately not flagged.
        d = result.data or {}
        if d.get("_status_degraded"):
            return (
                "GitHub queries hit auth or rate-limit errors (401/403/429); "
                "the empty result reflects a throttled or unauthorized scan, "
                "not the absence of repositories, code, or secrets"
            )
        return None

    async def _get_org(self, client: httpx.AsyncClient, org: str) -> dict[str, Any]:
        resp = await self._get(client, f"/orgs/{org}")
        if resp.status_code == 200:
            data = resp.json()
            return {
                "found": True, "name": data.get("login"),
                "description": data.get("description"), "blog": data.get("blog"),
                "public_repos": data.get("public_repos"),
                "public_gists": data.get("public_gists"),
                "followers": data.get("followers"), "following": data.get("following"),
                "location": data.get("location"), "email": data.get("email"),
                "created": data.get("created_at"), "updated": data.get("updated_at"),
            }
        return {"found": False}

    async def _get_org_repos(self, client: httpx.AsyncClient, org: str) -> dict[str, Any]:
        repos = []
        page = 1
        while True:
            resp = await self._get(client,
                f"/orgs/{org}/repos",
                params={"per_page": 100, "page": page, "sort": "updated"},
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            if not data:
                break
            for repo in data:
                repos.append({
                    "name": repo.get("full_name"),
                    "description": repo.get("description"),
                    "language": repo.get("language"),
                    "stars": repo.get("stargazers_count"),
                    "forks": repo.get("forks_count"),
                    "updated": repo.get("updated_at"),
                    "created": repo.get("created_at"),
                    "private": repo.get("private"),
                    "topics": repo.get("topics", []),
                    "clone_url": repo.get("clone_url"),
                })
            page += 1
            if len(data) < 100:
                break

        return {"total": len(repos), "repos": repos}

    async def _search_code(self, client: httpx.AsyncClient, domain: str) -> dict[str, Any]:
        resp = await self._get(client, "/search/code", params={
            "q": f'"{domain}"', "per_page": 10, "sort": "indexed", "order": "desc",
        })
        if resp.status_code == 200:
            data = resp.json()
            return {
                "total": data.get("total_count", 0),
                "items": [
                    {
                        "repo": item.get("repository", {}).get("full_name"),
                        "path": item.get("path"),
                        "url": item.get("html_url"),
                        "score": item.get("score"),
                    }
                    for item in data.get("items", [])[:10]
                ],
            }
        return {"total": 0, "items": []}

    async def _search_secrets(self, client: httpx.AsyncClient, target: str) -> dict[str, Any]:
        findings = []
        for dork in GITHUB_CODE_DORKS[:20]:  # top 20 most relevant
            q = f'"{dork}" org:{target}' if not target.startswith(("http", "www")) else f'"{dork}" "{target}"'
            resp = await self._get(client, "/search/code", params={"q": q, "per_page": 5})
            # GitHub's search-code endpoint enforces ~30 req/min — pause
            # between dorks to stay under the limit. Async sleep so we
            # yield the event loop to other tools running in parallel
            # (previously this was ``time.sleep`` which blocked everyone).
            await asyncio.sleep(1.1)
            if resp.status_code == 200:
                data = resp.json()
                count = data.get("total_count", 0)
                if count > 0:
                    findings.append({"dork": dork, "total": count, "sample_repos": [
                        item.get("repository", {}).get("full_name")
                        for item in data.get("items", [])[:3]
                    ]})

        return {"findings": findings}

    async def _get_user(self, client: httpx.AsyncClient, username: str) -> dict[str, Any]:
        resp = await self._get(client, f"/users/{username}")
        if resp.status_code == 200:
            data = resp.json()
            return {
                "found": True, "name": data.get("name"), "bio": data.get("bio"),
                "blog": data.get("blog"), "company": data.get("company"),
                "location": data.get("location"),
                "public_repos": data.get("public_repos"),
                "followers": data.get("followers"), "following": data.get("following"),
                "created": data.get("created_at"),
            }
        return {"found": False}

    async def _get_user_repos(self, client: httpx.AsyncClient, username: str) -> dict[str, Any]:
        resp = await self._get(client, f"/users/{username}/repos", params={"per_page": 100})
        if resp.status_code == 200:
            return {
                "total": len(resp.json()),
                "repos": [
                    {
                        "name": r.get("full_name"),
                        "language": r.get("language"),
                        "stars": r.get("stargazers_count"),
                        "description": r.get("description"),
                        "created": r.get("created_at"),
                        "updated": r.get("updated_at"),
                    }
                    for r in resp.json()
                ],
            }
        return {"total": 0, "repos": []}
