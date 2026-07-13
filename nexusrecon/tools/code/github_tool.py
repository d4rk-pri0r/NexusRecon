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

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        # The tool declares ``requires_keys = ["github_token"]`` but a
        # previous revision wrote ``token = self.config.get_secret(...)
        # or ""`` in ``_get_client``, falling back to an empty string
        # token. GitHub treats an empty ``Authorization: token`` header
        # as unauthenticated, which caps the rate at 60 req/hr — far
        # too low for the 20-dork scan in ``_search_secrets``. The
        # operator saw quiet rate-limit-driven empty results instead
        # of a clear "set GITHUB_TOKEN" error.
        token = self.config.get_secret("github_token")
        if not token:
            return ToolResult(
                success=False, source=self.name,
                error="GITHUB_TOKEN not set",
            )

        results: dict[str, Any] = {}
        # Every helper below swallows a non-200 into an empty fallback, so a
        # bad/expired token (401) or a rate-limit (403/429) empties the whole
        # result and looks identical to "this target has no GitHub presence".
        # Record the authenticated-call outcomes so ``assess_result`` can tell
        # a silent auth/rate-limit failure apart from a genuine absence. Note
        # GitHub meters the core REST pool and the /search/code pool
        # separately, so these signals are tracked independently rather than
        # collapsed into one "the token failed" verdict.
        health: dict[str, Any] = {
            "primary_status": None,       # /orgs or /users lookup status
            "repos_status": None,         # non-200 that aborted repo enumeration
            "secret_ok": 0,               # dork /search/code requests that returned 200
            "secret_transient_fail": 0,   # dork requests rejected by auth/rate-limit/server
            "secret_query_reject": 0,     # dork requests answered with a deterministic 4xx (422)
        }
        try:
            client = await self._get_client(token)

            # Determine target type
            target_type = kwargs.get("target_type", "domain")

            if target_type in ("github_org", "domain"):
                # Try as org name
                results["org"] = await self._get_org(client, target, health)
                results["org_repos"] = await self._get_org_repos(client, target, health)

                # Search for domain in code
                results["domain_in_code"] = await self._search_code(client, target)

                # Search with dorks
                results["secret_searches"] = await self._search_secrets(client, target, health)

            elif target_type == "github_user":
                results["user"] = await self._get_user(client, target, health)
                results["user_repos"] = await self._get_user_repos(client, target, health)

            await self._close()
            results["_recon_health"] = health
            repo_count = len(results.get("org_repos", {}).get("repos", []))
            return ToolResult(
                success=True, source=self.name, data=results,
                result_count=repo_count,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        d = result.data or {}
        health = d.get("_recon_health") or {}
        primary = health.get("primary_status")
        # Only a 401 on the primary lookup is a whole-result verdict: GitHub
        # returns 401 on every authenticated endpoint for a bad or expired
        # token, so a 401 means every call failed. A 403/429 is deliberately
        # NOT flagged wholesale here: the core REST pool and the /search/code
        # pool are metered separately, so an org-lookup rate-limit can coexist
        # with a code scan that ran fine (or even returned real findings), and
        # flagging the whole result would cry wolf on a run that did its job.
        # Pool-specific rate-limits are judged below via the repo-enumeration
        # and code-search failure counts instead.
        if primary == 401:
            return (
                "github rejected the access token (HTTP 401 on the primary lookup); "
                "every authenticated call failed, so this result is a token failure, "
                "not a genuine absence of GitHub exposure"
            )
        # Repo enumeration is a primary output (result_count derives from it).
        # If its first page was rejected, the empty repo list reflects a failed
        # call, not an org/user with no repositories. A 404 there is a genuine
        # "no such org/user" and is not treated as a failure.
        repos_status = health.get("repos_status")
        if repos_status is not None and (
            repos_status in (401, 403, 429) or repos_status >= 500
        ):
            return (
                f"github repository enumeration was rejected (HTTP {repos_status}); "
                "the empty repository list reflects a failed call, not a target with "
                "no repositories"
            )
        # The /search/code endpoint is a separate, strict rate-limit pool. Flag
        # only when at least one dork was rejected transiently, none returned
        # data, AND none was a deterministic query-reject. The query-reject gate
        # is what keeps a bare-domain run honest: its dorks all 422 on the
        # invalid ``org:<domain>`` qualifier, so the scan is a designed no-op,
        # and even if one request also catches a stray transient blip the run
        # is still a no-op, not a silent failure. A real org scan never emits
        # query-rejects (a valid org login has no dots), so its genuine
        # all-transient outage still fires. The zero-successes gate avoids
        # crying wolf on the partial rejection GitHub's per-minute cap makes
        # routine.
        ok = health.get("secret_ok", 0)
        transient_fail = health.get("secret_transient_fail", 0)
        query_reject = health.get("secret_query_reject", 0)
        if transient_fail > 0 and ok == 0 and query_reject == 0:
            return (
                "every github code-search request that reached the endpoint was "
                "rejected by an auth, rate-limit, or server error and none returned "
                "data; the code-exposure scan did not run, so 'no exposed secrets "
                "found' is a silent failure, not a clean result"
            )
        return None

    async def _get_org(self, client: httpx.AsyncClient, org: str,
                       health: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await client.get(f"/orgs/{org}")
        if health is not None:
            health["primary_status"] = resp.status_code
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

    async def _get_org_repos(self, client: httpx.AsyncClient, org: str,
                             health: dict[str, Any] | None = None) -> dict[str, Any]:
        repos = []
        page = 1
        while True:
            resp = await client.get(
                f"/orgs/{org}/repos",
                params={"per_page": 100, "page": page, "sort": "updated"},
            )
            if resp.status_code != 200:
                # Record only a first-page rejection: that means enumeration
                # failed outright (empty repo list = failed call, not "no
                # repos"). A later-page non-200 still leaves partial data, so
                # we do not flag it. A 404 (org does not exist) is recorded but
                # assess_result treats it as a genuine absence, not a failure.
                if health is not None and not repos:
                    health["repos_status"] = resp.status_code
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
        resp = await client.get("/search/code", params={
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

    async def _search_secrets(self, client: httpx.AsyncClient, target: str,
                              health: dict[str, Any] | None = None) -> dict[str, Any]:
        findings = []
        ok = 0
        transient_fail = 0
        query_reject = 0
        for dork in GITHUB_CODE_DORKS[:20]:  # top 20 most relevant
            q = f'"{dork}" org:{target}' if not target.startswith(("http", "www")) else f'"{dork}" "{target}"'
            resp = await client.get("/search/code", params={"q": q, "per_page": 5})
            # GitHub's search-code endpoint enforces ~30 req/min — pause
            # between dorks to stay under the limit. Async sleep so we
            # yield the event loop to other tools running in parallel
            # (previously this was ``time.sleep`` which blocked everyone).
            await asyncio.sleep(1.1)
            if resp.status_code == 200:
                ok += 1
                data = resp.json()
                count = data.get("total_count", 0)
                if count > 0:
                    findings.append({"dork": dork, "total": count, "sample_repos": [
                        item.get("repository", {}).get("full_name")
                        for item in data.get("items", [])[:3]
                    ]})
            elif resp.status_code in (401, 403, 429) or resp.status_code >= 500:
                # A transient/auth/server rejection: the endpoint was reachable
                # but refused to run the query, so this dork produced no signal
                # for a reason that has nothing to do with the target.
                transient_fail += 1
            elif 400 <= resp.status_code < 500:
                # A deterministic 4xx (notably 422): GitHub answered that the
                # query itself is invalid. A bare-domain target makes every dork
                # ``org:acme.com``, which 422s because org logins cannot contain
                # dots, so the whole dork scan is a designed no-op for domains.
                # Tracked separately so the degraded verdict below can tell that
                # apart from a scan the endpoint actually blocked -- counting it
                # as a failure would cry wolf on the most common input.
                query_reject += 1

        if health is not None:
            health["secret_ok"] = ok
            health["secret_transient_fail"] = transient_fail
            health["secret_query_reject"] = query_reject
        return {
            "findings": findings,
            "ok": ok,
            "transient_failures": transient_fail,
            "query_rejects": query_reject,
        }

    async def _get_user(self, client: httpx.AsyncClient, username: str,
                        health: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await client.get(f"/users/{username}")
        if health is not None:
            health["primary_status"] = resp.status_code
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

    async def _get_user_repos(self, client: httpx.AsyncClient, username: str,
                              health: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await client.get(f"/users/{username}/repos", params={"per_page": 100})
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
        # The only data-bearing secondary call on the user path: a non-200
        # here empties the repo list because the call failed, so record it
        # (the user path never runs the dork scan, so this is the sole
        # silent-failure signal assess_result has for a found user).
        if health is not None:
            health["repos_status"] = resp.status_code
        return {"total": 0, "repos": []}
