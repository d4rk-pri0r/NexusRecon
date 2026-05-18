"""Integration tests for the code-and-secrets tool category.

Each HTTP-based tool gets the four-test pattern this PR uses as its
standard across every category:

  1. **Happy path** — provider returns the canonical documented JSON
     (or HTML, for scrape tools); tool parses it and returns
     ``ToolResult(success=True)`` with the expected ``data`` shape.
  2. **Empty result** — provider returns an empty list / 404 / empty
     ``data`` envelope; tool returns ``success=True, result_count=0``
     rather than treating empty as an error.
  3. **Error path** — provider raises a connection-level error or a
     non-200 the tool treats as fatal; tool returns ``success=False``
     with a useful ``error`` string.
  4. **Schema drift** — provider returns malformed JSON (or unexpected
     shape); tool fails gracefully (no traceback escapes).

GitHub-API-backed tools also get a ``test_missing_key`` that confirms
the tool refuses to run without a ``GITHUB_TOKEN``.

Tools covered:
  - ``github_recon`` (GitHub REST: orgs, repos, code search, dorks)
  - ``github_actions_leaks`` (GitHub workflows code search + raw fetch)
  - ``dockerhub`` (Docker Hub v2 repositories)
  - ``postman`` (HTML scrape of public Postman workspace pages)
  - ``gitdorker`` (curated GitHub dork code search)

Notes on the per-tool behavior we're locking in:

  - ``github_recon`` tolerates non-200s on individual endpoints
    (treats them as "endpoint returned nothing"). Only an exception
    escaping the outer try/except produces ``success=False``. So the
    error-path test forces an exception via ``side_effect``.
  - ``github_recon`` and ``gitdorker`` call ``time.sleep(1.1)`` between
    20 dork searches. We patch ``time.sleep`` to a no-op so the suite
    stays under a second per test.
  - ``github_recon`` does NOT enforce ``github_token`` (it sends
    requests with ``Authorization: token `` when missing). That's
    intentional in the tool — we don't add a ``test_missing_key`` for
    it because there's no observable failure to assert on.
  - ``dockerhub`` swallows non-200s by breaking the pagination loop
    and returning ``success=True`` with whatever it collected; only
    an exception produces ``success=False``.
  - ``postman`` catches per-URL exceptions silently and continues; the
    outer try/except is the only path to ``success=False``.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from httpx import Response

from tests.fixtures import load_fixture, load_text_fixture

from nexusrecon.tools.code.dockerhub_tool import DockerHubTool
from nexusrecon.tools.code.github_tool import GitHubTool
from nexusrecon.tools.code.gitdorker_tool import GitDorkerTool
from nexusrecon.tools.code.postman_tool import PostmanTool
from nexusrecon.tools.cloud.github_actions_tool import GitHubActionsTool


# ────────────────────────────────────────────────────────────────────────
# github_recon — api.github.com (orgs, repos, /search/code)
# ────────────────────────────────────────────────────────────────────────

class TestGitHubReconTool:
    BASE = "https://api.github.com"

    @patch("nexusrecon.tools.code.github_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_happy_path(self, _secret, _sleep) -> None:
        tool = GitHubTool()
        org_fixture = load_fixture("github_recon/org.json")
        repos_fixture = load_fixture("github_recon/org_repos.json")
        code_domain_fixture = load_fixture("github_recon/search_code_domain.json")
        code_secret_fixture = load_fixture("github_recon/search_code_secret.json")

        with respx.mock:
            # /orgs/{org} — single org-detail endpoint
            respx.get(f"{self.BASE}/orgs/example.com").mock(
                return_value=Response(200, json=org_fixture)
            )
            # /orgs/{org}/repos — paged; second page returns [] so loop terminates
            respx.get(url__regex=r"https://api\.github\.com/orgs/example\.com/repos.*").mock(
                side_effect=[
                    Response(200, json=repos_fixture),
                    Response(200, json=[]),
                ]
            )
            # /search/code — the first call is the domain search; the next
            # 20 are dork searches. We return the same secret fixture for
            # every call so total_count>0 on all dorks (exercises the
            # "findings.append" branch).
            respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
                side_effect=(
                    [Response(200, json=code_domain_fixture)]
                    + [Response(200, json=code_secret_fixture)] * 20
                )
            )
            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["org"]["found"] is True
        assert result.data["org"]["name"] == "example-org"
        assert result.data["org_repos"]["total"] == 3
        assert result.result_count == 3
        # _search_code populates "domain_in_code"
        assert result.data["domain_in_code"]["total"] == 2
        repo_names = {item["repo"] for item in result.data["domain_in_code"]["items"]}
        assert "example-org/infra" in repo_names
        assert "example-org/backend" in repo_names
        # _search_secrets walks 20 dorks; each returns total_count=3 in our
        # fixture, so we expect 20 findings appended.
        findings = result.data["secret_searches"]["findings"]
        assert len(findings) == 20
        assert all(f["total"] == 3 for f in findings)

    @patch("nexusrecon.tools.code.github_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_empty_response(self, _secret, _sleep) -> None:
        """Org doesn't exist, no repos, no search hits — clean empty result."""
        tool = GitHubTool()
        with respx.mock:
            respx.get(f"{self.BASE}/orgs/example.com").mock(
                return_value=Response(404, json={"message": "Not Found"})
            )
            respx.get(url__regex=r"https://api\.github\.com/orgs/example\.com/repos.*").mock(
                return_value=Response(404, json={"message": "Not Found"})
            )
            respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["org"] == {"found": False}
        assert result.data["org_repos"] == {"total": 0, "repos": []}
        assert result.data["domain_in_code"]["total"] == 0
        assert result.data["secret_searches"]["findings"] == []

    @patch("nexusrecon.tools.code.github_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_error_path(self, _secret, _sleep) -> None:
        """Connection-level failure bubbles up to outer except → success=False."""
        tool = GitHubTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE).mock(
                side_effect=httpx.ConnectError("DNS resolution failed")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error  # any descriptive error string is fine
        assert "DNS" in result.error or "resolution" in result.error.lower()

    @patch("nexusrecon.tools.code.github_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_malformed_json(self, _secret, _sleep) -> None:
        """Non-JSON body on /orgs/{org} triggers .json() to raise → outer except."""
        tool = GitHubTool()
        with respx.mock:
            respx.get(f"{self.BASE}/orgs/example.com").mock(
                return_value=Response(200, text="not valid json")
            )
            # Pad the rest so respx doesn't error on unmatched requests
            respx.get(url__regex=r"https://api\.github\.com/orgs/example\.com/repos.*").mock(
                return_value=Response(200, json=[])
            )
            respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        """No GITHUB_TOKEN configured — tool refuses to run rather than
        falling back to unauthenticated requests (capped at 60 req/hr,
        which silently breaks the 20-dork scan)."""
        tool = GitHubTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "GITHUB_TOKEN" in result.error


# ────────────────────────────────────────────────────────────────────────
# github_actions_leaks — api.github.com (search/code + raw file fetch)
# ────────────────────────────────────────────────────────────────────────

class TestGitHubActionsLeaksTool:
    BASE = "https://api.github.com"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_happy_path(self, _secret) -> None:
        tool = GitHubActionsTool()
        search_fixture = load_fixture("github_actions_leaks/search_code.json")
        deploy_raw = load_text_fixture("github_actions_leaks/workflow_deploy.txt")
        ci_raw = load_text_fixture("github_actions_leaks/workflow_ci.txt")

        with respx.mock:
            respx.get(url__startswith=f"{self.BASE}/search/code").mock(
                return_value=Response(200, json=search_fixture)
            )
            # The tool re-fetches item.url with Accept: vnd.github.raw+json
            # to get raw file content. Our fixture has two items.
            respx.get(
                "https://api.github.com/repositories/100001/contents/.github/workflows/deploy.yml?ref=main"
            ).mock(return_value=Response(200, text=deploy_raw))
            respx.get(
                "https://api.github.com/repositories/100002/contents/.github/workflows/ci.yml?ref=main"
            ).mock(return_value=Response(200, text=ci_raw))
            result = await tool.run("example.com")

        assert result.success is True
        # Two workflows were reviewed
        assert len(result.data["workflows_reviewed"]) == 2
        assert "example-org/infra/.github/workflows/deploy.yml" in result.data["workflows_reviewed"]
        # The regex set should find: aws_access_key, aws_account_id,
        # credential (api_key/password), cloud_endpoint (s3.amazonaws.com-style)
        # — at minimum we expect aws_access_key + credential entries.
        types = set(result.data["types_found"])
        assert "aws_access_key" in types
        assert "credential" in types
        # Credential values should be redacted (only first 3 chars + ***)
        cred_findings = [f for f in result.data["findings"] if f["type"] == "credential"]
        assert cred_findings, "expected at least one credential finding"
        assert all(f["value"].endswith("***") for f in cred_findings)
        assert result.result_count == result.data["finding_count"]
        assert result.result_count >= 2

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_empty_response(self, _secret) -> None:
        tool = GitHubActionsTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE}/search/code").mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["findings"] == []
        assert result.data["workflows_reviewed"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_rate_limited(self, _secret) -> None:
        """GitHub returns 403 on rate-limit exhaustion — tool surfaces this
        as a typed failure rather than a silent empty result."""
        tool = GitHubActionsTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE}/search/code").mock(
                return_value=Response(403)
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower() or "GITHUB_TOKEN" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_malformed_json(self, _secret) -> None:
        tool = GitHubActionsTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE}/search/code").mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = GitHubActionsTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "GITHUB_TOKEN" in result.error


# ────────────────────────────────────────────────────────────────────────
# dockerhub — hub.docker.com/v2/repositories/<org>/
# ────────────────────────────────────────────────────────────────────────

class TestDockerHubTool:
    BASE = "https://hub.docker.com"

    async def test_happy_path(self) -> None:
        tool = DockerHubTool()
        # Target "example.com" becomes org "example" (split on dot, lowercased).
        url = f"{self.BASE}/v2/repositories/example/"
        fixture = load_fixture("dockerhub/repositories.json")
        with respx.mock:
            respx.get(url__startswith=url).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        names = [r["name"] for r in result.data["repos"]]
        assert "backend" in names
        assert "frontend" in names
        assert "worker" in names
        # Pull counts roundtrip from the fixture
        backend = next(r for r in result.data["repos"] if r["name"] == "backend")
        assert backend["pull_count"] == 1_450_000
        assert backend["is_private"] is False

    async def test_empty_response(self) -> None:
        tool = DockerHubTool()
        url = f"{self.BASE}/v2/repositories/example/"
        fixture = load_fixture("dockerhub/empty.json")
        with respx.mock:
            respx.get(url__startswith=url).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["repos"] == []

    async def test_error_path(self) -> None:
        """Connection-level failure → outer except → success=False.

        Non-200 alone is NOT treated as failure by this tool — it just
        breaks the pagination loop and returns empty. So we force a real
        exception here."""
        tool = DockerHubTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE).mock(
                side_effect=httpx.ConnectError("Network unreachable")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error
        assert "unreachable" in result.error.lower() or "network" in result.error.lower()

    async def test_malformed_json(self) -> None:
        tool = DockerHubTool()
        url = f"{self.BASE}/v2/repositories/example/"
        with respx.mock:
            respx.get(url__startswith=url).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # .json() on bad body raises → caught by outer except
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# postman — HTML scrape of postman.com/{org}, /{target-dashed}, /{org}-api
# ────────────────────────────────────────────────────────────────────────

class TestPostmanTool:
    """Postman tool hits three URLs per target, regex-extracts
    ``workspace/<id>`` from the raw HTML, and dedupes per URL."""

    async def test_happy_path(self) -> None:
        tool = PostmanTool()
        html = load_text_fixture("postman/workspace_page.html")
        # The fixture contains two distinct workspace IDs (plus a dupe
        # which the tool's ``set()`` should collapse).
        with respx.mock:
            respx.get("https://www.postman.com/example").mock(
                return_value=Response(200, text=html)
            )
            respx.get("https://www.postman.com/example-com").mock(
                return_value=Response(200, text=html)
            )
            respx.get("https://www.postman.com/example-api").mock(
                return_value=Response(200, text=html)
            )
            result = await tool.run("example.com")

        assert result.success is True
        assert len(result.data["workspaces"]) == 3  # three URL probes
        for entry in result.data["workspaces"]:
            ws_ids = entry["workspaces"]
            # Dedup leaves three distinct IDs from this fixture
            assert "abc12345-1111-2222-3333-444455556666" in ws_ids
            assert "def98765-9999-8888-7777-666655554444" in ws_ids
            assert "duplicateref-aaaa-bbbb" in ws_ids
            assert entry["status"] == 200
        # result_count is total IDs across all probes (3 IDs × 3 URLs = 9)
        assert result.result_count == 9

    async def test_empty_response(self) -> None:
        """All three probes return 404 — tool skips them and produces
        an empty ``workspaces`` list (still success=True)."""
        tool = PostmanTool()
        with respx.mock:
            respx.get(url__startswith="https://www.postman.com/").mock(
                return_value=Response(404, text="<html>404</html>")
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["workspaces"] == []

    async def test_page_without_workspace_ids(self) -> None:
        """HTML loads but contains no ``workspace/<id>`` pattern — tool
        records the URL with an empty workspaces list."""
        tool = PostmanTool()
        html = load_text_fixture("postman/no_workspaces.html")
        with respx.mock:
            respx.get(url__startswith="https://www.postman.com/").mock(
                return_value=Response(200, text=html)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # Three URLs probed, each yielding zero IDs
        assert len(result.data["workspaces"]) == 3
        assert all(e["workspaces"] == [] for e in result.data["workspaces"])
        assert result.result_count == 0

    async def test_error_path(self) -> None:
        """Per-URL ``Exception`` is swallowed by the tool's inner try/except,
        so a connection failure on every probe simply yields an empty list
        but the run still completes with ``success=True``.

        This locks in the documented "best-effort" behavior — we
        don't want a single bad probe to kill the whole tool."""
        tool = PostmanTool()
        with respx.mock:
            respx.get(url__startswith="https://www.postman.com/").mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.data["workspaces"] == []
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# gitdorker — curated dork search via api.github.com/search/code
# ────────────────────────────────────────────────────────────────────────

class TestGitDorkerTool:
    URL = "https://api.github.com/search/code"

    @patch("nexusrecon.tools.code.gitdorker_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_happy_path(self, _secret, _sleep) -> None:
        tool = GitDorkerTool()
        fixture = load_fixture("gitdorker/search_code.json")
        # 20 dorks → 20 search calls; same fixture for each, so we expect
        # 20 findings each with total=7 (sum=140).
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        findings = result.data["dork_results"]
        assert len(findings) == 20
        assert all(f["total"] == 7 for f in findings)
        # Description is the human-readable label from CURATED_DORKS
        descriptions = {f["description"] for f in findings}
        assert "AWS Access Keys" in descriptions
        # result_count sums total across findings → 20 * 7 = 140
        assert result.result_count == 140

    @patch("nexusrecon.tools.code.gitdorker_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_empty_response(self, _secret, _sleep) -> None:
        tool = GitDorkerTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["dork_results"] == []

    @patch("nexusrecon.tools.code.gitdorker_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_rate_limited(self, _secret, _sleep) -> None:
        """403 is treated as "skip this dork" — tool returns success with
        whatever was collected (nothing here). Mirrors the documented
        behavior of github_subdomains: rate-limit → partial success."""
        tool = GitDorkerTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(403))
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["dork_results"] == []

    @patch("nexusrecon.tools.code.gitdorker_tool.asyncio.sleep", new_callable=AsyncMock)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_malformed_json(self, _secret, _sleep) -> None:
        tool = GitDorkerTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # First .json() call raises on bad body → outer except
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = GitDorkerTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "GITHUB_TOKEN" in result.error
