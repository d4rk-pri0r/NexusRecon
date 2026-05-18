"""Integration tests for the vulnerability-intelligence tool category.

Each HTTP-based tool gets the four-test pattern this PR uses as its
standard across every category:

  1. **Happy path** — provider returns the canonical documented JSON;
     tool parses it and returns ``ToolResult(success=True)`` with the
     expected ``data`` shape.
  2. **Empty result** — provider returns an empty list / empty
     ``data`` envelope / no matches; tool returns
     ``success=True, result_count=0`` rather than treating empty as
     an error.
  3. **Error path** — provider returns 429/500/connection error;
     tool returns ``success=False`` with a useful ``error`` string
     (or, where the tool's contract is to absorb transport errors
     into an empty success, that behavior is asserted instead).
  4. **Schema drift** — provider returns malformed JSON; tool fails
     gracefully (no traceback escapes the boundary).

Tools covered: ``nvd``, ``kev``, ``epss``, ``osv``, ``exploitdb``,
``github_advisory``, ``nuclei_template``, ``vulners``. The last one
gets an additional ``test_missing_key`` since it is the only
key-requiring tool in this group.
"""
from __future__ import annotations

from unittest.mock import patch

import httpx
import respx
from httpx import Response

from tests.fixtures import load_fixture

from nexusrecon.tools.vuln.epss_tool import EPSSTool
from nexusrecon.tools.vuln.exploitdb_tool import ExploitDBTool
from nexusrecon.tools.vuln.github_advisory_tool import GitHubAdvisoryTool
from nexusrecon.tools.vuln.kev_tool import KEVTool
from nexusrecon.tools.vuln.nuclei_template_tool import NucleiTemplateTool
from nexusrecon.tools.vuln.nvd_tool import NVDTool
from nexusrecon.tools.vuln.osv_tool import OSVTool
from nexusrecon.tools.vuln.vulners_tool import VulnersTool


CVE = "CVE-2021-44228"


# ────────────────────────────────────────────────────────────────────────
# NVD — services.nvd.nist.gov/rest/json/cves/2.0
# ────────────────────────────────────────────────────────────────────────

class TestNVDTool:
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def test_happy_path(self) -> None:
        tool = NVDTool()
        fixture = load_fixture("nvd/cve_search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.data["total"] == 1
        assert result.result_count == 1
        vulns = result.data["vulns"]
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == CVE
        # description is truncated to 300 chars by tool, but for our fixture
        # the description is shorter so the prefix matches verbatim
        assert "Apache Log4j2" in vulns[0]["description"]
        assert vulns[0]["published"] == "2021-12-10T10:15:09.143"
        assert "https://logging.apache.org/log4j/2.x/security.html" in vulns[0]["references"]
        # CVSS metric block is passed through wholesale
        assert "cvssMetricV31" in vulns[0]["cvss"]

    async def test_empty_response(self) -> None:
        tool = NVDTool()
        fixture = load_fixture("nvd/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["total"] == 0
        assert result.data["vulns"] == []

    async def test_error_path(self) -> None:
        """Tool wraps everything in try/except. A connection-level
        error must surface as ``success=False`` with a non-empty
        ``error`` string."""
        tool = NVDTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error

    async def test_malformed_json(self) -> None:
        tool = NVDTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# CISA KEV — public JSON feed (no key)
# ────────────────────────────────────────────────────────────────────────

class TestKEVTool:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def test_happy_path(self) -> None:
        tool = KEVTool()
        fixture = load_fixture("kev/catalog.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        # Fixture has 3 KEV entries; only one matches the queried CVE
        assert result.data["total_kev"] == 3
        assert result.result_count == 1
        matches = result.data["matches"]
        assert len(matches) == 1
        assert matches[0]["cve_id"] == CVE
        assert matches[0]["vendor"] == "Apache"
        assert matches[0]["product"] == "Log4j2"
        assert matches[0]["known_ransom_campaign"] == "Known"
        assert matches[0]["date_added"] == "2021-12-10"

    async def test_happy_path_product_search(self) -> None:
        """Sanity check that non-CVE targets do substring matching on
        vendor/product/description fields. Two of the three fixture
        entries are Apache, so a query for ``apache`` returns both."""
        tool = KEVTool()
        fixture = load_fixture("kev/catalog.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("apache")
        assert result.success is True
        assert result.result_count == 2
        vendors = {m["vendor"] for m in result.data["matches"]}
        assert vendors == {"Apache"}

    async def test_empty_response(self) -> None:
        tool = KEVTool()
        fixture = load_fixture("kev/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["matches"] == []
        assert result.data["total_kev"] == 0

    async def test_error_path(self) -> None:
        """KEV checks status explicitly — non-200 returns success=False
        with the documented error string."""
        tool = KEVTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run(CVE)
        assert result.success is False
        assert "Failed to fetch" in result.error

    async def test_malformed_json(self) -> None:
        tool = KEVTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="<html>down for maintenance</html>")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# EPSS — api.first.org/data/v1/epss
# ────────────────────────────────────────────────────────────────────────

class TestEPSSTool:
    URL = "https://api.first.org/data/v1/epss"

    async def test_happy_path(self) -> None:
        tool = EPSSTool()
        fixture = load_fixture("epss/score.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 1
        assert result.data["cve"] == CVE
        # Tool coerces the stringified probability into a float
        assert result.data["epss_score"] == 0.97534
        assert result.data["percentile"] == 0.99986
        assert result.data["date"] == "2024-05-15"

    async def test_empty_response(self) -> None:
        """EPSS treats an empty data array as 'no score available' and
        returns success=False with a descriptive error — not a soft
        empty success — because callers expect a score or nothing."""
        tool = EPSSTool()
        fixture = load_fixture("epss/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert "No EPSS data" in result.error

    async def test_error_path(self) -> None:
        tool = EPSSTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(500))
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error

    async def test_malformed_json(self) -> None:
        tool = EPSSTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="<html>not json</html>")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# OSV.dev — api.osv.dev/v1/query
# ────────────────────────────────────────────────────────────────────────

class TestOSVTool:
    URL = "https://api.osv.dev/v1/query"

    async def test_happy_path(self) -> None:
        tool = OSVTool()
        fixture = load_fixture("osv/query.json")
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 1
        assert result.data["cve"] == CVE
        assert result.data["vuln_count"] == 1
        # Fixture has two affected packages across two ecosystems
        assert set(result.data["ecosystems"]) == {"Maven", "Packagist"}
        vuln = result.data["vulns"][0]
        assert vuln["id"] == "GHSA-jfh8-c2jp-5v3q"
        assert CVE in vuln["aliases"]
        assert len(vuln["affected_packages"]) == 2
        # Fixed versions are extracted from the events stream
        maven_pkg = next(p for p in vuln["affected_packages"] if p["ecosystem"] == "Maven")
        assert "2.3.1" in maven_pkg["fixed_versions"]
        assert "2.12.2" in maven_pkg["fixed_versions"]

    async def test_empty_response(self) -> None:
        tool = OSVTool()
        fixture = load_fixture("osv/empty.json")
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["vuln_count"] == 0
        assert result.data["vulns"] == []
        assert result.data["ecosystems"] == []

    async def test_error_path(self) -> None:
        tool = OSVTool()
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(return_value=Response(500))
            result = await tool.run(CVE)
        assert result.success is False
        assert "500" in result.error

    async def test_malformed_json(self) -> None:
        tool = OSVTool()
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# ExploitDB — exploit-db.com/search + GitHub repos/code search
# ────────────────────────────────────────────────────────────────────────

class TestExploitDBTool:
    EDB_URL = "https://www.exploit-db.com/search"
    GH_REPOS_URL = "https://api.github.com/search/repositories"
    GH_CODE_URL = "https://api.github.com/search/code"

    async def test_happy_path(self) -> None:
        tool = ExploitDBTool()
        edb = load_fixture("exploitdb/edb_search.json")
        repos = load_fixture("exploitdb/github_repos.json")
        code = load_fixture("exploitdb/github_code.json")
        with respx.mock:
            respx.get(url__startswith=self.EDB_URL).mock(
                return_value=Response(200, json=edb)
            )
            respx.get(url__startswith=self.GH_REPOS_URL).mock(
                return_value=Response(200, json=repos)
            )
            respx.get(url__startswith=self.GH_CODE_URL).mock(
                return_value=Response(200, json=code)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.data["cve"] == CVE
        # Two EDB rows + two GitHub PoCs in fixtures; result_count is the sum
        assert len(result.data["exploitdb"]) == 2
        assert len(result.data["github_pocs"]) == 2
        assert result.result_count == 4
        assert result.data["has_public_exploit"] is True
        assert result.data["has_metasploit"] is True
        # Top GitHub PoC carries through full repo metadata
        top = result.data["github_pocs"][0]
        assert top["repo"] == "kozmer/log4j-shell-poc"
        assert top["stars"] == 1800

    async def test_empty_response(self) -> None:
        """All three providers return empty/no-results; tool must
        return success=True with everything zeroed out and the
        ``has_public_exploit`` flag set to False."""
        tool = ExploitDBTool()
        with respx.mock:
            respx.get(url__startswith=self.EDB_URL).mock(
                return_value=Response(200, json={"data": []})
            )
            respx.get(url__startswith=self.GH_REPOS_URL).mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            respx.get(url__startswith=self.GH_CODE_URL).mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["exploitdb"] == []
        assert result.data["github_pocs"] == []
        assert result.data["has_public_exploit"] is False
        assert result.data["has_metasploit"] is False

    async def test_error_path(self) -> None:
        """A connection error against any of the three providers
        aborts the whole call. The tool surfaces the exception."""
        tool = ExploitDBTool()
        with respx.mock:
            respx.get(url__startswith=self.EDB_URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error

    async def test_malformed_json(self) -> None:
        """EDB returns garbage; the tool catches the parse error and
        keeps going with the other providers. Since both GH endpoints
        also fail to return anything useful here, end state is success
        with empty results."""
        tool = ExploitDBTool()
        with respx.mock:
            respx.get(url__startswith=self.EDB_URL).mock(
                return_value=Response(200, text="not valid json")
            )
            respx.get(url__startswith=self.GH_REPOS_URL).mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            respx.get(url__startswith=self.GH_CODE_URL).mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run(CVE)
        # The EDB JSON parse exception is swallowed inside the tool —
        # the remaining providers still run. End result is success
        # with empty exploit-db list.
        assert result.success is True
        assert result.data["exploitdb"] == []

    async def test_bad_cve_format(self) -> None:
        """Non-CVE input is rejected before any HTTP call goes out."""
        tool = ExploitDBTool()
        result = await tool.run("not-a-cve")
        assert result.success is False
        assert "CVE-" in result.error


# ────────────────────────────────────────────────────────────────────────
# GitHub Security Advisory — api.github.com/advisories
# ────────────────────────────────────────────────────────────────────────

class TestGitHubAdvisoryTool:
    URL = "https://api.github.com/advisories"

    async def test_happy_path(self) -> None:
        tool = GitHubAdvisoryTool()
        fixture = load_fixture("github_advisory/advisories.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 1
        assert result.data["cve"] == CVE
        assert result.data["advisory_count"] == 1
        adv = result.data["advisories"][0]
        assert adv["ghsa_id"] == "GHSA-jfh8-c2jp-5v3q"
        assert adv["severity"] == "critical"
        assert adv["cvss_score"] == 10.0
        assert "CWE-20" in adv["cwes"]
        # Affected packages get flattened from the GHSA shape
        assert len(adv["affected_packages"]) == 2
        assert adv["affected_packages"][0]["ecosystem"] == "maven"
        assert adv["affected_packages"][0]["first_patched"] == "2.3.1"

    async def test_empty_response(self) -> None:
        tool = GitHubAdvisoryTool()
        fixture = load_fixture("github_advisory/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["advisories"] == []

    async def test_rate_limited(self) -> None:
        tool = GitHubAdvisoryTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run(CVE)
        assert result.success is False
        assert "rate limit" in result.error.lower()

    async def test_malformed_json(self) -> None:
        tool = GitHubAdvisoryTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# Nuclei templates — api.github.com/search/code in projectdiscovery repo
# ────────────────────────────────────────────────────────────────────────

class TestNucleiTemplateTool:
    URL = "https://api.github.com/search/code"

    async def test_happy_path(self) -> None:
        tool = NucleiTemplateTool()
        fixture = load_fixture("nuclei_template/search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 2
        assert result.data["cve"] == CVE
        assert result.data["has_template"] is True
        assert result.data["template_count"] == 2
        # First template's path drives the nuclei run hint
        assert result.data["nuclei_run_hint"] == (
            "nuclei -u <target> -t http/cves/2021/CVE-2021-44228.yaml"
        )
        names = {t["name"] for t in result.data["templates"]}
        assert "CVE-2021-44228.yaml" in names

    async def test_empty_response(self) -> None:
        tool = NucleiTemplateTool()
        fixture = load_fixture("nuclei_template/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["has_template"] is False
        assert result.data["template_count"] == 0
        assert result.data["templates"] == []
        assert result.data["nuclei_run_hint"] is None

    async def test_rate_limited(self) -> None:
        tool = NucleiTemplateTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(403))
            result = await tool.run(CVE)
        assert result.success is False
        assert "rate limit" in result.error.lower()

    async def test_malformed_json(self) -> None:
        tool = NucleiTemplateTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# Vulners — vulners.com/api/v3/search/lucene (requires API key)
# ────────────────────────────────────────────────────────────────────────

class TestVulnersTool:
    URL = "https://vulners.com/api/v3/search/lucene/"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_happy_path(self, _secret) -> None:
        tool = VulnersTool()
        fixture = load_fixture("vulners/search.json")
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.data["cve"] == CVE
        # Fixture has 1 cve doc + 1 exploitdb + 1 metasploit ⇒ 2 exploits
        assert result.data["exploit_count"] == 2
        assert result.result_count == 2
        assert result.data["has_public_exploit"] is True
        assert result.data["has_metasploit"] is True
        # Non-exploit doc lands in references
        assert len(result.data["references"]) == 1
        assert result.data["references"][0]["id"] == CVE
        # Exploit list carries id, title, type, cvss, href
        ids = {e["id"] for e in result.data["exploits"]}
        assert "EDB-ID:50592" in ids
        assert "MSF:EXPLOIT-MULTI-HTTP-LOG4SHELL" in ids

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_empty_response(self, _secret) -> None:
        tool = VulnersTool()
        fixture = load_fixture("vulners/empty.json")
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run(CVE)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["exploits"] == []
        assert result.data["has_public_exploit"] is False
        assert result.data["has_metasploit"] is False

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret) -> None:
        tool = VulnersTool()
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run(CVE)
        assert result.success is False
        assert "Invalid" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_rate_limited(self, _secret) -> None:
        tool = VulnersTool()
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run(CVE)
        assert result.success is False
        assert "rate limit" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = VulnersTool()
        with respx.mock:
            respx.post(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run(CVE)
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = VulnersTool()
        result = await tool.run(CVE)
        assert result.success is False
        assert "VULNERS_API_KEY" in result.error
