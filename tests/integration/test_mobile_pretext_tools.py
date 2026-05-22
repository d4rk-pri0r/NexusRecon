"""Integration tests for the mobile + pretext tool categories.

Follows the same four-test pattern as ``test_subdomain_tools.py``:

  1. **Happy path** — provider returns the canonical documented JSON
     (or HTML, for scrape-based tools); the tool parses it and returns
     ``ToolResult(success=True)`` with the expected ``data`` shape.
  2. **Empty result** — provider returns an empty list / 404 / "no
     results" envelope; the tool returns ``success=True,
     result_count=0`` rather than treating empty as an error.
  3. **Error path** — provider returns 401 / 429 / 5xx / a connection
     error; the tool returns ``success=False`` with a useful ``error``
     string (or, for tools that never surface upstream errors,
     ``success=True`` with the documented "I tried but found nothing"
     shape).
  4. **Schema drift** — provider returns malformed JSON or an
     unexpected shape; the tool fails gracefully (no traceback
     escapes).

Two tools also exercise a ``test_missing_key`` path:

* ``crunchbase`` requires ``CRUNCHBASE_API_KEY``.
* ``github_org_members`` requires ``GITHUB_TOKEN``.

Tools covered: ``playstore``, ``apk_analyzer`` (mobile),
``wikipedia``, ``linkedin_dorks``, ``public_collab``, ``crunchbase``,
``github_org_members`` (pretext).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import httpx
import respx
from httpx import Response

from nexusrecon.tools.mobile.apk_analyzer_tool import APKAnalyzerTool
from nexusrecon.tools.mobile.playstore_tool import PlayStoreTool
from nexusrecon.tools.pretext.crunchbase_tool import CrunchbaseTool
from nexusrecon.tools.pretext.github_org_members_tool import GitHubOrgMembersTool
from nexusrecon.tools.pretext.linkedin_dorks_tool import LinkedInDorksTool
from nexusrecon.tools.pretext.public_collab_tool import PublicCollabTool
from nexusrecon.tools.pretext.wikipedia_tool import WikipediaTool
from tests.fixtures import load_fixture, load_text_fixture

# ────────────────────────────────────────────────────────────────────────
# Load the synthetic-APK helper. It sits next to the APKMirror HTML
# fixtures under tests/fixtures/apk_analyzer/, but that directory is
# not on pytest's collection path so it has to be loaded explicitly.
# ────────────────────────────────────────────────────────────────────────

_APK_HELPER_PATH = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "apk_analyzer"
    / "conftest.py"
)
_spec = importlib.util.spec_from_file_location(
    "tests.fixtures.apk_analyzer._helper", _APK_HELPER_PATH
)
_apk_helper = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["tests.fixtures.apk_analyzer._helper"] = _apk_helper
_spec.loader.exec_module(_apk_helper)  # type: ignore[union-attr]
build_synthetic_apk = _apk_helper.build_synthetic_apk


# ════════════════════════════════════════════════════════════════════════
# PlayStoreTool — google_play_scraper wrapper (no HTTP, mock the lib)
# ════════════════════════════════════════════════════════════════════════

class TestPlayStoreTool:
    """``playstore`` doesn't hit HTTP directly — it calls
    ``google_play_scraper.search``. We mock that callable. The tool also
    filters search hits to those whose ``developerEmail`` /
    ``developer`` / ``title`` matches the seed domain — assertions
    verify the filter."""

    async def test_happy_path(self) -> None:
        tool = PlayStoreTool()
        fixture = load_fixture("playstore/search_results.json")
        with patch(
            "google_play_scraper.search",
            return_value=fixture,
            create=True,
        ):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.data["target"] == "example.com"
        apps = result.data["apps"]
        # 3 of the 4 fixture entries match (developer email contains
        # example.com or title/developer contains "example"); the
        # "Random Game" by "Other Studios" should be filtered out.
        package_ids = {a["package"] for a in apps}
        assert "com.example.mainapp" in package_ids
        assert "com.example.tools" in package_ids
        assert "com.example.legacy" in package_ids
        assert "com.unrelated.game" not in package_ids
        assert result.result_count == len(apps) == 3
        # Spot-check field mapping on the top hit
        top = next(a for a in apps if a["package"] == "com.example.mainapp")
        assert top["title"] == "Example Mobile"
        assert top["developer"] == "Example Inc."
        assert top["developer_email"] == "android@example.com"
        assert top["install_count"] == 1000000
        assert top["url"] == "https://play.google.com/store/apps/details?id=com.example.mainapp"

    async def test_empty_response(self) -> None:
        tool = PlayStoreTool()
        with patch(
            "google_play_scraper.search",
            return_value=[],
            create=True,
        ):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["apps"] == []

    async def test_error_path(self) -> None:
        """Tool swallows scraper exceptions and returns success with an
        empty app list (it logs nothing else). Verifies the
        guard-rail."""
        tool = PlayStoreTool()
        def _boom(*_a, **_kw):
            raise RuntimeError("scraper crashed")
        with patch(
            "google_play_scraper.search",
            side_effect=_boom,
            create=True,
        ):
            result = await tool.run("example.com")
        # The tool catches the exception and returns success with no apps —
        # that's the documented graceful-degradation behavior.
        assert result.success is True
        assert result.result_count == 0
        assert result.data["apps"] == []

    async def test_malformed_response(self) -> None:
        """Scraper returns rows missing the expected keys — the tool
        coerces missing values to empty strings / zero and returns a
        clean ``apps`` list."""
        tool = PlayStoreTool()
        malformed = [
            {"appId": "com.example.partial", "title": "Example", "developer": "Example Inc.", "developerEmail": None, "realInstalls": None, "updated": None},
            {"appId": None, "title": None, "developer": None, "developerEmail": None},
        ]
        with patch(
            "google_play_scraper.search",
            return_value=malformed,
            create=True,
        ):
            result = await tool.run("example.com")
        assert result.success is True
        # The first row's title and developer both contain "example" → kept.
        # The second row has None title / developer / email → dropped.
        assert result.result_count == 1
        assert result.data["apps"][0]["package"] == "com.example.partial"
        assert result.data["apps"][0]["install_count"] == 0


# ════════════════════════════════════════════════════════════════════════
# APKAnalyzerTool — APKMirror HTML scrape (3 pages) → APK byte download
# ════════════════════════════════════════════════════════════════════════

class TestAPKAnalyzerTool:
    """``apk_analyzer`` walks 3 HTML pages on APKMirror, downloads the
    APK bytes, then scans the ZIP for secrets/endpoints/permissions.
    We mock all four HTTP calls (search HTML, release HTML, download
    HTML, final HEAD + GET for the APK bytes) and serve a
    purpose-built synthetic APK so the scanner finds known planted
    strings."""

    SEARCH_URL = "https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s=com.example.mainapp"
    RELEASE_PATH = "/apk/example-inc/example-mobile/example-mobile-1-2-3-release/"
    DOWNLOAD_PATH = "/apk/example-inc/example-mobile/example-mobile-1-2-3-release/example-mobile-1-2-3-android-apk-download/"
    FINAL_PATH = "/wp-content/themes/APKMirror/download.php?key=secret-download-token-1234&id=12345"

    async def test_happy_path(self) -> None:
        tool = APKAnalyzerTool()
        apk_bytes = build_synthetic_apk()
        search_html = load_text_fixture("apk_analyzer/apkmirror_search.html")
        release_html = load_text_fixture("apk_analyzer/apkmirror_release.html")
        download_html = load_text_fixture("apk_analyzer/apkmirror_download_page.html")
        with respx.mock:
            # 1. Search page (HTML with first <a class="fontBlack">)
            respx.get(url__startswith="https://www.apkmirror.com/?post_type=app_release").mock(
                return_value=Response(200, text=search_html)
            )
            # 2. Release page
            respx.get(
                f"https://www.apkmirror.com{self.RELEASE_PATH}"
            ).mock(return_value=Response(200, text=release_html))
            # 3. Download page
            respx.get(
                f"https://www.apkmirror.com{self.DOWNLOAD_PATH}"
            ).mock(return_value=Response(200, text=download_html))
            # 4a. HEAD on the final download URL (size guard)
            respx.head(
                f"https://www.apkmirror.com{self.FINAL_PATH}"
            ).mock(
                return_value=Response(200, headers={"content-length": str(len(apk_bytes))})
            )
            # 4b. GET on the final download URL — serves the synthetic APK.
            respx.get(
                f"https://www.apkmirror.com{self.FINAL_PATH}"
            ).mock(return_value=Response(200, content=apk_bytes))
            result = await tool.run("com.example.mainapp")

        assert result.success is True
        assert result.data["package"] == "com.example.mainapp"
        assert result.data["source"] == "apkmirror"
        assert result.data["version"] == "1.2.3"
        assert result.data["checksum_sha256"]  # 64 hex chars
        assert len(result.data["checksum_sha256"]) == 64

        # Planted AWS key should land in extracted_secrets.
        secret_values = [s["value_prefix"] for s in result.data["extracted_secrets"]]
        assert any(v.startswith("AKIAIOSFODNN7EXAMPLE"[:20]) for v in secret_values)
        secret_types = {s["type"] for s in result.data["extracted_secrets"]}
        assert "aws_access_key" in secret_types

        # Planted endpoint should appear in extracted_endpoints.
        assert "https://api.example.com/v1/users" in result.data["extracted_endpoints"]

        # Permissions from AndroidManifest.xml.
        assert "android.permission.INTERNET" in result.data["permissions"]

        # Native lib picked up.
        assert "libexample.so" in result.data["third_party_libs"]

        # Result count reflects unique extracted secrets.
        assert result.result_count == len(result.data["extracted_secrets"])

        # APKMirror warning surfaced.
        assert any("APKMirror" in w for w in result.data["warnings"])

    async def test_empty_response(self) -> None:
        """No matching app on either mirror — tool must succeed with a
        metadata-only result (no APK, no secrets) and surface a
        warning."""
        tool = APKAnalyzerTool()
        empty_search = load_text_fixture("apk_analyzer/apkmirror_no_results.html")
        apkpure_empty = load_text_fixture("apk_analyzer/apkpure_no_results.html")
        with respx.mock:
            respx.get(url__startswith="https://www.apkmirror.com/?post_type=app_release").mock(
                return_value=Response(200, text=empty_search)
            )
            respx.get(url__startswith="https://apkpure.com/search").mock(
                return_value=Response(200, text=apkpure_empty)
            )
            result = await tool.run("com.example.missing")

        assert result.success is True
        assert result.data["source"] == "metadata_only"
        assert result.data["version"] is None
        assert result.data["checksum_sha256"] is None
        assert result.data["extracted_secrets"] == []
        assert result.data["extracted_endpoints"] == []
        assert result.data["permissions"] == []
        assert result.data["third_party_libs"] == []
        # Warning text explicitly mentions the metadata-only fallback.
        assert any("metadata-only" in w for w in result.data["warnings"])

    async def test_error_path(self) -> None:
        """APKMirror returns 5xx; tool falls through to APKPure which
        also fails. Result is success+metadata-only, no exception."""
        tool = APKAnalyzerTool()
        with respx.mock:
            respx.get(url__startswith="https://www.apkmirror.com/?post_type=app_release").mock(
                return_value=Response(503)
            )
            respx.get(url__startswith="https://apkpure.com/search").mock(
                return_value=Response(503)
            )
            result = await tool.run("com.example.boom")
        # Tool's docstring says it always returns success — it surfaces
        # failure via the metadata source field and warnings list.
        assert result.success is True
        assert result.data["source"] == "metadata_only"
        assert result.data["extracted_secrets"] == []

    async def test_malformed_response(self) -> None:
        """APKMirror returns HTML that doesn't contain the expected
        ``a.fontBlack`` selector. Tool falls through to APKPure which
        also has nothing usable. Result: metadata-only."""
        tool = APKAnalyzerTool()
        with respx.mock:
            respx.get(url__startswith="https://www.apkmirror.com/?post_type=app_release").mock(
                return_value=Response(200, text="<html><body>totally broken page</body></html>")
            )
            respx.get(url__startswith="https://apkpure.com/search").mock(
                return_value=Response(200, text="<html><body>also broken</body></html>")
            )
            result = await tool.run("com.example.broken")
        assert result.success is True
        assert result.data["source"] == "metadata_only"


# ════════════════════════════════════════════════════════════════════════
# WikipediaTool — Wikidata search → Wikipedia summary → Wikidata entity
# ════════════════════════════════════════════════════════════════════════

class TestWikipediaTool:
    """Three sequential calls: ``wbsearchentities`` → ``page/summary``
    → ``Special:EntityData``. We mock each in turn."""

    WBSEARCH_URL = "https://www.wikidata.org/w/api.php"
    SUMMARY_URL_PREFIX = "https://en.wikipedia.org/api/rest_v1/page/summary/"
    ENTITY_URL_PREFIX = "https://www.wikidata.org/wiki/Special:EntityData/"

    async def test_happy_path(self) -> None:
        tool = WikipediaTool()
        wbsearch = load_fixture("wikipedia/wbsearch.json")
        summary = load_fixture("wikipedia/page_summary.json")
        entity = load_fixture("wikipedia/entity_data.json")
        with respx.mock:
            respx.get(url__startswith=self.WBSEARCH_URL).mock(
                return_value=Response(200, json=wbsearch)
            )
            respx.get(url__startswith=self.SUMMARY_URL_PREFIX).mock(
                return_value=Response(200, json=summary)
            )
            respx.get(url__startswith=self.ENTITY_URL_PREFIX).mock(
                return_value=Response(200, json=entity)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 1
        data = result.data
        assert data["found"] is True
        assert data["wikidata_id"] == "Q42"
        assert data["name"] == "Example Corp"
        assert data["description"] == "American multinational technology company"
        assert "Example Corp is an American multinational technology company" in data["summary"]
        assert data["wikipedia_url"] == "https://en.wikipedia.org/wiki/Example_Corp"
        # P571 inception (string form of the time value)
        assert data["founded"] is not None
        assert "+1998-09-04T00:00:00Z" in data["founded"]
        # P159 HQ — value is an entity-id wrapper dict; tool stringifies it
        assert data["headquarters"]
        # P452 industry — list of values
        assert isinstance(data["industry"], list)
        assert len(data["industry"]) >= 1
        # P169 CEO present
        assert data["ceo"]
        # P112 founded_by list
        assert isinstance(data["founded_by"], list)
        # P856 official website (string)
        assert data["official_website"] == "https://example.com"

    async def test_empty_response(self) -> None:
        """Wikidata search returns an empty ``search`` list — tool
        returns ``found=False`` with ``result_count=0`` and never hits
        the summary/entity endpoints."""
        tool = WikipediaTool()
        with respx.mock:
            respx.get(url__startswith=self.WBSEARCH_URL).mock(
                return_value=Response(200, json=load_fixture("wikipedia/wbsearch_empty.json"))
            )
            result = await tool.run("nothing.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["found"] is False

    async def test_error_path(self) -> None:
        """Wikidata search returns 5xx — tool reports failure."""
        tool = WikipediaTool()
        with respx.mock:
            respx.get(url__startswith=self.WBSEARCH_URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    async def test_malformed_json(self) -> None:
        tool = WikipediaTool()
        with respx.mock:
            respx.get(url__startswith=self.WBSEARCH_URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ════════════════════════════════════════════════════════════════════════
# LinkedInDorksTool — generates Google dorks; optionally Bing-search
# ════════════════════════════════════════════════════════════════════════

class TestLinkedInDorksTool:
    """Tool always returns success. Without a Bing key it just emits
    dorks; with a Bing key it also runs them through the API. We
    cover both paths."""

    BING_URL = "https://api.bing.microsoft.com/v7.0/search"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_happy_path(self, _secret) -> None:
        tool = LinkedInDorksTool()
        fixture = load_fixture("linkedin_dorks/bing_search.json")
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # 4 dorks × 2 LinkedIn URLs each = 8 profiles (the third entry
        # is a non-LinkedIn URL and gets filtered out).
        assert result.result_count == 8
        # All collected profile URLs must contain "linkedin.com/in/".
        for p in result.data["profiles"]:
            assert "linkedin.com/in/" in p["url"]
        # Dorks are always emitted regardless.
        assert len(result.data["dorks"]) >= 4
        # When a Bing key is configured, manual_search_hint is None.
        assert result.data["manual_search_hint"] is None

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_empty_response(self, _secret) -> None:
        tool = LinkedInDorksTool()
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(
                return_value=Response(200, json=load_fixture("linkedin_dorks/bing_empty.json"))
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["profiles"] == []
        # Dorks still emitted.
        assert len(result.data["dorks"]) >= 1

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_error_path(self, _secret) -> None:
        """Bing returns 401 — tool swallows the error and returns
        success with an empty profile list (dorks still surfaced)."""
        tool = LinkedInDorksTool()
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        # Tool does not propagate upstream errors; it logs them and
        # returns the dork list as a fallback.
        assert result.success is True
        assert result.result_count == 0
        assert result.data["profiles"] == []
        assert len(result.data["dorks"]) >= 1

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = LinkedInDorksTool()
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # Tool catches the JSON decode exception and returns dorks-only.
        assert result.success is True
        assert result.result_count == 0
        assert result.data["profiles"] == []


# ════════════════════════════════════════════════════════════════════════
# PublicCollabTool — Bing dorks + Trello board probe
# ════════════════════════════════════════════════════════════════════════

class TestPublicCollabTool:
    """Like ``linkedin_dorks``, this tool always succeeds. With a Bing
    key it pulls trello/notion/atlassian results; it also makes an
    unauthenticated Trello search probe."""

    BING_URL = "https://api.bing.microsoft.com/v7.0/search"
    TRELLO_URL = "https://trello.com/search"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_happy_path(self, _secret) -> None:
        tool = PublicCollabTool()
        fixture = load_fixture("public_collab/bing_search.json")
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(
                return_value=Response(200, json=fixture)
            )
            # Trello search probe: 200 with "boards" in the body adds
            # one extra synthesized result.
            respx.get(url__startswith=self.TRELLO_URL).mock(
                return_value=Response(200, text="<html>here are some boards</html>")
            )
            result = await tool.run("example.com")
        assert result.success is True
        platforms = {r["platform"] for r in result.data["results"]}
        assert "trello" in platforms
        assert "confluence/jira" in platforms
        assert "notion" in platforms
        # 5 dorks × 3 classifiable results + 1 trello synthesized = 16 results.
        # (The 4th result in fixture has no recognizable platform and is dropped.)
        assert result.data["results_found"] == result.result_count
        assert result.result_count >= 4
        assert result.data["manual_hint"] is None
        # Dorks emitted.
        assert len(result.data["dorks"]) >= 5

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_empty_response(self, _secret) -> None:
        tool = PublicCollabTool()
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(
                return_value=Response(200, json=load_fixture("public_collab/bing_empty.json"))
            )
            # Trello probe: 200 but no "boards" → no synthesized result.
            respx.get(url__startswith=self.TRELLO_URL).mock(
                return_value=Response(200, text="<html>nothing here</html>")
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["results"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_error_path(self, _secret) -> None:
        tool = PublicCollabTool()
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(return_value=Response(429))
            respx.get(url__startswith=self.TRELLO_URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        # Tool swallows both errors and returns dorks-only.
        assert result.success is True
        assert result.result_count == 0
        assert result.data["results"] == []
        assert len(result.data["dorks"]) >= 1

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-bing-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = PublicCollabTool()
        with respx.mock:
            respx.get(url__startswith=self.BING_URL).mock(
                return_value=Response(200, text="not valid json")
            )
            respx.get(url__startswith=self.TRELLO_URL).mock(
                return_value=Response(200, text="<html>nothing</html>")
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0


# ════════════════════════════════════════════════════════════════════════
# CrunchbaseTool — /entities/organizations/{permalink}
# ════════════════════════════════════════════════════════════════════════

class TestCrunchbaseTool:
    """One primary call to ``/entities/organizations/{permalink}``;
    falls back to autocomplete on 404."""

    BASE_URL = "https://api.crunchbase.com/api/v4"
    ORG_URL_PREFIX = "https://api.crunchbase.com/api/v4/entities/organizations"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-cb-key")
    async def test_happy_path(self, _secret) -> None:
        tool = CrunchbaseTool()
        fixture = load_fixture("crunchbase/org_entity.json")
        with respx.mock:
            respx.get(url__startswith=self.ORG_URL_PREFIX).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        data = result.data
        assert data["name"] == "Example Corp"
        assert data["permalink"] == "example"
        assert data["domain"] == "https://example.com"
        assert data["founded_on"] == {"value": "1998-09-04"}
        assert data["employee_count"] == "10001+"
        assert data["total_funding_usd"] == 36000000
        assert data["ipo_status"] == "public"
        assert data["headquarters"] == "Mountain View, California, United States"
        # Founders + leadership combined.
        assert len(data["founders"]) == 2
        assert {f["name"] for f in data["founders"]} == {"Jane Founder", "John Founder"}
        assert len(data["leadership"]) == 2
        # Funding rounds parsed with USD amounts.
        assert len(data["funding_rounds"]) == 2
        assert data["funding_rounds"][0]["amount_usd"] == 1670000000
        # Acquisitions list.
        assert "DoubleClick" in data["acquisitions"]
        assert "YouTube" in data["acquisitions"]
        # result_count = founders + leadership.
        assert result.result_count == 4

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-cb-key")
    async def test_empty_response(self, _secret) -> None:
        """Org exists but has no people / funding / acquisitions —
        success, result_count=0, empty lists in data."""
        tool = CrunchbaseTool()
        with respx.mock:
            respx.get(url__startswith=self.ORG_URL_PREFIX).mock(
                return_value=Response(200, json=load_fixture("crunchbase/empty_org.json"))
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["founders"] == []
        assert result.data["leadership"] == []
        assert result.data["funding_rounds"] == []
        assert result.data["acquisitions"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret) -> None:
        tool = CrunchbaseTool()
        with respx.mock:
            respx.get(url__startswith=self.ORG_URL_PREFIX).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "Invalid" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-cb-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = CrunchbaseTool()
        with respx.mock:
            respx.get(url__startswith=self.ORG_URL_PREFIX).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = CrunchbaseTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "CRUNCHBASE_API_KEY" in result.error


# ════════════════════════════════════════════════════════════════════════
# GitHubOrgMembersTool — /search/users + /orgs/.../members + /users/...
# ════════════════════════════════════════════════════════════════════════

class TestGitHubOrgMembersTool:
    """Tool walks: ``/search/users?q=<company> type:org`` →
    ``/orgs/{org}/members`` → per-user ``/users/{login}``. Uses
    ``asyncio.gather`` for the per-user step so we mock all user URLs
    with a generic respx route."""

    BASE_URL = "https://api.github.com"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_happy_path(self, _secret) -> None:
        tool = GitHubOrgMembersTool()
        search_users = load_fixture("github_org_members/search_users.json")
        members = load_fixture("github_org_members/org_members.json")
        users = {
            "alice-dev": load_fixture("github_org_members/user_alice.json"),
            "bob-sec": load_fixture("github_org_members/user_bob.json"),
            "carol-devops": load_fixture("github_org_members/user_carol.json"),
        }

        def _user_route(request: httpx.Request) -> Response:
            login = request.url.path.rsplit("/", 1)[-1]
            if login in users:
                return Response(200, json=users[login])
            return Response(404, json={"message": "Not Found"})

        with respx.mock:
            respx.get(url__startswith=f"{self.BASE_URL}/search/users").mock(
                return_value=Response(200, json=search_users)
            )
            # Members route: only "exampleorg" returns members; the
            # "example" handle tried directly returns 404 (irrelevant
            # in this test — but we mock it so respx doesn't blow up).
            respx.get(f"{self.BASE_URL}/orgs/exampleorg/members").mock(
                return_value=Response(200, json=members)
            )
            respx.get(f"{self.BASE_URL}/orgs/example/members").mock(
                return_value=Response(404, json={"message": "Not Found"})
            )
            # Per-user lookups (asyncio.gather across all members).
            respx.get(url__regex=rf"^{self.BASE_URL}/users/[^/]+$").mock(
                side_effect=_user_route
            )

            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["target"] == "example.com"
        # Tool tries the searched org "exampleorg" and the bare stem
        # "example"; only the former returns members.
        assert "exampleorg" in result.data["orgs_found"]
        assert result.data["member_count"] == 3
        # Member profile fields plumbed through.
        logins = {m["login"] for m in result.data["members"]}
        assert logins == {"alice-dev", "bob-sec", "carol-devops"}
        # Emails extracted (bob has email=None and must be skipped).
        emails = result.data["emails_found"]
        assert "alice@example.com" in emails
        assert "carol@example.com" in emails
        assert None not in emails
        assert len(emails) == 2

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_empty_response(self, _secret) -> None:
        """Search returns no org candidates and the direct stem also
        404s — success with zero members."""
        tool = GitHubOrgMembersTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE_URL}/search/users").mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            respx.get(url__regex=rf"^{self.BASE_URL}/orgs/[^/]+/members(\?.*)?$").mock(
                return_value=Response(404, json={"message": "Not Found"})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["member_count"] == 0
        assert result.data["members"] == []
        assert result.data["emails_found"] == []
        assert result.data["orgs_found"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_rate_limited(self, _secret) -> None:
        """All requests 403 — tool returns success with zero members
        (consistent with the existing github_subdomains pattern: GitHub
        rate-limit is a 'stop searching' signal, not a hard error)."""
        tool = GitHubOrgMembersTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE_URL}/search/users").mock(
                return_value=Response(403)
            )
            respx.get(url__regex=rf"^{self.BASE_URL}/orgs/[^/]+/members(\?.*)?$").mock(
                return_value=Response(403)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_malformed_json(self, _secret) -> None:
        tool = GitHubOrgMembersTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE_URL}/search/users").mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # The JSON decode raises inside the try/except — tool returns
        # failure with the exception text.
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = GitHubOrgMembersTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "GITHUB_TOKEN" in result.error
