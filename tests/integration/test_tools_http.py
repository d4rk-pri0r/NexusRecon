"""Integration tests for HTTP-based OSINT tools using respx mocking."""
import pytest
import respx
import httpx
from httpx import Response

from nexusrecon.tools.domain.crtsh_tool import CRTShTool
from nexusrecon.tools.web.webtech_tool import WebTechTool
from nexusrecon.tools.web.favicon_tool import FaviconTool
from nexusrecon.tools.web.dorks_tool import DorksTool
from nexusrecon.tools.web.metadata_tool import MetadataTool
from nexusrecon.tools.identity.breach_tool import BreachTool


CRTSH_URL = "https://crt.sh/"


class TestCRTShTool:
    """Certificate transparency log search via crt.sh API."""

    @pytest.mark.asyncio
    async def test_crtsh_returns_subdomains(self):
        crtsh = CRTShTool()
        mock_json = [
            {"name_value": "sub.example.com", "common_name": "*.example.com",
             "issuer_name": "Let's Encrypt", "not_before": "2025-01-01T00:00:00",
             "not_after": "2026-01-01T00:00:00"},
            {"name_value": "admin.example.com", "common_name": "admin.example.com",
             "issuer_name": "Let's Encrypt", "not_before": "2025-06-01T00:00:00",
             "not_after": "2026-06-01T00:00:00"},
        ]
        with respx.mock:
            respx.get(url__startswith=CRTSH_URL).mock(return_value=Response(200, json=mock_json))
            result = await crtsh.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        assert "sub.example.com" in result.data["subdomains"]
        assert "admin.example.com" in result.data["subdomains"]
        assert len(result.data["certs"]) == 2

    @pytest.mark.asyncio
    async def test_crtsh_empty_response(self):
        crtsh = CRTShTool()
        with respx.mock:
            respx.get(url__startswith=CRTSH_URL).mock(return_value=Response(200, json=[]))
            result = await crtsh.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []

    @pytest.mark.asyncio
    async def test_crtsh_non_200(self):
        crtsh = CRTShTool()
        with respx.mock:
            respx.get(url__startswith=CRTSH_URL).mock(return_value=Response(429))
            result = await crtsh.run("example.com")
        assert result.success is False
        assert "429" in result.error

    @pytest.mark.asyncio
    async def test_crtsh_malformed_json(self):
        crtsh = CRTShTool()
        with respx.mock:
            respx.get(url__startswith=CRTSH_URL).mock(return_value=Response(200, text="not json"))
            result = await crtsh.run("example.com")
        assert result.success is False
        assert "JSON" in result.error


class TestWebTechTool:
    """Web technology fingerprinting from HTTP headers and HTML."""

    HTML_WORDPRESS = """<!DOCTYPE html><html>
    <head><link rel="stylesheet" href="/wp-content/style.css"></head>
    <body><script src="/wp-includes/js/jquery.js"></script></body></html>"""

    @pytest.mark.asyncio
    async def test_detects_nginx(self):
        tool = WebTechTool()
        with respx.mock:
            respx.get("https://example.com/").mock(
                return_value=Response(200, headers={"Server": "nginx/1.24.0"}, text="<html></html>")
            )
            result = await tool.run("example.com")
        assert result.success is True
        techs = [t["name"] for t in result.data["technologies"]]
        assert "nginx" in techs

    @pytest.mark.asyncio
    async def test_detects_cloudflare(self):
        tool = WebTechTool()
        with respx.mock:
            respx.get("https://example.com/").mock(
                return_value=Response(200, headers={"Server": "cloudflare", "cf-ray": "abc123"}, text="ok")
            )
            result = await tool.run("example.com")
        assert result.success is True
        techs = [t["name"] for t in result.data["technologies"]]
        assert "cloudflare" in techs

    @pytest.mark.asyncio
    async def test_detects_wordpress(self):
        tool = WebTechTool()
        with respx.mock:
            respx.get("https://example.com/").mock(
                return_value=Response(200, text=self.HTML_WORDPRESS)
            )
            result = await tool.run("example.com")
        assert result.success is True
        techs = [t["name"] for t in result.data["technologies"]]
        assert "wordpress" in techs
        assert "jquery" in techs

    @pytest.mark.asyncio
    async def test_no_technologies_detected(self):
        tool = WebTechTool()
        with respx.mock:
            respx.get("https://example.com/").mock(
                return_value=Response(200, text="<html><body>plain</body></html>")
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.data["count"] == 0
        assert result.data["technologies"] == []

    @pytest.mark.asyncio
    async def test_connection_failure(self):
        tool = WebTechTool()
        with respx.mock:
            respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("timeout"))
            result = await tool.run("example.com")
        assert result.success is False


class TestFaviconTool:
    """Favicon hash computation and Shodan correlation."""

    @pytest.mark.asyncio
    async def test_favicon_detected(self):
        tool = FaviconTool()
        fake_icon = b"\x00\x01\x02\x03" * 100
        with respx.mock:
            respx.get("https://example.com/favicon.ico").mock(
                return_value=Response(200, content=fake_icon,
                                      headers={"content-type": "image/x-icon"})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count >= 1
        assert result.data["icons"][0]["url"].endswith("/favicon.ico")
        assert result.data["icons"][0]["size"] == 400

    @pytest.mark.asyncio
    async def test_no_favicon_found(self):
        tool = FaviconTool()
        with respx.mock:
            for path in [
                "/favicon.ico", "/favicon.png", "/favicon.svg",
                "/static/favicon.ico", "/assets/favicon.ico",
                "/assets/images/favicon.ico", "/images/favicon.ico",
                "/uploads/favicon.ico", "/apple-touch-icon.png",
            ]:
                respx.get(f"https://example.com{path}").mock(
                    return_value=Response(404)
                )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0

    @pytest.mark.asyncio
    async def test_small_content_ignored(self):
        tool = FaviconTool()
        with respx.mock:
            respx.get("https://example.com/favicon.ico").mock(
                return_value=Response(200, content=b"small")
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0


class TestDorksTool:
    """Google dork automation with Bing fallback."""

    @pytest.mark.asyncio
    async def test_google_search_success(self):
        tool = DorksTool()
        html = '<html><a href="https://example.com/doc.pdf">PDF</a></html>'
        with respx.mock:
            respx.get(url__startswith="https://www.google.com/search").mock(
                return_value=Response(200, text=html)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count >= 1

    @pytest.mark.asyncio
    async def test_google_fails_falls_back_to_bing(self):
        tool = DorksTool()
        bing_html = '<html><cite>https://example.com/file.pdf</cite></html>'
        with respx.mock:
            respx.get(url__startswith="https://www.google.com/search").mock(return_value=Response(403))
            respx.get(url__startswith="https://www.bing.com/search").mock(
                return_value=Response(200, text=bing_html)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count >= 1

    @pytest.mark.asyncio
    async def test_both_search_engines_fail(self):
        tool = DorksTool()
        with respx.mock:
            respx.get(url__startswith="https://www.google.com/search").mock(return_value=Response(403))
            respx.get(url__startswith="https://www.bing.com/search").mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0


class TestMetadataTool:
    """Metadata extraction from publicly accessible files."""

    @pytest.mark.asyncio
    async def test_detects_sensitive_files(self):
        tool = MetadataTool()
        with respx.mock:
            respx.get("https://example.com/robots.txt").mock(
                return_value=Response(200, text="User-agent: *\nDisallow: /admin")
            )
            respx.get("https://example.com/.env").mock(
                return_value=Response(200, text="DB_PASSWORD=secret123\nAPI_KEY=abc")
            )
            for path in ["/sitemap.xml", "/security.txt", "/.well-known/security.txt",
                         "/README.md", "/CHANGELOG.md", "/package.json", "/Dockerfile",
                         "/docker-compose.yml", "/.gitignore", "/composer.json",
                         "/requirements.txt", "/Gemfile", "/Cargo.toml", "/go.mod"]:
                respx.get(f"https://example.com{path}").mock(return_value=Response(404))
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count >= 2
        assert len(result.data["env_leaks"]) >= 1

    @pytest.mark.asyncio
    async def test_no_files_found(self):
        tool = MetadataTool()
        with respx.mock:
            for path in ["/sitemap.xml", "/robots.txt", "/security.txt",
                         "/.well-known/security.txt", "/.env", "/README.md",
                         "/CHANGELOG.md", "/package.json", "/Dockerfile",
                         "/docker-compose.yml", "/.gitignore", "/composer.json",
                         "/requirements.txt", "/Gemfile", "/Cargo.toml", "/go.mod"]:
                respx.get(f"https://example.com{path}").mock(return_value=Response(404))
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0


class TestBreachTool:
    """Breach data lookup via HIBP API."""

    HIBP_BASE = "https://haveibeenpwned.com/api/v3"

    @pytest.fixture(autouse=True)
    def _set_hibp_key(self):
        import os
        from nexusrecon.core.config import get_config
        old = os.environ.get("NEXUS_HAVEIBEENPWNED_API_KEY") or os.environ.get("HAVEIBEENPWNED_API_KEY")
        os.environ["HAVEIBEENPWNED_API_KEY"] = "test-key-123"
        get_config.cache_clear()
        yield
        if old:
            os.environ["HAVEIBEENPWNED_API_KEY"] = old
        else:
            os.environ.pop("HAVEIBEENPWNED_API_KEY", None)
        get_config.cache_clear()

    @pytest.mark.asyncio
    async def test_hibp_finds_breaches(self):
        tool = BreachTool()
        mock_breaches = [
            {"Name": "Adobe", "BreachDate": "2013-10-01", "Domain": "adobe.com",
             "DataClasses": ["Email", "Password"], "Description": "Adobe breach"},
            {"Name": "LinkedIn", "BreachDate": "2012-05-01", "Domain": "linkedin.com",
             "DataClasses": ["Email", "Password"], "Description": "LinkedIn breach"},
        ]
        with respx.mock:
            respx.get(url__startswith=f"{self.HIBP_BASE}/breachedaccount/").mock(
                return_value=Response(200, json=mock_breaches)
            )
            result = await tool.run("test@example.com", target_type="email")
        assert result.success is True
        assert result.result_count == 2
        assert result.data["hibp"]["found"] is True
        assert result.data["hibp"]["breaches"][0]["name"] == "Adobe"

    @pytest.mark.asyncio
    async def test_hibp_no_breaches(self):
        tool = BreachTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.HIBP_BASE}/breachedaccount/").mock(
                return_value=Response(404)
            )
            result = await tool.run("safe@example.com", target_type="email")
        assert result.success is True
        assert result.data["hibp"]["found"] is False
        assert result.data["hibp"]["breaches"] == []

    @pytest.mark.asyncio
    async def test_hibp_no_api_key(self):
        import os
        from nexusrecon.core.config import get_config
        old = os.environ.pop("HAVEIBEENPWNED_API_KEY", None)
        get_config.cache_clear()
        try:
            tool = BreachTool()
            result = await tool.run("test@example.com")
            assert result.data["hibp"].get("error") is not None
        finally:
            if old:
                os.environ["HAVEIBEENPWNED_API_KEY"] = old
            get_config.cache_clear()

    @pytest.mark.asyncio
    async def test_hibp_domain_lookup(self):
        tool = BreachTool()
        mock_breaches = [
            {"Name": "TestCorp", "BreachDate": "2024-01-01", "Domain": "testcorp.com",
             "DataClasses": ["Email"], "Description": "Test breach"},
        ]
        with respx.mock:
            respx.get(url__startswith=f"{self.HIBP_BASE}/breaches").mock(
                return_value=Response(200, json=mock_breaches)
            )
            result = await tool.run("testcorp.com", target_type="domain")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["hibp"]["breaches"][0]["name"] == "TestCorp"


# ── NewsTool ────────────────────────────────────────────────────────────────

RSS_XML = """<?xml version="1.0"?>
<rss version="2.0">
<channel>
<item>
  <title>TestCorp Announces New AI Platform</title>
  <link>https://example.com/news/1</link>
  <description>TestCorp launched their new AI platform today</description>
  <pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate>
</item>
<item>
  <title>TestCorp Acquires Startup</title>
  <link>https://example.com/news/2</link>
  <description>TestCorp acquired a startup for $1B</description>
  <pubDate>Tue, 02 Jan 2026 00:00:00 GMT</pubDate>
</item>
</channel>
</rss>"""


class TestNewsTool:
    @pytest.mark.asyncio
    async def test_rss_fallback(self):
        from nexusrecon.tools.pretext.news_tool import NewsTool
        tool = NewsTool()
        with respx.mock:
            respx.get(url__startswith="https://news.google.com/rss/search").mock(
                return_value=Response(200, text=RSS_XML)
            )
            result = await tool.run("testcorp.com")
        assert result.success is True
        assert result.result_count >= 2
        assert result.data["total_articles"] >= 2
        assert result.data["sources_used"] == ["rss"]

    @pytest.mark.asyncio
    async def test_empty_rss(self):
        from nexusrecon.tools.pretext.news_tool import NewsTool
        tool = NewsTool()
        with respx.mock:
            respx.get(url__startswith="https://news.google.com/rss/search").mock(
                return_value=Response(200, text="<?xml version=\"1.0\"?><rss><channel></channel></rss>")
            )
            result = await tool.run("testcorp.com")
        assert result.success is True
        assert result.result_count == 0

    @pytest.mark.asyncio
    async def test_all_sources_fail(self):
        from nexusrecon.tools.pretext.news_tool import NewsTool
        tool = NewsTool()
        with respx.mock:
            respx.get(url__startswith="https://news.google.com/rss/search").mock(
                return_value=Response(503)
            )
            respx.get(url__startswith="https://finance.yahoo.com/rss/headline").mock(
                return_value=Response(503)
            )
            result = await tool.run("testcorp.com")
        assert result.success is True
        assert result.result_count == 0

    @pytest.mark.asyncio
    async def test_newsapi_with_key(self):
        import os
        from nexusrecon.core.config import get_config
        from nexusrecon.tools.pretext.news_tool import NewsTool

        os.environ["NEWSAPI_API_KEY"] = "test-key"
        get_config.cache_clear()
        try:
            tool = NewsTool()
            mock_response = {
                "articles": [
                    {"title": "Breaking News", "source": {"name": "TestWire"},
                     "url": "https://example.com", "publishedAt": "2026-01-01T00:00:00Z",
                     "description": "A breaking story"},
                ]
            }
            with respx.mock:
                respx.get("https://newsapi.org/v2/everything").mock(
                    return_value=Response(200, json=mock_response)
                )
                result = await tool.run("testcorp.com")
            assert result.success is True
            assert result.result_count >= 1
            assert "newsapi" in result.data["sources_used"]
        finally:
            os.environ.pop("NEWSAPI_API_KEY", None)
            get_config.cache_clear()


# ── JobsTool ─────────────────────────────────────────────────────────────────

class TestJobsTool:
    @pytest.mark.asyncio
    async def test_google_jobs_scrape(self):
        from nexusrecon.tools.pretext.jobs_tool import JobsTool
        tool = JobsTool()
        html = """
        <html><body>
        <div class="jobTitle">Senior Python Developer</div>
        <div class="companyName">TestCorp</div>
        <div class="jobTitle">DevOps Engineer</div>
        <div class="companyName">TestCorp</div>
        </body></html>
        """
        with respx.mock:
            respx.get(url__startswith="https://www.google.com/search").mock(
                return_value=Response(200, text=html)
            )
            result = await tool.run("testcorp.com")
        assert result.success is True
        assert result.result_count >= 2
        assert "google_jobs" in result.data["sources_used"]

    @pytest.mark.asyncio
    async def test_jobs_no_results(self):
        from nexusrecon.tools.pretext.jobs_tool import JobsTool
        tool = JobsTool()
        with respx.mock:
            respx.get(url__startswith="https://www.google.com/search").mock(
                return_value=Response(200, text="<html></html>")
            )
            result = await tool.run("testcorp.com")
        assert result.success is True
        assert result.result_count == 0

    @pytest.mark.asyncio
    async def test_jobs_extracts_tech_stack(self):
        from nexusrecon.tools.pretext.jobs_tool import JobsTool, TECH_KEYWORDS
        tool = JobsTool()
        html = """
        <html><body>
        <div class="jobTitle">Senior Python Developer - AWS, Kubernetes</div>
        <div class="companyName">TestCorp</div>
        </body></html>
        """
        with respx.mock:
            respx.get(url__startswith="https://www.google.com/search").mock(
                return_value=Response(200, text=html)
            )
            result = await tool.run("testcorp.com")
        assert result.success is True
        tech_stack = result.data.get("tech_stack", {})
        assert "python" in tech_stack or "aws" in tech_stack or "kubernetes" in tech_stack

    @pytest.mark.asyncio
    async def test_adzuna_api(self):
        import os
        from nexusrecon.core.config import get_config
        from nexusrecon.tools.pretext.jobs_tool import JobsTool

        os.environ["ADZUNA_APP_ID"] = "test-id"
        os.environ["ADZUNA_API_KEY"] = "test-key"
        get_config.cache_clear()
        try:
            tool = JobsTool()
            mock_response = {
                "results": [
                    {"title": "Senior Backend Engineer", "company": {"display_name": "TestCorp"},
                     "location": {"display_name": "San Francisco"},
                     "description": "Python, AWS, and Kubernetes experience required",
                     "redirect_url": "https://example.com/job", "category": {"label": "Engineering"},
                     "salary_min": 150000, "salary_max": 200000},
                ]
            }
            with respx.mock:
                respx.get(url__startswith="https://api.adzuna.com/v1/api/jobs").mock(
                    return_value=Response(200, json=mock_response)
                )
                result = await tool.run("testcorp.com")
            assert result.success is True
            assert "adzuna" in result.data["sources_used"]
        finally:
            os.environ.pop("ADZUNA_APP_ID", None)
            os.environ.pop("ADZUNA_API_KEY", None)
            get_config.cache_clear()


# ── SECEdgarTool ─────────────────────────────────────────────────────────────

class TestSECEdgarTool:
    @pytest.mark.asyncio
    async def test_domain_to_company(self):
        from nexusrecon.tools.pretext.sec_edgar_tool import SECEdgarTool
        assert SECEdgarTool._domain_to_company("testcorp.com") == "Testcorp"
        assert SECEdgarTool._domain_to_company("acme-corp.com") == "Acme Corp"
        assert SECEdgarTool._domain_to_company("api.example.com") == "Example"

    @pytest.mark.asyncio
    async def test_search_edgar(self):
        from nexusrecon.tools.pretext.sec_edgar_tool import SECEdgarTool
        tool = SECEdgarTool()
        mock_hits = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "formType": "10-K", "companyName": "TestCorp", "cik": "12345",
                            "filedAt": "2026-01-15", "description": "Annual report",
                            "fileUrl": "/ix?doc=/Archives/edgar/data/1/2/3/test-10k.htm",
                        }
                    }
                ]
            }
        }
        with respx.mock:
            respx.get("https://efts.sec.gov/LATEST/search-index").mock(
                return_value=Response(200, json=mock_hits)
            )
            respx.get(url__startswith="https://www.sec.gov/ix?doc=").mock(
                return_value=Response(200, text="<html><body>cybersecurity risk factors data breach</body></html>")
            )
            result = await tool.run("testcorp.com", company_name="TestCorp")
        assert result.success is True
        assert result.result_count >= 1
        assert result.data["total_filings"] >= 1
        assert "cybersecurity" in result.data.get("relevant_tech_mentions", {})
        assert "data breach" in result.data.get("relevant_tech_mentions", {})

    @pytest.mark.asyncio
    async def test_search_edgar_no_results(self):
        from nexusrecon.tools.pretext.sec_edgar_tool import SECEdgarTool
        tool = SECEdgarTool()
        with respx.mock:
            respx.get("https://efts.sec.gov/LATEST/search-index").mock(
                return_value=Response(200, json={"hits": {"hits": []}})
            )
            result = await tool.run("testcorp.com", company_name="TestCorp")
        assert result.success is True
        assert result.result_count == 0

    @pytest.mark.asyncio
    async def test_search_edgar_server_error(self):
        from nexusrecon.tools.pretext.sec_edgar_tool import SECEdgarTool
        tool = SECEdgarTool()
        with respx.mock:
            respx.get("https://efts.sec.gov/LATEST/search-index").mock(
                return_value=Response(500)
            )
            result = await tool.run("testcorp.com", company_name="TestCorp")
        assert result.success is True
        assert result.result_count == 0
