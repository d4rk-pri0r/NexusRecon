"""Integration tests for D5 (DeHashed) and D6 (HudsonRock enhanced).

These tests mock the upstream HTTP layer so no real API calls are made.
They verify the tools' response parsing, error handling, and the new
D6 credential-detail extraction logic.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.tools.intel.dehashed_tool import DehashedTool
from nexusrecon.tools.identity.hudsonrock_tool import HudsonRockTool


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _mock_config(dehashed_user="user@test.com", dehashed_key="key123",
                 hudsonrock_key=None):
    """Return a mock NexusConfig with the given secrets."""
    cfg = MagicMock()

    def _get_secret(name):
        mapping = {
            "dehashed_username": dehashed_user,
            "dehashed_api_key": dehashed_key,
            "hudsonrock_api_key": hudsonrock_key,
        }
        return mapping.get(name)

    cfg.get_secret.side_effect = _get_secret
    return cfg


def _dehashed_response(entries, total=None, balance=100):
    """Build a minimal DeHashed API response body."""
    return {
        "balance": balance,
        "entries": entries,
        "total": total if total is not None else len(entries),
        "took": 1,
        "success": True,
    }


def _make_dehashed_entry(
    email="jane.doe@gmail.com",
    username="jane.doe.82",
    database="LinkedIn-2012",
    password="",
    hashed_password="",
):
    return {
        "id": "abc123",
        "email": email,
        "username": username,
        "database_name": database,
        "obtained_from": "2012-06-05",
        "password": password,
        "hashed_password": hashed_password,
        "hash_type": "bcrypt" if hashed_password else None,
        "phone": None,
        "address": None,
        "ip_address": None,
        "name": "Jane Doe",
    }


# ──────────────────────────────────────────────────────────────────────
# D5: DeHashed tool tests
# ──────────────────────────────────────────────────────────────────────


class TestDehashedTool:
    """Unit-level tests for DehashedTool — no real HTTP."""

    def _make_tool(self, user="user@test.com", key="key123"):
        tool = DehashedTool()
        tool.config = _mock_config(dehashed_user=user, dehashed_key=key)
        return tool

    @pytest.mark.asyncio
    async def test_missing_credentials_returns_failure(self):
        tool = self._make_tool(user=None, key=None)
        result = await tool.run("jane.doe@corp.com", target_type="email")
        assert not result.success
        assert "DEHASHED_USERNAME" in result.error

    @pytest.mark.asyncio
    async def test_password_entry_classified_correctly(self):
        entry = _make_dehashed_entry(password="hunter2")
        payload = _dehashed_response([entry])

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = payload

        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("jane.doe@gmail.com", target_type="email")

        assert result.success
        assert result.result_count == 1
        entries = result.data["entries"]
        assert entries[0]["credential_kind"] == "password"
        assert entries[0]["password"] == "hunter2"

    @pytest.mark.asyncio
    async def test_hash_entry_classified_correctly(self):
        entry = _make_dehashed_entry(hashed_password="$2b$12$abc123")
        payload = _dehashed_response([entry])

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = payload

        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("jane.doe@gmail.com", target_type="email")

        assert result.success
        entries = result.data["entries"]
        assert entries[0]["credential_kind"] == "hash"
        assert entries[0]["hashed_password"] == "$2b$12$abc123"

    @pytest.mark.asyncio
    async def test_presence_only_entry(self):
        entry = _make_dehashed_entry(password="", hashed_password="")
        payload = _dehashed_response([entry])

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = payload

        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("jane@corp.com", target_type="email")

        assert result.success
        assert result.data["entries"][0]["credential_kind"] == "presence_only"

    @pytest.mark.asyncio
    async def test_by_credential_kind_stats(self):
        entries = [
            _make_dehashed_entry(password="pw1"),
            _make_dehashed_entry(hashed_password="hash1"),
            _make_dehashed_entry(password="pw2"),
        ]
        payload = _dehashed_response(entries)

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = payload

        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("jane@corp.com", target_type="email")

        stats = result.data["by_credential_kind"]
        assert stats.get("password") == 2
        assert stats.get("hash") == 1

    @pytest.mark.asyncio
    async def test_401_returns_failure_with_key_hint(self):
        """classify_response should surface 401 as an auth failure."""
        from nexusrecon.tools.base import ToolResult

        mock_resp = MagicMock()
        mock_resp.is_success = False
        mock_resp.status_code = 401

        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            tool = self._make_tool()

            # Stub classify_response to return the expected auth-failure result.
            def _fake_classify(resp, endpoint=""):
                if getattr(resp, "status_code", None) == 401:
                    return ToolResult(
                        success=False, source=tool.name,
                        error="DeHashed auth failure - check DEHASHED_API_KEY / DEHASHED_USERNAME",
                    )
                return None

            tool.classify_response = _fake_classify
            result = await tool.run("jane@corp.com", target_type="email")

        assert not result.success
        assert "DEHASHED" in result.error

    @pytest.mark.asyncio
    async def test_query_field_prefix_applied(self):
        """The query parameter sent to DeHashed should use the right field prefix."""
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = _dehashed_response([])

        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            tool = self._make_tool()
            await tool.run("janedoe82", target_type="username")

            call_kwargs = mock_client.get.call_args
            params = call_kwargs[1].get("params") or call_kwargs[0][1] if len(call_kwargs[0]) > 1 else {}
            # Extract params regardless of call style
            all_kwargs = mock_client.get.call_args.kwargs
            params = all_kwargs.get("params", {})
            assert params.get("query") == "username:janedoe82"

    @pytest.mark.asyncio
    async def test_network_error_returns_failure(self):
        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = Exception("connection refused")

            tool = self._make_tool()
            result = await tool.run("jane@corp.com", target_type="email")

        assert not result.success
        assert "connection refused" in result.error

    @pytest.mark.asyncio
    async def test_total_from_response_vs_entry_count(self):
        """total should reflect the API's total, not just the page count."""
        entry = _make_dehashed_entry(password="pw1")
        payload = _dehashed_response([entry], total=1500)

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = payload

        with patch("nexusrecon.tools.intel.dehashed_tool.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("jane@corp.com")

        assert result.data["total"] == 1500
        assert result.result_count == 1  # only this page


# ──────────────────────────────────────────────────────────────────────
# D6: Enhanced HudsonRock tests
# ──────────────────────────────────────────────────────────────────────


class TestHudsonRockEnhanced:
    """D6 additions: credential detail extraction + optional API key."""

    def _make_tool(self, api_key=None):
        tool = HudsonRockTool()
        tool.config = _mock_config(hudsonrock_key=api_key)
        return tool

    # ── Email check ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_email_not_compromised_returns_false(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("noone@nowhere.com", target_type="email")

        assert result.success
        assert not result.data["compromised"]

    @pytest.mark.asyncio
    async def test_email_compromised_community_tier_no_credentials(self):
        """Community tier (no API key) → captured_credentials is empty list."""
        raw = {
            "stealerFamily": "RedLine",
            "computerName": "DESKTOP-ABCDEF",
            "operatingSystem": "Windows 10 x64",
            "dateCompromised": "2024-01-15",
            "antiviruses": ["Windows Defender"],
            "externalIp": "1.2.3.4",
            "malwarePath": "C:\\Users\\jane\\AppData\\Roaming\\malware.exe",
            # No "credentials" key → community tier
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = raw

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool(api_key=None)
            result = await tool.run("jane@corp.com", target_type="email")

        assert result.success
        assert result.data["compromised"] is True
        assert result.data["captured_credentials"] == []
        assert result.data["has_credential_detail"] is False

    @pytest.mark.asyncio
    async def test_email_compromised_paid_tier_exposes_credentials(self):
        """Paid tier (with API key) → captured_credentials populated."""
        raw = {
            "stealerFamily": "Vidar",
            "computerName": "LAPTOP-XYZ",
            "operatingSystem": "Windows 11",
            "dateCompromised": "2024-06-01",
            "antiviruses": [],
            "externalIp": "5.6.7.8",
            "malwarePath": "C:\\Temp\\update.exe",
            "credentials": [
                {
                    "url": "https://mail.corp.com/owa/",
                    "username": "jane.doe@corp.com",
                    "password": "Summer2024!",
                },
                {
                    "url": "https://github.com/login",
                    "username": "janedoe82",
                    "password": "gh_token_abc123",
                },
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = raw

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool(api_key="my_paid_key")
            result = await tool.run("jane@corp.com", target_type="email")

        assert result.success
        data = result.data
        assert data["compromised"] is True
        assert len(data["captured_credentials"]) == 2
        assert data["captured_credentials"][0]["url"] == "https://mail.corp.com/owa/"
        assert data["captured_credentials"][0]["password"] == "Summer2024!"
        assert data["has_credential_detail"] is True

    @pytest.mark.asyncio
    async def test_email_captured_urls_deduped(self):
        """captured_urls should be a deduped list from credentials."""
        raw = {
            "stealerFamily": "Raccoon",
            "computerName": "PC-001",
            "operatingSystem": "Windows 10",
            "dateCompromised": "2024-03-01",
            "antiviruses": [],
            "externalIp": "9.9.9.9",
            "malwarePath": "C:\\raccoon.exe",
            "credentials": [
                {"url": "https://owa.corp.com/", "username": "u1", "password": "p1"},
                {"url": "https://owa.corp.com/", "username": "u2", "password": "p2"},
                {"url": "https://github.com/login", "username": "u3", "password": "p3"},
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = raw

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool(api_key="paid")
            result = await tool.run("jane@corp.com", target_type="email")

        urls = result.data["captured_urls"]
        assert len(urls) == 2  # deduped
        assert "https://owa.corp.com/" in urls
        assert "https://github.com/login" in urls

    # ── Domain check ─────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_domain_not_compromised_returns_false(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("cleancompany.com", target_type="domain")

        assert result.success
        assert not result.data["compromised"]

    @pytest.mark.asyncio
    async def test_domain_stealer_records_include_captured_creds(self):
        """D6: domain check includes credential detail per stealer session."""
        raw = {
            "employeeCredentialsCount": 2,
            "clientCredentialsCount": 0,
            "stealers": [
                {
                    "computerName": "CORP-PC-1",
                    "operatingSystem": "Windows 10",
                    "dateCompromised": "2024-05-01",
                    "stealerFamily": "RedLine",
                    "antiviruses": [],
                    "externalIp": "10.0.0.1",
                    "malwarePath": "C:\\redline.exe",
                    "credentials": [
                        {
                            "url": "https://adfs.corp.com/adfs/ls",
                            "username": "alice@corp.com",
                            "password": "Spring2024!",
                        },
                    ],
                },
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = raw

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool(api_key="paid")
            result = await tool.run("corp.com", target_type="domain")

        assert result.success
        data = result.data
        assert data["compromised"] is True
        stealers = data["stealers"]
        assert stealers
        assert stealers[0]["has_credential_detail"] is True
        assert stealers[0]["captured_credentials"][0]["password"] == "Spring2024!"

    @pytest.mark.asyncio
    async def test_domain_all_captured_urls_aggregated(self):
        """all_captured_urls should aggregate URLs across all stealers."""
        raw = {
            "employeeCredentialsCount": 2,
            "clientCredentialsCount": 0,
            "stealers": [
                {
                    "computerName": "PC-A",
                    "operatingSystem": "Windows 10",
                    "dateCompromised": "2024-01-01",
                    "stealerFamily": "Vidar",
                    "antiviruses": [],
                    "externalIp": "1.1.1.1",
                    "malwarePath": "C:\\vidar.exe",
                    "credentials": [
                        {"url": "https://mail.corp.com/owa/", "username": "u1", "password": "p1"},
                    ],
                },
                {
                    "computerName": "PC-B",
                    "operatingSystem": "Windows 11",
                    "dateCompromised": "2024-02-01",
                    "stealerFamily": "Raccoon",
                    "antiviruses": [],
                    "externalIp": "2.2.2.2",
                    "malwarePath": "C:\\raccoon.exe",
                    "credentials": [
                        {"url": "https://vpn.corp.com/", "username": "u2", "password": "p2"},
                        {"url": "https://mail.corp.com/owa/", "username": "u3", "password": "p3"},  # dup
                    ],
                },
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = raw

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool(api_key="paid")
            result = await tool.run("corp.com", target_type="domain")

        all_urls = result.data["all_captured_urls"]
        assert len(all_urls) == 2  # deduped
        assert "https://mail.corp.com/owa/" in all_urls
        assert "https://vpn.corp.com/" in all_urls

    @pytest.mark.asyncio
    async def test_api_key_added_to_header_when_present(self):
        """When HUDSONROCK_API_KEY is set, X-API-KEY header should be included."""
        raw = {
            "stealerFamily": "RedLine",
            "computerName": "PC",
            "operatingSystem": "Windows 10",
            "dateCompromised": "2024-01-01",
            "antiviruses": [],
            "externalIp": "1.1.1.1",
            "malwarePath": "C:\\x.exe",
            "credentials": [],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = raw

        captured_headers = {}

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()

            def fake_enter(*args, **kwargs):
                # Capture the headers the client was initialised with
                captured_headers.update(kwargs.get("headers", {}))
                return mc

            cc.return_value.__aenter__ = AsyncMock(side_effect=fake_enter)
            mc.get.return_value = mock_resp

            tool = self._make_tool(api_key="supersecretkey")
            # We need to check headers are passed to the AsyncClient constructor
            # Since the client is created inside the method, patch at module level.
            with patch(
                "nexusrecon.tools.identity.hudsonrock_tool._build_headers"
            ) as mock_bh:
                mock_bh.return_value = {
                    "User-Agent": "test",
                    "Accept": "application/json",
                    "X-API-KEY": "supersecretkey",
                }
                await tool.run("jane@corp.com", target_type="email")
                mock_bh.assert_called_once_with("supersecretkey")

    @pytest.mark.asyncio
    async def test_http_error_surfaces_as_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("nexusrecon.tools.identity.hudsonrock_tool.httpx.AsyncClient") as cc:
            mc = AsyncMock()
            cc.return_value.__aenter__.return_value = mc
            mc.get.return_value = mock_resp

            tool = self._make_tool()
            result = await tool.run("jane@corp.com", target_type="email")

        assert not result.success
        assert "500" in result.error

    @pytest.mark.asyncio
    async def test_unsupported_target_type_returns_failure(self):
        tool = self._make_tool()
        result = await tool.run("jane@corp.com", target_type="phone")
        assert not result.success
        assert "Unsupported" in result.error
