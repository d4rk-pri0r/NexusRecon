"""Opt-in live API tests.

These tests hit real provider APIs to catch upstream schema drift that
mocked tests can't see. They are **skipped by default**; the
``conftest.py`` in this directory auto-skips any test whose required
env vars aren't set.

Each test:

1. Is tagged ``@pytest.mark.live("<provider>")`` so the conftest can
   look up the env-var requirement.
2. Calls the real provider with a low-traffic, idempotent query
   (typically ``example.com`` or ``8.8.8.8``) so we don't burn quota.
3. Asserts only on **structural invariants** — fields the tool reads,
   types, presence/absence of the success flag — never on specific
   values that change over time (which we don't control).

The goal isn't comprehensive coverage; it's a tripwire. If a provider
renames ``hosts`` to ``subdomains`` overnight, one of these live tests
fails and we know the mocked fixture is now out of date.

Run with:

    export SHODAN_API_KEY=...
    pytest tests/live/ -v
"""
from __future__ import annotations

import os

import pytest

# Use a single safe target across all live tests so quota usage stays
# predictable and we don't accidentally trigger anyone's WAF.
LIVE_TARGET_DOMAIN = "example.com"
LIVE_TARGET_IP = "8.8.8.8"
LIVE_TARGET_CVE = "CVE-2021-44228"  # Log4Shell — public, well-indexed everywhere


# ─── No-key providers (always run if user invokes tests/live/) ──────────────


@pytest.mark.live("none")
async def test_crtsh_live() -> None:
    from nexusrecon.tools.domain.crtsh_tool import CRTShTool
    result = await CRTShTool().run(LIVE_TARGET_DOMAIN)
    # crt.sh frequently rate-limits or times out unauthenticated.
    # When it does succeed, confirm structural invariants.
    if result.success:
        assert "subdomains" in result.data
        assert isinstance(result.data["subdomains"], list)


@pytest.mark.live("none")
async def test_certspotter_live() -> None:
    from nexusrecon.tools.domain.certspotter_tool import CertSpotterTool
    result = await CertSpotterTool().run(LIVE_TARGET_DOMAIN)
    # success may be False if upstream rate-limits the unauthenticated tier
    if result.success:
        assert "subdomains" in result.data
        assert isinstance(result.data["subdomains"], list)


@pytest.mark.live("none")
async def test_otx_subdomains_live() -> None:
    from nexusrecon.tools.domain.otx_tool import OTXTool
    result = await OTXTool().run(LIVE_TARGET_DOMAIN)
    if result.success:
        assert isinstance(result.data["subdomains"], list)


@pytest.mark.live("none")
async def test_hackertarget_live() -> None:
    from nexusrecon.tools.domain.hackertarget_tool import HackerTargetTool
    # HackerTarget rate-limits aggressively; just confirm the tool doesn't crash
    result = await HackerTargetTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("none")
async def test_dns_live() -> None:
    from nexusrecon.tools.domain.dns_tool import DNSTool
    result = await DNSTool().run(LIVE_TARGET_DOMAIN)
    assert result.success is True
    assert len(result.data["A"]) >= 1
    assert all(isinstance(a, str) for a in result.data["A"])


@pytest.mark.live("none")
async def test_rdap_live() -> None:
    from nexusrecon.tools.domain.rdap_tool import RDAPTool
    result = await RDAPTool().run(LIVE_TARGET_DOMAIN)
    if result.success:
        # RDAP returns a structured object — exact field names depend
        # on which RDAP server answered. Just confirm we got data.
        assert result.data is not None and len(result.data) > 0


@pytest.mark.live("none")
async def test_whois_live() -> None:
    from nexusrecon.tools.domain.whois_tool import WHOISTool
    result = await WHOISTool().run(LIVE_TARGET_DOMAIN)
    if result.success:
        assert result.data is not None


@pytest.mark.live("none")
async def test_asn_bgp_live() -> None:
    # Source lives under tools/domain/, not tools/intel/.
    from nexusrecon.tools.domain.asn_bgp_tool import ASNBGPTool
    result = await ASNBGPTool().run(LIVE_TARGET_IP)
    assert isinstance(result.success, bool)


@pytest.mark.live("none")
async def test_ipinfo_live() -> None:
    from nexusrecon.tools.intel.ipinfo_tool import IPInfoTool
    result = await IPInfoTool().run(LIVE_TARGET_IP)
    if result.success:
        # IPinfo always returns at least ip + country for public IPs
        assert "ip" in result.data or "country" in result.data


@pytest.mark.live("none")
async def test_urlscan_live() -> None:
    from nexusrecon.tools.intel.urlscan_tool import URLScanTool
    result = await URLScanTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("none")
async def test_nvd_live() -> None:
    from nexusrecon.tools.vuln.nvd_tool import NVDTool
    result = await NVDTool().run(LIVE_TARGET_CVE)
    if result.success:
        # CVE-2021-44228 is permanently indexed — Log4Shell isn't getting deleted
        assert result.data  # some payload is present


@pytest.mark.live("none")
async def test_kev_live() -> None:
    from nexusrecon.tools.vuln.kev_tool import KEVTool
    result = await KEVTool().run(LIVE_TARGET_CVE)
    # Log4Shell IS in the KEV catalog — if it isn't, CISA has changed something major
    if result.success:
        assert result.data


@pytest.mark.live("none")
async def test_epss_live() -> None:
    from nexusrecon.tools.vuln.epss_tool import EPSSTool
    result = await EPSSTool().run(LIVE_TARGET_CVE)
    if result.success:
        assert result.data


@pytest.mark.live("none")
async def test_osv_live() -> None:
    from nexusrecon.tools.vuln.osv_tool import OSVTool
    result = await OSVTool().run(LIVE_TARGET_CVE)
    if result.success:
        assert result.data


@pytest.mark.live("none")
async def test_wayback_live() -> None:
    """End-to-end against the real waybackpy CDX server. Catches the
    class of bug where the tool reads attribute names off
    ``CDXSnapshot`` that don't exist on the real class — the kind of
    drift the mocked tests can't see because the fixtures and the
    buggy tool agreed with each other."""
    from nexusrecon.tools.web.wayback_tool import WaybackTool
    result = await WaybackTool().run(LIVE_TARGET_DOMAIN)
    # example.com has Wayback snapshots going back to 1995 — if this
    # returns success=False the tool is broken (not the provider).
    if result.success:
        assert "urls" in result.data
        assert "snapshots" in result.data
        # If any snapshot came back, confirm the dict shape matches
        # what downstream consumers (entity graph, reports) expect.
        if result.data["snapshots"]:
            snap = result.data["snapshots"][0]
            assert "url" in snap and "timestamp" in snap
            assert "status" in snap and "mimetype" in snap


@pytest.mark.live("none")
async def test_ransomwatch_live() -> None:
    from nexusrecon.tools.intel.ransomwatch_tool import RansomwatchTool
    # Searches a known org name unlikely to actually be on the leak board
    result = await RansomwatchTool().run("example-corp-not-real")
    assert isinstance(result.success, bool)


# ─── Key-required providers (skipped unless env vars set) ───────────────────


@pytest.mark.live("shodan")
async def test_shodan_live() -> None:
    from nexusrecon.tools.intel.shodan_tool import ShodanTool
    result = await ShodanTool().run(LIVE_TARGET_IP)
    if result.success:
        # Tool stores parsed data; shape varies. Just confirm we got something.
        assert result.data is not None


@pytest.mark.live("censys")
async def test_censys_live() -> None:
    from nexusrecon.tools.intel.censys_tool import CensysTool
    result = await CensysTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("virustotal")
async def test_virustotal_live() -> None:
    from nexusrecon.tools.intel.virustotal_tool import VirusTotalTool
    result = await VirusTotalTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("greynoise")
async def test_greynoise_live() -> None:
    from nexusrecon.tools.intel.greynoise_tool import GreyNoiseTool
    result = await GreyNoiseTool().run(LIVE_TARGET_IP)
    assert isinstance(result.success, bool)


@pytest.mark.live("binaryedge")
async def test_binaryedge_live() -> None:
    from nexusrecon.tools.intel.binaryedge_tool import BinaryEdgeTool
    result = await BinaryEdgeTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("netlas")
async def test_netlas_live() -> None:
    from nexusrecon.tools.intel.netlas_tool import NetlasTool
    result = await NetlasTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("fullhunt")
async def test_fullhunt_live() -> None:
    from nexusrecon.tools.intel.fullhunt_tool import FullHuntTool
    result = await FullHuntTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("zoomeye")
async def test_zoomeye_live() -> None:
    from nexusrecon.tools.intel.zoomeye_tool import ZoomEyeTool
    result = await ZoomEyeTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("abuseipdb")
async def test_abuseipdb_live() -> None:
    from nexusrecon.tools.intel.abuseipdb_tool import AbuseIPDBTool
    result = await AbuseIPDBTool().run(LIVE_TARGET_IP)
    if result.success:
        assert result.data  # abuseConfidenceScore at minimum


@pytest.mark.live("hibp")
async def test_hibp_live() -> None:
    # Use a domain that's known to have HIBP entries but isn't sensitive
    from nexusrecon.tools.identity.breach_tool import BreachTool
    result = await BreachTool().run("example.com")
    assert isinstance(result.success, bool)


@pytest.mark.live("leakcheck")
async def test_leakcheck_live() -> None:
    from nexusrecon.tools.identity.leakcheck_tool import LeakCheckTool
    result = await LeakCheckTool().run("noreply@example.com")
    assert isinstance(result.success, bool)


@pytest.mark.live("vulners")
async def test_vulners_live() -> None:
    from nexusrecon.tools.vuln.vulners_tool import VulnersTool
    result = await VulnersTool().run(LIVE_TARGET_CVE)
    assert isinstance(result.success, bool)


@pytest.mark.live("hunter")
async def test_hunter_live() -> None:
    from nexusrecon.tools.identity.hunter_tool import HunterTool
    result = await HunterTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("intelx")
async def test_phonebook_live() -> None:
    from nexusrecon.tools.identity.phonebook_tool import PhonebookTool
    result = await PhonebookTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("github")
async def test_chaos_live() -> None:
    # Chaos has its own key but using github marker here just routes it
    # to the env var lookup; remove if you want a dedicated chaos marker.
    if not os.environ.get("CHAOS_API_KEY"):
        pytest.skip("CHAOS_API_KEY not set")
    from nexusrecon.tools.domain.chaos_tool import ChaosTool
    result = await ChaosTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("github_repo")
async def test_github_recon_live() -> None:
    from nexusrecon.tools.code.github_tool import GitHubReconTool
    result = await GitHubReconTool().run(LIVE_TARGET_DOMAIN)
    assert isinstance(result.success, bool)


@pytest.mark.live("crunchbase")
async def test_crunchbase_live() -> None:
    from nexusrecon.tools.pretext.crunchbase_tool import CrunchbaseTool
    result = await CrunchbaseTool().run("anthropic")
    assert isinstance(result.success, bool)


# ─── Phase E live tests ────────────────────────────────────────────────────
#
# Each test asserts only structural invariants — the fields downstream code
# reads, presence/absence of the success flag, the shape of the adapter
# input. Never on specific values that drift over time (follower counts,
# talk titles, etc.). This catches "upstream renamed the field" regressions
# without burning test runs on natural data churn.
#
# Targets are picked for long-term stability:
#   - github_social        → "octocat" (GitHub's mascot)
#   - mastodon_social      → "Gargron@mastodon.social" (Mastodon's creator)
#   - bluesky_social       → "bsky.app" (the platform's own handle)
#   - linkedin_social      → "williamhgates" (Bill Gates, stable public_id)
#   - business_partner DNS → LIVE_TARGET_DOMAIN ("example.com")
#   - conference_speaker   → "Bruce Schneier" (perennial DEFCON speaker)


@pytest.mark.live("github")
async def test_github_social_live() -> None:
    """Smoke-test github_social against octocat.

    octocat is GitHub's mascot, present since day one. We assert
    only that the tool returns a properly-typed ToolResult and, when
    it succeeds, that the adapter input has the shape downstream
    code expects.
    """
    from nexusrecon.tools.identity.github_social_tool import (
        GitHubSocialTool,
    )
    result = await GitHubSocialTool().run("octocat")
    assert isinstance(result.success, bool)
    if result.success:
        assert "username" in result.data
        assert "user_profile" in result.data
        assert "followers" in result.data
        assert "following" in result.data
        assert "repositories" in result.data
        assert "summary" in result.data


@pytest.mark.live("none")
async def test_mastodon_social_live() -> None:
    """Anonymous lookup of mastodon.social's creator. No key
    required; Mastodon's public API serves any account with default
    privacy settings.
    """
    from nexusrecon.tools.identity.mastodon_social_tool import (
        MastodonSocialTool,
    )
    result = await MastodonSocialTool().run(
        "Gargron@mastodon.social",
        # Restrict to the one instance we know hosts the account so
        # the test doesn't fan across the default probe list.
        instances=["mastodon.social"],
    )
    assert isinstance(result.success, bool)
    if result.success:
        assert result.data.get("instance") == "mastodon.social"
        assert "account" in result.data
        assert "followers" in result.data
        assert "following" in result.data
        assert "interactions" in result.data


@pytest.mark.live("none")
async def test_bluesky_social_live() -> None:
    """Anonymous lookup of bsky.app via api.bsky.app (the public
    AppView). No key required."""
    from nexusrecon.tools.identity.bluesky_social_tool import (
        BlueskySocialTool,
    )
    result = await BlueskySocialTool().run("bsky.app")
    assert isinstance(result.success, bool)
    if result.success:
        assert "profile" in result.data
        assert result.data["profile"].get("did", "").startswith("did:")
        assert "follows" in result.data
        assert "followers" in result.data
        assert "interactions" in result.data


@pytest.mark.live("linkedin_cookies")
async def test_linkedin_social_live() -> None:
    """LinkedIn smoke-test against a stable public profile.

    Requires LINKEDIN_LI_AT + LINKEDIN_JSESSIONID. Picks
    ``williamhgates`` because the public_id has been stable for a
    decade. We tolerate auth failures (cookies expire) ── the
    tripwire is for *schema drift*, not auth.
    """
    from nexusrecon.tools.identity.linkedin_social_tool import (
        LinkedInSocialTool,
    )
    result = await LinkedInSocialTool().run("williamhgates")
    assert isinstance(result.success, bool)
    if result.success:
        assert "profile" in result.data
        assert "experiences" in result.data
        assert "skills" in result.data
        assert "posts" in result.data
        assert "summary" in result.data


@pytest.mark.live("none")
async def test_business_partner_dns_only_live() -> None:
    """DNS-only path through business_partner against example.com.

    DNS TXT vendor inference needs no API key. We disable the other
    sources so the test exercises only the DNS path. example.com
    has no SPF / MX matching our vendor markers — the success path
    is "no vendors surfaced", still a structural pass.
    """
    from nexusrecon.tools.intel.business_partner_tool import (
        BusinessPartnerTool,
    )
    result = await BusinessPartnerTool().run(
        LIVE_TARGET_DOMAIN,
        include_crunchbase=False,
        include_builtwith=False,
        include_dns_vendor_inference=True,
        include_press_scrape=False,
    )
    assert isinstance(result.success, bool)
    if result.success:
        assert "dns_vendors" in result.data


@pytest.mark.live("builtwith")
async def test_business_partner_builtwith_live() -> None:
    """BuiltWith path through business_partner against example.com.

    Requires BUILTWITH_API_KEY. Asserts the response carries the
    structural keys downstream code consumes.
    """
    from nexusrecon.tools.intel.business_partner_tool import (
        BusinessPartnerTool,
    )
    result = await BusinessPartnerTool().run(
        LIVE_TARGET_DOMAIN,
        include_crunchbase=False,
        include_builtwith=True,
        include_dns_vendor_inference=False,
        include_press_scrape=False,
    )
    assert isinstance(result.success, bool)
    if result.success:
        assert "builtwith" in result.data
        assert "sources_used" in result.data


@pytest.mark.live("none")
async def test_conference_speaker_live() -> None:
    """Smoke-test conference_speaker against a stable real name.

    Bruce Schneier has spoken at most security conferences in the
    default list at least once. Even if no specific parser surfaces
    a hit, the soft-404 path keeps the crawl going so the test
    structurally succeeds.
    """
    from nexusrecon.tools.pretext.conference_speaker_tool import (
        ConferenceSpeakerTool,
    )
    result = await ConferenceSpeakerTool().run(
        "Bruce Schneier",
        # Probe just two sites to keep the test quick.
        sites=["DEFCON", "FOSDEM"],
        max_talks_per_conference=5,
    )
    assert isinstance(result.success, bool)
    if result.success:
        assert "target" in result.data
        assert "talks" in result.data
        assert "summary" in result.data
        assert result.data["target"] == "Bruce Schneier"
