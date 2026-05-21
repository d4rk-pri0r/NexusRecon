"""Auto-skip live tests when their required API keys aren't set.

Each test in ``tests/live/`` is tagged with one or more
``@pytest.mark.live("<provider>")`` markers, where ``<provider>`` is
a short string that maps via :data:`LIVE_KEY_REQUIREMENTS` to the env
vars required to make a real API call. If any required env var is
missing, the test is skipped — so a developer with only a Shodan key
will see the Shodan tests run and everything else skip, with no
explicit configuration on their part.

The skip happens at collection time so the pytest output shows them
as ``SKIPPED`` rather than running and erroring on the missing key.

Adding a new live test: pick (or add) an entry in
:data:`LIVE_KEY_REQUIREMENTS`, then decorate the test:

    @pytest.mark.live("shodan")
    async def test_shodan_host_lookup_live() -> None:
        ...

For tools that don't need a key (crt.sh, OSV, KEV feed) use
``@pytest.mark.live("none")`` — those tests always run when the
``tests/live/`` directory is targeted.
"""
from __future__ import annotations

import os

import pytest

# Map from ``live("<provider>")`` marker arg to the env vars that must
# be present for the test to make a real API call. The same provider
# may appear in many tests; the lookup happens once per test in
# ``pytest_collection_modifyitems``.
LIVE_KEY_REQUIREMENTS: dict[str, list[str]] = {
    # No-key providers — live tests always allowed.
    "none": [],
    # Subdomain enumeration
    "chaos": ["CHAOS_API_KEY"],
    "github": ["GITHUB_TOKEN"],
    # DNS / passive DNS
    "securitytrails": ["SECURITYTRAILS_API_KEY"],
    # Cloud probes — no key required (Azure/M365/AWS public endpoints)
    # Code & repos
    "github_repo": ["GITHUB_TOKEN"],
    # Email & identity
    "hunter": ["HUNTER_API_KEY"],
    "intelx": ["INTELX_API_KEY"],
    # Infrastructure intel
    "shodan": ["SHODAN_API_KEY"],
    "censys": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    "virustotal": ["VIRUSTOTAL_API_KEY"],
    "greynoise": ["GREYNOISE_API_KEY"],
    "binaryedge": ["BINARYEDGE_API_KEY"],
    "netlas": ["NETLAS_API_KEY"],
    "fullhunt": ["FULLHUNT_API_KEY"],
    "zoomeye": ["ZOOMEYE_API_KEY"],
    "abuseipdb": ["ABUSEIPDB_API_KEY"],
    # Breach
    "hibp": ["HAVEIBEENPWNED_API_KEY"],
    "leakcheck": ["LEAKCHECK_API_KEY"],
    # Vuln intel
    "vulners": ["VULNERS_API_KEY"],
    # Pretext
    "crunchbase": ["CRUNCHBASE_API_KEY"],
    # Phase E
    "builtwith": ["BUILTWITH_API_KEY"],
    # LinkedIn — cookie auth (preferred). The tool also accepts
    # LINKEDIN_USERNAME + LINKEDIN_PASSWORD as a fallback but the
    # live test only exercises the cookie path because cookies are
    # the recommended red-team posture and skip-when-missing is
    # cleaner than testing OR-semantics in conftest.
    "linkedin_cookies": ["LINKEDIN_LI_AT", "LINKEDIN_JSESSIONID"],
}


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``live`` marker so pytest doesn't warn about it."""
    config.addinivalue_line(
        "markers",
        "live(provider): test that calls a real external API. Skipped "
        "unless the env vars for <provider> (see LIVE_KEY_REQUIREMENTS "
        "in tests/live/conftest.py) are set.",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-skip live tests whose required env vars are missing."""
    for item in items:
        # Only the live tests have this marker; everyone else is untouched.
        marker = item.get_closest_marker("live")
        if marker is None:
            continue
        if not marker.args:
            # Marker with no provider arg: skip unconditionally to be safe.
            item.add_marker(
                pytest.mark.skip(reason="@live marker missing provider arg")
            )
            continue
        provider = marker.args[0]
        required = LIVE_KEY_REQUIREMENTS.get(provider, [])
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            item.add_marker(
                pytest.mark.skip(
                    reason=(
                        f"live test for '{provider}' needs env: "
                        f"{', '.join(missing)}"
                    )
                )
            )
