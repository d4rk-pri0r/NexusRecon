"""Opt-in tests that hit real provider APIs.

These tests are **skipped by default**. They only run when the
corresponding API keys are present in the environment, and they exist
to catch upstream schema drift that the mocked tests cannot —
e.g. Shodan adding a field to ``/shodan/host/{ip}``, or HIBP changing
the date format on breach records.

Usage:

    export SHODAN_API_KEY=...
    export GITHUB_TOKEN=...
    pytest tests/live/                           # runs whatever keys are present
    pytest tests/live/ -k shodan                 # narrow to one provider
    pytest tests/live/ -m live                   # explicit marker filter

Tests are tagged with ``@pytest.mark.live("<provider>")`` where
``<provider>`` maps to the env-var requirement in ``conftest.py``.
"""
