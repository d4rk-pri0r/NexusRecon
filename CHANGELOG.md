# Changelog

All notable changes to NexusRecon land here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [SemVer](https://semver.org/) with the pre-1.0 caveat that
minor bumps (0.x → 0.x+1) may break APIs.

## [Unreleased]

### Added

- Apache 2.0 LICENSE + NOTICE (replaces the earlier proprietary
  declaration in `pyproject.toml`).
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `ROADMAP.md`.
- `.github/ISSUE_TEMPLATE/` (bug + feature templates) and
  `.github/workflows/test.yml` running `pytest tests/unit
  tests/integration tests/smoke` on every PR.
- Centralised User-Agent pool at `nexusrecon/opsec/useragent.py`
  with a `random_ua()` helper. 47 tools now rotate UAs from the
  ~30-entry pool instead of all hardcoding the same Firefox-128
  string, closes the "everyone running NexusRecon has an identical
  TLS+UA fingerprint" issue.

### Fixed

- `github_recon` and `gitdorker`: replaced blocking `time.sleep(1.1)`
  with `await asyncio.sleep(1.1)` so dork-loop pauses don't block
  the event loop for tools running in parallel.

### Changed

- `examples/sample_run/README.md`: flagged as a walkthrough only;
  the actual checked-in real-target report run is the v0.6.0
  milestone (see `ROADMAP.md`).

## [0.5.0], 2026-05-18, pre-beta

The first version that has integration-test coverage across the full
tool registry and a documented bug-fix audit trail. Everything below
this line landed during the pre-beta hardening sprint.

### Added

- **351 integration tests** across 13 category files, one TestClass
  per tool, four-test pattern (happy / empty / error / malformed) per
  tool.
- **32 opt-in live tests** in `tests/live/test_live_apis.py` for
  upstream-drift detection. Auto-skipped unless API keys present.
- **`tests/fixtures/`** directory, 120 JSON / HTML / XML / text
  fixtures built from each provider's public API documentation.
- **`TESTING_PLAN.md`**: methodology doc covering the five mocking
  strategies (HTTP / binary / DNS / pure-logic / stub).
- Custom **`ChunkyBar`** progress widget in the TUI runner screen.
- **Live structlog stream panel** in the TUI runner screen, operators
  can watch the framework's internal logs in real time during a
  campaign.
- **1 Hz live-stats refresh** on the runner screen, elapsed time,
  LLM cost, and counter fields tick smoothly between phase
  boundaries.
- **`@work` worker reference tracking** so the Abort key actually
  cancels the running campaign and saves partial state for resume.
- **Two-press Abort confirmation** to prevent stray keypress kills.

### Fixed

Eighteen tool bugs surfaced and pinned during the test-writing pass.

- `email_format`: regex anchor mismatch made every input resolve to
  `"unknown"`.
- `wayback`: read `.url` / `.status` attributes that don't exist on
  `waybackpy.CDXSnapshot` (real names: `.original` / `.statuscode`).
- `dnstwist`: called non-existent `FuzzDomain` class, actual class
  is `Fuzzer`. Tool was 100% non-functional.
- `pastebin_scan`: didn't base64-decode GitHub Contents API
  responses, so credential regex never matched real leaks.
- `greynoise`, `shodan`, `censys`, `virustotal`, `hunter`,
  `passive_dns`: all silently swallowed 401/429/5xx as empty success
  responses. Operators couldn't tell "no data" from "bad key /
  quota exhausted / provider outage".
- `fullhunt`: read `metadata.all_results` when the documented field
  is `all_results_count`.
- `github_recon`: didn't enforce `GITHUB_TOKEN`, sent requests with
  an empty `Authorization` header which capped the rate at 60 req/hr.
- `cdn_detect`: swallowed DNS + HTTP failures entirely; returned
  `success=True` with no diagnostic when probes failed.
- `aws_recon`: used `S3_REGIONS[:10]` for Lambda URL probes,
  silently excluding three valid EU regions.
- `gcp_recon`: App Engine probe treated `status != 404` as "found",
  so 500-class errors were reported as discovered apps.
- `azure_m365_recon`: inconsistent federation-detection field reads
  vs. its sibling `azure_tenant_enum`.
- `whois`: reported `result_count=1` for fully-empty responses,
  inflating campaign aggregate metrics.
- `hudsonrock`: 5xx errors stashed in `data["error"]` while
  `success` stayed `True`, hiding provider outages.

### Changed

- TUI runner screen redesigned with bordered phase header, live
  stats panel, activity log, and toggleable structlog stream.
- Wizard's stealth-profile dropdown corrected to the four
  model-validated values (`paranoid / high / normal / loud`), the
  previous `low / medium / high` choices were rejected by
  `ScopeModel` validation, silently breaking campaign launch.
- README rewritten as a fresh-visitor front door; agentic value
  proposition leads, worked example follows.
- Version honesty: codebase, package metadata, banners, and docs now
  consistently reflect `0.5.0` pre-beta.

### Removed

- The non-functional TUI "Pause" binding (the campaign runner has no
  cooperative checkpointing to pause at).

---

## Earlier history

Pre-`0.5.0` activity tracked only in `git log`. The project went
through a "V2 Gold Standard" and "V3 UX Polish" iteration during
internal development before adopting semver with the `0.5.0`
pre-beta release.
