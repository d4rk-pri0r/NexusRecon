# NexusRecon: Tool Testing Plan

_Working document. Step 1: classify every registered tool by how we can
test it without paid API keys. Step 2 (post-review): execute._

The current registry has **89 tools** at the moment this document was
written (`source venv/bin/activate && nexusrecon tools | wc -l` is the
authoritative live count). Tools come and go between releases, the
plan is structured around _classes_ of tools, not specific counts, so
adding or removing a tool only requires touching one row of the table
below.

---

## Methodology

Every tool falls into one of five mocking-strategy buckets. The bucket
determines the test pattern; the table at the bottom places every tool
in exactly one bucket.

### Bucket A: HTTP-only tool (mock with `respx`)

Tool wraps a public or commercial REST API. We already have `respx`
wired up at `tests/integration/test_tools_http.py` (585 lines, 9
tools covered: `crtsh`, `webtech`, `favicon`, `dorks`, `metadata`,
`breach`, `news`, `jobs`, `sec_edgar`). Same pattern for the rest:

```python
import respx
from httpx import Response

with respx.mock:
    respx.get(url__startswith=...).mock(return_value=Response(200, json=...))
    result = await tool.run(target)
    assert result.success
```

The "sample output" we feed `Response(json=...)` is **the JSON shape
published in the provider's API docs**. For paid APIs we never call
the live endpoint, `respx` intercepts before the request leaves the
process.

### Bucket B: Binary-wrapping tool (mock `subprocess`)

Tool invokes a CLI binary (`subfinder`, `httpx`, `nuclei`, …) via the
`OSINTTool.run_subprocess` helper. We stub that one helper and feed
back a canned stdout string. The binary's actual stdout is documented
in each project's README; for the JSON-output binaries (subfinder
`-json`, httpx `-json`, nuclei `-json`) the schema is stable.

```python
from unittest.mock import patch

with patch.object(tool, "run_subprocess") as run:
    run.return_value.stdout = '{"host":"www.acme.com","port":443}\n...'
    run.return_value.returncode = 0
    result = await tool.run("acme.com")
```

### Bucket C: DNS-based tool (mock `dnspython`)

Tool resolves DNS records directly via `dns.resolver` /
`dns.asyncresolver`. Mock the resolver itself so tests don't hit live
DNS:

```python
with patch("dns.asyncresolver.Resolver.resolve") as resolve:
    resolve.return_value = [MockAnswer("198.51.100.5")]
    result = await tool.run("acme.com")
```

### Bucket D: Pure-logic tool (no external calls)

Tool transforms input data with no network/binary dependency. Just
feed input, assert output. No mocking required.

### Bucket E: Stub (assert canned response)

Tool is marked `(stubbed)` in its `description`. The implementation
returns a canned `ToolResult` whose contents are part of the contract.
We assert that contract holds, without touching anything external.

---

## Master index

Columns:

- **Tool**: `name` attribute as registered.
- **Cat**: category (subdomain/cert/dns/cloud/code/identity/intel/…).
- **Tier**: T0 passive, T1 semi-passive, T2 light active, T3 active.
- **Key**: env var(s) needed for live use. `, ` = none. Tests never
  hit the live endpoint regardless of key status.
- **Bucket**: A=HTTP, B=Binary, C=DNS, D=Pure logic, E=Stub.
- **Sample source**: where the canonical response shape comes from.
- **Status**: ✅ already covered by `test_tools_http.py`, 📘 public
  doc with sample JSON readily available, 📦 binary stdout schema
  published in upstream repo, 🛠 stubbed tool (contract test only),
  🔬 needs a brief verification pass before mocking.

### Subdomain enumeration

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `crtsh` | T0 | | A | `tests/integration/test_tools_http.py::TestCRTShTool` (already mocked) | ✅ |
| `certspotter` | T0 | | A | https://sslmate.com/help/reference/api/certificate_search | 📘 |
| `certstream_recent` | T0 | | A | crt.sh JSON (same as `crtsh`); 7-day filter applied client-side | ✅ |
| `subfinder` | T0 | | B | https://github.com/projectdiscovery/subfinder `-json` output schema | 📦 |
| `amass` | T0 | | B | https://github.com/owasp-amass/amass `-json` output | 📦 |
| `chaos` | T0 | `chaos_api_key` | A | https://chaos.projectdiscovery.io/#/docs | 📘 |
| `otx_subdomains` | T0 | optional | A | https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns | 📘 |
| `github_subdomains` | T0 | `github_token` | A | https://docs.github.com/en/rest/search (code search) | 📘 |

### Certificates & DNS

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `dns` | T1 | | C | dnspython `Answer` mocks; record types A/AAAA/MX/TXT/NS/SOA/CAA/SRV/CNAME | 📘 |
| `dnsx` | T1 | | B | https://github.com/projectdiscovery/dnsx `-json` output | 📦 |
| `passive_dns` | T0 | `securitytrails_api_key` | A | https://docs.securitytrails.com/reference/history-dns | 📘 |
| `hackertarget` | T0 | | A | https://hackertarget.com/ip-tools/ (line-based, `host,ip\n`) | 📘 |

### Domain intelligence

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `whois` | T0 | | A+C | python-whois library output; also queries RDAP fallback | 📘 |
| `rdap` | T0 | | A | RFC 7483 + https://rdap.org/ + https://www.rdap.org/protocol | 📘 |
| `dnstwist` | T0 | | D | dnstwist Python pkg, deterministic generator, no network in tests | 📘 |
| `cdn_detect` | T0 | | A | Custom, IP ranges + CNAME + headers. Sample: Cloudflare CF-Ray, Fastly Fastly-Restart | 📘 |

### Cloud (AWS / Azure / GCP)

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `aws_recon` | T0 | | A | S3 bucket probe responses (200/403/404), https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGET.html | 📘 |
| `bucket_enum` | T2 | | A | Same S3 sample + GCS error JSON + Azure Blob 404 page | 📘 |
| `azure_m365_recon` | T0 | | A | `login.microsoftonline.com/getuserrealm.srf?login={x}&xml=1` returns XML; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-azods/ | 📘 |
| `azure_tenant_enum` | T0 | | A | `/{tenant}/.well-known/openid-configuration` JSON, public Microsoft endpoint | 📘 |
| `gcp_recon` | T0 | | A+E | GCS list-objects XML; Firebase/Cloud Run are partial stubs | 🛠+📘 |

### Code & repos

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `github_recon` | T0 | `github_token` | A | https://docs.github.com/en/rest (REST + search) | 📘 |
| `github_actions_leaks` | T0 | `github_token` | A | GitHub REST (Actions workflows endpoint) | 📘 |
| `github_org_members` | T0 | `github_token` | A | https://docs.github.com/en/rest/orgs/members | 📘 |
| `dockerhub` | T0 | | A | https://docs.docker.com/docker-hub/api/latest/ | 📘 |
| `postman` | T0 | | A | https://www.postman.com/api/ (public workspaces) | 🔬 |

### Secrets

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `gitleaks` | T0 | | B | https://github.com/gitleaks/gitleaks `--report-format=json` output | 📦 |
| `trufflehog` | T0 | | B | https://github.com/trufflesecurity/trufflehog v3 `--json` output | 📦 |
| `gitdorker` | T0 | `github_token` | A | Github search REST (same as `github_recon`) | 📘 |

### Email & identity

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `theharvester` | T0 | | B | https://github.com/laramies/theHarvester `-f` JSON report | 📦 |
| `hunter` | T0 | `hunter_api_key` | A | https://hunter.io/api-documentation/v2 | 📘 |
| `email_format` | T0 | | D | Pure inference from email samples; no external calls | 📘 |
| `email_sec` | T0 | | C | DNS TXT for SPF/DMARC; well-known record formats | 📘 |
| `phonebook` | T0 | `intelx_api_key` | A | https://intelx.io/help?topic=api | 📘 |
| `holehe` | T0 | | A | https://github.com/megadose/holehe, ~120 service URL patterns | 📘 |
| `maigret` | T0 | | B+E | Stubbed if binary missing; https://github.com/soxoj/maigret `--json` schema | 📦/🛠 |

### Infrastructure intel

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `shodan` | T0 | `shodan_api_key` | A | https://developer.shodan.io/api | 📘 |
| `censys` | T0 | `censys_api_id`, `censys_api_secret` | A | https://search.censys.io/api | 📘 |
| `virustotal` | T0 | `virustotal_api_key` | A | https://docs.virustotal.com/reference | 📘 |
| `greynoise` | T0 | `greynoise_api_key` | A | https://docs.greynoise.io/reference | 📘 |
| `binaryedge` | T0 | `binaryedge_api_key` | A | https://docs.binaryedge.io | 📘 |
| `netlas` | T0 | `netlas_api_key` | A | https://docs.netlas.io | 📘 |
| `fullhunt` | T0 | `fullhunt_api_key` | A | https://api-docs.fullhunt.io | 🔬 |
| `zoomeye` | T0 | `zoomeye_api_key` | A | https://www.zoomeye.org/doc | 📘 |
| `abuseipdb` | T0 | `abuseipdb_api_key` | A | https://docs.abuseipdb.com | 📘 |
| `ipinfo` | T0 | | A | https://ipinfo.io/developers | 📘 |
| `urlscan` | T0 | | A | https://urlscan.io/docs/api/ | 📘 |
| `leakix` | T0 | | A | https://leakix.net/api-documentation | 📘 |
| `asn_bgp` | T0 | | A | https://bgpview.docs.apiary.io | 📘 |
| `ahmia` | T0 | | A | HTML scrape; small fixture from public results page | 📘 |
| `ransomwatch` | T0 | | A | https://github.com/joshhighet/ransomwatch `posts.json` (raw GitHub URL is public) | 📘 |
| `pastebin_scan` | T0 | | A | https://psbdmp.ws/api + GitHub Gists REST | 🔬 |

### Breach intel

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `breach_lookup` | T0 | `haveibeenpwned_api_key` | A | `tests/integration/test_tools_http.py::TestBreachTool` (already mocked) | ✅ |
| `emailrep` | T0 | | A | https://emailrep.io/about/api | 📘 |
| `hudsonrock` | T0 | | A | https://cavalier.hudsonrock.com/api docs page | 🔬 |
| `leakcheck` | T0 | `leakcheck_api_key` | A | https://leakcheck.io/api_v2 | 📘 |

### Vulnerability intel

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `nvd` | T0 | | A | https://nvd.nist.gov/developers/vulnerabilities | 📘 |
| `kev` | T0 | | A | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 📘 |
| `epss` | T0 | | A | https://www.first.org/epss/api | 📘 |
| `osv` | T0 | | A | https://google.github.io/osv.dev/api/ | 📘 |
| `exploitdb` | T0 | | A | Offline DB clone + https://docs.github.com/en/rest (PoC search) | 📘 |
| `github_advisory` | T0 | | A | https://docs.github.com/en/graphql/reference/objects#securityadvisory | 📘 |
| `nuclei_template` | T0 | | A | https://github.com/projectdiscovery/nuclei-templates raw paths | 📘 |
| `vulners` | T0 | `vulners_api_key` | A | https://vulners.com/docs/API_wrapper/ | 📘 |

### Mobile

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `playstore` | T0 | | A | Play Store search HTML; small fixture from a known org page | 📘 |
| `apk_analyzer` | T1 | | A+B | APKMirror download + Python `androguard` on a tiny synthetic APK in fixtures | 🔬 |

### Pretext / HUMINT

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `news_intel` | T0 | | A | `tests/integration/test_tools_http.py::TestNewsTool` (already mocked) | ✅ |
| `jobs_intel` | T0 | | A | `tests/integration/test_tools_http.py::TestJobsTool` (already mocked) | ✅ |
| `sec_edgar` | T0 | | A | `tests/integration/test_tools_http.py::TestSECEdgarTool` (already mocked) | ✅ |
| `wikipedia` | T0 | | A | https://www.mediawiki.org/wiki/API:Main_page + Wikidata REST | 📘 |
| `linkedin_dorks` | T0 | | A | Generates Google dork URLs; small fixture for search HTML | 📘 |
| `public_collab` | T0 | | A | Searches for Trello/Confluence/Notion public boards via dorks | 🔬 |
| `github_org_members` | T0 | `github_token` | A | (listed above in Code & repos) | 📘 |
| `crunchbase` | T0 | `crunchbase_api_key` | A | https://data.crunchbase.com/docs/using-the-api | 📘 |

### Web (T0/T1/T2)

| Tool | Tier | Key | Bucket | Sample source | Status |
|---|---|---|---|---|---|
| `dorks` | T0 | | A | `tests/integration/test_tools_http.py::TestDorksTool` (already mocked) | ✅ |
| `metadata` | T0 | | A | `tests/integration/test_tools_http.py::TestMetadataTool` (already mocked) | ✅ |
| `wayback` | T0 | | A | https://archive.org/help/wayback_api.php (`/wayback/available`, `/web/timemap`) | 📘 |
| `gau` | T0 | | B+E | Stub if binary missing; https://github.com/lc/gau output schema | 📦/🛠 |
| `cms_detect` | T1 | | A | Custom HTTP fingerprints (WP `wp-content`, Joomla `Joomla!`, etc.) | 📘 |
| `webtech` | T2 | | A | `tests/integration/test_tools_http.py::TestWebTechTool` (already mocked) | ✅ |
| `linkfinder` | T1 | | A | Custom regex on JS bundles; sample fixture from any minified JS | 📘 |
| `sslyze` | T1 | | D | sslyze is a Python pkg, mock its `Scanner.queue_scans()` / `get_results()` | 📘 |
| `subdomain_takeover` | T1 | | A+C | DNS CNAME mock + httpx body fingerprint (e.g. GitHub Pages "There isn't a GitHub Pages site here") | 📘 |
| `wafw00f` | T1 | | A | https://github.com/EnableSecurity/wafw00f response signatures | 📘 |
| `favicon` | T2 | | A | `tests/integration/test_tools_http.py::TestFaviconTool` (already mocked) | ✅ |
| `gowitness` | T2 | | E | Hardcoded stubbed response, contract test only | 🛠 |
| `httpx` | T2 | | B | https://github.com/projectdiscovery/httpx `-json` output schema | 📦 |
| `katana` | T2 | | B | https://github.com/projectdiscovery/katana `-json` output | 📦 |
| `nuclei` | T2 | | B | https://github.com/projectdiscovery/nuclei `-json` output (`info`, `matched-at`, `severity`, …) | 📦 |
| `arjun` | T2 | | B | https://github.com/s0md3v/Arjun `--json` output | 📦 |

---

## Coverage summary

| Status | Count | Meaning |
|---|---|---|
| ✅ Already mocked | 9 | Live `respx` test in `tests/integration/test_tools_http.py` |
| 📘 Public doc available | ~60 | Provider publishes sample JSON / response shape in their docs; copy-paste fixture |
| 📦 Binary output schema | 12 | Project repo documents `--json` output; mock via `patch("run_subprocess")` |
| 🛠 Stub contract | 3 | `gowitness` always; `gau` / `maigret` when binary missing |
| 🔬 Worth a verification pass | 5 | `postman`, `fullhunt`, `pastebin_scan`, `hudsonrock`, `apk_analyzer`, `public_collab`, provider docs less complete; quick lookup needed before writing fixture |

The 🔬 set is small enough that I can spend 5-10 minutes per tool
verifying the response shape against the live provider docs before
writing the fixture, and if any of them turn out to not have stable
public sample output we drop them from the auto-test set and rely on
contract tests + manual spot-checks instead.

---

## What I'd like agreement on before executing

1. **One PR per category** (subdomain, cert/dns, cloud, code, …) or
   one big PR for everything? My recommendation: per-category, ~10
   PRs total, so each one is reviewable in a single sitting.
2. **Test depth per tool**: for each tool I'd write:
   - **Happy path**: provider returns expected JSON, tool produces
     expected `ToolResult.data`.
   - **Empty result**: provider returns `[]` / `{}` / 404; tool
     returns `success=True, result_count=0`.
   - **Error path**: provider returns 429 / 500 / connection error;
     tool returns `success=False, error="..."`.
   - **Schema drift**: provider returns malformed JSON; tool
     doesn't crash.
   That's ~4 tests/tool × ~80 uncovered tools ≈ 320 new tests.
3. **Live-key opt-in**: for the API-key tools, add a separate
   `tests/live/` directory that's skipped by default but runs against
   the real APIs when env vars are present. Useful for catching
   schema drift from upstream without paying for it on every CI run.
4. **Verification pass for the 🔬 set first**: I'd rather verify
   those six are mockable up front than discover halfway through that
   one of them needs a different approach.

If 1-4 look right I'll start with the verification pass for the 🔬
set, then begin Bucket A category-by-category. If you'd rather
reorder (e.g. start with the highest-value categories like
infrastructure intel, since those are the heaviest paid APIs), say
the word.
