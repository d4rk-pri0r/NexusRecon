# NexusRecon: Configuration Guide

> **Audience:** operators preparing NexusRecon for first use.
> **Companion to:** `.env.example` (the template), `MANUAL.md` §3 (reference),
> `TESTING_RUNBOOK.md` (operational guide).
>
> This document is the single source of truth for what each environment
> variable does, what value to put there, where to obtain it, and which
> NexusRecon capabilities it unlocks. Designed to be wiki-friendly and to
> seed a future GUI configuration tool.

---

## How to use this guide

1. Copy `.env.example` to `.env` (the install script does this for you).
2. Pick a **profile** from the next section based on how deeply you intend
   to use the platform.
3. Work through the keys for that profile in the suggested order. Each
   entry below has the signup URL and an estimate of how long it takes.
4. Verify after each key with: `nexusrecon tools | grep <toolname>`.
   missing → ready.

---

## Profiles, pick your starting point

### Minimum tester (5 keys, ~25 min)

Sufficient to exercise every campaign phase against a controlled target.

```
ANTHROPIC_API_KEY        (LLM, paid, you likely already have one)
GITHUB_TOKEN             (free; unlocks 5 code/secret tools)
VIRUSTOTAL_API_KEY       (free; 500/day)
SHODAN_API_KEY           (free tier limited; $5-$59 one-time is worth it)
HUNTER_API_KEY           (free; 50 searches/month)
```

### Standard operator (15 keys, ~2 hours)

Everything above plus the free intelligence keys. Best ratio of effort to
campaign quality.

```
+ ABUSEIPDB_API_KEY      + URLSCAN_API_KEY        + IPINFO_API_KEY
+ GREYNOISE_API_KEY      + CENSYS_API_ID/SECRET   + NETLAS_API_KEY
+ OTX_API_KEY            + CERTSPOTTER_API_KEY    + VULNERS_API_KEY
+ CHAOS_API_KEY          + LEAKIX_API_KEY         + FULLHUNT_API_KEY
```

### Power user (all keys + paid tiers, half day + recurring cost)

Adds paid breach/identity sources (DeHashed, IntelX, LeakCheck), Crunchbase
for HUMINT, Bing for live LinkedIn search, and AWS recon credentials.
Realistic monthly cost: $50-$200 depending on volume.

---

# §1 LLM Providers (REQUIRED)

NexusRecon needs at least ONE LLM provider configured. Without one, agent
synthesis is replaced by `MockLLM` (keyword-counted summaries), campaigns
still complete but lose the prose analysis layer.

| Variable | Purpose | Cost | Notes |
|----------|---------|------|-------|
| `ANTHROPIC_API_KEY` | Primary LLM (Claude). Recommended. | Paid, ~$3 per campaign typical | https://console.anthropic.com/ |
| `OPENAI_API_KEY` | Alternate LLM (GPT-4o etc.) | Paid, ~$4 per campaign typical | https://platform.openai.com/api-keys |
| `OLLAMA_BASE_URL` | Local LLM endpoint | Free (your hardware) | Default `http://localhost:11434`; needs Ollama running |
| `OLLAMA_MODEL` | Local model name | | e.g. `llama3.1:8b`, `qwen2.5:14b`; must already be pulled in Ollama |
| `NEXUS_LLM_PROVIDER` | Which provider to use | | `anthropic` \| `openai` \| `ollama` |
| `NEXUS_LLM_MODEL` | Specific model ID | | e.g. `claude-opus-4-5`, `gpt-4o`, `llama3.1:8b` |
| `NEXUS_LLM_TEMPERATURE` | Sampling temperature | | `0.1` recommended (low for reproducible analysis) |

**Recommended default:** Anthropic with Claude Sonnet 4.5 or 4.6. Best
reasoning per dollar for OSINT synthesis. Anthropic accounts also include
prompt caching which cuts cost ~40% on multi-phase campaigns.

**Local-only option:** set `NEXUS_LLM_PROVIDER=ollama` and point at any
reasonably capable local model. Quality drops noticeably below 8B params;
Qwen 2.5 14B or Llama 3.1 70B (if your hardware allows) work well.

---

# §2 Infrastructure Intelligence

These keys unlock the bulk of NexusRecon's value: host fingerprinting,
exposed-service discovery, IP reputation, certificate transparency.

| Variable | Tool unlocked | Free tier | Cost | Signup URL | Time |
|----------|---------------|-----------|------|------------|------|
| `SHODAN_API_KEY` | `shodan` (host/port fingerprinting) | 1 query/sec, limited filters | Free tier OR one-time membership $5-$59 (recurring discounts on Black Friday) | https://account.shodan.io/register | 5 min |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | `censys` (host search, cert search) | 250 queries/month | Paid tiers from $99/mo | https://search.censys.io/register | 5 min |
| `VIRUSTOTAL_API_KEY` | `virustotal` (domain/IP reputation + passive DNS) | 500 queries/day, 4/min | Free public tier | https://www.virustotal.com/gui/join-us | 3 min |
| `GREYNOISE_API_KEY` | `greynoise` (IP scanner background-noise classification) | Community tier free | Free with email | https://viz.greynoise.io/signup | 3 min |
| `ABUSEIPDB_API_KEY` | `abuseipdb` (IP abuse reports) | 1000 queries/day | Free | https://www.abuseipdb.com/register | 3 min |
| `URLSCAN_API_KEY` | `urlscan` (URL scan results + screenshots) | 5000 public scans/day | Free | https://urlscan.io/user/signup | 3 min |
| `BINARYEDGE_API_KEY` | `binaryedge` (host/service intel) | 250 queries/month | Paid plans available | https://app.binaryedge.io/sign-up | 5 min |
| `FULLHUNT_API_KEY` | `fullhunt` (attack surface intel) | 100 queries/day | Free | https://fullhunt.io/ | 3 min |
| `ZOOMEYE_API_KEY` | `zoomeye` (cyberspace search) | Free tier | Paid plans available | https://www.zoomeye.org/login | 5 min |
| `NETLAS_API_KEY` | `netlas` (host/service intel, more EU coverage) | Free tier | Paid plans available | https://app.netlas.io/registration/ | 5 min |
| `IPINFO_API_KEY` | `ipinfo` (geolocation, ASN, VPN/proxy/Tor flags) | 50k req/month | Free; paid tier unlocks privacy/threat fields | https://ipinfo.io/signup | 3 min |
| `SECURITYTRAILS_API_KEY` | `passive_dns` (historical DNS) | 50 queries/month | Paid from $50/mo | https://securitytrails.com/app/signup | 5 min |
| `LEAKIX_API_KEY` *(optional)* | `leakix` (leaked service indexing) | Works without key; key raises rate limit | Free | https://leakix.net/auth/register | 3 min |

**Priority order:** VirusTotal → AbuseIPDB → GreyNoise → URLScan →
IPinfo → FullHunt → Netlas → BinaryEdge → Censys → Shodan → ZoomEye →
SecurityTrails → LeakIX.

The top 5 alone get you ~80% of infrastructure intel coverage.

---

# §3 Email & Identity

| Variable | Tool unlocked | Free tier | Cost | Signup URL | Time |
|----------|---------------|-----------|------|------------|------|
| `HUNTER_API_KEY` | `hunter` (email harvesting + format) | 50 searches/month | Paid from $34/mo | https://hunter.io/users/sign_up | 5 min |
| `HAVEIBEENPWNED_API_KEY` | `breach_lookup` (email→breaches) | None | $3.50/month minimum | https://haveibeenpwned.com/API/Key | 5 min |
| `EMAILREP_API_KEY` *(optional)* | `emailrep` (email reputation) | Free tier without key (low volume); key for high volume | Invite-only paid | https://emailrep.io/ | varies |
| `DEHASHED_USERNAME` + `DEHASHED_API_KEY` | (not yet implemented; planned breach source) | None | ~$5/month minimum | https://www.dehashed.com/login | 10 min |
| `INTELX_API_KEY` | `phonebook` (Intelligence X email/subdomain search) | None | Paid, varies | https://intelx.io/account?tab=developer | 10 min |
| `LEAKCHECK_API_KEY` | `leakcheck` (breach DB queries) | None | Paid from $9/mo | https://leakcheck.io/ | 5 min |

**Priority order:** Hunter → HaveIBeenPwned → others. The breach DBs are
worth paying for if you do red team work regularly; for one-off testing,
the free Hunter tier + the keyless `hudsonrock` (infostealer) and
`emailrep` (low-volume) tools cover a lot.

---

# §4 Vulnerability Intelligence

| Variable | Tool unlocked | Free tier | Cost | Signup URL | Time |
|----------|---------------|-----------|------|------------|------|
| `VULNERS_API_KEY` | `vulners` (CVE enrichment + Metasploit module detection) | Free tier | Paid plans available | https://vulners.com/profile/ | 5 min |

The other vuln tools (`nvd`, `kev`, `epss`, `exploitdb`, `github_advisory`,
`osv`, `nuclei_template`) are all keyless. Vulners is the only paid-ish
enrichment source, and even its free tier is generous enough for testing.

---

# §5 Passive Sources (optional keys, tools work without them)

These services have public APIs that work key-free. Adding a key raises
the rate limit, which matters during deep campaigns but is irrelevant
for testing.

| Variable | Tool affected | Without key | With key | Signup URL | Time |
|----------|---------------|-------------|----------|------------|------|
| `OTX_API_KEY` | `otx_subdomains` | ~10 req/min global | Per-user quota much higher | https://otx.alienvault.com/ | 3 min |
| `CERTSPOTTER_API_KEY` | `certspotter` | Rate-limited | Raised limits | https://sslmate.com/account/api_credentials | 5 min |
| `CHAOS_API_KEY` | `chaos` (ProjectDiscovery subdomain intel) | Tool gated; key required | Free for community via Discord | https://chaos.projectdiscovery.io/ (Discord verification step) | 10 min |

`CHAOS_API_KEY` is the only entry here that fully gates a tool, others
degrade gracefully. Discord verification is the unusual step; budget
extra time.

---

# §6 Pretext & HUMINT

| Variable | Tool affected | Free tier | Cost | Signup URL | Time |
|----------|---------------|-----------|------|------------|------|
| `CRUNCHBASE_API_KEY` | `crunchbase` (org/funding/leadership intel) | None | Expensive, Enterprise tier only as of writing | https://about.crunchbase.com/products/crunchbase-api/ | 30+ min (sales call) |
| `BING_SEARCH_API_KEY` *(optional)* | `linkedin_dorks`, `public_collab` (live web search vs static dork list) | Without: dorks only, no execution. With: live results. | Free 1000/month tier on Azure | https://portal.azure.com/ → Cognitive Services → Bing Search | 15 min (Azure signup) |

**Realistic recommendation:** skip Crunchbase for testing; it's locked
behind sales. The keyless `wikipedia` and `sec_edgar` tools cover much of
the same ground. Bing is worth the 15-min Azure signup if you intend to
do real phishing prep, it materially improves `linkedin_dorks` and
`public_collab`.

---

# §7 Code & Repo

| Variable | Tools unlocked | Free tier | Cost | Signup URL | Time |
|----------|----------------|-----------|------|------------|------|
| `GITHUB_TOKEN` | `github_recon`, `github_subdomains`, `github_actions_leaks`, `github_org_members`, `gitdorker` (5 tools!) | 5000 req/hour authenticated | Free with any GitHub account | github.com → Settings → Developer settings → Personal access tokens (classic). Scopes: `public_repo`, `read:org`, `read:user` | 5 min |
| `GITLAB_TOKEN` | (planned tools) | 2000 req/min | Free | https://gitlab.com/-/profile/personal_access_tokens | 5 min |
| `BITBUCKET_TOKEN` | (planned tools) | varies | Free | https://bitbucket.org/account/settings/app-passwords/ | 5 min |

**GitHub is by far the highest-leverage key.** It unlocks 5 distinct tools
including secret discovery and org member harvesting. Configure this
even if you skip everything else paid.

**Token scopes for GITHUB_TOKEN:** `public_repo`, `read:org`, `read:user`.
Do NOT grant write scopes. Tools only ever read.

---

# §8 Cloud Credentials (AWS recon)

| Variable | Purpose | Cost | Notes |
|----------|---------|------|-------|
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | `aws_recon` (account-level AWS recon if you own AWS accounts in scope) | Pennies per campaign | Use a least-privilege IAM user with `SecurityAudit` + `ReadOnlyAccess` policies only. NEVER use root creds. |
| `AWS_DEFAULT_REGION` | Default region for AWS API calls | | `us-east-1` is fine |

**Skip these unless you have your own AWS account to recon.** They're not
needed for testing against external targets, those use the keyless
`bucket_enum` tool which probes public S3 by name pattern.

---

# §9 OPSEC / Network

These don't require signup, they're operational hardening for advanced
use.

| Variable | Purpose | Default | When to change |
|----------|---------|---------|----------------|
| `NEXUS_PROXY_URL` | All outbound HTTP traffic | `socks5://127.0.0.1:9050` | When you have a SOCKS5 proxy (commercial proxy service, Tor, custom). Comment out to disable. |
| `NEXUS_TOR_PROXY` | Tor-specific routing (for `--validate-via-tor` flag) | `socks5://127.0.0.1:9050` | Only used when validating harvested credentials via Tor to avoid CloudTrail correlation back to operator IP |
| `NEXUS_DNS_RESOLVERS` | Custom DNS servers (comma-separated) | `1.1.1.1,8.8.8.8,9.9.9.9` | Set to your own resolver if doing private/passive DNS |
| `NEXUS_VALIDATE_VIA_TOR` | When `--validate-creds` is set, route validation calls through Tor | `false` | Set `true` if you want CloudTrail/audit logs to show Tor exit IPs rather than your real IP |

**Default safety note:** the proxy/Tor settings are commented `# SOCKS5
proxy...` in `.env.example` but ACTIVE. If you don't have Tor running on
9050, comment them out or set to empty before running campaigns.
otherwise every outbound request will hang on connection refused.

---

# §10 Storage

| Variable | Purpose | Default | When to change |
|----------|---------|---------|----------------|
| `NEXUS_OUTPUT_DIR` | Where campaign artifacts are written | `./campaigns` | Set to absolute path if running NexusRecon from a different working directory |
| `NEXUS_DB_PATH` | SQLite state + cache database | `./nexusrecon.db` | Set to a faster/larger disk if doing extended monitoring campaigns |

**Default behavior is fine for most users.** Just be aware of where
artifacts go (gigabytes possible for large engagements).

---

# §11 Vault Integration (optional, production)

| Variable | Purpose | When to use |
|----------|---------|-------------|
| `OP_SERVICE_ACCOUNT_TOKEN` | 1Password service account token | Production deploys where keys are managed in a vault rather than `.env` |
| `VAULT_ADDR` + `VAULT_TOKEN` | HashiCorp Vault | Enterprise deploys with existing Vault infrastructure |

**Skip for testing.** These are for production multi-operator deployments
where you don't want plaintext keys on disk. NexusRecon's secret loader
checks the vault if these are set, otherwise falls back to `.env`.

---

# §12 Debug / Development

| Variable | Purpose | Default | Values |
|----------|---------|---------|--------|
| `NEXUS_LOG_LEVEL` | Logging verbosity | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` |
| `NEXUS_LOG_FORMAT` | Log output format | `json` | `json` \| `text` |
| `NEXUS_DRY_RUN` | Skip actual tool execution | `false` | `true` \| `false`. Equivalent to `--dry-run` CLI flag |

**Set `NEXUS_LOG_LEVEL=DEBUG` when reporting bugs.** Otherwise leave at
defaults.

---

# Appendix A: Tools-unlocked-by-key reverse lookup

When deciding whether to procure a specific key, use this to gauge ROI:

| Key | Tools unlocked | Free tier campaign-usable? |
|-----|----------------|---------------------------|
| `GITHUB_TOKEN` | `github_recon`, `github_subdomains`, `github_actions_leaks`, `github_org_members`, `gitdorker` | Yes (5000 req/hour) |
| `VIRUSTOTAL_API_KEY` | `virustotal` | Yes (500/day) |
| `SHODAN_API_KEY` | `shodan` | Limited (free tier crippled) |
| `CENSYS_API_ID`+`SECRET` | `censys` | Yes (250/month tight but works) |
| `ABUSEIPDB_API_KEY` | `abuseipdb` | Yes (1000/day) |
| `GREYNOISE_API_KEY` | `greynoise` | Yes (community) |
| `URLSCAN_API_KEY` | `urlscan` | Yes (5000/day) |
| `IPINFO_API_KEY` | `ipinfo` | Yes (50k/month) |
| `HUNTER_API_KEY` | `hunter` | Limited (50/month) |
| `HAVEIBEENPWNED_API_KEY` | `breach_lookup` | No free tier |
| `LEAKCHECK_API_KEY` | `leakcheck` | No free tier |
| `INTELX_API_KEY` | `phonebook` | No free tier |
| `CHAOS_API_KEY` | `chaos` | Yes (community via Discord) |
| `OTX_API_KEY` | `otx_subdomains` | Tool keyless; key raises rate limit |
| `CERTSPOTTER_API_KEY` | `certspotter` | Tool keyless; key raises rate limit |
| `LEAKIX_API_KEY` | `leakix` | Tool keyless; key raises rate limit |
| `BINARYEDGE_API_KEY` | `binaryedge` | Yes (250/month) |
| `FULLHUNT_API_KEY` | `fullhunt` | Yes (100/day) |
| `ZOOMEYE_API_KEY` | `zoomeye` | Yes (free tier) |
| `NETLAS_API_KEY` | `netlas` | Yes (free tier) |
| `SECURITYTRAILS_API_KEY` | `passive_dns` | Limited (50/month) |
| `VULNERS_API_KEY` | `vulners` | Yes (free tier) |
| `CRUNCHBASE_API_KEY` | `crunchbase` | No (enterprise only) |
| `BING_SEARCH_API_KEY` | `linkedin_dorks`, `public_collab` (live search mode) | Yes (Azure 1000/month free) |
| `EMAILREP_API_KEY` | `emailrep` | Tool keyless for low volume |

---

# Appendix B: Sequential signup checklist

Print, follow top-to-bottom. Realistic timing assumes captcha + email
verification round-trips.

```
TIER 1, Minimum tester (~25 min total)
[ ] LLM provider (Anthropic recommended)           ~5 min
[ ] GITHUB_TOKEN                                    ~5 min
[ ] VIRUSTOTAL_API_KEY                              ~3 min
[ ] SHODAN_API_KEY (free or $5-$59 one-time)        ~5 min
[ ] HUNTER_API_KEY                                  ~5 min

TIER 2, Standard operator (~2 hours additional)
[ ] ABUSEIPDB_API_KEY                               ~3 min
[ ] GREYNOISE_API_KEY                               ~3 min
[ ] URLSCAN_API_KEY                                 ~3 min
[ ] IPINFO_API_KEY                                  ~3 min
[ ] OTX_API_KEY                                     ~3 min
[ ] CERTSPOTTER_API_KEY                             ~5 min
[ ] CENSYS (ID + SECRET)                            ~5 min
[ ] NETLAS_API_KEY                                  ~5 min
[ ] FULLHUNT_API_KEY                                ~3 min
[ ] BINARYEDGE_API_KEY                              ~5 min
[ ] VULNERS_API_KEY                                 ~5 min
[ ] LEAKIX_API_KEY (optional)                       ~3 min
[ ] CHAOS_API_KEY (Discord verification)           ~10 min
[ ] ZOOMEYE_API_KEY                                 ~5 min
[ ] SECURITYTRAILS_API_KEY                          ~5 min

TIER 3, Power user (~half day + recurring cost)
[ ] HAVEIBEENPWNED_API_KEY ($3.50/mo)               ~5 min
[ ] LEAKCHECK_API_KEY ($9/mo+)                      ~10 min
[ ] INTELX_API_KEY (varies)                         ~15 min
[ ] DEHASHED ($5/mo+)                               ~10 min
[ ] BING_SEARCH_API_KEY (Azure account)             ~15 min
[ ] CRUNCHBASE_API_KEY (enterprise sales call)      ~30 min + days waiting
[ ] AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY       ~10 min (if you own an AWS account)
```

After each key: verify with `nexusrecon tools`, the corresponding row
should flip from `✗ missing` to `✓ ready`.

---

# Appendix C: Notes for a future GUI configuration tool

Every entry in this guide is structured: variable name, signup URL, free
tier limit, cost, time estimate, tool(s) unlocked, optional/required
status. A GUI builder could:

1. Parse this Markdown directly (one row per `|`-delimited table entry)
2. Group by section heading for the navigation tree
3. Use the "Time" column to drive a progress estimator
4. Use the "Tools unlocked" column to show the operator what each key buys
5. Open the signup URL in the user's browser on click
6. Test the key live by invoking the corresponding tool (`nexusrecon
   tools <name> --self-test` doesn't exist yet but should, file as a
   GitHub issue)

The data model is stable. If you extract to JSON for the GUI, that JSON
should derive from this Markdown, keep one source of truth, not two.

---

# Maintenance

- **Add a new variable:** create an entry in the appropriate section
  table (LLM / Infrastructure / Identity / etc.), update Appendix A
  (tools-unlocked reverse lookup), and update Appendix B (signup
  checklist) if applicable.
- **Pricing changes:** services change tiers. The "Free tier" and "Cost"
  columns are accurate as of the file's last update. When you re-procure
  a key and notice a discrepancy, fix the row.
- **Tool retirement:** when a tool is removed, also remove its key entry
  here if no other tool uses it.
