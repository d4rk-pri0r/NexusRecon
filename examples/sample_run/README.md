# Sample Campaign Walkthrough

> **⚠️ Walkthrough only, actual report files aren't checked in yet.**
> This document narrates what a realistic campaign run *would* produce.
> A real end-to-end run against a known-vulnerable public target (with
> the actual `master_report.md`, `findings.json`, `audit.jsonl`, etc.
> committed alongside) is the v0.6.0 milestone, see [ROADMAP.md](../../ROADMAP.md).

This directory is annotated output from a realistic campaign run.

## Scenario: Bug Bounty: Example Corp (example.com)

### Scope File

```yaml
engagement:
  client: "Example Corp"
  engagement_id: "BB-2026-Q1-EX01"
  authorized_by: "Bug Bounty Program"
  authorization_date: "2026-03-01"
  signed_sow_hash: "sha256:program-terms-hash"
  start_date: "2026-03-01"
  end_date: "2026-06-01"

scope:
  in_scope:
    domains: ["example.com"]
  out_of_scope:
    domains: ["*.partner.example.com"]

constraints:
  max_tier: "T1"
  stealth_profile: "high"
  max_llm_cost_usd: 20.0
```

### Run Command

```bash
nexusrecon run --scope examples/scopes/m365_enterprise.yaml --seeds "example.com" --mode medium
```

### Typical Output

```
[*] Loading scope...
[+] Scope validated: example.com (T1, high stealth)
[+] Campaign launched: nr-20260501-120000-a1b2c3d4

[*] Phase 1: Passive Footprinting
  [+] crt.sh: 47 subdomains found
  [+] subfinder: 52 subdomains found
  [+] DNS sweep: A, AAAA, MX, NS, TXT records collected
  [+] WHOIS: registration data collected
  [+] Phase 1 complete: 52 subdomains, 12 IPs

[*] Phase 2: Identity & Cloud
  [+] Azure/M365: Managed federation, tenant ID discovered
  [+] AWS: 3 public S3 buckets found (1 publicly readable)
  [+] Email: 28 addresses from Hunter + theHarvester
  [+] Email format: first.last (confidence: 82%)

[*] Phase 3: Code Leakage
  [+] GitHub: 12 repos found, 3 contain hardcoded secrets
  [+] gitleaks: 7 secrets detected
  [+] TruffleHog: 12 findings (4 verified active)

[*] Phase 4: Correlation
  [+] 3 high-value leads identified
  [+] 5 open hypotheses generated

[*] Phase 5: Light Active (T2)
  [+] httpx: 38/52 subdomains alive
  [+] Shodan: 8 hosts indexed
  [+] Tech fingerprint: WordPress, Nginx, CloudFront

[*] Phase 6: Active (T3), SKIPPED (max tier: T1)

[*] Phase 7: Vulnerability Correlation
  [+] 3 CVEs mapped to fingerprinted technologies

[*] Phase 8: Attack Surface
  [+] 1 critical, 4 high, 12 medium findings ranked

[*] Phase 9: Reporting
  [+] 9 reports generated

Campaign Complete
  Findings: 17
  Entities: 127
  Reports: 9
  Output: ./campaigns/example_corp/BB-2026-Q1-EX01/nr-20260501-120000-a1b2c3d4
  Audit Chain: VALID
```

### Key Findings (Anonymized)

1. **[CRITICAL]** Public S3 bucket `example-prod-data` contains customer PII
2. **[HIGH]** GitHub repo `example-api` contains hardcoded AWS credentials (active)
3. **[HIGH]** DMARC policy set to `p=none`, sender spoofing possible
4. **[HIGH]** M365 federation type: Managed (password hash sync)
5. **[MEDIUM]** 12 subdomains with outdated TLS configurations
6. **[MEDIUM]** Azure DevOps org `example-dev` publicly visible
7. **[MEDIUM]** TruffleHog found expired GitHub tokens in CI logs

### Reports Generated

- `executive_summary.md`, 1-page summary
- `full_report.md`, Complete engagement report
- `asset_inventory.md` + `.json` + `.csv`, 52 subdomains, 28 emails, 3 cloud assets
- `phishing_package.md`, 28 emails, first.last pattern (82%), DMARC p=none
- `cloud_posture.md`, M365 Managed federation, 3 public S3 buckets
- `attack_surface.md`, 17 findings ranked by severity
- `findings.json`, Full findings with evidence hashes
- `campaign_meta.json`, Campaign metadata with scope hash
- `maltego_export.csv`, 127 entities for Maltego import
