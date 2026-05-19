# Report Quality Manual Checklist

Run this once before tagging a beta release. Ten authorised target
shapes, each producing a real campaign. What we're verifying:

1. The framework actually completes against varied targets without
   crashing.
2. The deliverables hold up to a human read ── narrative coherence,
   tone, no LLM artifacts in prose.
3. Findings are deduplicated across overlapping tools.
4. Every CVE citation resolves to a real CVE record.
5. Footer metadata (scope hash, campaign ID, tool versions) is
   present in every report.

Automated coverage for points 3-5 lives in
`tests/unit/test_report_quality.py`. **This checklist is point 1 and
point 2** ── the things only a human can judge. When you find a
failure here that *could* be automated, file a follow-up to convert
it into a test under `tests/unit/test_report_quality.py`.

---

## Prerequisites

- A pre-funded Anthropic or OpenAI API key in `.env`. Budget ~$5
  per campaign in medium mode; ~$2 per campaign in light mode.
- A non-trivial set of API keys configured: at minimum Shodan, GitHub,
  Hunter, HaveIBeenPwned, VirusTotal. The more keys, the more useful
  the campaign.
- Explicit authorisation to scan each target. **Do not run this
  checklist against targets you aren't authorised to test.** See
  `DISCLAIMER.md`.

---

## The ten target shapes

For each row, run a campaign and walk through the checklist below. If
the row says "lite mode" or "medium mode," respect that ── beta
verification doesn't need DEEP mode against every target.

| #  | Target shape | Suggested public target | Mode |
|----|---|---|---|
| 1  | Acunetix-style vulnerable testbed | `testphp.vulnweb.com` | medium |
| 2  | Small marketing site | A single-page brochure site you control | light |
| 3  | Mid-size SaaS with M365 + Azure AD | A B2B SaaS company's external surface | medium |
| 4  | AWS-native startup | A startup with public S3 + Lambda + Route53 footprint | medium |
| 5  | GCP-native organisation | A target using App Engine + GCS + Cloud Run | medium |
| 6  | GitHub-heavy engineering org | A company with 50+ public repos | medium |
| 7  | E-commerce with WAF | A Shopify or BigCommerce-fronted shop | light |
| 8  | Multi-domain conglomerate | A holding company with 5+ subsidiary domains | medium |
| 9  | Legacy-stack enterprise | A target running pre-2018 Windows + on-prem infra | medium |
| 10 | Self-test against your own infra | Your own authorised lab/personal site | deep |

A bug bounty program with explicit OSINT scope is a great source for
authorised targets at scales 3-9. Pick targets with broad OSINT scope
in their program briefs.

---

## Per-campaign checklist

Open each generated report directory and step through these items.
Make a note next to each ── pass / fail / N/A ── and a one-line
observation if relevant.

### `master_report.md`

- [ ] **Opens cleanly** ── no "As a large language model" or
      "I'd be happy to help" leftovers. (Should be caught by
      `tests/unit/test_report_quality.py::TestAITellScanner` but
      verify in actual LLM output too.)
- [ ] **Narrative coherence** ── the report reads as if one analyst
      wrote it, not as if each phase was written by a different LLM.
- [ ] **Tone is operator-to-operator** ── pragmatic, slightly skeptical,
      grounded in evidence. Not marketing copy, not academic.
- [ ] **No invented findings** ── every claim cites a specific tool
      result, evidence hash, or external source.
- [ ] **Footer present** ── scope hash, campaign ID, engagement ID,
      generated timestamp.

### `top_threads.md`

- [ ] **Top 5-10 threads are actually distinct attack paths**, not
      restatements of one underlying issue.
- [ ] **Each thread maps to MITRE PRE-ATT&CK or ATT&CK** with the
      technique ID (T-something) cited.
- [ ] **Next action is concrete** ── "run `nuclei` against
      `staging.example.com` with template `cve-2021-44228`," not
      "investigate the exposed service."

### `executive_summary.md` / `.html`

- [ ] **Severity counts match** the detailed report ── if the master
      narrative cites 3 criticals, the executive summary's table
      should too.
- [ ] **First page tells the story** ── an exec who reads only the
      first screen should know whether to act.

### `asset_inventory.md`

- [ ] **Subdomain count is reasonable** for the target. A small biz
      with 5 subdomains shouldn't show 5,000 (DNS poisoning?
      crt.sh wildcard madness?).
- [ ] **No duplicate hostnames** ── case differences (`API.example.com`
      vs `api.example.com`) shouldn't produce two entries.
- [ ] **Each subdomain has at least one source attribution**.

### `vuln_correlation.md`

- [ ] **Every CVE cited matches `CVE-YYYY-NNNN`** format. (Automated
      check at `test_report_quality.py::TestCVECitationFormat`, but
      spot-check the actual content for typos.)
- [ ] **CVE IDs are real** ── pick 3 at random and look them up at
      `nvd.nist.gov`. They should resolve.
- [ ] **KEV-listed CVEs are flagged** with the KEV badge.
- [ ] **No CVE appears twice** ── a CVE surfaced by multiple tools
      should be merged.

### `phishing_package/`

If `--generate-phishing` was set and emails were harvested:

- [ ] **Each draft has a real pretext hook** ── not generic
      "we noticed unusual activity" boilerplate.
- [ ] **Email format inference matches the target** ── if real-world
      emails are `first.last@`, the drafts should follow that
      pattern.
- [ ] **Sender domain is plausible** ── not literally `example.com`.
- [ ] **No drafts target out-of-scope addresses** ── the scope guard
      should have filtered.

### `harvested_credentials.md` (if Phase 7.5 ran)

- [ ] **Each credential has source attribution** ── which breach,
      which year.
- [ ] **No credentials are echoed in plaintext** for known-active
      accounts. Old breaches are fine; current ones should be
      summarised but not paste-able.
- [ ] **Hudson Rock infostealer entries** show the family
      (RedLine / Vidar / etc.) and date range.

### `attack_surface_matrix.html` / `.md`

- [ ] **Severity distribution is sensible** ── not 50 criticals, not
      zero findings on a real target.
- [ ] **Each row maps back to a finding ID** that exists in
      `findings.json`.

### `audit.jsonl`

- [ ] **Every tool invocation produced a line** ── grep for the
      tools you expect to have fired.
- [ ] **Each line carries the campaign ID + scope hash**.
- [ ] **Hash chain is intact** ── if you have time, run the
      audit-chain verifier and confirm no breaks.
- [ ] **No secrets in the audit lines** ── API keys, harvested
      credentials, scope-file contents should NOT appear in
      audit log entries.

---

## What to do when something fails

1. **AI-tell phrase in static text** → add the phrase to the relevant
   list in `tests/unit/test_report_quality.py` and re-run the
   automated scanner. The test will fail, you'll fix the source,
   the test will pass.

2. **Duplicate finding** → file a bug against
   `nexusrecon/core/scoring.py` with the duplicated `finding_id`
   and the two tools that surfaced it. Add a regression test under
   `TestFindingsDeduplication` keyed by the dedup property
   that broke (e.g. `test_cve_scoring_dedupes_within_state`,
   `test_breach_scoring_dedupes_by_email`).

3. **Malformed CVE citation** → `test_engine_has_no_malformed_cve_references`
   should already catch the static case. If a citation came from
   LLM-generated prose, add a sanitisation pass to the report engine.

4. **Missing scope hash / tool versions in footer** → the report
   engine has the data; the template or generator method dropped
   it. Fix the report generation, add the assertion to
   `TestReportEvidenceChain`.

5. **Scope-guard bypass** (out-of-scope domain in any output) →
   **stop, file a security advisory** per `SECURITY.md`. This is
   the framework's most important invariant.

6. **Anything else** → file a regular issue. Tag with `report-quality`
   so we can see the patterns across releases.

---

## Sign-off

Once all ten campaigns are complete and the per-campaign checklist
items either pass or have a tracked follow-up issue, sign off in a
PR comment on the beta-tag PR:

```
Report quality manual checklist: <date>
Operator: <handle>
Campaigns run: <10 target shapes>
Items passed: <count>
Items with follow-up issues: <count>, see #<issue numbers>
```

Beta launch can proceed once sign-off lands. No exceptions for
"we'll fix it in 0.6.1." If a report-quality failure ships, the
operators who download it will judge the framework by what they
saw, not by what's coming next release.
