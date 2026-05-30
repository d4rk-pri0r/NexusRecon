# Killer demo: producing and publishing a sample run

The committed demo lives in [`examples/sample_run/`](../examples/sample_run/):
a real, redacted NexusRecon campaign against `gitlab.com` run under
GitLab's public HackerOne program. This doc is the runbook for
reproducing it (or refreshing it against the current codebase) and the
checklist for publishing the output safely.

The demo is the answer to "what is the agentic value proposition,
concretely" so it must stay (a) real, (b) honest about what the
framework did and did not conclude, and (c) free of any data that would
amplify the OSINT signal beyond what the target already exposes.

## Authorization first

A demo campaign is still a campaign. Only run against a target you are
authorized to test:

- A public bug-bounty program whose scope and safe-harbor language cover
  external recon (the committed demo uses
  <https://hackerone.com/gitlab>), or
- A target you own, or have explicit written permission to test.

Read the program rules before running. See `DISCLAIMER.md` at the repo
root. Out-of-scope seeds are dropped and logged by the scope guard, but
authorization is yours to establish, not the tool's.

## Reproducing the run

```sh
# Required:
#   ANTHROPIC_API_KEY        # the LLM agents
# Recommended (more tools fire with more keys):
#   SHODAN_API_KEY VIRUSTOTAL_API_KEY GITHUB_TOKEN HUNTER_API_KEY
#   ABUSEIPDB_API_KEY OPENAI_API_KEY
# Optional binaries:
#   pipx install maigret     # username account checking

nexusrecon run \
  --scope examples/sample_run/scope.yaml \
  --seeds gitlab.com \
  --mode medium \
  --use-graph \
  --dispatch-mode full
```

Ballpark from the committed run: ~20 minutes wall-clock, about `$2.32`
of LLM spend against the `$10` scope cap. Output lands under
`campaigns/<client>/<engagement-id>/<run-id>/` (gitignored).

Do NOT pass `--generate-phishing` for a published demo: the no-phishing-
artifact line holds even for authorized targets.

## Publishing checklist

Run the full campaign privately, then publish only a redacted subset.
Everything below must be true before committing anything under
`examples/sample_run/`:

- [ ] **Authorization documented.** The `scope.yaml` is hash-anchored to
      the program URL (the SOW equivalent) and the README names the
      authorization basis.
- [ ] **No real credentials anywhere.** `harvested_credentials.md`,
      `credential_exposure_paths.md`, and the credential punch list stay
      in the private campaign dir. Never publish a real credential, even
      redacted.
- [ ] **Per-person data withheld.** People identity map, per-employee
      emails/names/titles, and any personal-identity linkage stay
      private. Published reports carry aggregate counts only (for the
      demo: "10 employee emails surfaced", not the addresses).
- [ ] **Phishing drafts excluded.** No `--generate-phishing` output, and
      no `spear_phishing_intelligence.md` with real target names. If used
      as demo material at all, sanitize to fictional examples.
- [ ] **Tenant / account identifiers redacted.** Azure tenant ID, cloud
      account IDs, and similar phishing-prep signals replaced with
      `[REDACTED-...]` placeholders even when publicly discoverable.
- [ ] **Vulnerabilities go through disclosure first.** If the run found a
      specific exploitable issue, it goes through the program's
      disclosure channel before any mention in the demo, never straight
      into the repo.
- [ ] **Redacted filenames are explicit.** Publish narrative reports as
      `*.redacted.md` and say what was redacted in the README table.
- [ ] **Audit excerpt proves integrity, not content.** Commit the first
      ~60 hash-chained audit entries (`audit_excerpt.jsonl`) so the
      chain-of-custody claim is checkable; trim anything sensitive.
- [ ] **Dispatcher trace is the headline.** `dispatcher_trace.md` (every
      tool fire, result, and error in order) is the most valuable
      artifact; make sure it is current and complete.
- [ ] **Honesty about gaps.** Document the issues the run surfaced. A
      demo that hides its rough edges reads as marketing; one that names
      them reads as evidence.

The detailed redaction rationale for the current demo is in
[`examples/sample_run/README.md`](../examples/sample_run/README.md)
under "What's NOT in this directory" and the Phase D + E publishing
posture in [`ROADMAP.md`](../ROADMAP.md).

## Refreshing the demo

The committed run predates the Wave F (signal quality + failure honesty)
and OPSEC-binding work. Its README's "Known framework issues" section
lists three bugs that have since been fixed:

- `top_threads.md` reporting "No ranked threats available" despite ranked
  findings (Wave F-B1 now renders the coverage/threads sections from
  state).
- The CLI completion box showing `Findings: 0` while the data was
  correct (cost/telemetry and summary trust fixed in Wave F-A6).
- The stealth profile declared but not enforced at the wire (closed by
  the production OPSEC binding via `build_opsec`).

A refresh against the current codebase would show the run-health banner,
the deduplicated and provenance-checked findings, the enforced stealth
cadence, and (optionally) the `nexusrecon[tls]` JA3 client. It is a nice
follow-up but not required: the committed artifact is already a real,
honest demo. If you refresh, re-run this checklist before publishing.
