# Security Policy

NexusRecon is reconnaissance tooling. The framework itself can have
security bugs, bad scope-guard logic, secret leakage into logs,
audit-chain integrity issues, parser bugs that crash on hostile
input. We treat those seriously.

---

## Supported versions

The project is pre-beta (``0.5.x``). Security fixes ship against
the current minor only. There is no LTS branch.

| Version  | Supported       |
|----------|-----------------|
| 0.5.x    | ✅ Active fixes |
| < 0.5.0  | ❌ Pre-release internal iterations; not for external use |

---

## Reporting a vulnerability

**Do not file a public GitHub issue for security bugs in NexusRecon
itself.** Public issues are visible to anyone watching the repo and
can be exploited before a fix lands.

**Contact**: open a [GitHub Security Advisory](https://github.com/d4rk-pri0r/NexusRecon/security/advisories/new)
from the repository's Security tab. This is private until the
maintainer publishes the advisory; only the reporter and the
maintainer can see it during triage.

If you can't use the Security Advisory flow for any reason, email
the maintainer through the GitHub profile contact at
<https://github.com/d4rk-pri0r>. PGP keys, if any, will be linked
from that profile.

Include in your report:

- A description of the vulnerability and its impact.
- Reproduction steps, ideally a minimal scope file + command line
  that triggers the issue.
- The git commit you tested against (``git rev-parse HEAD``).
- Your environment (Python version, OS, install path).
- Whether you've shared the finding with anyone else.

We aim to acknowledge within **3 business days** and ship a fix
within **30 days** for high-severity issues. Coordinated disclosure
timeline is negotiable on the report, say what works for you.

---

## What's in scope

The kind of bugs we want to hear about:

- **Scope-guard bypass**: any input that lets a tool fire against a
  target not authorised in the loaded scope file. This is the most
  important property of the framework.
- **Credential leakage**: anything that causes secrets (API keys,
  harvested credentials, scope-file contents, LLM API keys) to land
  in:
  - Stdout / stderr / TUI display
  - `master_report.md` or any other generated report
  - `audit.jsonl` or `findings.json`
  - Crash tracebacks
  - LLM prompt context (where the operator didn't opt in to that
    data being sent to the LLM provider)
- **Audit-chain integrity**: any way to forge, delete, or reorder
  audit log entries without detection.
- **Configuration / TUI exploits**: code execution via crafted
  scope YAML, malicious LLM outputs that get executed as code,
  injection via tool result parsing.
- **Subprocess command injection**: anywhere a tool builds a
  subprocess argv from user input without proper escaping
  (`subfinder -d`, `gitleaks --source`, etc.).
- **Denial of service**: anything that lets a single tool exhaust
  memory / CPU / disk on the operator's machine in a way the rate
  limiter / timeout machinery doesn't catch.

---

## What's out of scope

The following aren't security bugs in NexusRecon:

- **Vulnerabilities in upstream tools or APIs**: report those to
  the respective project (subfinder, amass, Shodan, etc.).
- **Vulnerabilities in scanned targets**: that's the *point* of the
  tool. If you find a real vuln in a target you're authorised to
  test, report it through the target's coordinated disclosure
  channel.
- **Operators using the tool against unauthorised targets**: that's
  a legal and ethical issue, not a software bug. See
  [DISCLAIMER.md](DISCLAIMER.md).
- **LLM behaviour**: if Anthropic / OpenAI / Ollama emit unexpected
  output, report that to the LLM provider. We treat their outputs
  as untrusted and parse defensively (see B26 attribution-gating in
  the agent executor).
- **Theoretical findings without a demonstrable exploit**: e.g.
  "this regex is technically a ReDoS candidate but only fires on a
  300MB pasted-in URL." Demonstrate the impact.

---

## Disclosure

After a fix ships, we publish a GitHub Security Advisory describing
the issue, the impact, and the fix commit. We credit the reporter by
name (or pseudonym, or anonymous) per their preference.

The advisory is filed in
<https://github.com/d4rk-pri0r/NexusRecon/security/advisories>.

---

## A note on legal posture

NexusRecon is licensed under Apache 2.0, which includes the standard
"NO WARRANTY" disclaimer. We don't promise the framework is
bug-free; we promise we'll respond seriously when you find one.

Operators are responsible for using the framework within the bounds
of their engagement authorisation (see [DISCLAIMER.md](DISCLAIMER.md)).
A security bug in NexusRecon does not transfer your authorisation to
us, if you discover a vuln by running NexusRecon outside an
authorised engagement, you still ran it outside an authorised
engagement.
