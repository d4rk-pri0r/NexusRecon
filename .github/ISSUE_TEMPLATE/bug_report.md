---
name: Bug report
about: Something inside the framework misbehaved during a real campaign or test run.
title: "[bug] "
labels: bug
---

> **⚠️ Don't file security vulnerabilities here.** Use
> [Security Advisories](https://github.com/d4rk-pri0r/NexusRecon/security/advisories/new)
> instead, see `SECURITY.md` for the policy.

### What happened

<!-- One paragraph. Be specific about which tool / phase / report file misbehaved. -->

### What you expected

<!-- What did you think would happen instead? -->

### Reproduction

Provide enough for someone else to hit the same bug:

```bash
# Exact command line you ran:
nexusrecon run --scope my-scope.yaml --mode medium

# Or, if launching the TUI:
nexusrecon
# (then describe the click path through the wizard)
```

If the bug is in a specific tool, the **minimal scope file** that
triggers it (sensitive values redacted):

```yaml
engagement:
  client: "redacted"
  ...
```

### Environment

- NexusRecon version (`pip show nexusrecon | grep Version` or
  `cat nexusrecon/__init__.py`):
- Python version (`python3 --version`):
- OS + arch (`uname -a` on macOS / Linux):
- Install path: `./install.sh` / `pipx` / Docker / other:
- API keys configured (just the names, no values): e.g.
  `ANTHROPIC_API_KEY`, `SHODAN_API_KEY`, `GITHUB_TOKEN`

### Logs / output

Paste the relevant portion of the diagnostic log
(`~/.nexusrecon/logs/tui-<timestamp>.log`) or terminal output.
**Redact API keys, scope hashes, and any client-identifying
information** before pasting.

```
<paste here>
```

### Anything else

<!-- Workarounds you tried, related issues, screenshots, etc. -->
