# NexusRecon — Install Pipeline Fix Plan

> **Audience:** Sonnet 4.6 with extended thinking, working autonomously.
> **Goal:** Make the install path bulletproof for first-time users (and beta
> testers) on macOS + Debian/Ubuntu/Kali. A fresh `git clone` → `./install.sh`
> → working `nexusrecon` should "just work" without manual workarounds.
> **Working directory:** `/Users/waifumachine/agentic-osint`
> **Reference spec:** Section 0 of `EXECUTION_PLAN_V2_GOLD_STANDARD.md` —
> codebase conventions still apply (no new abstractions, no compat shims,
> surgical edits).

---

## Context: Why this exists

The operator hit a chain of install failures on macOS with Homebrew Python:

1. `install.sh` defaulted to Homebrew's **Python 3.14** (just released, no
   CrewAI support yet — CrewAI requires `<3.14`).
2. `install.sh` ran `pip install -e ".[dev]"` outside a venv, triggering
   **PEP 668** (`externally-managed-environment`) on the Homebrew Python.
3. The brew package list contains entries that aren't brew formulae
   (`waybackurls`, possibly `naabu`/`dnstwist`).
4. `pyproject.toml` has `requires-python = ">=3.11"` — no upper bound.
   Pip happily attempts dependency resolution against Python 3.14 and
   spends 30+ minutes spelunking the version index before failing.

These compound on each other. Result: even an experienced user has to
diagnose three layers of breakage before getting `nexusrecon --help` to
work. **Beta testers will not get past this.**

This document specifies the proactive fixes. After implementation, the
acceptance test is: a fresh clone + `./install.sh` (and the documented
follow-up) produces a working install on any supported platform.

---

## Issue Inventory

Each issue below has a fix specified later. Reference by ID (I1–I9) when
asking clarifying questions.

| ID | Severity | File | Issue |
|----|----------|------|-------|
| I1 | CRITICAL | `pyproject.toml:11` | `requires-python = ">=3.11"` lacks upper bound. Should be `">=3.11,<3.14"` to match CrewAI's window and fail fast. |
| I2 | CRITICAL | `install.sh:208–224` | `install_python_packages()` runs `pip install -e ".[dev]"` directly. No venv detection. Fails on PEP-668-enabled Pythons (Homebrew, recent Debian/Ubuntu, Fedora). |
| I3 | CRITICAL | `install.sh:43–52` | Python version gate only checks lower bound (`>=3.11`). Does not reject `>=3.14`, so script proceeds before CrewAI inevitably fails. |
| I4 | HIGH | `install.sh:65–76` | `BREW_PKGS` list contains non-formula names: `waybackurls` (must be `go install`), `naabu` (formula is `projectdiscovery/naabu`), `dnstwist` (PyPI only). The user's run showed `waybackurls` failing. |
| I5 | HIGH | `install.sh:163–168` | `$PIP install dnstwist` runs outside a venv — PEP 668 same as I2. |
| I6 | MEDIUM | `install.sh` | No end-of-install verification. Script exits successfully even if `nexusrecon --help` would fail. |
| I7 | MEDIUM | `install.sh` | No phased operation. User cannot skip system packages, cannot do Python-only, cannot run unattended. |
| I8 | MEDIUM | `README.md:99`, `MANUAL.md:55–69` | Install instructions say `pip3 install -e ".[dev]"` with no mention of a venv. Will fail on any modern macOS/Linux. |
| I9 | LOW | `nexusrecon/cli/main.py` | No first-run sanity check inside the CLI itself. If a user somehow has a broken install, the error surface is whatever traceback Python emits — not actionable. |

---

## Fix 1 (I1) — Tighten `pyproject.toml` Python bound

**File:** `pyproject.toml` line 11

Change:
```toml
requires-python = ">=3.11"
```
To:
```toml
requires-python = ">=3.11,<3.14"
```

This makes `pip install -e .` fail immediately at metadata read with a
clear error when the user is on an unsupported Python, instead of grinding
through dependency resolution for half an hour.

**Acceptance:**
- `python3.14 -m pip install -e .` (or equivalent) fails within seconds
  with `ERROR: Package 'nexusrecon' requires a different Python: 3.14.x not
  in '>=3.11,<3.14'`.

**Pitfall:** Whenever CrewAI bumps its supported Python upper bound, this
line will need updating. Add a one-line comment above it noting the
dependency: `# Upper bound tracks crewai's requires-python constraint.`

---

## Fix 2 (I2, I5) — Venv strategy in `install.sh`

The script must work whether the user has activated a venv or not. Use
this strategy:

1. **If `VIRTUAL_ENV` is set in the environment, use it.** Print a banner
   confirming which venv we're installing into.
2. **If not, and `./venv/` exists in the repo root, activate it.**
3. **If not, and `./venv/` does not exist, create one.** Use the same
   Python the script's version gate accepted. Activate it. Print a banner
   telling the user how to re-activate it later.
4. **From this point forward in the script, all `pip` and `$PIP` calls
   target the venv.**

Add a helper near the top of `install.sh`:

```bash
ensure_venv() {
    # If user already activated a venv, respect it
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        info "Using active venv: $VIRTUAL_ENV"
        return 0
    fi

    # Existing project venv?
    if [[ -d "./venv" && -f "./venv/bin/activate" ]]; then
        info "Activating existing ./venv"
        # shellcheck disable=SC1091
        source ./venv/bin/activate
        return 0
    fi

    # Create one with the validated Python
    info "Creating ./venv with $PYTHON"
    "$PYTHON" -m venv ./venv
    # shellcheck disable=SC1091
    source ./venv/bin/activate
    log "venv created. After install, run: source venv/bin/activate"
}
```

Call `ensure_venv` immediately after the Python version gate passes and
before any `pip` / `$PIP` invocation. After activation, redefine:

```bash
PIP="python -m pip"
PYTHON="python"
```

so all subsequent calls use the venv's interpreter. Drop the `--quiet`
flag from the `pip install` call — install errors should be visible.

**Acceptance:**
- Fresh clone, no venv → `./install.sh` creates `./venv/` and installs into
  it successfully.
- Fresh clone, user has run `source /path/to/some/venv/bin/activate` →
  `./install.sh` uses that venv.
- Existing `./venv/` from previous attempt → reused, not clobbered.
- `which nexusrecon` after install shows `.../venv/bin/nexusrecon`.

**Pitfall:** `set -euo pipefail` is on. If `source ./venv/bin/activate`
fails (corrupted venv), the script will abort. Add a `|| { err "venv
activation failed — delete ./venv and retry"; exit 1; }` guard.

---

## Fix 3 (I3) — Python upper-bound gate

**File:** `install.sh:43–52`

Replace the current version check with:

```bash
PYTHON_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

# Lower bound: 3.11
if [[ $PY_MAJOR -lt 3 ]] || { [[ $PY_MAJOR -eq 3 ]] && [[ $PY_MINOR -lt 11 ]]; }; then
    err "Python 3.11+ required. Found: $PYTHON_VERSION"
    err "Install Python 3.13 (recommended) and re-run with PYTHON=python3.13 ./install.sh"
    exit 1
fi

# Upper bound: <3.14 (tracks crewai)
if [[ $PY_MAJOR -gt 3 ]] || { [[ $PY_MAJOR -eq 3 ]] && [[ $PY_MINOR -ge 14 ]]; }; then
    err "Python $PYTHON_VERSION is too new — crewai requires <3.14"
    err ""
    err "Detected Python is: $($PYTHON -c 'import sys; print(sys.executable)')"
    err ""
    err "To fix: install Python 3.13 and re-run with:"
    err "    PYTHON=python3.13 ./install.sh"
    err ""
    err "On macOS:    brew install python@3.13"
    err "On Debian:   apt-get install python3.13 python3.13-venv"
    exit 1
fi

log "Python $PYTHON_VERSION OK"
```

**Acceptance:**
- On Python 3.14: script exits 1 with the multi-line guidance above.
- On Python 3.13: script proceeds.
- On Python 3.10 or older: script exits 1 with the lower-bound message.
- User can override by setting `PYTHON=python3.13` environment variable.

---

## Fix 4 (I4) — Clean up `BREW_PKGS`

**File:** `install.sh:65–76`

Current list contains items that aren't brew formulae. Replace `BREW_PKGS`
with **only** real Homebrew formulae:

```bash
BREW_PKGS=(
    go
    subfinder
    amass
    httpx
    dnsx
    git
    jq
)
```

Remove: `naabu` (formula is `projectdiscovery/projectdiscovery/naabu` —
non-standard tap, not worth the friction; nuclei + httpx covers it),
`waybackurls` (go install only), `gau` (go install only — though brew
may have it now; if so leave it, but the script's `go install` call covers
the fallback), `dnstwist` (PyPI only).

Then route the previously-failing tools through the existing
`install_go_tools()` function, which already handles `waybackurls`, `gau`,
and `gowitness`. Make sure this function is called from `install_macos()`
too, not just `install_debian()`. Currently it's only called from Debian.

Add `dnstwist` install into the **Python packages** step (Fix 2), or add
an explicit one-liner after venv activation:

```bash
python -m pip install dnstwist
```

**Acceptance:**
- `./install.sh` on macOS produces zero `[!] Failed to install <pkg> (optional)`
  lines for tools the project actually needs (`subfinder`, `amass`,
  `httpx`, `dnsx`, `gau`, `waybackurls`, `gowitness`).
- Optional binaries (`nuclei`, `katana`, `arjun`) — note in the runbook
  whether to add them to `install_go_tools()`. Decision: **yes, add them**.
  `nuclei` and `katana` are go installs from projectdiscovery, `arjun` is
  `pip install arjun` (add to Python step).

**Updated `install_go_tools()` list:**

```bash
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/sensepost/gowitness@latest"
)
```

---

## Fix 5 (I7) — Phased operation flags

The current script is all-or-nothing. Add three flags:

```
--skip-system   Skip Homebrew/apt package install (binaries assumed present)
--skip-python   Skip Python venv + pip install (Python deps assumed present)
--yes           Non-interactive; assume defaults; never prompt
```

Implement with simple arg parsing at the top of `main()`:

```bash
SKIP_SYSTEM=0
SKIP_PYTHON=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-system) SKIP_SYSTEM=1; shift ;;
        --skip-python) SKIP_PYTHON=1; shift ;;
        --yes|-y)      ASSUME_YES=1; shift ;;
        --help|-h)
            echo "Usage: ./install.sh [--skip-system] [--skip-python] [--yes]"
            exit 0 ;;
        *)
            err "Unknown flag: $1"; exit 1 ;;
    esac
done
```

Wire them into the existing flow:

- `--skip-system` → skip `install_system_packages`, `install_gitleaks`,
  `install_trufflehog`, `install_amass`
- `--skip-python` → skip `ensure_venv` and `install_python_packages`
- `--yes` → currently the script doesn't prompt, but if you add any
  prompts in the verification step (Fix 6), gate them on `$ASSUME_YES`

**Acceptance:**
- `./install.sh --skip-system` runs Python install only against a venv,
  exits cleanly.
- `./install.sh --skip-python` installs binaries only, exits cleanly.
- `./install.sh --skip-system --skip-python` is a no-op and exits cleanly.
- `./install.sh --help` prints usage.

---

## Fix 6 (I6) — End-of-install verification

After all install steps, run a smoke check:

```bash
verify_install() {
    info "Verifying install..."

    # Python deps importable?
    if ! python -c "import nexusrecon; from nexusrecon.tools.registry import get_registry" 2>/dev/null; then
        err "nexusrecon package not importable inside venv"
        return 1
    fi
    log "nexusrecon package imports OK"

    # CLI entry point present?
    if ! command -v nexusrecon >/dev/null 2>&1; then
        err "nexusrecon CLI not on PATH (venv may not be activated)"
        return 1
    fi
    log "nexusrecon CLI on PATH: $(command -v nexusrecon)"

    # Tool registry populates?
    tool_count=$(python -c "
import nexusrecon.tools.domain, nexusrecon.tools.pretext, nexusrecon.tools.cloud
import nexusrecon.tools.intel, nexusrecon.tools.web, nexusrecon.tools.vuln
import nexusrecon.tools.identity, nexusrecon.tools.mobile
from nexusrecon.tools.registry import get_registry
print(len(list(get_registry()._tools.values())))
" 2>/dev/null) || tool_count=0

    if [[ "$tool_count" -lt 80 ]]; then
        warn "Tool registry returned only $tool_count tools (expected ~89)"
    else
        log "Tool registry OK: $tool_count tools registered"
    fi

    # Binaries present (informational; missing is OK for optional tools)
    info "External binary presence check:"
    for b in subfinder amass httpx dnsx nuclei katana gowitness gau waybackurls gitleaks trufflehog maigret arjun; do
        if command -v "$b" >/dev/null 2>&1; then
            echo "  [+] $b"
        else
            echo "  [ ] $b — gated tool will be unavailable"
        fi
    done
}
```

Call `verify_install` at the end of `main()` before the "Installation
complete!" banner. If it returns non-zero, exit 1 — don't pretend
everything's fine.

**Acceptance:**
- After a clean install, script prints:
  - `[+] nexusrecon package imports OK`
  - `[+] nexusrecon CLI on PATH: /path/to/venv/bin/nexusrecon`
  - `[+] Tool registry OK: 89 tools registered`
  - A binary-presence checklist
- If something is broken (e.g., user has stale `./venv` with old install),
  the script fails loudly instead of declaring success.

---

## Fix 7 (I8) — Refresh user-facing install docs

### `README.md`

Find the "Quick Start" section (around line 92) and replace the Install
subsection with:

```markdown
### 1. Install

**Recommended path** (handles Python venv + system binaries automatically):

\`\`\`bash
git clone <repo> && cd agentic-osint
./install.sh
source venv/bin/activate
\`\`\`

**Python 3.13 is required** (not 3.14 — CrewAI compatibility). If your
default `python3` is 3.14, override:

\`\`\`bash
PYTHON=python3.13 ./install.sh
\`\`\`

**Manual install** (if you prefer to manage your own venv):

\`\`\`bash
python3.13 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
./install.sh --skip-python    # binaries only
\`\`\`

After install, you must `source venv/bin/activate` in every new shell
session before running `nexusrecon`.
```

### `MANUAL.md`

Section 1 ("Prerequisites") line 24–30: add a callout:

```markdown
> **Python version:** 3.11, 3.12, or 3.13 (NOT 3.14 — CrewAI does not
> support 3.14 as of this writing). On macOS with Homebrew, the default
> `python3` may now be 3.14; install Python 3.13 with
> `brew install python@3.13` and override with `PYTHON=python3.13`.
```

Section 2 ("Installation") line 52–70: rewrite to put the venv step
first, mirroring the README. Add a sub-section: "Why a venv? PEP 668
prevents global pip installs on most modern Python distributions
(Homebrew, recent Debian/Ubuntu, Fedora). A venv is mandatory."

Section 12 (Troubleshooting) line 1101+: add three new troubleshooting
entries:

```markdown
### `error: externally-managed-environment`
PEP 668. You ran `pip install` outside a venv. Solution:
\`\`\`bash
python3.13 -m venv venv
source venv/bin/activate
pip install -e .
\`\`\`

### `ERROR: Could not find a version that satisfies the requirement crewai>=0.80.0`
Your Python is too new. CrewAI requires <3.14. Solution:
\`\`\`bash
brew install python@3.13
deactivate; rm -rf venv
PYTHON=python3.13 ./install.sh
\`\`\`

### `nexusrecon: command not found` after install
The venv isn't activated in your current shell.
\`\`\`bash
source venv/bin/activate
which nexusrecon  # should show .../venv/bin/nexusrecon
\`\`\`
```

**Acceptance:**
- README quick-start can be followed by a fresh user on a clean macOS
  with no priors and produces a working install.
- MANUAL troubleshooting section answers each error string we know users
  will see.

---

## Fix 8 (I9) — CLI first-run sanity check (OPTIONAL)

If you have time after the above, add to `nexusrecon/cli/main.py` a
top-of-module check that runs before any subcommand:

```python
def _check_runtime_env() -> None:
    """Fail fast if the runtime environment is obviously broken."""
    import sys
    if sys.version_info < (3, 11) or sys.version_info >= (3, 14):
        sys.stderr.write(
            f"\n[ERROR] NexusRecon requires Python 3.11–3.13. "
            f"Detected: {sys.version_info.major}.{sys.version_info.minor}.\n"
            f"Install 3.13 and re-run inside its venv.\n\n"
        )
        sys.exit(1)
    # Confirm the venv-installed nexusrecon is what's being run
    import nexusrecon
    if "venv" not in (nexusrecon.__file__ or ""):
        sys.stderr.write(
            "[WARN] nexusrecon may not be running inside the project venv. "
            "If commands fail unexpectedly, run: source venv/bin/activate\n"
        )

_check_runtime_env()
```

Place it at module-import time, BEFORE the `app = typer.Typer(...)` line.

**Acceptance:**
- Running `nexusrecon` on Python 3.14 produces a clear error, not a
  CrewAI import traceback.
- Running `nexusrecon` from outside the venv (e.g., user's bare shell)
  prints a soft warning but still works if deps are present.

This fix is **lower priority** because Fix 1 already prevents the user
from installing on the wrong Python. But it catches the case where the
user has multiple Pythons and accidentally invokes the wrong one.

---

## End-to-End Verification (run after all fixes)

Simulate a fresh-clone install. Do this in a clean directory:

```bash
# 0. Pre-flight: confirm syntax
bash -n install.sh                              # zero output = pass

# 1. Simulated fresh clone (skip if you're working in place)
cd /tmp && rm -rf test-install
git clone /Users/waifumachine/agentic-osint test-install
cd test-install

# 2. Test the "wrong Python" gate (must fail loudly)
PYTHON=python3.14 ./install.sh                  # expect: clear error, exit 1
# If you don't have 3.14, simulate by editing install.sh's PYTHON_MINOR
# check to artificially require >=99

# 3. Test the happy path
PYTHON=python3.13 ./install.sh                  # expect: completes cleanly
ls venv/bin/nexusrecon                          # expect: exists
source venv/bin/activate
which nexusrecon                                # expect: /tmp/test-install/venv/bin/nexusrecon
nexusrecon --help                               # expect: Typer help screen
nexusrecon tools | head -5                      # expect: tool table

# 4. Test phase flags
./install.sh --help                             # expect: usage text
./install.sh --skip-system                      # expect: skips binary section
./install.sh --skip-python                      # expect: skips venv/pip section

# 5. Test re-run idempotency
./install.sh                                    # expect: completes cleanly
                                                # all "already installed"

# 6. Test broken-venv recovery path
rm -rf venv && mkdir venv                       # corrupted venv
./install.sh                                    # expect: clean error or rebuild
```

Capture the output of each step. If anything diverges from the expected
behavior, that's a regression to fix before declaring done.

---

## Working Rules (apply to all fixes)

1. Follow Section 0 of `EXECUTION_PLAN_V2_GOLD_STANDARD.md`. No new
   abstractions, no compat shims, surgical edits.
2. After every edit batch, run `bash -n install.sh` for syntax and
   `python3 -m py_compile $(find nexusrecon -name '*.py')` for the
   Python side.
3. Do NOT create git commits. Operator commits manually after review.
4. Do NOT install system binaries while testing — the operator already
   has them. Test by reading the bash logic and simulating.
5. If any fix uncovers an architectural decision that's not specified
   here, stop and ask before guessing.
6. End-of-turn report: under 15 lines per fix. List files changed,
   verification result, any deviations.

---

## Out of Scope (do NOT do)

- Don't rewrite `install.sh` from scratch. Edit in place.
- Don't introduce a `Makefile`, `justfile`, or other build runner.
- Don't move to `uv`, `poetry`, or `pdm` — `pip` + `venv` is the contract.
- Don't add Docker handling here (it's covered separately in
  `docker-compose.yml`).
- Don't refactor the package layout. The `pip install -e .` path stays
  exactly as it is now (repo root, not the nested `nexusrecon/`
  directory).

---

## Estimated Effort

- Fix 1 (pyproject bound): 2 min
- Fix 2 (venv strategy): 30 min
- Fix 3 (Python gate): 10 min
- Fix 4 (brew list cleanup): 15 min
- Fix 5 (phased flags): 20 min
- Fix 6 (verification step): 20 min
- Fix 7 (docs refresh): 30 min
- Fix 8 (CLI runtime check, optional): 15 min

**Total: ~2 hours autonomous Sonnet work.**

Budget ~30% rework due to bash edge cases and the inevitable
"this works in zsh but not bash" surprise.
