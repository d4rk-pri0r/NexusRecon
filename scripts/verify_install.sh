#!/usr/bin/env bash
# ============================================================
# NexusRecon standalone post-install verifier.
#
# Runnable any time after install (not only at the tail of install.sh).
# Confirms the Python package imports, the CLI is reachable, the version
# resolves, and the tool registry builds and reports a sane active vs.
# skipped breakdown via the F-A3 availability_report. Ends with a single
# matrix-ready RESULT line so platform coverage
# (docs/install-verification.md) is one paste.
#
# CI-safe: no network, no API keys required. Key-gated tools are reported
# as "need keys", not failures; external CLI binaries are informational
# (a fresh install legitimately lacks most of them).
#
# Usage:
#   ./scripts/verify_install.sh
#   PYTHON=python3.13 ./scripts/verify_install.sh
#
# Exit 0 = core install sound. Exit 1 = a hard failure (package import,
# version resolution, or registry build).
# ============================================================
set -uo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }
info() { echo -e "${BLUE}[*]${NC} $*"; }

# Pick the interpreter: explicit PYTHON > active venv > ./venv > python3.
if [[ -n "${PYTHON:-}" ]]; then
    PYBIN="$PYTHON"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
    PYBIN="$VIRTUAL_ENV/bin/python"
elif [[ -x "./venv/bin/python" ]]; then
    PYBIN="./venv/bin/python"
elif command -v python >/dev/null 2>&1; then
    PYBIN="python"
else
    PYBIN="python3"
fi

info "NexusRecon install verifier"
info "Interpreter: $PYBIN ($("$PYBIN" --version 2>&1))"

# CLI entry point. A warning, not a hard fail: "python -m nexusrecon" works
# even when the console script is not on PATH (e.g. venv not activated).
if command -v nexusrecon >/dev/null 2>&1; then
    log "nexusrecon CLI on PATH: $(command -v nexusrecon)"
else
    warn "nexusrecon CLI not on PATH (venv not activated?); package import still checked"
fi

# Core checks run in Python so we can reuse availability_report directly.
"$PYBIN" - <<'PY'
import importlib
import platform
import sys

fail: list[str] = []

# 1) Package import + version.
try:
    import nexusrecon  # noqa: F401
    from nexusrecon import __version__ as ver
except Exception as exc:
    print(f"[-] nexusrecon import FAILED: {exc}")
    sys.exit(1)

if not ver or ver == "unknown":
    print(f"[-] version did not resolve (got {ver!r})")
    fail.append("version")
else:
    print(f"[+] nexusrecon {ver} imports OK")

# 2) Tool registry + availability_report (F-A3 bucketing). Importing the
#    registry triggers tool registration; the subpackage imports are a
#    belt-and-suspenders guard in case discovery is ever made lazy.
try:
    for sub in (
        "domain", "pretext", "cloud", "intel", "web", "vuln",
        "identity", "mobile", "code", "secret", "social", "news", "email",
    ):
        try:
            importlib.import_module(f"nexusrecon.tools.{sub}")
        except Exception:
            pass
    from nexusrecon.tools.registry import get_registry
    counts = get_registry().availability_report()["counts"]
except Exception as exc:
    print(f"[-] tool registry / availability_report FAILED: {exc}")
    sys.exit(1)

total = sum(counts.values())
active = counts.get("active", 0)
print(
    f"[+] registry OK: {total} tools "
    f"({active} active, {counts.get('missing_key', 0)} need keys, "
    f"{counts.get('missing_binary', 0)} need install, "
    f"{counts.get('stubbed', 0)} stub)"
)
if total < 50:
    print(f"[-] implausibly low tool count ({total}); registration likely broke")
    fail.append("registry")

# 3) Optional extras (informational only; absence is expected by default).
for extra, mod in (
    ("tls", "curl_cffi"), ("pdf", "weasyprint"),
    ("avatar", "PIL"), ("neo4j", "neo4j"),
):
    try:
        importlib.import_module(mod)
        print(f"[+] extra [{extra}] available ({mod})")
    except Exception:
        print(f"[ ] extra [{extra}] not installed ({mod}) - optional")

plat = f"{platform.system()} {platform.machine()} / Python {platform.python_version()}"
verdict = "FAIL" if fail else "PASS"
print()
print(
    f"RESULT: {verdict} | {plat} | nexusrecon {ver} | "
    f"{active}/{total} tools active"
    + (f" | issues: {','.join(fail)}" if fail else "")
)
sys.exit(1 if fail else 0)
PY
rc=$?

# External binary presence (informational; missing is fine on a fresh box).
# Mirrors install.sh's go-tools + gitleaks/trufflehog/amass/maigret set.
info "External binary presence (informational):"
present=0
total_bins=0
for b in subfinder amass httpx dnsx nuclei katana gowitness gau \
         waybackurls gitleaks trufflehog maigret arjun; do
    total_bins=$((total_bins + 1))
    if command -v "$b" >/dev/null 2>&1; then
        echo "  [+] $b"
        present=$((present + 1))
    else
        echo "  [ ] $b"
    fi
done
info "Binaries present: $present/$total_bins"

if [[ $rc -eq 0 ]]; then
    log "VERIFY PASSED"
else
    err "VERIFY FAILED (see issues above)"
fi
exit $rc
