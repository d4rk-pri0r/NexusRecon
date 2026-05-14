#!/usr/bin/env bash
# NexusRecon smoke test runner
# Usage: ./smoke_test.sh [extra pytest args]
#
# Runs the smoke test suite against real module code with synthetic data.
# Network-dependent tests are soft-skipped in CI (no API keys / no network).
# Hard failures indicate real integration bugs that must be fixed before release.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SMOKE_DIR="tests/smoke"

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  NexusRecon Smoke Test Suite"
echo "══════════════════════════════════════════════════════════"
echo ""

# Run pytest, capturing exit code without triggering set -e
set +e
pytest "$SMOKE_DIR" -v --tb=short "$@"
EXIT_CODE=$?
set -e

echo ""
echo "══════════════════════════════════════════════════════════"

# Re-run with --tb=no just to extract the summary line for display
SUMMARY=$(pytest "$SMOKE_DIR" --tb=no -q "$@" 2>/dev/null | tail -1)

if [ $EXIT_CODE -eq 0 ]; then
    echo "  RESULT: ALL SMOKE TESTS PASSED"
    echo "  $SUMMARY"
    echo "══════════════════════════════════════════════════════════"
    echo ""
    exit 0
elif [ $EXIT_CODE -eq 5 ]; then
    # pytest exit code 5 = no tests collected (unusual but non-fatal)
    echo "  RESULT: NO TESTS COLLECTED — check smoke test directory"
    echo "══════════════════════════════════════════════════════════"
    echo ""
    exit 1
else
    echo "  RESULT: SMOKE TESTS FAILED (exit $EXIT_CODE)"
    echo "  $SUMMARY"
    echo "  Fix the failures above before proceeding to Phase C."
    echo "══════════════════════════════════════════════════════════"
    echo ""
    exit $EXIT_CODE
fi
