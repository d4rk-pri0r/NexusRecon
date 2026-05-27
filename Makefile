# NexusRecon — operator-facing convenience targets.
#
# These are thin wrappers over commands the README documents. They
# exist so first-timers and CI don't need to memorise the exact
# invocation. Run ``make`` with no args to see the menu.

.PHONY: help demo demo-clean test test-unit test-fast

help:  ## Show available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

demo:  ## Re-record the README demo gif (requires `vhs` on PATH)
	@command -v vhs >/dev/null 2>&1 || { \
		echo "[err] 'vhs' not found on PATH."; \
		echo "      Install it (macOS): brew install vhs ttyd ffmpeg"; \
		echo "      See docs/demo/RECORDING.md for full setup."; \
		exit 1; \
	}
	vhs docs/demo/nexusrecon.tape
	@echo
	@echo "Wrote docs/demo/nexusrecon.gif"
	@ls -lh docs/demo/nexusrecon.gif 2>/dev/null || true

demo-clean:  ## Remove the rendered demo gif
	rm -f docs/demo/nexusrecon.gif

test:  ## Run the full unit test suite
	python -m pytest tests/unit/ -q

test-unit:  ## Alias for `make test`
	$(MAKE) test

test-fast:  ## Quick smoke: TUI + reports only
	python -m pytest tests/unit/test_tui_phase_*.py tests/unit/test_report_quality*.py -q
