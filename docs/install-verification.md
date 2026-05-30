# Install verification

`./install.sh` is the dependency installer; `scripts/verify_install.sh` is
the standalone post-install health check. Run the verifier after a fresh
install on each target platform and record the result in the coverage
matrix below. This closes the "Fresh-VM install verification" beta blocker
once all three rows are green.

## Running the verifier

```sh
./scripts/verify_install.sh
# or pin the interpreter:
PYTHON=python3.13 ./scripts/verify_install.sh
```

It auto-detects the interpreter (explicit `PYTHON` > active venv >
`./venv` > `python3`) and is CI-safe: no network calls, no API keys
required. It checks, in order:

1. The `nexusrecon` package imports and its version resolves (not
   `unknown`).
2. The CLI console script is on `PATH` (a warning, not a failure:
   `python -m nexusrecon` works even when the venv is not activated).
3. The tool registry builds and reports a sane active / skipped breakdown
   via the F-A3 `availability_report` (`need keys` vs. `need install` are
   distinguished). A total under 50 tools is treated as a registration
   failure.
4. Optional extras (`tls` / `pdf` / `avatar` / `neo4j`) are reported as
   present or absent (informational only).
5. External CLI binaries (`subfinder`, `amass`, `httpx`, `nuclei`, ...)
   are listed as present or missing (informational; a fresh box
   legitimately lacks most of them, and the tools that need them are
   bucketed as `need install` rather than failing).

The script exits `0` when the core install is sound and prints a
matrix-ready `RESULT:` line. It exits `1` only on a hard failure (package
import, version resolution, or registry build).

## Platform coverage matrix

Paste the verifier's `RESULT:` line into the row, with the date and any
notes. "install.sh" records whether the installer itself completed
cleanly on that platform.

| Platform | Arch | Python | install.sh | verify_install | Date | Notes |
|---|---|---|---|---|---|---|
| macOS (M-series) | arm64 | 3.13.13 | ok | PASS (80/97 active) | 2026-05-30 | 11/13 binaries present (`maigret`, `arjun` absent); extras `tls`+`avatar` present. Verified on the dev workstation. |
| Linux x86_64 | x86_64 | | not yet run | not yet run | | Debian/Ubuntu/Kali path in `install.sh`. |
| Linux arm64 | arm64 | | not yet run | not yet run | | Same Debian path; confirm Go-tool and gitleaks/amass arm64 release URLs resolve. |

### Notes on the macOS run

- `install.sh` had already provisioned this workstation; the Go tools
  (`subfinder`/`httpx`/`dnsx`/`nuclei`/`katana`/`gowitness`/`gau`/`waybackurls`),
  `gitleaks`, `trufflehog`, and `amass` are all on `PATH`.
- `maigret` and `arjun` are not installed, so they correctly bucket as
  `need install` (2 tools) rather than as failures. `maigret` ships via
  `pipx install maigret`; `arjun` via `pipx install arjun`.
- `curl_cffi` (the `[tls]` extra for JA3 impersonation) is present in
  this venv; `weasyprint` (`[pdf]`) and `neo4j` are not, which is the
  expected default.

## What "verified" means for the beta blocker

The blocker asks for `./install.sh` to be tested on M-series macOS, Linux
x86_64, and Linux arm64, with platform-specific failures documented and
`pipx install nexusrecon` confirmed once published. The verifier gives a
reproducible, paste-once result per platform so the matrix is filled by
running one command on each box rather than by eyeballing a log. The
macOS row is verified; the two Linux rows need a run on the respective
hardware (or VM) to close the blocker.
