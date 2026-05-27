# Recording the README demo gif

The 90-second TUI walkthrough embedded in the [README](../../README.md)
is captured deterministically with [VHS](https://github.com/charmbracelet/vhs)
— a CLI that drives a real terminal session from a scripted tape file
and emits a GIF. Doing it this way (instead of hand-recording with
screen-capture software) means:

- The recording reproduces byte-for-byte on every machine.
- Edits to the script live in version control alongside the code
  they document.
- The gif gets refreshed by re-running one command after a UI change.

## One-time setup

VHS uses `ttyd` and a headless browser to render the terminal. Install
both via Homebrew (macOS) or the package manager of your choice:

```sh
brew install vhs ttyd ffmpeg
```

Confirm VHS is on `$PATH`:

```sh
vhs --version
```

## Render the gif

From the repo root:

```sh
make demo
```

That target runs `vhs docs/demo/nexusrecon.tape` and produces
`docs/demo/nexusrecon.gif`. The README references that path directly
— no further action needed.

If `make` isn't available, run VHS yourself:

```sh
vhs docs/demo/nexusrecon.tape
```

## Recording prerequisites

The tape script assumes:

1. **`nexusrecon` is on `$PATH`** (e.g. via `pipx install -e .` from the
   repo root, or `source venv/bin/activate` in a venv where the
   package is installed in editable mode).
2. **An LLM provider key is configured** so the dashboard's onboarding
   nudge is dismissed and the demo lands on a populated dashboard.
   The tape doesn't run a campaign, so token cost is zero — but the
   key needs to exist or the "👋 Press c to configure" nudge will
   linger.
3. **A clean `~/.nexusrecon/.onboarding_dismissed` flag** so the
   nudge stays hidden:

   ```sh
   mkdir -p ~/.nexusrecon
   touch ~/.nexusrecon/.onboarding_dismissed
   ```

4. **`JetBrains Mono` (or a comparable monospace font)** installed
   locally — the tape pins this in `Set FontFamily`. Swap to whatever
   you have if needed.

## Editing the script

`docs/demo/nexusrecon.tape` is the VHS DSL. The grammar is documented
at <https://github.com/charmbracelet/vhs#vhs-command-reference>. The
high-level beats:

| Beat | Tape lines | Duration |
|------|------------|----------|
| Launch | `Type "nexusrecon"` → `Enter` | ~3s |
| Dashboard tour | initial `Sleep 2.5s` | ~3s |
| Arrow nav to Tools | three `Down` + `Enter` | ~4s |
| Tools filter + detail | `Type "/"` + filter + `Tab` | ~5s |
| Edit modal demo | `Type "c"` + placeholder text + `Escape` | ~5s |
| Config screen | `Type "c"` + category cycling | ~6s |
| Command palette | `Ctrl+P` + filter + `Escape` | ~4s |
| Quit | `Type "q"` | ~1s |

Total budget is ~90 seconds at default speed — keep individual
`Sleep` values modest so the gif doesn't feel laggy.

## What NOT to include in the recording

- **Real API keys.** The placeholder string in the tape
  (`ghp_DEMO_TOKEN_PLACEHOLDER`) is never saved (we hit `Escape`
  before the modal commits). Don't substitute a real token for the
  recording.
- **Campaign output.** The demo doesn't run a campaign, so no client
  data lands on screen. Don't record against a real engagement.
- **A `.env` file with secrets visible.** The tape doesn't open
  the Config edit modal far enough to render the masked value, but
  set `ANTHROPIC_API_KEY` to a known throwaway in your shell before
  recording if you want zero risk.

## Verifying the recording

After `make demo`:

```sh
file docs/demo/nexusrecon.gif        # should report "GIF image data"
ls -lh docs/demo/nexusrecon.gif      # ~1-3 MB at the default geometry
```

Open the gif in a viewer and confirm:

1. The dashboard banner is visible.
2. The sidebar cursor moves on each `Down` event.
3. The Tools filter narrows the centre list.
4. The EditKeyModal title shows `GITHUB_TOKEN` (or whichever key
   the editable-target heuristic picked).
5. The Config screen shows only LLM / OPSEC / Storage / Debug
   categories — no tool API-key categories.

If any of those drift (UI redesign, new beta, etc.), edit the tape
to match and re-run `make demo`.
