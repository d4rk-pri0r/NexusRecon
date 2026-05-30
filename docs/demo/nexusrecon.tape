# VHS tape for the NexusRecon 90-second README demo.
#
# Render with:
#     make demo            # from repo root (requires `vhs` on PATH)
#   OR
#     vhs docs/demo/nexusrecon.tape
#
# Output: docs/demo/nexusrecon.gif (referenced from the README).
#
# What this captures:
#   1. Launching the TUI.
#   2. Dashboard with sidebar nav + Tool health card (active / need keys /
#      need install breakdown) + Top gaps + Needs-install hint.
#   3. Arrow-key navigation into the Tools browser.
#   4. Tools filter, per-tool detail, per-key configured/missing markers.
#   5. The Config screen showing only app-wide settings (no tool keys).
#   6. Command palette (Ctrl+P).
#   7. Clean quit.
#
# Total budget: ~90 seconds at default speed.
#
# Editing notes:
#   - `Sleep` values: keep individual pauses ≤ 3s so the gif doesn't
#     feel laggy. Use `Sleep 2.5` between sections; `Sleep 800ms` for
#     beats between keystrokes.
#   - `Type` sends literal text; use `Enter` for the return key,
#     `Tab`, `Up`, `Down`, `Ctrl+P`, etc. for non-text keys.
#   - The `Set` directives at the top fix the recording geometry so
#     the gif looks the same on every machine.

# ── Recording geometry ──────────────────────────────────────────────
Output docs/demo/nexusrecon.gif
Set Shell "zsh"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1280
Set Height 800
Set Padding 20
Set TypingSpeed 60ms
Set Theme "Dracula"

# ── Cold open ───────────────────────────────────────────────────────
# Show the prompt so viewers know what command kicked it off.
Type "nexusrecon"
Sleep 800ms
Enter
# TUI launch — banner + first paint take a beat.
Sleep 3s

# ── Dashboard tour ──────────────────────────────────────────────────
# Let the viewer absorb the dashboard for a moment before we move.
Sleep 2.5s

# Arrow down to "Tools" entry (Dashboard → New → Past → Tools = 3 ↓).
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 800ms

# Open the Tools browser.
Enter
Sleep 2.5s

# ── Tools browser ───────────────────────────────────────────────────
# Filter to a tool we want to highlight.
Type "/"
Sleep 500ms
Type "github_recon"
Sleep 2s

# Show the detail pane's per-key required/optional status by pressing
# down once (centre list).
Tab
Sleep 600ms
Sleep 2s

# Press `c` to open the EditKeyModal directly on the first
# unconfigured key (GITHUB_TOKEN, when not already set).
Type "c"
Sleep 2s

# Show that we'd type a token here — we DON'T actually save one in
# the demo. Esc closes the modal.
Type "ghp_DEMO_TOKEN_PLACEHOLDER"
Sleep 1.5s
Escape
Sleep 1s

# Back out of the Tools screen.
Escape
Sleep 1.5s

# ── Config screen ───────────────────────────────────────────────────
# Show the slimmed Config menu (LLM / OPSEC / Storage / Debug only —
# tool keys live in Tools, not here).
Type "c"
Sleep 2.5s

# Cycle a couple of categories so the right-hand panel updates.
Down
Sleep 800ms
Down
Sleep 800ms
Down
Sleep 1.5s

Escape
Sleep 1.5s

# ── Command palette ─────────────────────────────────────────────────
Ctrl+P
Sleep 1.5s
Type "help"
Sleep 1.5s
Escape
Sleep 800ms

# ── Quit ────────────────────────────────────────────────────────────
Type "q"
Sleep 1s
