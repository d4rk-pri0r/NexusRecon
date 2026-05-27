"""Textual themes for NexusRecon.

The TUI used to ship with a single hardcoded palette baked straight
into ``app.tcss``. This module externalises the colour story behind
two named themes so:

  1. Operators can pick a variant via the ``NEXUSRECON_TUI_THEME`` env
     var (or the config screen — TUI-1 follow-up).
  2. CSS now references Textual's standard colour variables
     (``$primary``, ``$accent``, ``$background``, etc.) instead of
     hardcoded hex strings ── the whole UI re-themes when the
     active theme changes.
  3. The ``variables`` block exposes NexusRecon-specific colours
     (severity tints, dim/muted text) so per-screen CSS rules stay
     theme-aware.

Two themes ship today:

  - ``nexusrecon-dark`` — the canonical "terminal-hacker" look.
    Deep-navy backgrounds, mint-green accents, sober blue
    secondaries. Matches the 0.5.x TUI defaults pixel-for-pixel
    where possible.
  - ``nexusrecon-hicontrast`` — accessibility / bright-terminal
    variant. Pure-white text on near-black backgrounds, saturated
    primary/success/error to maximise contrast for low-vision
    operators and high-ambient-light environments.

Both themes are :class:`textual.theme.Theme` instances. The app
registers them in :meth:`NexusReconApp.on_mount` via
:meth:`App.register_theme`.
"""
from __future__ import annotations

from textual.theme import Theme

# ──────────────────────────────────────────────────────────────────────
# Shared severity palette
# ──────────────────────────────────────────────────────────────────────
# Severity tints are the same across both themes so a "critical" finding
# always reads the same way regardless of which theme the operator picked.
_SEVERITY = {
    "severity-critical": "#ff3838",
    "severity-high": "#ff8c00",
    "severity-medium": "#f1c40f",
    "severity-low": "#5dade2",
    "severity-info": "#7f8c8d",
}


# ──────────────────────────────────────────────────────────────────────
# nexusrecon-dark — the canonical look
# ──────────────────────────────────────────────────────────────────────

NEXUSRECON_DARK = Theme(
    name="nexusrecon-dark",
    primary="#00ff9c",       # mint accent — borders, primary buttons
    secondary="#1f6feb",     # cobalt — secondary borders, info panels
    accent="#00ff9c",
    background="#0a0e1a",    # deep navy
    surface="#11151f",       # one notch above bg for elevated panels
    panel="#11151f",
    foreground="#c9d1d9",    # primary text
    success="#00ff9c",
    warning="#f1c40f",
    error="#ff5555",
    dark=True,
    variables={
        # NexusRecon-specific extensions (referenced from .tcss as $nx-*)
        "nx-bg-detail": "#07090f",      # darker than bg for detail panes
        "nx-text-muted": "#7f8c8d",     # secondary / metadata text
        "nx-text-dim": "#4a5568",       # tertiary / disabled / hints
        "nx-border-muted": "#7f8c8d",   # panels that shouldn't grab attention
        **_SEVERITY,
    },
)


# ──────────────────────────────────────────────────────────────────────
# nexusrecon-hicontrast — accessibility / bright-terminal variant
# ──────────────────────────────────────────────────────────────────────

NEXUSRECON_HICONTRAST = Theme(
    name="nexusrecon-hicontrast",
    primary="#00ff00",       # pure green — maximum contrast accent
    secondary="#00aaff",     # bright cyan
    accent="#00ff00",
    background="#000000",
    surface="#1a1a1a",
    panel="#1a1a1a",
    foreground="#ffffff",
    success="#00ff00",
    warning="#ffff00",
    error="#ff0000",
    dark=True,
    variables={
        "nx-bg-detail": "#0d0d0d",
        "nx-text-muted": "#b0b0b0",     # bright enough to read clearly
        "nx-text-dim": "#888888",
        "nx-border-muted": "#b0b0b0",
        **_SEVERITY,
    },
)


# ──────────────────────────────────────────────────────────────────────
# Public registration helper
# ──────────────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────────────
# nexusrecon-light — bright-environment / projector variant
# ──────────────────────────────────────────────────────────────────────

NEXUSRECON_LIGHT = Theme(
    name="nexusrecon-light",
    primary="#0a7d4b",       # forest green — readable on light surfaces
    secondary="#1f6feb",     # cobalt holds up across themes
    accent="#0a7d4b",
    background="#fafafa",    # near-white but not pure (less eye strain)
    surface="#f1f5f9",       # one tone deeper for elevated panels
    panel="#f1f5f9",
    foreground="#0f172a",    # near-black text
    success="#10b981",       # emerald — passes AA on light bg
    warning="#d97706",       # amber — passes AA
    error="#dc2626",         # red — passes AA
    dark=False,
    variables={
        "nx-bg-detail": "#e2e8f0",      # deeper grey for detail panes
        "nx-text-muted": "#64748b",     # slate — secondary text
        "nx-text-dim": "#94a3b8",       # lighter slate — disabled/dim
        "nx-border-muted": "#94a3b8",
        **_SEVERITY,
    },
)


#: Themes the app registers on startup, keyed by name.
THEMES: dict[str, Theme] = {
    NEXUSRECON_DARK.name: NEXUSRECON_DARK,
    NEXUSRECON_HICONTRAST.name: NEXUSRECON_HICONTRAST,
    NEXUSRECON_LIGHT.name: NEXUSRECON_LIGHT,
}

#: Theme used when no operator preference is set.
DEFAULT_THEME = NEXUSRECON_DARK.name


def resolve_theme_name(requested: str | None) -> str:
    """Pick a theme name, falling back to the default on unknown input.

    ``requested`` typically comes from a config setting or env var; an
    unknown value (typo, theme removed in a future release) is silently
    coerced to :data:`DEFAULT_THEME` rather than crashing the app at
    startup.
    """
    if requested and requested in THEMES:
        return requested
    return DEFAULT_THEME


# ──────────────────────────────────────────────────────────────────────
# User-contributed themes (TUI-8)
# ──────────────────────────────────────────────────────────────────────


USER_THEMES_DIR = "~/.nexusrecon/themes"


def _parse_user_theme(path) -> Theme | None:
    """Build a :class:`Theme` from a TOML file at ``path``.

    Expected schema:

    .. code-block:: toml

        name      = "my-theme"
        primary   = "#00ff9c"
        secondary = "#1f6feb"
        accent    = "#00ff9c"
        background = "#0a0e1a"
        surface   = "#11151f"   # optional
        panel     = "#11151f"   # optional
        foreground = "#c9d1d9"
        success   = "#00ff9c"
        warning   = "#f1c40f"
        error     = "#ff5555"
        dark      = true

        [variables]
        nx-bg-detail     = "#07090f"
        nx-text-muted    = "#7f8c8d"
        nx-text-dim      = "#4a5568"
        nx-border-muted  = "#7f8c8d"

    Missing optional fields fall back to the shipped-dark equivalents so
    operators don't have to repeat the entire palette to tweak one
    color. Severity tints (severity-critical, etc.) are always inherited
    from ``_SEVERITY`` — operators don't customize these because they
    carry semantic meaning across the app.

    Returns ``None`` (and logs to stderr) on parse failure so a broken
    theme file can't tank app startup.
    """
    import sys
    import tomllib
    from pathlib import Path

    p = Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        sys.stderr.write(
            f"[warn] Skipping user theme {p.name}: parse failed ── {exc}\n",
        )
        return None

    name = data.get("name")
    if not name or not isinstance(name, str):
        sys.stderr.write(
            f"[warn] Skipping user theme {p.name}: missing 'name' field\n",
        )
        return None

    # Merge user variables on top of the severity baseline so users
    # can override nx-* without re-specifying severity tints.
    user_vars = data.get("variables") or {}
    if not isinstance(user_vars, dict):
        user_vars = {}
    merged_vars = {**_SEVERITY, **user_vars}

    try:
        return Theme(
            name=name,
            primary=data.get("primary", NEXUSRECON_DARK.primary),
            secondary=data.get("secondary", NEXUSRECON_DARK.secondary),
            accent=data.get("accent", data.get("primary", NEXUSRECON_DARK.accent)),
            background=data.get("background", NEXUSRECON_DARK.background),
            surface=data.get("surface", data.get("background", NEXUSRECON_DARK.surface)),
            panel=data.get("panel", data.get("surface", NEXUSRECON_DARK.panel)),
            foreground=data.get("foreground", NEXUSRECON_DARK.foreground),
            success=data.get("success", NEXUSRECON_DARK.success),
            warning=data.get("warning", NEXUSRECON_DARK.warning),
            error=data.get("error", NEXUSRECON_DARK.error),
            dark=bool(data.get("dark", True)),
            variables=merged_vars,
        )
    except Exception as exc:
        sys.stderr.write(
            f"[warn] Skipping user theme {p.name}: Theme() ── {exc}\n",
        )
        return None


def load_user_themes(
    themes_dir: str | None = None,
) -> dict[str, Theme]:
    """Discover and parse every ``*.toml`` file under
    ``~/.nexusrecon/themes/`` (or ``themes_dir`` when supplied
    for testing).

    Returns a dict keyed by theme name. Failures on individual
    files do NOT raise — they log to stderr and the loader keeps
    going. The shipped themes always remain available; user
    themes are additive.
    """
    import os
    from pathlib import Path

    base = Path(os.path.expanduser(themes_dir or USER_THEMES_DIR))
    out: dict[str, Theme] = {}
    if not base.exists():
        return out
    for path in sorted(base.glob("*.toml")):
        theme = _parse_user_theme(path)
        if theme is not None:
            out[theme.name] = theme
    return out


def all_themes() -> dict[str, Theme]:
    """Return the shipped themes merged with any user themes
    discovered on disk. User themes can OVERRIDE a shipped name
    (operator's choice — if they want their own
    ``nexusrecon-dark``, they get it)."""
    out = dict(THEMES)
    out.update(load_user_themes())
    return out
