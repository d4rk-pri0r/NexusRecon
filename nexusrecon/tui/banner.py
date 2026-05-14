"""ASCII banner for the TUI welcome screen.

Exposes the brand as three separate text blocks (logo, version,
attribution) so each can be rendered as its own widget and centered
independently. Earlier versions glued them together with hardcoded
trailing spaces — that broke as soon as the parent container resized.
"""
from __future__ import annotations

import os
import shutil

# Single source of truth for the version string — derived from the
# package __version__ in `nexusrecon/__init__.py` (which mirrors
# pyproject.toml). Bump the version in __init__.py; the banner picks
# it up automatically.
try:
    from nexusrecon import __version__ as _PKG_VERSION
except Exception:
    _PKG_VERSION = "?.?.?"


# The ASCII logo block. Each line starts at column 0 and the rightmost
# glyph lands at column 45. Width of the logo when measured by visible
# columns: ~46 chars.
BANNER_LOGO = """\
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝"""

VERSION_STR = f"RECON v{_PKG_VERSION}"

ATTRIBUTION = "// d4rk pri0r · darkpriorlabs //"

# Fallback for narrow / non-UTF-8 terminals — single line so it fits.
# Strips the "RECON " prefix from VERSION_STR since "NEXUSRECON" already
# contains it — avoids the awkward "NEXUSRECON RECON v0.5.0" doubling.
BANNER_FALLBACK = f"NEXUSRECON v{_PKG_VERSION}  {ATTRIBUTION}"


def _terminal_supports_full_banner() -> bool:
    """True when the terminal is wide enough and capable of rendering the
    ASCII block. Falls back to plain text on dumb / narrow terminals."""
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        cols = 80
    term = os.environ.get("TERM", "")
    return cols >= 50 and "dumb" not in term


def render_banner() -> str:
    """Return the logo block (no version, no attribution).

    Welcome screen renders this in a Static that's wrapped in a Center
    container so the whole block centers horizontally regardless of
    the parent's width.
    """
    if not _terminal_supports_full_banner():
        return BANNER_FALLBACK
    return BANNER_LOGO


def render_version() -> str:
    """Return the formatted version string (e.g. 'RECON v0.5.0').

    Rendered as a separate small Static below the logo so it centers
    independently from the ASCII art.
    """
    if not _terminal_supports_full_banner():
        return ""
    return VERSION_STR


def render_attribution() -> str:
    """Return the dim author attribution line, or empty on dumb terminals
    (the fallback banner already inlines the attribution there)."""
    if not _terminal_supports_full_banner():
        return ""
    return ATTRIBUTION
