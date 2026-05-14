"""ASCII banner for the TUI welcome screen.

Split into three pieces so the welcome screen can colorize them
independently — the logo + version line render in bright accent green
while the attribution stays in dim gray (subtle, not competing for
attention with the headline brand)."""
from __future__ import annotations

import os
import shutil


# The ASCII logo block + version line — rendered in bright accent.
BANNER_LOGO = """\
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
                                    RECON v3.0"""

# Subtle author attribution — rendered separately in dim gray so it
# reads like a comment/footer, not a competing brand line.
ATTRIBUTION = "// d4rk pri0r · darkpriorlabs //"

# Fallback for narrow / non-UTF-8 terminals.
BANNER_FALLBACK = "NEXUSRECON v3.0  // d4rk pri0r · darkpriorlabs //"


def _terminal_supports_full_banner() -> bool:
    """True if the terminal is wide enough and capable of rendering the
    ASCII block. Falls back to plain text on dumb / narrow terminals."""
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        cols = 80
    term = os.environ.get("TERM", "")
    return cols >= 50 and "dumb" not in term


def render_banner() -> str:
    """Return the logo+version block (without the attribution).

    Kept as a single function for backward compatibility with existing
    callers that expect one string. The welcome screen renders the
    attribution as a separate dim-styled widget below this block.
    """
    if not _terminal_supports_full_banner():
        return BANNER_FALLBACK
    return BANNER_LOGO


def render_attribution() -> str:
    """Return the dim-styled attribution line, or empty on dumb terminals
    (the BANNER_FALLBACK already inlines the attribution there)."""
    if not _terminal_supports_full_banner():
        return ""
    return ATTRIBUTION
