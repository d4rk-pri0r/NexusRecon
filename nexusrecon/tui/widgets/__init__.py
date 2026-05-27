"""Reusable widgets for the NexusRecon TUI shell.

Widgets here are framework-aware but screen-agnostic — they can be
mounted on any :class:`Screen` and surface persistent state (status
bar, sidebar) that the shell needs.
"""
from nexusrecon.tui.widgets.gauges import (
    INTENSITY_STOPS,
    IntensityGauge,
    MiniSparkline,
    PhaseStrip,
    pick_intensity_color,
)
from nexusrecon.tui.widgets.sidebar import Sidebar
from nexusrecon.tui.widgets.status_bar import StatusBar

__all__ = [
    "INTENSITY_STOPS",
    "IntensityGauge",
    "MiniSparkline",
    "PhaseStrip",
    "Sidebar",
    "StatusBar",
    "pick_intensity_color",
]
