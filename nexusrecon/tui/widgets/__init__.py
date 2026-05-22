"""Reusable widgets for the NexusRecon TUI shell.

Widgets here are framework-aware but screen-agnostic — they can be
mounted on any :class:`Screen` and surface persistent state (status
bar, sidebar) that the shell needs.
"""
from nexusrecon.tui.widgets.sidebar import Sidebar
from nexusrecon.tui.widgets.status_bar import StatusBar

__all__ = ["Sidebar", "StatusBar"]
