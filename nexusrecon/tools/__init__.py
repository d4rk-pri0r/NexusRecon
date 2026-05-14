"""Tool module packages."""
from . import base, registry
from .base import OSINTTool, Tier, Category, ToolResult
from .registry import ToolRegistry, register_tool, get_registry

# Import all tool subpackages so that @register_tool decorators fire at import time.
# Without these imports the global ToolRegistry is empty at runtime.
from . import domain, cloud, code, identity, intel, web, vuln, pretext, mobile