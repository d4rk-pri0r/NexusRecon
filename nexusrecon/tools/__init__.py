"""Tool module packages."""
# Import all tool subpackages so that @register_tool decorators fire at import time.
# Without these imports the global ToolRegistry is empty at runtime.
from . import base, cloud, code, domain, identity, intel, mobile, pretext, registry, vuln, web
from .base import Category, OSINTTool, Tier, ToolResult
from .registry import ToolRegistry, get_registry, register_tool
