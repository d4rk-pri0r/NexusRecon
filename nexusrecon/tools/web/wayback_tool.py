"""Wayback Machine deep crawl tool."""
from __future__ import annotations

from typing import Any

from waybackpy import WaybackMachineCDXServerAPI

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class WaybackTool(OSINTTool):
    name = "wayback"
    tier = Tier.T0
    category = Category.WEB
    requires_keys = []
    description = "Wayback Machine URL and snapshot discovery"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            cdx = WaybackMachineCDXServerAPI(target, user_agent="NexusRecon/1.0")
            urls = set()
            snapshots = []
            count = 0
            for snapshot in cdx.snapshots():
                count += 1
                if count > 1000:
                    break
                # ``waybackpy.CDXSnapshot`` exposes the captured URL as
                # ``.original`` and the HTTP status code as ``.statuscode``
                # (see venv/lib/.../waybackpy/cdx_snapshot.py). An earlier
                # version of this tool read ``.url`` and ``.status`` which
                # don't exist on the real class — every live call raised
                # ``AttributeError`` inside the outer ``try`` and the
                # operator just saw ``success=False``.
                url = snapshot.original
                urls.add(url)
                snapshots.append({
                    "url": url,
                    "timestamp": snapshot.timestamp,
                    "status": snapshot.statuscode,
                    "mimetype": snapshot.mimetype,
                })

            return ToolResult(
                success=True, source=self.name,
                data={"urls": sorted(urls), "snapshots": snapshots[:50]},
                result_count=len(urls),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))
