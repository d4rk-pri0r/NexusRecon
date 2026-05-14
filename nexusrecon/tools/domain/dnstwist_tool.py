"""DNSTWIST typosquat detection tool."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class DNSTwistTool(OSINTTool):
    name = "dnstwist"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "Typosquat domain detection via dnstwist"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            # Generate fuzzed domains using dnstwist library
            try:
                import dnstwist
                fuzzed = dnstwist.FuzzDomain(target)
                fuzzed.generate()
                results = [
                    {
                        "domain": d["domain-name"],
                        "fuzzer": d["fuzzer"],
                        "registered": d.get("dns-a") is not None,
                        "dns_a": d.get("dns-a", []),
                        "mx": d.get("dns-mx", []),
                    }
                    for d in fuzzed.get()
                    if d.get("dns-a")  # Only registered domains
                ]
            except ImportError:
                # Fallback: basic permutation without dnstwist
                results = self._basic_permutations(target)

            return ToolResult(
                success=True, source=self.name, data={"typosquats": results},
                result_count=len(results),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    @staticmethod
    def _basic_permutations(domain: str) -> List[Dict]:
        """Basic permutation fallback when dnstwist is not installed."""
        name = domain.split(".")[0]
        tld = ".".join(domain.split(".")[1:])
        perms = []
        # Bit flips, additions, etc.
        variations = [
            name + "1", name + "2", "my" + name, "get" + name, name + "app",
            name + "dev", name + "prod", name + "api", name + "login",
            name + "mail", name + "secure",
        ]
        for v in variations:
            perms.append({"domain": f"{v}.{tld}", "fuzzer": "basic", "registered": False})
        return perms
