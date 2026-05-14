"""Full DNS record sweep tool."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import dns.asyncresolver
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class DNSTool(OSINTTool):
    name = "dns"
    tier = Tier.T1
    category = Category.DNS
    requires_keys = []
    description = "Full DNS record sweep (A, AAAA, MX, TXT, NS, SOA, CAA, SRV, PTR, CNAME)"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolvers = self.config.dns_resolver_list()
            if resolvers:
                resolver.nameservers = resolvers
            resolver.timeout = 5
            resolver.lifetime = 10

            record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "CNAME"]
            results: Dict[str, List[str]] = {}

            for rtype in record_types:
                try:
                    answers = await resolver.resolve(target, rtype)
                    results[rtype] = [str(rdata).rstrip(".") for rdata in answers]
                except Exception:
                    results[rtype] = []

            # SPF / DKIM / DMARC extraction from TXT records
            txt_records = results.get("TXT", [])
            results["spf_records"] = [r for r in txt_records if r.startswith("v=spf1")]
            results["dmarc_records"] = [r for r in txt_records if "v=DMARC1" in r]
            results["dkim_candidates"] = [r for r in txt_records if "v=DKIM1" in r]

            # DMARC check
            try:
                answers = await resolver.resolve(f"_dmarc.{target}", "TXT")
                results["dmarc_record"] = [str(r).rstrip(".") for r in answers]
            except Exception:
                results["dmarc_record"] = []

            # MX target resolution
            mx_targets = []
            for mx in results.get("MX", []):
                # Parse priority and hostname
                parts = mx.split()
                if len(parts) >= 2:
                    mx_targets.append(parts[-1])

            return ToolResult(
                success=True, source=self.name, data=results,
                result_count=sum(len(v) for v in results.values()),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))
