"""Email security posture assessment tool — SPF/DKIM/DMARC/MTA-STS/BIMI scoring."""
from __future__ import annotations

import re
from typing import Any

import dns.asyncresolver

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class EmailSecTool(OSINTTool):
    name = "email_sec"
    tier = Tier.T0
    category = Category.EMAIL
    requires_keys = []
    description = "SPF/DKIM/DMARC/MTA-STS/BIMI parse and security score"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolvers = self.config.dns_resolver_list()
            if resolvers:
                resolver.nameservers = resolvers
            resolver.timeout = 5
            resolver.lifetime = 10

            results: dict[str, Any] = {}

            # SPF
            results["spf"] = await self._check_spf(resolver, target)

            # DMARC
            results["dmarc"] = await self._check_dmarc(resolver, target)

            # DKIM selectors
            results["dkim"] = await self._check_dkim(resolver, target)

            # MTA-STS
            results["mta_sts"] = await self._check_mta_sts(resolver, target)

            # BIMI
            results["bimi"] = await self._check_bimi(resolver, target)

            # TLS-RPT
            results["tls_rpt"] = await self._check_tls_rpt(resolver, target)

            # Overall score
            results["score"] = self._calculate_score(results)

            return ToolResult(
                success=True, source=self.name, data=results, result_count=1,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    async def _check_spf(self, resolver, domain: str) -> dict[str, Any]:
        try:
            answers = await resolver.resolve(domain, "TXT")
            spf_records = [str(r).strip('"') for r in answers if "v=spf1" in str(r)]
            if spf_records:
                record = spf_records[0]
                has_all = "-all" in record
                has_soft = "~all" in record
                has_neutral = "?all" in record
                has_none = "+all" in record

                score = 80
                if has_all:
                    score = 100
                    status = "strong"
                elif has_soft:
                    score = 60
                    status = "moderate"
                elif has_neutral:
                    score = 30
                    status = "weak"
                elif has_none:
                    score = 0
                    status = "dangerous"
                else:
                    score = 40
                    status = "unknown"

                includes = re.findall(r'include:([^\s]+)', record)
                return {
                    "found": True, "record": record, "score": score,
                    "status": status, "includes": includes,
                }
        except Exception:
            pass
        return {"found": False, "score": 0, "status": "missing"}

    async def _check_dmarc(self, resolver, domain: str) -> dict[str, Any]:
        try:
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            records = [str(r).strip('"') for r in answers if "v=DMARC1" in str(r)]
            if records:
                record = records[0]
                policy = re.search(r'p=([a-z]+)', record)
                pct = re.search(r'pct=(\d+)', record)
                rua = re.search(r'rua=([^\s;]+)', record)
                ruf = re.search(r'ruf=([^\s;]+)', record)
                sp = re.search(r'sp=([a-z]+)', record)

                policy_val = policy.group(1) if policy else "none"
                score = {"reject": 100, "quarantine": 70, "none": 20}.get(policy_val, 0)

                return {
                    "found": True, "record": record, "policy": policy_val,
                    "pct": int(pct.group(1)) if pct else 100,
                    "rua": bool(rua), "ruf": bool(ruf),
                    "subdomain_policy": sp.group(1) if sp else None,
                    "score": score,
                }
        except Exception:
            pass
        return {"found": False, "score": 0, "status": "missing"}

    async def _check_dkim(self, resolver, domain: str) -> dict[str, Any]:
        selectors = ["selector1", "selector2", "google", "default"]
        found = []
        for sel in selectors:
            try:
                qname = f"{sel}._domainkey.{domain}"
                answers = await resolver.resolve(qname, "CNAME")
                found.append({"selector": sel, "cname": str(answers[0]).rstrip(".")})
            except Exception:
                try:
                    answers = await resolver.resolve(qname, "TXT")
                    found.append({"selector": sel, "txt": str(answers[0])[:100]})
                except Exception:
                    continue

        return {
            "found": len(found), "selectors": found,
            "score": 100 if len(found) >= 2 else (50 if len(found) == 1 else 0),
        }

    async def _check_mta_sts(self, resolver, domain: str) -> dict[str, Any]:
        try:
            answers = await resolver.resolve(f"_mta-sts.{domain}", "TXT")
            records = [str(r).strip('"') for r in answers if "v=STSv1" in str(r)]
            return {"found": True, "records": records, "score": 100} if records else {"found": False, "score": 0}
        except Exception:
            return {"found": False, "score": 0}

    async def _check_bimi(self, resolver, domain: str) -> dict[str, Any]:
        try:
            answers = await resolver.resolve(f"default._bimi.{domain}", "TXT")
            records = [str(r).strip('"') for r in answers if "v=BIMI1" in str(r)]
            return {"found": True, "records": records, "score": 100} if records else {"found": False, "score": 0}
        except Exception:
            return {"found": False, "score": 0}

    async def _check_tls_rpt(self, resolver, domain: str) -> dict[str, Any]:
        try:
            answers = await resolver.resolve(f"_smtp._tls.{domain}", "TXT")
            records = [str(r).strip('"') for r in answers if "v=TLSRPTv1" in str(r)]
            return {"found": True, "records": records, "score": 100} if records else {"found": False, "score": 0}
        except Exception:
            return {"found": False, "score": 0}

    @staticmethod
    def _calculate_score(results: dict) -> dict[str, Any]:
        components = {
            "spf": results.get("spf", {}).get("score", 0),
            "dmarc": results.get("dmarc", {}).get("score", 0),
            "dkim": results.get("dkim", {}).get("score", 0),
            "mta_sts": results.get("mta_sts", {}).get("score", 0),
            "bimi": results.get("bimi", {}).get("score", 0),
            "tls_rpt": results.get("tls_rpt", {}).get("score", 0),
        }
        avg = sum(components.values()) / len(components) if components else 0
        return {
            "overall": round(avg, 1),
            "components": components,
            "grade": "A" if avg >= 80 else "B" if avg >= 60 else "C" if avg >= 40 else "D" if avg >= 20 else "F",
        }
