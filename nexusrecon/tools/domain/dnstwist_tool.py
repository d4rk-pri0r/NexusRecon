"""DNSTWIST typosquat detection tool.

Generates domain permutations via :class:`dnstwist.Fuzzer` and resolves
each candidate against DNS to identify the ones that are actually
registered (i.e. resolve to an A record). Only resolving permutations
are surfaced to the operator — the unresolved ones are noise from a
defensive standpoint.

An earlier revision of this tool called ``dnstwist.FuzzDomain``, which
does not exist in the modern (>=20240000) ``dnstwist`` library — the
real class is ``Fuzzer``. The typo caused every live call to raise
``AttributeError`` inside the broad ``try/except`` and surface as a
silent ``success=False``. See ``venv/lib/.../dnstwist.py`` for the
authoritative API.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import dns.asyncresolver

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


# Cap how many permutations we DNS-resolve in a single call. ``dnstwist``
# typically generates 1000+ candidates per domain; checking all of them
# costs ~30s and floods the local resolver. 200 covers the highest-value
# fuzzers (replacement, omission, addition, homoglyph) with margin.
_MAX_DNS_CHECK = 200

# Per-lookup timeouts. Generous enough that genuinely-slow upstream
# nameservers don't get reported as "not registered" but tight enough
# that the total call stays under ~10s for the full 200-candidate sweep.
_DNS_TIMEOUT_SEC = 2.0
_DNS_LIFETIME_SEC = 4.0


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
            try:
                import dnstwist
            except ImportError:
                results = self._basic_permutations(target)
                return ToolResult(
                    success=True, source=self.name,
                    data={"typosquats": results},
                    result_count=len(results),
                )

            fuzzer = dnstwist.Fuzzer(target)
            fuzzer.generate()

            # ``Fuzzer.domains`` is a set of ``Permutation`` dicts; each
            # has at minimum ``domain`` and ``fuzzer`` keys. The fuzzer
            # also yields a ``*original`` entry representing the input
            # itself — skip it; we only care about permutations.
            candidates: List[Dict[str, Any]] = []
            for perm in fuzzer.domains:
                fuzzer_name = perm.get("fuzzer")
                domain = perm.get("domain")
                if not domain or fuzzer_name == "*original":
                    continue
                candidates.append({"fuzzer": fuzzer_name, "domain": domain})

            # DNS-resolve up to _MAX_DNS_CHECK candidates concurrently.
            # Operators can disable this by passing ``check_dns=False`` —
            # useful for offline workflows or when we only want the
            # generation step (e.g. feeding into a separate scanner).
            check_dns = kwargs.get("check_dns", True)
            max_check = kwargs.get("max_dns_check", _MAX_DNS_CHECK)

            if not check_dns:
                results = [
                    {
                        "domain": c["domain"],
                        "fuzzer": c["fuzzer"],
                        "registered": None,
                        "dns_a": [],
                        "mx": [],
                    }
                    for c in candidates[:max_check]
                ]
                return ToolResult(
                    success=True, source=self.name,
                    data={"typosquats": results},
                    result_count=len(results),
                )

            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = _DNS_TIMEOUT_SEC
            resolver.lifetime = _DNS_LIFETIME_SEC

            async def _resolve(candidate: Dict[str, str]) -> Optional[Dict[str, Any]]:
                dom = candidate["domain"]
                try:
                    a_answers = await resolver.resolve(dom, "A")
                    a_records = [str(r) for r in a_answers]
                except Exception:
                    a_records = []
                if not a_records:
                    # Only registered (resolving) typosquats are interesting
                    # for defense. Unregistered ones are dropped here.
                    return None
                try:
                    mx_answers = await resolver.resolve(dom, "MX")
                    # MX rdata stringifies as "10 mail.example.com." — take
                    # the host and strip the trailing dot for consistency
                    # with the rest of the tools.
                    mx_records = [
                        str(r).split()[-1].rstrip(".") for r in mx_answers
                    ]
                except Exception:
                    mx_records = []
                return {
                    "domain": dom,
                    "fuzzer": candidate["fuzzer"],
                    "registered": True,
                    "dns_a": a_records,
                    "mx": mx_records,
                }

            checked = await asyncio.gather(
                *(_resolve(c) for c in candidates[:max_check]),
                return_exceptions=False,
            )
            results = [r for r in checked if r is not None]

            return ToolResult(
                success=True, source=self.name,
                data={"typosquats": results},
                result_count=len(results),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    @staticmethod
    def _basic_permutations(domain: str) -> List[Dict[str, Any]]:
        """Basic permutation fallback when the dnstwist library is not
        installed. Returns a curated list of "subdomain-style" variants
        commonly used for phishing — not full typosquat coverage, just
        enough to keep the tool usable in air-gapped or offline runs."""
        name = domain.split(".")[0]
        tld = ".".join(domain.split(".")[1:])
        variations = [
            name + "1", name + "2", "my" + name, "get" + name, name + "app",
            name + "dev", name + "prod", name + "api", name + "login",
            name + "mail", name + "secure",
        ]
        return [
            {
                "domain": f"{v}.{tld}",
                "fuzzer": "basic",
                "registered": False,
                "dns_a": [],
                "mx": [],
            }
            for v in variations
        ]
