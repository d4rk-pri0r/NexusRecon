"""Maigret tool ── wraps the maigret CLI for username/email account discovery.

Maigret checks a username against ~3000 sites for account existence ── an
order of magnitude wider than holehe's ~120-module coverage. The
combination of the two is the framework's "agentic loop value prop"
showcase: holehe surfaces the email's known service registrations,
:mod:`nexusrecon.core.username_derivation` derives likely handle
patterns from the email + harvested names, and maigret expands the
account footprint across niche communities holehe doesn't cover.

Maigret is a subprocess wrapper, not a library import, because the
maigret PyPI package pins ``networkx<3`` which conflicts with
NexusRecon's ``networkx>=3.3`` requirement. The recommended install
is via pipx::

    pipx install maigret

That isolates maigret's deps in its own environment while making the
``maigret`` binary available on PATH. If pipx isn't an option, a
standalone venv install or a Docker pull (``soxoj/maigret`` image)
also works ── the tool just needs the binary discoverable.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from nexusrecon.core.attribution import score_handle_attribution
from nexusrecon.core.linked_accounts import (
    cross_reference_with_hits,
    extract_linked_accounts,
)
from nexusrecon.core.profile_fetcher import fetch_profiles_batch
from nexusrecon.core.username_derivation import derive_usernames
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


# Maigret's default site set is too large for the framework's stealth
# budget (a single check fans out to ~3000 services). Cap by default
# to the top 500 most-popular sites; operators can override via the
# ``top_sites`` kwarg or by passing ``site=[...]`` for a specific list.
_DEFAULT_TOP_SITES = 500

# Per-site timeout. Maigret's default is 30 seconds; we tighten to 10
# so a slow site doesn't blow our wall-clock budget when checking many
# usernames. Tunable via the ``timeout`` kwarg.
_DEFAULT_SITE_TIMEOUT = 10


@register_tool
class MaigretTool(OSINTTool):
    name = "maigret"
    tier = Tier.T1  # semi-passive: queries third-party services about the username
    category = Category.IDENTITY
    requires_keys = []
    binary_required = "maigret"
    description = (
        "Check username (or email-derived candidates) across ~3000 sites "
        "via maigret CLI. Install with: pipx install maigret"
    )
    target_types = ["username", "email"]
    dynamic_trigger_hints = [
        "username candidate derived",
        "email registered at multiple services",
        "handle pattern identified",
    ]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.is_available():
            return ToolResult(
                success=False, source=self.name,
                error="maigret binary not found ── install with: pipx install maigret",
            )

        # Resolve the username candidate set. Three input shapes:
        #
        # 1. Explicit username ── target arrives directly. We probe it.
        # 2. Email ── we derive likely usernames using the
        #    ``username_derivation`` heuristics and probe the top N.
        # 3. Email + harvested names via ``names=[...]`` kwarg ── same
        #    as (2) but the derivation gets a richer signal.
        #
        # The ``max_candidates`` kwarg caps the derivation. Default is
        # conservative (3) to keep a per-email maigret run under ~1 minute
        # at the configured per-site timeout.
        candidates: List[str]
        target_type = kwargs.get("target_type", "username")
        if "@" in target or target_type == "email":
            candidates = derive_usernames(
                email=target,
                names=kwargs.get("names") or [],
                max_candidates=kwargs.get("max_candidates", 3),
            )
            if not candidates:
                return ToolResult(
                    success=True, source=self.name,
                    data={
                        "input": target,
                        "candidates": [],
                        "registered_count": 0,
                        "registered_services": [],
                        "reason": "no username candidates derivable (role account or too-short local-part)",
                    },
                    result_count=0,
                )
        else:
            candidates = [target.strip().lower()]

        # Maigret writes its findings to a per-username JSON file in
        # the cwd. Use a temp dir so we don't litter the operator's
        # working directory and so we can clean up reliably.
        timeout = int(kwargs.get("timeout", _DEFAULT_SITE_TIMEOUT))
        top_sites = int(kwargs.get("top_sites", _DEFAULT_TOP_SITES))
        all_findings: List[Dict[str, Any]] = []

        try:
            with tempfile.TemporaryDirectory(prefix="nexus-maigret-") as tmpdir:
                tmpdir_path = Path(tmpdir)
                for username in candidates:
                    findings = await self._probe_one(
                        username, tmpdir_path, timeout, top_sites,
                    )
                    all_findings.extend(findings)
        except FileNotFoundError as exc:
            return ToolResult(
                success=False, source=self.name,
                error=f"maigret invocation failed (binary missing?): {exc}",
            )
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        # Deduplicate by (username, service) tuple. Sometimes two
        # candidates produce the same hit on the same service; the
        # second hit is uninteresting.
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for hit in all_findings:
            key = (hit.get("username", ""), hit.get("service", ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(hit)

        # Phase A: initial confidence scoring on the raw maigret data.
        # We pass the original target (which may be an email) plus
        # harvested names so the scorer can apply derivation rank +
        # uniqueness + service tier. Profile-coherence at this stage
        # is mostly 0.0 because maigret's ``profile`` dict is sparse;
        # Phase B re-scores after fetching real bios.
        email_anchor = target if "@" in target else None
        harvested_names = kwargs.get("names") or []

        def _rescore(hit: Dict[str, Any], profile_payload: Any, cross_ref: bool) -> None:
            attribution = score_handle_attribution(
                email=email_anchor,
                handle=hit.get("username", ""),
                service=hit.get("service", ""),
                profile_data=profile_payload,
                harvested_names=harvested_names,
                cross_referenced=cross_ref,
            )
            hit["confidence"] = attribution.score
            hit["confidence_band"] = attribution.confidence_band
            hit["confidence_signals"] = attribution.signals
            hit["confidence_rationale"] = attribution.rationale

        for hit in deduped:
            _rescore(hit, hit.get("profile", {}), cross_ref=False)

        # Phase B: for hits above the initial-score floor, fetch real
        # profile data and re-score with the richer evidence. Skip the
        # fetch when:
        #   - ``fetch_profiles=False`` is passed (test mode, fast
        #     runs, or operator preference)
        #   - The initial score is already below ``rescore_floor``
        #     (default 0.4) ── noise stays noise even with a bio
        # Concurrency capped at ``profile_fetch_concurrency`` (default 5)
        # to be polite to GitHub / Reddit / etc. APIs.
        fetch_profiles = kwargs.get("fetch_profiles", True)
        rescore_floor = float(kwargs.get("rescore_floor", 0.4))
        profile_fetch_concurrency = int(kwargs.get("profile_fetch_concurrency", 5))

        if fetch_profiles:
            candidates_to_fetch = [
                h for h in deduped if h.get("confidence", 0.0) >= rescore_floor
            ]
            if candidates_to_fetch:
                try:
                    fetched_profiles = await fetch_profiles_batch(
                        candidates_to_fetch,
                        max_concurrent=profile_fetch_concurrency,
                    )
                except Exception:
                    # Profile fetching is a best-effort enrichment ──
                    # if the batch crashes (network meltdown, etc.) we
                    # carry on with the initial scoring.
                    fetched_profiles = []

                # B4: extract linked-account references from each
                # fetched bio. We accumulate all references across
                # all hits, then cross-reference once at the end so
                # one service's profile claiming another service's
                # handle can flag that other hit.
                all_linked_refs = []
                profile_by_hit_id: Dict[int, Any] = {}
                for hit, profile in zip(candidates_to_fetch, fetched_profiles):
                    profile_by_hit_id[id(hit)] = profile
                    if profile.fetched:
                        refs = extract_linked_accounts(
                            source_service=profile.service,
                            profile_text=profile.bio or "",
                            profile_blog=profile.blog_url or "",
                        )
                        profile.linked_accounts = [r.to_dict() for r in refs]
                        all_linked_refs.extend(refs)

                # Cross-reference extracted links against ALL deduped
                # hits (not just the fetch candidates) ── a high-band
                # hit may have a bio that confirms a medium-band hit
                # elsewhere.
                if all_linked_refs:
                    cross_reference_with_hits(all_linked_refs, deduped)

                # Re-score every fetch candidate with the richer
                # profile data + cross-reference flag.
                for hit in candidates_to_fetch:
                    profile = profile_by_hit_id[id(hit)]
                    cross_ref = bool(hit.get("cross_referenced_from"))
                    if profile.fetched:
                        # Attach a JSON-safe profile snapshot for the
                        # agent to read alongside the rationale.
                        hit["fetched_profile"] = profile.to_dict()
                        _rescore(hit, profile, cross_ref=cross_ref)
                    elif cross_ref:
                        # No fetch but cross-referenced ── still bump
                        # the score via the cross-ref signal.
                        _rescore(hit, hit.get("profile", {}), cross_ref=True)

        # Sort by (possibly updated) confidence descending so the most
        # credible hits are at the top of the result list ── important
        # for downstream truncation (the agent only sees the first N
        # entries).
        deduped.sort(key=lambda h: -h.get("confidence", 0.0))

        # Aggregate counts by confidence band so the caller knows what
        # they're looking at without re-iterating the hit list.
        band_counts = {"high": 0, "medium": 0, "noise": 0}
        for hit in deduped:
            band_counts[hit.get("confidence_band", "noise")] = (
                band_counts.get(hit.get("confidence_band", "noise"), 0) + 1
            )

        return ToolResult(
            success=True, source=self.name,
            data={
                "input": target,
                "candidates": candidates,
                "registered_count": len(deduped),
                "actionable_count": band_counts["high"] + band_counts["medium"],
                "high_confidence_count": band_counts["high"],
                "registered_services": deduped,
                "confidence_breakdown": band_counts,
            },
            # ``result_count`` stays as the raw hit count for framework
            # metrics consistency. Downstream consumers that want to
            # avoid acting on noise should read ``actionable_count`` or
            # filter ``registered_services`` by ``confidence_band``.
            result_count=len(deduped),
        )

    async def _probe_one(
        self,
        username: str,
        tmpdir: Path,
        timeout: int,
        top_sites: int,
    ) -> List[Dict[str, Any]]:
        """Run maigret against a single username and return parsed hits.

        Errors during this single-username probe are logged and skipped
        ── we don't abort the whole campaign if one candidate fails.
        """
        # Build the maigret command. ``--json simple`` is the most
        # compact format; ``--folderoutput`` puts results in our temp
        # dir; ``--top-sites`` limits coverage; ``--no-color``,
        # ``--no-recursion``, and ``--no-progressbar`` cut noise.
        cmd = [
            "maigret",
            username,
            "--json", "simple",
            "--folderoutput", str(tmpdir),
            "--top-sites", str(top_sites),
            "--timeout", str(timeout),
            "--no-color",
            "--no-recursion",
            "--no-progressbar",
        ]

        # Total wall-clock cap: top_sites × timeout would be the worst
        # case if maigret ran sequentially; it doesn't, but allow a
        # safety margin proportional to top_sites. Cap at 5 minutes to
        # bound the longest valid run; floor at 60s for tiny site lists.
        overall_timeout = min(300, max(60, top_sites * timeout // 50))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, _stderr = await asyncio.wait_for(proc.communicate(), timeout=overall_timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return []  # one slow username doesn't fail the whole tool

        # Maigret writes ``<username>_simple.json`` (or similar) into
        # the folder. Locate it and parse.
        for candidate in tmpdir.glob(f"{username}*.json"):
            try:
                with candidate.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                return _parse_simple_json(username, data)
            except (json.JSONDecodeError, OSError):
                continue
        return []


def _parse_simple_json(username: str, data: Any) -> List[Dict[str, Any]]:
    """Parse maigret's ``--json simple`` output into our result shape.

    The simple format is a dict keyed by site name; each value carries
    a ``status.status`` field indicating whether the account was found.
    Maigret evolves this schema occasionally so we treat absent fields
    defensively.
    """
    findings: List[Dict[str, Any]] = []
    if not isinstance(data, dict):
        return findings
    for site_name, site_data in data.items():
        if not isinstance(site_data, dict):
            continue
        status_block = site_data.get("status") or {}
        status_value = (
            status_block.get("status") if isinstance(status_block, dict) else None
        )
        # Maigret uses "Claimed" for confirmed accounts; older versions
        # used "Found". Treat both as positive hits.
        if status_value not in ("Claimed", "Found"):
            continue
        findings.append({
            "username": username,
            "service": site_name,
            "url": site_data.get("url_user") or site_data.get("url") or "",
            "profile": (
                status_block.get("ids", {}) if isinstance(status_block, dict) else {}
            ),
        })
    return findings
