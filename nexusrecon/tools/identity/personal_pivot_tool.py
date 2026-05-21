"""
Personal identity pivot orchestrator (Phase D3).

Takes a confirmed corporate identity and:

  1. Generates personal handle + personal email candidates via D2.
  2. Probes the handles against personal-tier services
     (Reddit, Discord, gaming, dating, hobby forums) via maigret.
  3. Probes the emails against breach DBs (HIBP, IntelX, DeHashed,
     Hudson Rock) for personal credential exposure.
  4. Scores each new finding's cross-domain linkage confidence ──
     how confident we are that this personal account belongs to the
     same human as the corp identity.
  5. Extends the IdentityGraph with the discovered personal
     identifiers + any credential exposures, attached to the same
     identity_id as the corp anchor.

## Cross-domain linkage scoring

Phase A/B/C scored "is this account on Reddit the same person as
``jane.doe@gitlab.com``?" with derivation as the dominant signal.
That worked when the handle was a corp-pattern variant of the
email. For personal-tier accounts, the derivation tie is weaker by
design ── personal handles aren't derived from corp emails. So D3
uses a different scoring axis:

  - **Pattern plausibility (from D2)**: the handle's quality
    score as a personal-handle candidate. Higher base quality =
    more likely to be the kind of handle this person would pick.
  - **Service tier**: as before. Tier-1 services with identity
    validation outweigh anonymous forums.
  - **Cross-service convergence**: when the SAME personal handle
    hits on multiple personal-tier services, confidence rises.
    Two random users with handle ``jane.knits.82`` is unlikely;
    one person with that handle on three services is much more
    likely.
  - **Avatar match with corp identity**: Phase C1's avatar
    hashing applies cross-domain too. If the personal handle's
    profile picture matches the corp identity's GitHub avatar,
    we've closed the identity loop visually.
  - **Geographic / interest convergence**: when the personal
    profile's bio / location matches the corp identity's known
    location / interests, that corroborates.

## Test mode

Probing is expensive (every email × every breach DB = N API calls).
The orchestrator accepts kwargs:

  - ``probe_handles`` (default True): fire maigret on personal
    handle candidates.
  - ``probe_emails`` (default True): fire breach DB tools on
    personal email candidates.
  - ``max_handle_candidates`` (default 8): cap handle probes.
  - ``max_email_candidates`` (default 6): cap email probes.
  - ``personal_service_tier`` (default 2): maigret will probe the
    top N most-popular personal-tier services. Wider = slower.

In tests, callers pass ``probe_handles=False`` and
``probe_emails=False`` to exercise the orchestration logic without
firing real tools.
"""
from __future__ import annotations

import asyncio
from typing import Any

import structlog

from nexusrecon.core.identity_graph import (
    BreachConfidence,
    CredentialExposure,
    Identifier,
    IdentifierType,
    IdentityGraph,
)
from nexusrecon.core.personal_handle_derivation import (
    EmailCandidate,
    HandleCandidate,
    derive_personal_emails,
    derive_personal_handles,
)
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

log = structlog.get_logger(__name__)


# Personal-service tiers ── maigret site categories where personal
# (rather than corporate) identity is most likely to surface. Used to
# bias the maigret invocation toward services that produce signal.
# Defined here rather than in maigret_tool because the bias is
# specific to the pivot use case.
_PERSONAL_TIER_HINTS = (
    # Social media used personally
    "Reddit", "Twitter", "Mastodon", "Bluesky", "Discord", "Twitch",
    # Hobby / interest
    "Last.fm", "Lastfm", "Spotify", "SoundCloud", "Goodreads",
    "Letterboxd", "MyAnimeList", "AniList",
    # Gaming
    "Steam", "Roblox", "Minecraft",
    # Creative
    "DeviantArt", "Behance", "Dribbble", "Flickr", "500px", "Pixabay",
    "Imgur",
    # Dating (low-trust per attribution but personal-only)
    "OkCupid", "Bumble",
    # Generic forums + blogs
    "Tumblr", "Pinterest", "Medium", "Substack",
)


@register_tool
class PersonalPivotTool(OSINTTool):
    """Bridges corporate identity to personal identity.

    Run by Phase 2.5 (per the D7 wiring) once Phase 2 has confirmed
    a corporate identity. Output extends the IdentityGraph in place
    with newly discovered personal identifiers + credential exposures.

    The tool itself doesn't fire maigret or HIBP directly ── it goes
    through ``registry.execute()`` so the OPSEC stack (rate limiter,
    proxy, audit log) applies. This means the tool needs a registry
    reference at runtime; we use the registry singleton.
    """

    name = "personal_pivot"
    tier = Tier.T0   # purely derivative + third-party API queries
    category = Category.IDENTITY
    requires_keys = []  # no direct keys; downstream tools have their own
    description = (
        "Pivots from a corporate identity to personal identity + "
        "breach-data credential exposures. Bridges Phase D's identity "
        "graph from corp anchors to personal accounts."
    )
    target_types = ["identity"]
    dynamic_trigger_hints = [
        "corporate identity confirmed",
        "personal identity unknown",
        "credential exposure check requested",
    ]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        """Pivot one corporate identity to its likely personal identity.

        Args:
            target: The corporate identifier this pivot starts from
                (e.g. ``"jane.doe@gitlab.com"``). Used for logging
                + result attribution.
            **kwargs: see module docstring for full kwarg list.

        Returns:
            ToolResult with ``data``:

              - ``corp_identifier``: target
              - ``handle_candidates``: serialised HandleCandidate list
              - ``email_candidates``: serialised EmailCandidate list
              - ``handle_hits``: per-candidate maigret hit summary
              - ``email_hits``: per-candidate breach DB hit summary
              - ``credential_exposures``: list of redacted-by-default
                CredentialExposure records, attributable to the
                target identity
              - ``cross_domain_score``: best-of-all per-finding
                cross-domain confidence in [0, 1]
              - ``identity_extensions``: serialised Identifier list
                ready to attach to the corp identity in the graph
        """
        name = kwargs.get("name") or ""
        if not name:
            return ToolResult(
                success=False, source=self.name,
                error="personal_pivot needs a name kwarg to derive personal handles",
            )

        # Derive handle + email candidates from the supplied context.
        handle_candidates = derive_personal_handles(
            name=name,
            age_range=kwargs.get("age_range"),
            career_years=kwargs.get("career_years"),
            interests=kwargs.get("interests"),
            location=kwargs.get("location"),
            max_candidates=int(kwargs.get("max_handle_candidates", 8)),
        )
        email_candidates = derive_personal_emails(
            name=name,
            age_range=kwargs.get("age_range"),
            career_years=kwargs.get("career_years"),
            location=kwargs.get("location"),
            personal_domain=kwargs.get("personal_domain"),
            max_candidates=int(kwargs.get("max_email_candidates", 6)),
        )

        # Optionally probe the candidates via existing tools.
        handle_hits: list[dict[str, Any]] = []
        if kwargs.get("probe_handles", True) and handle_candidates:
            handle_hits = await self._probe_handles(handle_candidates)

        email_hits: list[dict[str, Any]] = []
        credential_exposures: list[CredentialExposure] = []
        if kwargs.get("probe_emails", True) and email_candidates:
            email_hits, credential_exposures = await self._probe_emails(
                email_candidates,
            )

        # Score cross-domain linkage per finding.
        identity_extensions = self._build_extensions(
            handle_hits=handle_hits,
            email_hits=email_hits,
            handle_candidates=handle_candidates,
            email_candidates=email_candidates,
        )

        best_score = max(
            (ext["confidence"] for ext in identity_extensions),
            default=0.0,
        )

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "corp_identifier": target,
                "handle_candidates": [c.to_dict() for c in handle_candidates],
                "email_candidates": [c.to_dict() for c in email_candidates],
                "handle_hits": handle_hits,
                "email_hits": email_hits,
                "credential_exposures": [
                    ce.to_dict(redact_value=True)  # redact for ToolResult
                    for ce in credential_exposures
                ],
                "cross_domain_score": round(best_score, 3),
                "identity_extensions": identity_extensions,
            },
            result_count=len(identity_extensions),
        )

    # ── Probing ──────────────────────────────────────────────────

    async def _probe_handles(
        self,
        candidates: list[HandleCandidate],
    ) -> list[dict[str, Any]]:
        """Fire maigret against personal-handle candidates.

        Uses the registry's ``execute`` path so OPSEC + audit apply.
        Maigret with ``target_type=username`` runs against its full
        site list; we don't filter to personal-tier here because
        maigret's site-tier knobs are coarse. Downstream scoring
        weights personal-tier hits higher (per :data:`_PERSONAL_TIER_HINTS`)."""
        from nexusrecon.tools.registry import get_registry
        registry = get_registry()

        results: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(2)  # be polite to maigret subprocesses

        async def _run_one(cand: HandleCandidate) -> None:
            async with sem:
                try:
                    r = await registry.execute(
                        "maigret",
                        cand.value,
                        "username",
                        fetch_profiles=False,  # speed; phase 2 already fetches
                        top_sites=200,         # narrower than default 500
                    )
                except Exception as exc:
                    log.debug("personal_pivot maigret failed",
                              handle=cand.value, error=str(exc))
                    return
                if not r.success or not r.data:
                    return
                for hit in r.data.get("registered_services", []) or []:
                    # Augment each hit with the candidate's pattern
                    # provenance so scoring can use it.
                    hit_record = dict(hit)
                    hit_record["pivot_candidate_value"] = cand.value
                    hit_record["pivot_candidate_pattern"] = cand.pattern
                    hit_record["pivot_candidate_quality"] = cand.quality
                    results.append(hit_record)

        await asyncio.gather(*(_run_one(c) for c in candidates))
        return results

    async def _probe_emails(
        self,
        candidates: list[EmailCandidate],
    ) -> tuple[list[dict[str, Any]], list[CredentialExposure]]:
        """Fire breach DB tools against personal email candidates.

        Returns ``(email_hits, credential_exposures)``:

          - ``email_hits``: per-tool per-email summary (counts +
            metadata, no credential values)
          - ``credential_exposures``: typed records for the
            credential_correlation step (D4). These carry the actual
            values when the DB returned them.

        Tools fired: ``breach_lookup`` (HIBP), ``intelx``,
        ``hudsonrock``, and (when available) ``dehashed``. Each one
        skips cleanly when its key isn't configured ── the
        ``is_available()`` gate at the registry level handles that.
        """
        from nexusrecon.tools.registry import get_registry
        registry = get_registry()

        email_hits: list[dict[str, Any]] = []
        exposures: list[CredentialExposure] = []
        sem = asyncio.Semaphore(3)

        async def _probe_one(cand: EmailCandidate) -> None:
            async with sem:
                # Run each breach DB in parallel for this email.
                breach_tools = ("breach_lookup", "intelx", "hudsonrock",
                                "dehashed")
                tool_results = await asyncio.gather(
                    *(self._safe_execute(registry, t, cand.value, "email")
                      for t in breach_tools),
                    return_exceptions=True,
                )
                for tool_name, r in zip(breach_tools, tool_results):
                    if isinstance(r, BaseException):
                        continue
                    if r is None or not r.success or not r.data:
                        continue
                    email_hits.append({
                        "email": cand.value,
                        "tool": tool_name,
                        "candidate_pattern": cand.pattern,
                        "candidate_quality": cand.quality,
                        "result_count": r.result_count,
                        "data_summary": _summarise_breach_data(r.data),
                    })
                    # Lift any per-tool credential records into typed
                    # CredentialExposure entries.
                    exposures.extend(
                        _extract_credential_exposures(
                            tool_name=tool_name,
                            email=cand.value,
                            data=r.data,
                        )
                    )

        await asyncio.gather(*(_probe_one(c) for c in candidates))
        return email_hits, exposures

    @staticmethod
    async def _safe_execute(registry, tool_name: str, target: str,
                            target_type: str) -> ToolResult | None:
        """Wrapper around ``registry.execute`` that swallows the
        ``tool not registered`` / ``prereqs not met`` error cases
        rather than counting them as failures. The personal pivot
        tries multiple breach DBs and treats absent ones as a skip,
        not a fault."""
        try:
            r = await registry.execute(tool_name, target, target_type)
        except Exception:
            return None
        if r is None or r.success is False:
            err = (r.error if r else "") or ""
            if "not registered" in err or "prereqs not met" in err:
                return None
        return r

    # ── Identity-extension assembly + scoring ────────────────────

    def _build_extensions(
        self,
        handle_hits: list[dict[str, Any]],
        email_hits: list[dict[str, Any]],
        handle_candidates: list[HandleCandidate],
        email_candidates: list[EmailCandidate],
    ) -> list[dict[str, Any]]:
        """Build the per-finding identity-extension records.

        Each extension is a dict shaped like an :class:`Identifier`
        plus a ``confidence`` field carrying the cross-domain linkage
        score. The caller (Phase 2.5 / the credential_correlation
        step) consumes these to extend the IdentityGraph.
        """
        out: list[dict[str, Any]] = []

        # Tally cross-service handle convergence ── same handle on N
        # services raises confidence.
        convergence: dict[str, int] = {}
        for hit in handle_hits:
            uname = (hit.get("username") or "").lower()
            convergence[uname] = convergence.get(uname, 0) + 1

        for hit in handle_hits:
            handle = hit.get("username") or ""
            service = hit.get("service") or ""
            if not handle or not service:
                continue

            confidence = self._score_handle_hit(hit, convergence)

            out.append({
                "value": handle,
                "identifier_type": IdentifierType.HANDLE.value,
                "service": service,
                "source": "personal_pivot:maigret",
                "confidence": round(confidence, 3),
                "metadata": {
                    "pattern": hit.get("pivot_candidate_pattern"),
                    "candidate_quality": hit.get("pivot_candidate_quality"),
                    "url": hit.get("url"),
                    "rationale": hit.get("confidence_rationale"),
                    "cross_service_count": convergence.get(handle.lower(), 1),
                },
            })

        for hit in email_hits:
            email = hit.get("email") or ""
            if not email:
                continue

            confidence = self._score_email_hit(hit)

            out.append({
                "value": email,
                "identifier_type": IdentifierType.PERSONAL_EMAIL.value,
                "source": f"personal_pivot:{hit.get('tool')}",
                "confidence": round(confidence, 3),
                "metadata": {
                    "pattern": hit.get("candidate_pattern"),
                    "candidate_quality": hit.get("candidate_quality"),
                    "breach_tool": hit.get("tool"),
                    "data_summary": hit.get("data_summary"),
                },
            })

        # Sort by confidence descending.
        out.sort(key=lambda r: -r.get("confidence", 0.0))
        return out

    @staticmethod
    def _score_handle_hit(
        hit: dict[str, Any],
        convergence: dict[str, int],
    ) -> float:
        """Cross-domain confidence that this personal-tier hit is
        attributable to the corp identity the pivot started from.

        Combines four signals:

          - Pattern quality (from D2): how plausible the handle
            STRING is for someone with this name. Range [0, 1].
          - Service tier: Tier-1 wins, Tier-4 loses. Reuses the
            Phase A scorer's bands via direct module access so the
            two stay in sync.
          - Cross-service convergence: bonus when the same handle
            appears on N>=2 personal services.
          - Existing per-hit confidence from maigret (Phase A/B/C):
            if maigret's own attribution scorer already returned a
            confidence, blend it in.

        Output capped at [0, 1].
        """
        from nexusrecon.core.attribution import _service_tier

        base = float(hit.get("pivot_candidate_quality", 0.5) or 0.5)
        tier = _service_tier(hit.get("service") or "")
        maigret_conf = float(hit.get("confidence", 0.0) or 0.0)

        # Convergence bonus: 1 service = no bonus; 2 = +0.1; 3+ = +0.2.
        conv = convergence.get((hit.get("username") or "").lower(), 1)
        conv_bonus = 0.0
        if conv >= 3:
            conv_bonus = 0.20
        elif conv == 2:
            conv_bonus = 0.10

        # Personal-tier hits (per the bias list) get a small boost
        # because personal handles are more meaningful on those
        # services.
        personal_boost = 0.05 if (hit.get("service") or "") in _PERSONAL_TIER_HINTS else 0.0

        # Weighted blend.
        score = (
            base * 0.35
            + tier * 0.20
            + max(maigret_conf, 0.0) * 0.25
            + conv_bonus
            + personal_boost
        )
        return max(0.0, min(1.0, score))

    @staticmethod
    def _score_email_hit(hit: dict[str, Any]) -> float:
        """Cross-domain confidence that this personal-email candidate
        belongs to the corp identity, given a breach DB found it.

        Heuristic: pattern_quality × tool_trust × presence_strength.

          - pattern_quality: from D2 (how plausible the email STRING
            is for someone with this name).
          - tool_trust: DBs that return verified plaintext credentials
            (DeHashed, Hudson Rock infostealer) outweigh presence-only
            (HIBP). Captured per tool below.
          - presence_strength: was this a hit at all? 0 if no hit.
            Higher when multiple records exist for the same email.
        """
        pattern_q = float(hit.get("candidate_quality", 0.5) or 0.5)
        tool = (hit.get("tool") or "").lower()
        tool_trust = {
            "dehashed": 0.95,
            "hudsonrock": 0.85,   # infostealer log = real credentials
            "intelx": 0.65,
            "breach_lookup": 0.45,  # HIBP, presence-only
        }.get(tool, 0.40)
        presence = 1.0 if (hit.get("result_count", 0) or 0) > 0 else 0.0
        return pattern_q * 0.45 + tool_trust * 0.35 + presence * 0.20


# ──────────────────────────────────────────────────────────────────────
# Breach-data → CredentialExposure adapters
# ──────────────────────────────────────────────────────────────────────


def _summarise_breach_data(data: dict[str, Any]) -> dict[str, Any]:
    """Reduce a breach-DB tool's ``ToolResult.data`` to a non-
    sensitive summary suitable for the ``email_hits`` field. Never
    include credential values here ── those go to credential_exposures
    only."""
    if not isinstance(data, dict):
        return {}
    return {
        "result_count": data.get("result_count", 0),
        "breach_count": (
            len(data.get("breaches", []))
            if isinstance(data.get("breaches"), list) else 0
        ),
        "stealer_count": (
            len(data.get("stealers", []))
            if isinstance(data.get("stealers"), list) else 0
        ),
        "compromised": data.get("compromised", False),
    }


def _extract_credential_exposures(
    tool_name: str,
    email: str,
    data: dict[str, Any],
) -> list[CredentialExposure]:
    """Convert a breach-DB tool's raw ``data`` into typed
    :class:`CredentialExposure` records.

    Each tool has a different output shape so we dispatch on
    ``tool_name``. Records lacking actual credential values (presence-
    only HIBP hits, for example) still produce a record with
    ``credential_kind="presence_only"`` and empty
    ``credential_value`` so the credential_correlation step (D4)
    knows the email is implicated even if it can't propose a password
    to test.
    """
    if not isinstance(data, dict):
        return []
    out: list[CredentialExposure] = []

    if tool_name == "dehashed":
        # DeHashed returns a list of records with optional 'password'
        # / 'hashed_password' fields. D5 will produce this shape.
        for entry in data.get("entries", []) or []:
            if not isinstance(entry, dict):
                continue
            pwd = entry.get("password") or entry.get("hashed_password") or ""
            kind = "password" if entry.get("password") else (
                "hash" if entry.get("hashed_password") else "presence_only"
            )
            out.append(CredentialExposure(
                breach_source=f"DeHashed:{entry.get('database', 'unknown')}",
                breach_date=entry.get("breach_date"),
                observed_at_identifier=email,
                credential_kind=kind,
                credential_value=str(pwd) if pwd else "",
                confidence=BreachConfidence.VERIFIED if pwd else BreachConfidence.UNVERIFIED,
                provenance={k: v for k, v in entry.items()
                            if k not in ("password", "hashed_password")
                            and v},
            ))

    elif tool_name == "hudsonrock":
        # Hudson Rock infostealer ── ``data["compromised"]`` boolean.
        #
        # Shape varies by check type + tier (D6 enhancements):
        #
        #  • email-check, paid tier:
        #      data["captured_credentials"] = [{url, username, password}]
        #      data["stealer_family"]/computer_name/etc at top level
        #
        #  • email-check, community tier:
        #      data["captured_credentials"] = []  (no detail)
        #      stealer-session top-level fields still present
        #
        #  • domain-check (either tier):
        #      data["stealers"] = [{..., captured_credentials: [...]}]
        #      each stealer is one infected machine
        #
        # We extract REAL credentials when ``captured_credentials`` is
        # populated (paid tier) and fall back to one ``presence_only``
        # record per stealer otherwise.
        if data.get("compromised"):
            stealer_family_top = data.get("stealer_family")
            date_top = data.get("date_compromised")

            # ── email-check path: top-level captured_credentials ──
            top_creds = data.get("captured_credentials") or []
            if isinstance(top_creds, list) and top_creds:
                for c in top_creds:
                    if not isinstance(c, dict):
                        continue
                    pwd = (c.get("password") or "").strip()
                    out.append(CredentialExposure(
                        breach_source=f"HudsonRock:{stealer_family_top or 'unknown'}",
                        breach_date=date_top,
                        observed_at_identifier=email,
                        credential_kind="password" if pwd else "presence_only",
                        credential_value=pwd,
                        confidence=BreachConfidence.VERIFIED if pwd else BreachConfidence.LIKELY,
                        provenance={
                            "captured_url": c.get("url"),
                            "captured_username": c.get("username"),
                            "computer_name": data.get("computer_name"),
                            "operating_system": data.get("operating_system"),
                            "external_ip": data.get("external_ip"),
                        },
                    ))

            # ── domain-check path: per-stealer records ──
            stealers = data.get("stealers") or []
            for s in stealers:
                if not isinstance(s, dict):
                    continue
                family = s.get("stealer_family") or "unknown"
                date_s = s.get("date_compromised")
                provenance_base = {
                    "computer_name": s.get("computer_name"),
                    "operating_system": s.get("operating_system"),
                    "antiviruses": s.get("antiviruses"),
                    "external_ip": s.get("external_ip"),
                }
                cap = s.get("captured_credentials") or []
                if isinstance(cap, list) and cap:
                    for c in cap:
                        if not isinstance(c, dict):
                            continue
                        pwd = (c.get("password") or "").strip()
                        prov = dict(provenance_base)
                        prov["captured_url"] = c.get("url")
                        prov["captured_username"] = c.get("username")
                        out.append(CredentialExposure(
                            breach_source=f"HudsonRock:{family}",
                            breach_date=date_s,
                            observed_at_identifier=email,
                            credential_kind="password" if pwd else "presence_only",
                            credential_value=pwd,
                            confidence=BreachConfidence.VERIFIED if pwd else BreachConfidence.LIKELY,
                            provenance=prov,
                        ))
                else:
                    # Community tier — stealer record without credential detail.
                    out.append(CredentialExposure(
                        breach_source=f"HudsonRock:{family}",
                        breach_date=date_s,
                        observed_at_identifier=email,
                        credential_kind="presence_only",
                        credential_value="",
                        confidence=BreachConfidence.VERIFIED,
                        provenance=provenance_base,
                    ))

            # ── Last-resort presence record ──
            #
            # Compromised flag set but neither top-level nor per-stealer
            # detail extracted — record presence so D4 still surfaces
            # the identity as exposed.
            if not out:
                out.append(CredentialExposure(
                    breach_source=f"HudsonRock:{stealer_family_top or 'Cavalier'}",
                    breach_date=date_top,
                    observed_at_identifier=email,
                    credential_kind="presence_only",
                    credential_value="",
                    confidence=BreachConfidence.LIKELY,
                    provenance={"message": data.get("message")},
                ))

    elif tool_name == "breach_lookup":  # HIBP
        # HIBP returns a list of breach names. Presence-only ── no
        # passwords without the paid tier.
        for b in data.get("breaches", []) or []:
            name = b.get("Name") if isinstance(b, dict) else b
            date = b.get("BreachDate") if isinstance(b, dict) else None
            out.append(CredentialExposure(
                breach_source=f"HIBP:{name or 'unknown'}",
                breach_date=date,
                observed_at_identifier=email,
                credential_kind="presence_only",
                credential_value="",
                confidence=BreachConfidence.UNVERIFIED,
                provenance={"breach": b} if isinstance(b, dict) else {},
            ))

    elif tool_name == "intelx":
        # IntelX returns search hits with optional content. The data
        # shape varies by record type. Treat as presence-only unless
        # an explicit ``password`` field is present.
        for entry in data.get("records", []) or []:
            if not isinstance(entry, dict):
                continue
            pwd = entry.get("password") or ""
            out.append(CredentialExposure(
                breach_source=f"IntelX:{entry.get('bucket', 'unknown')}",
                breach_date=entry.get("date"),
                observed_at_identifier=email,
                credential_kind="password" if pwd else "presence_only",
                credential_value=str(pwd) if pwd else "",
                confidence=BreachConfidence.LIKELY if pwd else BreachConfidence.UNVERIFIED,
                provenance={k: v for k, v in entry.items()
                            if k not in ("password",) and v},
            ))

    return out


# ──────────────────────────────────────────────────────────────────────
# Graph-extension helper
# ──────────────────────────────────────────────────────────────────────


def apply_extensions_to_graph(
    graph: IdentityGraph,
    corp_identity_id: str,
    pivot_result: dict[str, Any],
) -> None:
    """Attach the personal_pivot tool's extensions to an Identity in
    the graph.

    Takes the ``identity_extensions`` + ``credential_exposures`` from
    a successful pivot ToolResult and adds them to the named identity.
    Skips silently when the identity isn't in the graph (the caller
    should have created it during Phase 2)."""
    identity = graph.get(corp_identity_id)
    if identity is None:
        return

    for ext in pivot_result.get("identity_extensions", []) or []:
        try:
            ident_type = IdentifierType(ext.get("identifier_type"))
        except ValueError:
            ident_type = IdentifierType.OTHER
        identity.add_identifier(Identifier(
            value=ext.get("value", ""),
            identifier_type=ident_type,
            service=ext.get("service"),
            source=ext.get("source", "personal_pivot"),
            confidence=float(ext.get("confidence", 0.0)),
            metadata=dict(ext.get("metadata") or {}),
        ))

    # Credential exposures arrive in redacted dict form from the
    # ToolResult; the orchestrator's own tests pass unredacted in
    # via the typed list. Here we accept the dict form and reattach.
    for ce in pivot_result.get("credential_exposures", []) or []:
        if not isinstance(ce, dict):
            continue
        try:
            conf = BreachConfidence(ce.get("confidence", "unverified"))
        except ValueError:
            conf = BreachConfidence.UNVERIFIED
        identity.add_credential_exposure(CredentialExposure(
            breach_source=ce.get("breach_source", "unknown"),
            breach_date=ce.get("breach_date"),
            observed_at_identifier=ce.get("observed_at_identifier", ""),
            credential_kind=ce.get("credential_kind", "presence_only"),
            credential_value=ce.get("credential_value", ""),
            confidence=conf,
            provenance=dict(ce.get("provenance") or {}),
        ))
