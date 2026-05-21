"""Credential correlation — Phase D4 punch-list generator.

Takes an :class:`~nexusrecon.core.identity_graph.IdentityGraph` that has
been extended by Phase 2.5 (personal pivot) and produces ranked
:class:`CredentialSprayCandidate` records.

INFORMATIONAL ONLY — this module:
  - Does NOT initiate network connections.
  - Does NOT write credentials to disk (unredacted values stay in memory).
  - Does NOT perform any authentication attempts.
  - Sets ``do_not_execute = True`` on every candidate.

The operator reads the punch list, evaluates scope + risk, and decides
which candidates (if any) to manually test.

Confidence model (additive):
  Credential kind base:
    password       → 0.70
    hash           → 0.40
    presence_only  → 0.20
  Breach confidence modifier:
    verified       → +0.10
    likely         → +0.05
    unverified     →  0.00
  Endpoint type modifier:
    adfs           → +0.05  (NTLM relay / WS-Fed spray)
    o365_managed   → +0.05  (MSOnline spray)
    owa            → +0.03
    vpn            → +0.03
    portal         → +0.01
  MFA expected penalty:
    mfa_expected   → −0.20
  Recency bonus (breach < 2 years old):
                   → +0.05

Candidates with confidence < 0.15 are suppressed as noise.

MITRE PRE-ATT&CK references:
  T1110.003  Password Spraying
  T1110.002  Password Cracking (hash candidates)
  T1550.002  Pass-the-Hash (NTLM-capable endpoints + hash kind)
  T1078      Valid Accounts (post-success path — informational only)
  T1589.002  Email Addresses (presence-only candidates)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from nexusrecon.core.identity_graph import (
    BreachConfidence,
    CredentialExposure,
    Identity,
    IdentityGraph,
    IdentifierType,
)

# ── Constants ──────────────────────────────────────────────────────────────

_MIN_CONFIDENCE = 0.15           # Below this → suppressed
_DEFAULT_MAX_CANDIDATES = 50

# Confidence contributions
_BASE_CONFIDENCE: Dict[str, float] = {
    "password": 0.70,
    "hash": 0.40,
    "token": 0.55,
    "cookie": 0.35,
    "presence_only": 0.20,
}
_BREACH_CONF_MOD: Dict[str, float] = {
    BreachConfidence.VERIFIED.value: 0.10,
    BreachConfidence.LIKELY.value: 0.05,
    BreachConfidence.UNVERIFIED.value: 0.00,
}
_ENDPOINT_TYPE_MOD: Dict[str, float] = {
    "adfs": 0.05,
    "o365_managed": 0.05,
    "owa": 0.03,
    "vpn": 0.03,
    "portal": 0.01,
}
_MFA_PENALTY = 0.20
_RECENCY_BONUS = 0.05
_RECENCY_THRESHOLD_YEARS = 2

# MITRE technique mapping by (credential_kind, endpoint_type)
_MITRE_MAP: Dict[Tuple[str, str], List[str]] = {
    ("password", "adfs"):        ["T1110.003", "T1078"],
    ("password", "o365_managed"): ["T1110.003", "T1078"],
    ("password", "owa"):         ["T1110.003", "T1078"],
    ("password", "vpn"):         ["T1110.003", "T1078"],
    ("password", "portal"):      ["T1110.003", "T1078"],
    ("hash", "adfs"):            ["T1110.002", "T1550.002", "T1078"],
    ("hash", "o365_managed"):    ["T1110.002", "T1078"],
    ("hash", "owa"):             ["T1110.002", "T1550.002", "T1078"],
    ("hash", "vpn"):             ["T1110.002", "T1078"],
    ("hash", "portal"):          ["T1110.002", "T1078"],
    ("token", "adfs"):           ["T1550.001", "T1078"],
    ("cookie", "portal"):        ["T1550.004", "T1078"],
    ("presence_only", "adfs"):   ["T1589.002"],
    ("presence_only", "o365_managed"): ["T1589.002"],
}

# Well-known auth endpoint patterns for URL classification
_URL_PATTERNS: List[Tuple[str, str]] = [
    (r"/adfs/", "adfs"),
    (r"adfs\.", "adfs"),
    (r"sts\.", "adfs"),
    (r"/owa/", "owa"),
    (r"mail\.", "owa"),
    (r"webmail\.", "owa"),
    (r"exchange\.", "owa"),
    (r"vpn\.", "vpn"),
    (r"\.vpn\.", "vpn"),
    (r"remote\.", "vpn"),
    (r"pulse\.secure", "vpn"),
    (r"globalprotect", "vpn"),
    (r"anyconnect", "vpn"),
    (r"login\.microsoftonline\.com", "o365_managed"),
    (r"logon\.microsoftonline\.com", "o365_managed"),
]


# ── Data classes ───────────────────────────────────────────────────────────


@dataclass
class AuthEndpoint:
    """A discovered authentication surface extracted from cloud_intel.

    Attributes:
        url: Full URL of the auth endpoint.
        endpoint_type: One of "adfs", "owa", "o365_managed", "vpn", "portal".
        domain: The organisational domain this endpoint serves.
        mfa_expected: True when cloud_intel signals MFA is enforced (e.g.
            Azure MFA, ADFS multi-factor policy, Duo).
        lockout_policy_unknown: When True, the framework couldn't determine
            account lockout policy — treat as if lockout is possible.
        notes: Any free-text annotation (e.g. "ADFS via WS-Trust").
    """

    url: str
    endpoint_type: str
    domain: str
    mfa_expected: bool = False
    lockout_policy_unknown: bool = True
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "endpoint_type": self.endpoint_type,
            "domain": self.domain,
            "mfa_expected": self.mfa_expected,
            "lockout_policy_unknown": self.lockout_policy_unknown,
            "notes": self.notes,
        }


@dataclass
class CredentialSprayCandidate:
    """One entry in the operator punch list.

    Attributes:
        identity_id: Stable ID of the :class:`~nexusrecon.core.identity_graph.Identity`.
        identity_label: Human-readable label from the identity graph.
        corp_email: The corp email address to test credentials against.
        observed_at: The personal identifier where the breach was observed
            (e.g. ``"jane.doe.82@gmail.com"``).
        breach_source: Name of the breach / infostealer source.
        breach_date: ISO-8601 date of the breach (best-effort).
        credential_kind: "password", "hash", "token", "cookie", "presence_only".
        credential_value: Raw value — REDACTED in ``to_dict()`` by default.
        breach_confidence: :class:`~nexusrecon.core.identity_graph.BreachConfidence`.
        test_endpoint_url: Where to test (ADFS URL, O365 token endpoint, …).
        endpoint_type: Endpoint classification string.
        endpoint_domain: Organisational domain of the endpoint.
        mfa_expected: Whether the endpoint likely enforces MFA.
        confidence: Overall operator confidence [0, 1] this test is viable.
        risk_flags: Flags the operator should evaluate before proceeding.
        mitre_techniques: Relevant MITRE ATT&CK techniques.
        recommendation: Plain-English guidance for the operator.
        do_not_execute: Always ``True`` — this framework NEVER auto-executes.
        notes: Rationale and caveats.
    """

    identity_id: str
    identity_label: str
    corp_email: str
    observed_at: str
    breach_source: str
    breach_date: Optional[str]
    credential_kind: str
    credential_value: str
    breach_confidence: BreachConfidence
    test_endpoint_url: str
    endpoint_type: str
    endpoint_domain: str
    mfa_expected: bool
    confidence: float
    risk_flags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    recommendation: str = ""
    do_not_execute: bool = True
    notes: str = ""

    def to_dict(self, redact_value: bool = True) -> Dict[str, Any]:
        """JSON-safe representation. Redacts credential_value by default."""
        return {
            "identity_id": self.identity_id,
            "identity_label": self.identity_label,
            "corp_email": self.corp_email,
            "observed_at": self.observed_at,
            "breach_source": self.breach_source,
            "breach_date": self.breach_date,
            "credential_kind": self.credential_kind,
            "credential_value": "[REDACTED]" if redact_value else self.credential_value,
            "breach_confidence": self.breach_confidence.value,
            "test_endpoint_url": self.test_endpoint_url,
            "endpoint_type": self.endpoint_type,
            "endpoint_domain": self.endpoint_domain,
            "mfa_expected": self.mfa_expected,
            "confidence": round(self.confidence, 3),
            "risk_flags": list(self.risk_flags),
            "mitre_techniques": list(self.mitre_techniques),
            "recommendation": self.recommendation,
            "do_not_execute": self.do_not_execute,
            "notes": self.notes,
        }


# ── Auth endpoint extraction ───────────────────────────────────────────────


def extract_auth_endpoints(cloud_intel: Dict[str, Any]) -> List[AuthEndpoint]:
    """Parse cloud_intel (from Phase 2) into AuthEndpoint objects.

    Recognises Azure/M365 federation data, OWA indicators, VPN prefixes,
    and captured infostealer URLs (from D6 HudsonRock).  Returns an empty
    list when cloud_intel is absent or has no auth surface signal.

    The caller (``correlate_credentials``) handles the case where no
    endpoints are discovered by synthesising a generic fallback set.

    Shape contract — reads from the actual ``azure_m365_recon`` output:
      - ``data["user_realm"]["is_federated"]``      bool (Microsoft realm API)
      - ``data["user_realm"]["federation_protocol"]`` str (WSTrust, SAML, …)
      - ``data["adfs"]["endpoints"]``               list of detected
            ADFS subdomain probes (each: ``{subdomain, url, status,
            likely_adfs}``).
      - Hudson Rock additions:
        ``data["captured_urls"]`` / ``data["all_captured_urls"]``    str list.
      - Future-compatible (no-op when absent):
        ``data["owa_url"]``, ``data["vpn_url"]``, ``data["mfa_enforced"]``.
    """
    endpoints: List[AuthEndpoint] = []
    seen_urls: set[str] = set()

    def _add(ep: AuthEndpoint) -> None:
        key = ep.url.lower().rstrip("/")
        if key not in seen_urls:
            seen_urls.add(key)
            endpoints.append(ep)

    for intel_key, data in (cloud_intel or {}).items():
        if not isinstance(data, dict):
            continue

        # Derive the domain from the cloud_intel key (e.g. "azure/gitlab.com")
        domain = _domain_from_key(intel_key)

        # ── Azure / M365 federation realm ────────────────────────────

        user_realm = data.get("user_realm") or {}
        is_federated = False
        federation_protocol = ""
        if isinstance(user_realm, dict) and user_realm.get("found"):
            is_federated = bool(user_realm.get("is_federated"))
            federation_protocol = (user_realm.get("federation_protocol") or "").strip()

        # MFA signal is rarely surfaced by Microsoft's realm API.  We
        # accept any of these field names as "MFA expected" but tolerate
        # their absence.  ``conditional_access_likely`` is an inferred
        # signal that future Azure-tool work may add.
        mfa_flag = bool(
            data.get("mfa_enforced") or
            data.get("conditional_access") or
            data.get("conditional_access_likely") or
            (isinstance(user_realm, dict) and user_realm.get("mfa_required"))
        )

        # An explicit ``auth_url`` is rare — kept for compatibility with
        # tooling that supplies it directly.
        explicit_auth_url = ""
        if isinstance(user_realm, dict):
            explicit_auth_url = (user_realm.get("auth_url") or "").strip()
        if is_federated and explicit_auth_url:
            ep_type = _classify_url(explicit_auth_url) or "adfs"
            _add(AuthEndpoint(
                url=explicit_auth_url,
                endpoint_type=ep_type,
                domain=domain,
                mfa_expected=mfa_flag,
                lockout_policy_unknown=True,
                notes=f"Azure federation; protocol={federation_protocol or 'unknown'}",
            ))

        # ── ADFS endpoints discovered by ``_detect_adfs`` ────────────
        #
        # azure_m365_recon stores its ADFS probe results at
        # ``data["adfs"]["endpoints"]`` — a list of probed subdomain
        # patterns (adfs/sts/login/sso).  Only the entries flagged
        # ``likely_adfs`` came back with content matching ADFS markers.

        adfs_data = data.get("adfs") or {}
        if isinstance(adfs_data, dict):
            for ep_data in (adfs_data.get("endpoints") or []):
                if not isinstance(ep_data, dict):
                    continue
                url = (ep_data.get("url") or "").strip()
                if not url:
                    continue
                # Keep only endpoints that actually responded with ADFS
                # content; bare 200 responses on unrelated services
                # would otherwise pollute the punch list.
                likely = bool(ep_data.get("likely_adfs"))
                status = ep_data.get("status")
                if not likely and status not in (200, 302, 401, 403):
                    continue
                _add(AuthEndpoint(
                    url=url,
                    endpoint_type="adfs",
                    domain=domain,
                    mfa_expected=mfa_flag,
                    lockout_policy_unknown=True,
                    notes=(
                        f"ADFS probe ({ep_data.get('subdomain', 'n/a')}, "
                        f"likely_adfs={likely})"
                    ),
                ))

        # ── Synthesized ADFS fallback for federated tenants ──────────
        #
        # When the realm API says "federated" but no concrete ADFS URL
        # came back from the probe, synthesize the common subdomain
        # pattern so the punch list still has a candidate to test
        # against.  Marked as a synthesised guess in the notes.

        if is_federated and not any(
            ep.endpoint_type == "adfs" and ep.domain == domain
            for ep in endpoints
        ):
            for sub in ("sts", "adfs", "login", "sso"):
                _add(AuthEndpoint(
                    url=f"https://{sub}.{domain}/adfs/ls/",
                    endpoint_type="adfs",
                    domain=domain,
                    mfa_expected=mfa_flag,
                    lockout_policy_unknown=True,
                    notes=(
                        f"Synthesised ADFS pattern ({sub}); federation "
                        f"protocol={federation_protocol or 'unknown'}"
                    ),
                ))

        # ── Managed M365 token endpoint ──────────────────────────────

        if isinstance(user_realm, dict) and user_realm.get("found") and not is_federated:
            # Managed M365 — spray via the per-tenant token endpoint.
            _add(AuthEndpoint(
                url=f"https://login.microsoftonline.com/{domain}/oauth2/token",
                endpoint_type="o365_managed",
                domain=domain,
                mfa_expected=mfa_flag,
                lockout_policy_unknown=True,
                notes=f"O365 managed tenant ({domain})",
            ))

        # ── OWA (future-compatible: harmless when absent) ─────────────

        for owa_field in ("owa_url", "exchange_url", "mail_url"):
            owa_url = (data.get(owa_field) or "").strip()
            if owa_url:
                _add(AuthEndpoint(
                    url=owa_url,
                    endpoint_type="owa",
                    domain=domain,
                    mfa_expected=mfa_flag,
                    notes="OWA / Exchange Web Services",
                ))

        # ── VPN / remote access (future-compatible) ───────────────────

        for vpn_field in ("vpn_url", "remote_access_url", "ssl_vpn_url"):
            vpn_url = (data.get(vpn_field) or "").strip()
            if vpn_url:
                _add(AuthEndpoint(
                    url=vpn_url,
                    endpoint_type="vpn",
                    domain=domain,
                    mfa_expected=False,
                    notes="Remote access / VPN portal",
                ))

        # ── Hudson Rock captured URLs (D6) ────────────────────────────

        for url_field in ("all_captured_urls", "captured_urls"):
            for cap_url in (data.get(url_field) or []):
                if not isinstance(cap_url, str) or not cap_url.strip():
                    continue
                ep_type = _classify_url(cap_url) or "portal"
                _add(AuthEndpoint(
                    url=cap_url.strip(),
                    endpoint_type=ep_type,
                    domain=_domain_from_url(cap_url) or domain,
                    mfa_expected=False,
                    lockout_policy_unknown=True,
                    notes="Captured by infostealer (Hudson Rock)",
                ))

    return endpoints


def _domain_from_key(key: str) -> str:
    """Extract domain from a cloud_intel key like ``"azure/gitlab.com"``."""
    parts = key.split("/", 1)
    return parts[-1] if len(parts) > 1 else key


def _domain_from_url(url: str) -> str:
    """Best-effort domain extraction from a URL string."""
    m = re.search(r"https?://([^/:?#]+)", url)
    if m:
        host = m.group(1)
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
    return ""


def _classify_url(url: str) -> Optional[str]:
    """Classify a URL into an endpoint type using known patterns."""
    url_lower = url.lower()
    for pattern, ep_type in _URL_PATTERNS:
        if re.search(pattern, url_lower):
            return ep_type
    return None


# ── Confidence + risk scoring ──────────────────────────────────────────────


def _score(
    exposure: CredentialExposure,
    endpoint: AuthEndpoint,
) -> float:
    """Compute the overall operator confidence score [0, 1]."""
    base = _BASE_CONFIDENCE.get(exposure.credential_kind, 0.15)
    mod = _BREACH_CONF_MOD.get(exposure.confidence.value, 0.0)
    ep_mod = _ENDPOINT_TYPE_MOD.get(endpoint.endpoint_type, 0.0)
    mfa_pen = _MFA_PENALTY if endpoint.mfa_expected else 0.0
    recency = _recency_bonus(exposure.breach_date)
    return max(0.0, min(1.0, base + mod + ep_mod - mfa_pen + recency))


def _recency_bonus(breach_date: Optional[str]) -> float:
    """Return ``_RECENCY_BONUS`` if the breach date is within threshold.

    Handles year-only ("2024"), ISO date ("2024-01-15"), and ISO datetime
    ("2024-01-15T12:00:00") formats.  The slice length must match the
    *date string* width, not the format string width (``len("%Y")`` is 2,
    but a 4-digit year string needs 4 characters).
    """
    if not breach_date:
        return 0.0
    try:
        # (format, date-string character count) pairs
        for fmt, date_len in (
            ("%Y-%m-%dT%H:%M:%S", 19),
            ("%Y-%m-%d", 10),
            ("%Y", 4),
        ):
            if len(breach_date) < date_len:
                continue
            try:
                dt = datetime.strptime(breach_date[:date_len], fmt)
                years_ago = (datetime.now() - dt).days / 365.25
                return _RECENCY_BONUS if years_ago <= _RECENCY_THRESHOLD_YEARS else 0.0
            except ValueError:
                continue
    except Exception:
        pass
    return 0.0


def _build_risk_flags(
    exposure: CredentialExposure,
    endpoint: AuthEndpoint,
) -> List[str]:
    """Return a list of risk flags the operator must consider."""
    flags: List[str] = []

    # Account lockout is always possible when spraying.
    flags.append("account_lockout_risk")

    if endpoint.mfa_expected:
        flags.append("mfa_expected")

    if endpoint.lockout_policy_unknown:
        flags.append("lockout_threshold_unknown")

    if exposure.credential_kind == "hash":
        flags.append("hash_requires_cracking_or_relay")

    if exposure.credential_kind == "presence_only":
        flags.append("presence_only_no_credential_value")

    if endpoint.endpoint_type in ("adfs", "o365_managed"):
        flags.append("ids_alert_likely_on_spray")

    if exposure.confidence == BreachConfidence.UNVERIFIED:
        flags.append("breach_unverified_signal_only")

    return flags


def _build_mitre(
    credential_kind: str,
    endpoint_type: str,
) -> List[str]:
    """Return MITRE ATT&CK technique IDs for this combination."""
    key = (credential_kind, endpoint_type)
    techniques = list(_MITRE_MAP.get(key, []))
    # Always add T1078 for any credential kind that could result in access,
    # unless it's already present or the kind is presence-only.
    if credential_kind != "presence_only" and "T1078" not in techniques:
        techniques.append("T1078")
    return techniques


def _build_recommendation(
    identity_label: str,
    corp_email: str,
    breach_source: str,
    credential_kind: str,
    endpoint_type: str,
    endpoint_url: str,
    mfa_expected: bool,
    confidence: float,
) -> str:
    """Produce a short, plain-English operator recommendation."""
    kind_phrase = {
        "password": "cleartext password from this breach",
        "hash": "password hash — crack or relay before testing",
        "token": "credential token — validate scope before use",
        "cookie": "session cookie — verify it hasn't expired",
        "presence_only": "presence signal only (no credential value)",
    }.get(credential_kind, credential_kind)

    ep_phrase = {
        "adfs": "ADFS portal",
        "o365_managed": "O365 managed auth (MSOnline spray endpoint)",
        "owa": "Outlook Web Access",
        "vpn": "VPN / remote access portal",
        "portal": "captured login portal",
    }.get(endpoint_type, "auth endpoint")

    mfa_note = " Note: MFA appears to be enforced — cleartext password alone is insufficient." if mfa_expected else ""

    return (
        f"[{confidence:.0%} confidence] {identity_label} ({corp_email}): "
        f"test the {kind_phrase} from '{breach_source}' against the {ep_phrase} "
        f"at {endpoint_url}.{mfa_note} "
        f"OPERATOR DECISION REQUIRED — do not execute without explicit authorisation."
    )


# ── Main correlation function ──────────────────────────────────────────────


def correlate_credentials(
    graph: IdentityGraph,
    cloud_intel: Optional[Dict[str, Any]] = None,
    *,
    max_candidates: int = _DEFAULT_MAX_CANDIDATES,
    min_confidence: float = _MIN_CONFIDENCE,
    include_presence_only: bool = False,
) -> List[CredentialSprayCandidate]:
    """Correlate breach data with auth surfaces and produce a punch list.

    Args:
        graph: The campaign's identity graph, populated by Phases 2 + 2.5.
        cloud_intel: State key ``cloud_intel`` from Phase 2 — carries
            federation / ADFS / OWA data from the Azure/M365 recon.
        max_candidates: Cap the returned list.
        min_confidence: Suppress candidates below this threshold.
        include_presence_only: Whether to include presence-only signals
            (breach confirmed but no credential value).  Defaults to
            ``False`` because they don't yield a testable credential.

    Returns:
        List of :class:`CredentialSprayCandidate` sorted by confidence
        descending.

    Notes:
        This function makes no network calls and has no side effects.
        Every returned candidate carries ``do_not_execute = True``.
    """
    candidates: List[CredentialSprayCandidate] = []
    endpoints = extract_auth_endpoints(cloud_intel or {})

    # If cloud_intel produced no endpoints, synthesise a generic O365 fallback
    # so we can still generate presence-only candidates for the report.
    if not endpoints:
        for seed in _infer_seeds_from_graph(graph):
            endpoints.append(AuthEndpoint(
                url=f"https://login.microsoftonline.com/{seed}/oauth2/token",
                endpoint_type="o365_managed",
                domain=seed,
                mfa_expected=False,
                lockout_policy_unknown=True,
                notes="Synthesised fallback — no cloud_intel endpoint discovered",
            ))

    for identity in graph.all():
        # Skip identities with no corp email — nothing to spray.
        corp_id = identity.best_identifier_for(IdentifierType.CORP_EMAIL)
        if not corp_id:
            continue
        corp_email = corp_id.value

        # Filter endpoints to those matching this identity's email domain.
        email_domain = corp_email.split("@")[-1].lower()
        matching_endpoints = [
            ep for ep in endpoints
            if ep.domain and (
                ep.domain.lower() == email_domain or
                email_domain.endswith("." + ep.domain.lower()) or
                ep.domain.lower().endswith("." + email_domain)
            )
        ] or endpoints  # Fallback: if no domain match, try all endpoints.

        for exposure in identity.credential_exposures:
            # Skip presence-only unless explicitly requested.
            if exposure.credential_kind == "presence_only" and not include_presence_only:
                continue

            for endpoint in matching_endpoints:
                conf = _score(exposure, endpoint)
                if conf < min_confidence:
                    continue

                risk_flags = _build_risk_flags(exposure, endpoint)
                mitre = _build_mitre(exposure.credential_kind, endpoint.endpoint_type)
                rec = _build_recommendation(
                    identity_label=identity.primary_label or corp_email,
                    corp_email=corp_email,
                    breach_source=exposure.breach_source,
                    credential_kind=exposure.credential_kind,
                    endpoint_type=endpoint.endpoint_type,
                    endpoint_url=endpoint.url,
                    mfa_expected=endpoint.mfa_expected,
                    confidence=conf,
                )

                candidate = CredentialSprayCandidate(
                    identity_id=identity.identity_id,
                    identity_label=identity.primary_label or corp_email,
                    corp_email=corp_email,
                    observed_at=exposure.observed_at_identifier,
                    breach_source=exposure.breach_source,
                    breach_date=exposure.breach_date,
                    credential_kind=exposure.credential_kind,
                    credential_value=exposure.credential_value,
                    breach_confidence=exposure.confidence,
                    test_endpoint_url=endpoint.url,
                    endpoint_type=endpoint.endpoint_type,
                    endpoint_domain=endpoint.domain,
                    mfa_expected=endpoint.mfa_expected,
                    confidence=conf,
                    risk_flags=risk_flags,
                    mitre_techniques=mitre,
                    recommendation=rec,
                    do_not_execute=True,
                    notes=endpoint.notes,
                )
                candidates.append(candidate)

    # Sort by confidence descending, then by breach_confidence as tiebreaker.
    _bc_order = {
        BreachConfidence.VERIFIED: 3,
        BreachConfidence.LIKELY: 2,
        BreachConfidence.UNVERIFIED: 1,
    }
    candidates.sort(
        key=lambda c: (c.confidence, _bc_order.get(c.breach_confidence, 0)),
        reverse=True,
    )

    return candidates[:max_candidates]


def _infer_seeds_from_graph(graph: IdentityGraph) -> List[str]:
    """Extract unique email domains from corp_email identifiers in the graph."""
    domains: List[str] = []
    seen: set[str] = set()
    for identity in graph.all():
        for ident in identity.identifiers:
            if ident.identifier_type == IdentifierType.CORP_EMAIL:
                domain = ident.value.split("@")[-1].lower()
                if domain and domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains


# ── Convenience summary ────────────────────────────────────────────────────


def summarise_punch_list(candidates: List[CredentialSprayCandidate]) -> Dict[str, Any]:
    """Build a statistics dict for the report header."""
    if not candidates:
        return {
            "total_candidates": 0,
            "by_credential_kind": {},
            "by_endpoint_type": {},
            "by_confidence_band": {},
            "identities_with_candidates": 0,
            "mfa_exposure_count": 0,
        }

    by_kind: Dict[str, int] = {}
    by_ep: Dict[str, int] = {}
    by_band: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    identity_ids: set[str] = set()
    mfa_count = 0

    for c in candidates:
        by_kind[c.credential_kind] = by_kind.get(c.credential_kind, 0) + 1
        by_ep[c.endpoint_type] = by_ep.get(c.endpoint_type, 0) + 1
        identity_ids.add(c.identity_id)
        if c.mfa_expected:
            mfa_count += 1
        if c.confidence >= 0.70:
            by_band["high"] += 1
        elif c.confidence >= 0.40:
            by_band["medium"] += 1
        else:
            by_band["low"] += 1

    return {
        "total_candidates": len(candidates),
        "by_credential_kind": by_kind,
        "by_endpoint_type": by_ep,
        "by_confidence_band": by_band,
        "identities_with_candidates": len(identity_ids),
        "mfa_exposure_count": mfa_count,
    }
