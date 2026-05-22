"""
First-class identity model for Phase D attribution work.

Before Phase D, identity data lived as a dict-of-dicts under
``email_intel.emails[em]``. That worked for the simple corp-email case
(one email = one person, attached holehe/maigret hits as sub-fields)
but breaks down once we model the real-attacker view: a single human
has multiple identifiers (corporate email, personal email, multiple
handles per service, personal phone), they have credential exposures
that don't tie to any single identifier, and they have relationship
edges to other humans (Phase E).

The :class:`Identity` model centralises all of this. Phase 2 builds
identities from harvested emails + names. Phase 2.5 (the personal
pivot, see D3) extends each identity with personal identifiers and
credential exposures. Phase E (relationship graph) attaches
human-to-human edges.

Key design choices documented inline:

  - **Identities are content-addressable** ── the framework
    derives an ``identity_id`` from the strongest available
    identifier so the same person discovered via two paths
    (corp email + personal email) merges to one identity rather
    than duplicating.
  - **Identifiers are typed** ── ``Identifier`` carries
    ``identifier_type`` (``corp_email``, ``personal_email``,
    ``handle``, ``phone``, ``real_name``) plus a ``source`` (which
    tool surfaced it) and a ``confidence`` (how sure we are it
    belongs to this identity). The same handle appearing on two
    different services counts as two ``Identifier`` rows so the
    framework knows the per-service confidence independently.
  - **Credential exposures are first-class** ── Phase D4 produces
    ``CredentialExposure`` records that the punch-list generator
    consumes. Storing them as graph children of the identity (not
    of any specific identifier) means a credential found in a breach
    against the personal email can be tested against the corp email
    without re-keying.
  - **Forward-compatible with Phase E** ── ``Identity.related_to``
    holds outbound relationship edges populated by Phase E. The
    field exists but is empty until E1 lands; this lets D ship
    independently.
  - **JSON-safe out of the box** ── every dataclass has a
    ``to_dict()`` that produces a JSON-serialisable representation.
    The audit log and the report engine both write JSON; we don't
    want to teach them about our Python types.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# ──────────────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────────────


class IdentifierType(StrEnum):
    """What kind of thing this identifier is.

    Used by the personal pivot (D3) and credential correlation (D4)
    to know which identifiers can be tested against which auth
    surfaces (e.g., a ``handle`` can't be sprayed against ADFS, but a
    ``corp_email`` can).
    """

    CORP_EMAIL = "corp_email"
    PERSONAL_EMAIL = "personal_email"
    HANDLE = "handle"          # username on a service
    PHONE = "phone"
    REAL_NAME = "real_name"
    DOMAIN = "domain"          # personal domain owned by the person
    OTHER = "other"


class LinkageStrength(StrEnum):
    """How strongly an identifier is linked to an identity.

    Maps onto the same confidence bands the Phase A scorer uses for
    accounts: ``high`` >= 0.7, ``medium`` >= 0.4, ``noise`` < 0.4.
    Used as a quick filter when the credential correlation only wants
    actionable signal.
    """

    HIGH = "high"
    MEDIUM = "medium"
    NOISE = "noise"

    @classmethod
    def from_score(cls, score: float) -> LinkageStrength:
        if score >= 0.7:
            return cls.HIGH
        if score >= 0.4:
            return cls.MEDIUM
        return cls.NOISE


class BreachConfidence(StrEnum):
    """How confident we are that a credential record is real + still
    relevant. Affects punch-list ranking."""

    VERIFIED = "verified"      # provider returned cleartext + checksum
    LIKELY = "likely"          # hashed credential matched a known plaintext
    UNVERIFIED = "unverified"  # presence-only signal (HIBP without paid tier)


# ──────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────


@dataclass
class Identifier:
    """One identifier (email, handle, phone, etc.) tied to an identity.

    Multiple identifiers per identity ── a person has one ``corp_email``
    plus N ``handle`` rows (one per discovered service) plus possibly a
    ``personal_email`` and a ``phone``.

    Attributes:
        value: The identifier's literal string (``"jane.doe@gitlab.com"``,
            ``"janedoe"``, ``"+1-555-0123"``, ``"Jane Doe"``).
        identifier_type: One of :class:`IdentifierType`.
        service: When ``identifier_type`` is ``HANDLE``, which service
            (e.g. ``"GitHub"``). ``None`` for emails / phones / names.
        source: Tool that surfaced this identifier
            (``"hunter"``, ``"maigret"``, ``"linkedin"``, etc.). The
            same identifier discovered by two tools deserves two rows
            so we can audit which sources contributed.
        confidence: Linkage confidence in ``[0, 1]``. For corp emails
            discovered via hunter this is 1.0 (the email IS the
            anchor); for personal handles guessed via name + year
            pattern this might be 0.4 until corroborating signal
            confirms.
        first_observed: ISO-8601 timestamp of when the framework first
            saw this identifier. Used by ageing logic in Phase E for
            recency-decayed scoring.
        metadata: Service-specific extras (verified flag, follower
            count, etc.) that don't fit the core schema.
    """

    value: str
    identifier_type: IdentifierType
    service: str | None = None
    source: str = ""
    confidence: float = 1.0
    first_observed: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def linkage_strength(self) -> LinkageStrength:
        return LinkageStrength.from_score(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "identifier_type": self.identifier_type.value,
            "service": self.service,
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "linkage_strength": self.linkage_strength.value,
            "first_observed": self.first_observed,
            "metadata": self.metadata,
        }


@dataclass
class CredentialExposure:
    """A credential surfaced by a breach DB or infostealer log.

    Attributes:
        breach_source: Name of the breach / source
            (``"DeHashed:LinkedIn-2012"``, ``"HudsonRock:Vidar-2024-08"``,
            ``"IntelX:Collection1"``).
        breach_date: ISO-8601 date the breach is dated to (best-effort
            from the source).
        observed_at_identifier: Which identifier in the identity this
            credential was tied to (e.g. ``"jane.doe.82@gmail.com"``).
            This is critical for the credential-correlation step: the
            password came from THIS personal email's exposure, and we
            propose testing it against the corp email.
        credential_kind: ``"password"``, ``"hash"``, ``"cookie"``,
            ``"token"`` etc.
        credential_value: For ``password`` and ``hash`` kinds: the
            value itself. NEVER printed to logs, NEVER published in
            generated reports ── only available to the operator
            reading the raw findings.
        confidence: :class:`BreachConfidence` band.
        provenance: Free-text source detail for the operator's
            audit (URL the infostealer logged into when the cred was
            captured, list of co-credentials in the same record, etc.).
    """

    breach_source: str
    breach_date: str | None
    observed_at_identifier: str
    credential_kind: str
    credential_value: str
    confidence: BreachConfidence
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, redact_value: bool = True) -> dict[str, Any]:
        """Serialise the exposure. ``redact_value=True`` (the default)
        replaces the credential string with ``"[REDACTED]"`` ── used
        anywhere the output might be persisted to disk or printed.
        Operator code paths that need the actual value (the punch-list
        generator) pass ``redact_value=False`` explicitly."""
        out = {
            "breach_source": self.breach_source,
            "breach_date": self.breach_date,
            "observed_at_identifier": self.observed_at_identifier,
            "credential_kind": self.credential_kind,
            "credential_value": "[REDACTED]" if redact_value else self.credential_value,
            "confidence": self.confidence.value,
            "provenance": self.provenance,
        }
        return out


@dataclass
class RelationshipEdge:
    """Outbound edge to another identity. Phase E (relationship graph)
    populates these; Phase D leaves the list empty.

    Stored on the source identity so traversing the graph from any
    identity is a flat lookup. Cycles are permitted (Alice → Bob and
    Bob → Alice as separate edges with potentially different
    interaction histories).
    """

    target_identity_id: str
    interaction_type: str  # "co-author", "follower", "co-speaker", etc.
    strength: float  # [0, 1], recency-decayed at scoring time
    last_observed: str | None = None  # ISO-8601 of most recent obs
    sources: list[str] = field(default_factory=list)  # ["github", "twitter"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_identity_id": self.target_identity_id,
            "interaction_type": self.interaction_type,
            "strength": round(self.strength, 3),
            "last_observed": self.last_observed,
            "sources": list(self.sources),
        }


@dataclass
class Identity:
    """One human, modelled by everything we know about them.

    The :class:`IdentityGraph` (below) holds a collection of these
    keyed by ``identity_id``. The identity_id is content-derived
    (see :func:`derive_identity_id`) so the same person discovered
    via two paths merges to one identity rather than duplicating.

    Attributes:
        identity_id: Stable hex string derived from the strongest
            available identifier (corp email > personal email >
            (handle, service) > real_name). Same person, same id.
        primary_label: Human-readable label for reports
            (``"Jane Doe (VP Engineering, GitLab)"``). Best-effort
            from the available identifiers.
        identifiers: All known identifiers tied to this person.
        credential_exposures: Breach DB / infostealer findings.
            Populated by D4 credential correlation.
        related_to: Outbound relationship edges to other identities
            (Phase E). Empty until E1 lands.
        metadata: Bag for things that don't yet have a typed slot:
            department, role, location, ageing signals, etc. Avoid
            putting credentials or sensitive PII here ── those have
            their own typed fields.
    """

    identity_id: str
    primary_label: str = ""
    identifiers: list[Identifier] = field(default_factory=list)
    credential_exposures: list[CredentialExposure] = field(default_factory=list)
    related_to: list[RelationshipEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── Identifier helpers ────────────────────────────────────────

    def add_identifier(self, identifier: Identifier) -> None:
        """Add an identifier if it's not already present.

        Deduplication key: ``(value, identifier_type, service)``.
        When a duplicate is added, the higher-confidence one wins
        and the metadata is merged (rather than replaced).
        """
        key = self._identifier_key(identifier)
        for existing in self.identifiers:
            if self._identifier_key(existing) == key:
                if identifier.confidence > existing.confidence:
                    existing.confidence = identifier.confidence
                # Always merge metadata ── later sources may add fields.
                for mk, mv in identifier.metadata.items():
                    existing.metadata.setdefault(mk, mv)
                return
        self.identifiers.append(identifier)

    def add_credential_exposure(self, exposure: CredentialExposure) -> None:
        """Add a credential exposure if not already present.

        Deduplication key: ``(breach_source, observed_at_identifier,
        credential_kind, credential_value)``. Repeated reports of the
        same exposure are absorbed."""
        key = (
            exposure.breach_source,
            exposure.observed_at_identifier,
            exposure.credential_kind,
            exposure.credential_value,
        )
        for existing in self.credential_exposures:
            existing_key = (
                existing.breach_source,
                existing.observed_at_identifier,
                existing.credential_kind,
                existing.credential_value,
            )
            if existing_key == key:
                return
        self.credential_exposures.append(exposure)

    @staticmethod
    def _identifier_key(i: Identifier) -> tuple[str, str, str | None]:
        return (i.value.lower(), i.identifier_type.value, i.service)

    # ── Query helpers ─────────────────────────────────────────────

    def corp_emails(self) -> list[Identifier]:
        return [i for i in self.identifiers if i.identifier_type == IdentifierType.CORP_EMAIL]

    def personal_emails(self) -> list[Identifier]:
        return [i for i in self.identifiers if i.identifier_type == IdentifierType.PERSONAL_EMAIL]

    def handles(self, service: str | None = None) -> list[Identifier]:
        out = [i for i in self.identifiers if i.identifier_type == IdentifierType.HANDLE]
        if service:
            out = [i for i in out if (i.service or "").lower() == service.lower()]
        return out

    def best_identifier_for(self, kind: IdentifierType) -> Identifier | None:
        """Return the highest-confidence identifier of the given kind,
        or None if there are none."""
        candidates = [i for i in self.identifiers if i.identifier_type == kind]
        if not candidates:
            return None
        return max(candidates, key=lambda i: i.confidence)

    def has_actionable_credential(self) -> bool:
        """True when the identity has at least one credential exposure
        that carries a usable value (password/hash/token, not just
        presence-only)."""
        return any(
            ce.credential_kind in ("password", "hash", "token", "cookie")
            and ce.credential_value
            and ce.credential_value != "[REDACTED]"
            for ce in self.credential_exposures
        )

    # ── Serialisation ─────────────────────────────────────────────

    def to_dict(self, redact_credentials: bool = True) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "primary_label": self.primary_label,
            "identifiers": [i.to_dict() for i in self.identifiers],
            "credential_exposures": [
                ce.to_dict(redact_value=redact_credentials)
                for ce in self.credential_exposures
            ],
            "related_to": [r.to_dict() for r in self.related_to],
            "metadata": self.metadata,
        }


# ──────────────────────────────────────────────────────────────────────
# Identity-ID derivation
# ──────────────────────────────────────────────────────────────────────


def derive_identity_id(identifiers: list[Identifier]) -> str:
    """Compute a stable ID for an identity from its known identifiers.

    Priority order for the seed:
      1. The corp email with highest confidence.
      2. The personal email with highest confidence (when no corp email).
      3. The (handle, service) pair with highest confidence.
      4. The real_name when nothing else is available.
      5. A timestamp-based fallback when even the name is missing.

    The chosen seed is SHA-256-hashed and the first 16 hex chars are
    returned. This is intentionally short ── meant for report
    readability, not cryptographic uniqueness within a campaign.

    The same person discovered via the same seed identifier always
    gets the same ID, which is how :func:`IdentityGraph.merge` knows
    to combine duplicates rather than create twins.
    """
    if not identifiers:
        # Fallback ── unique-enough timestamp + random.
        seed = f"unknown:{time.time_ns()}"
    else:
        # Pick the strongest available identifier as the seed.
        seed = _pick_seed_identifier(identifiers)

    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return digest[:16]


def _pick_seed_identifier(identifiers: list[Identifier]) -> str:
    """Choose the seed identifier per the documented priority order."""
    priority = [
        IdentifierType.CORP_EMAIL,
        IdentifierType.PERSONAL_EMAIL,
        IdentifierType.HANDLE,
        IdentifierType.REAL_NAME,
    ]
    for kind in priority:
        candidates = [i for i in identifiers if i.identifier_type == kind]
        if not candidates:
            continue
        best = max(candidates, key=lambda i: i.confidence)
        if kind == IdentifierType.HANDLE and best.service:
            return f"handle:{best.service.lower()}:{best.value.lower()}"
        return f"{kind.value}:{best.value.lower()}"
    # Last resort.
    return f"misc:{identifiers[0].value.lower()}"


# ──────────────────────────────────────────────────────────────────────
# Identity graph
# ──────────────────────────────────────────────────────────────────────


class IdentityGraph:
    """Per-campaign collection of all known identities.

    Built by Phase 2 from harvested emails + names. Extended by
    Phase 2.5 (the personal-identity pivot, D3) with personal
    identifiers and credential exposures. Extended again by Phase E
    with relationship edges. Consumed by Phase 8 (the risk_analyst
    agent) and Phase 9 (report generation) for the per-target
    deliverables.

    Identities are stored in a dict keyed by ``identity_id``. Lookup
    by identifier value (``"jane.doe@gitlab.com"``) traverses the
    map; for large campaigns this is O(N*M) so we maintain a reverse
    index ``_by_identifier_value`` for O(1) lookup.
    """

    def __init__(self) -> None:
        self._identities: dict[str, Identity] = {}
        # Reverse index: identifier value (lowercased) → identity_id.
        # Same identifier across multiple identities is allowed but
        # signals an attribution conflict the operator should
        # investigate ── we keep the most recent.
        self._by_identifier_value: dict[str, str] = {}

    # ── Construction ──────────────────────────────────────────────

    def add_identity(self, identity: Identity) -> None:
        """Add or merge an identity. If an identity with the same id
        already exists, the new identity's identifiers and exposures
        are merged in."""
        existing = self._identities.get(identity.identity_id)
        if existing is None:
            self._identities[identity.identity_id] = identity
            for ident in identity.identifiers:
                self._by_identifier_value[ident.value.lower()] = identity.identity_id
            return

        # Merge into existing.
        for ident in identity.identifiers:
            existing.add_identifier(ident)
            self._by_identifier_value[ident.value.lower()] = existing.identity_id
        for ce in identity.credential_exposures:
            existing.add_credential_exposure(ce)
        for edge in identity.related_to:
            # Edges deduped by target + interaction_type.
            existing.related_to.append(edge)
        # Promote a more informative primary label if the merge-in
        # has one and the existing didn't.
        if identity.primary_label and not existing.primary_label:
            existing.primary_label = identity.primary_label
        # Metadata merge ── later sources fill in gaps.
        for k, v in identity.metadata.items():
            existing.metadata.setdefault(k, v)

    def add_identifier_to(self, identity_id: str, identifier: Identifier) -> None:
        """Add a single identifier to an existing identity. Convenience
        for the personal pivot when it surfaces a new personal handle
        for an already-known identity."""
        identity = self._identities.get(identity_id)
        if identity is None:
            raise KeyError(f"No identity with id {identity_id!r}")
        identity.add_identifier(identifier)
        self._by_identifier_value[identifier.value.lower()] = identity_id

    # ── Lookup ────────────────────────────────────────────────────

    def get(self, identity_id: str) -> Identity | None:
        return self._identities.get(identity_id)

    def by_identifier(self, value: str) -> Identity | None:
        """Find the identity that owns a given identifier value
        (case-insensitive)."""
        if not value:
            return None
        ident_id = self._by_identifier_value.get(value.lower())
        if ident_id is None:
            return None
        return self._identities.get(ident_id)

    def all(self) -> list[Identity]:
        return list(self._identities.values())

    def __len__(self) -> int:
        return len(self._identities)

    def __contains__(self, identity_id: str) -> bool:
        return identity_id in self._identities

    # ── Filters / aggregates ──────────────────────────────────────

    def identities_with_credentials(self) -> list[Identity]:
        """All identities with at least one usable credential exposure."""
        return [i for i in self._identities.values() if i.has_actionable_credential()]

    def identities_with_personal_email(self) -> list[Identity]:
        """All identities for which the personal pivot found a
        confident personal email. Useful for the credential-correlation
        target set."""
        return [
            i for i in self._identities.values()
            if any(ident.identifier_type == IdentifierType.PERSONAL_EMAIL
                   and ident.confidence >= 0.6
                   for ident in i.identifiers)
        ]

    # ── Serialisation ─────────────────────────────────────────────

    def to_dict(self, redact_credentials: bool = True) -> dict[str, Any]:
        return {
            "identity_count": len(self._identities),
            "identities": [
                i.to_dict(redact_credentials=redact_credentials)
                for i in self._identities.values()
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdentityGraph:
        """Rebuild an IdentityGraph from a ``to_dict()`` payload. Used
        by the campaign-resume path so a paused campaign can restore
        the identity graph from its checkpoint without re-running
        Phase 2."""
        graph = cls()
        for ident_data in data.get("identities", []):
            identifiers = [
                Identifier(
                    value=i["value"],
                    identifier_type=IdentifierType(i["identifier_type"]),
                    service=i.get("service"),
                    source=i.get("source", ""),
                    confidence=float(i.get("confidence", 1.0)),
                    first_observed=float(i.get("first_observed", time.time())),
                    metadata=dict(i.get("metadata", {})),
                )
                for i in ident_data.get("identifiers", [])
            ]
            exposures = [
                CredentialExposure(
                    breach_source=ce["breach_source"],
                    breach_date=ce.get("breach_date"),
                    observed_at_identifier=ce["observed_at_identifier"],
                    credential_kind=ce["credential_kind"],
                    credential_value=ce.get("credential_value", ""),
                    confidence=BreachConfidence(ce.get("confidence", "unverified")),
                    provenance=dict(ce.get("provenance", {})),
                )
                for ce in ident_data.get("credential_exposures", [])
            ]
            edges = [
                RelationshipEdge(
                    target_identity_id=e["target_identity_id"],
                    interaction_type=e["interaction_type"],
                    strength=float(e["strength"]),
                    last_observed=e.get("last_observed"),
                    sources=list(e.get("sources", [])),
                )
                for e in ident_data.get("related_to", [])
            ]
            identity = Identity(
                identity_id=ident_data["identity_id"],
                primary_label=ident_data.get("primary_label", ""),
                identifiers=identifiers,
                credential_exposures=exposures,
                related_to=edges,
                metadata=dict(ident_data.get("metadata", {})),
            )
            graph.add_identity(identity)
        return graph


# ──────────────────────────────────────────────────────────────────────
# Phase 2 adapter ── build an IdentityGraph from email_intel
# ──────────────────────────────────────────────────────────────────────


def build_from_email_intel(email_intel: dict[str, Any]) -> IdentityGraph:
    """Convert the legacy ``email_intel.emails`` dict-of-dicts into a
    proper IdentityGraph. Used by Phase 2's wiring during the
    transition: Phase 2's existing code populates ``email_intel``,
    then we adapt it for Phase 2.5 + downstream consumers without
    rewriting Phase 2.

    Once all phases consume the IdentityGraph directly, this adapter
    can retire.
    """
    graph = IdentityGraph()
    emails = email_intel.get("emails", {}) if isinstance(email_intel, dict) else {}

    for email, record in emails.items():
        if not isinstance(record, dict):
            continue

        identifiers: list[Identifier] = [
            Identifier(
                value=email,
                identifier_type=IdentifierType.CORP_EMAIL,
                source=record.get("source", "harvested"),
                confidence=1.0,
            ),
        ]

        # Real name from Hunter.io fields, if available.
        first = record.get("first_name") or ""
        last = record.get("last_name") or ""
        full_name = " ".join(p for p in (first, last) if p)
        if full_name:
            identifiers.append(Identifier(
                value=full_name,
                identifier_type=IdentifierType.REAL_NAME,
                source=record.get("source", "hunter"),
                confidence=0.9,
            ))

        # Holehe-discovered service registrations: each is a handle
        # at a specific service, attribution is "the email is
        # registered at this service" not "this handle on the service
        # belongs to this email's owner" ── still useful as a marker.
        for svc in record.get("registered_services") or []:
            svc_name = svc.get("service") if isinstance(svc, dict) else str(svc)
            if svc_name:
                identifiers.append(Identifier(
                    value=email,  # holehe attaches by email, not handle
                    identifier_type=IdentifierType.CORP_EMAIL,
                    service=svc_name,
                    source="holehe",
                    confidence=0.95,
                    metadata={"holehe_registered": True},
                ))

        # Maigret-derived handles at confidence >= 0.6 (actionable).
        for hit in record.get("maigret_accounts") or []:
            handle = hit.get("username") if isinstance(hit, dict) else None
            service = hit.get("service") if isinstance(hit, dict) else None
            conf = hit.get("confidence", 0.0) if isinstance(hit, dict) else 0.0
            if handle and service and conf >= 0.6:
                identifiers.append(Identifier(
                    value=handle,
                    identifier_type=IdentifierType.HANDLE,
                    service=service,
                    source="maigret",
                    confidence=float(conf),
                    metadata={
                        "url": hit.get("url"),
                        "rationale": hit.get("confidence_rationale"),
                    },
                ))

        ident_id = derive_identity_id(identifiers)
        primary_label = full_name or email
        if record.get("position"):
            primary_label = f"{primary_label} ({record['position']})"

        identity = Identity(
            identity_id=ident_id,
            primary_label=primary_label,
            identifiers=identifiers,
            metadata={
                k: v for k, v in record.items()
                if k not in ("registered_services", "maigret_accounts",
                             "derived_usernames")
                and not k.startswith("_")
            },
        )
        graph.add_identity(identity)

    return graph
