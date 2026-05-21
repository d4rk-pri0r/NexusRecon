"""Tests for nexusrecon.core.identity_graph: D1 foundational model."""
from __future__ import annotations

import json

import pytest

from nexusrecon.core.identity_graph import (
    BreachConfidence,
    CredentialExposure,
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    LinkageStrength,
    RelationshipEdge,
    build_from_email_intel,
    derive_identity_id,
)

# ──────────────────────────────────────────────────────────────────────
# LinkageStrength threshold bands
# ──────────────────────────────────────────────────────────────────────


class TestLinkageStrengthBands:
    def test_high_band_at_or_above_07(self):
        assert LinkageStrength.from_score(0.7) == LinkageStrength.HIGH
        assert LinkageStrength.from_score(0.85) == LinkageStrength.HIGH
        assert LinkageStrength.from_score(1.0) == LinkageStrength.HIGH

    def test_medium_band_between_04_and_07(self):
        assert LinkageStrength.from_score(0.4) == LinkageStrength.MEDIUM
        assert LinkageStrength.from_score(0.55) == LinkageStrength.MEDIUM
        assert LinkageStrength.from_score(0.69) == LinkageStrength.MEDIUM

    def test_noise_band_below_04(self):
        assert LinkageStrength.from_score(0.0) == LinkageStrength.NOISE
        assert LinkageStrength.from_score(0.2) == LinkageStrength.NOISE
        assert LinkageStrength.from_score(0.39) == LinkageStrength.NOISE


# ──────────────────────────────────────────────────────────────────────
# Identifier
# ──────────────────────────────────────────────────────────────────────


class TestIdentifier:
    def test_corp_email_identifier(self):
        i = Identifier(
            value="jane.doe@gitlab.com",
            identifier_type=IdentifierType.CORP_EMAIL,
            source="hunter",
            confidence=1.0,
        )
        assert i.identifier_type == IdentifierType.CORP_EMAIL
        assert i.linkage_strength == LinkageStrength.HIGH

    def test_handle_identifier_with_service(self):
        i = Identifier(
            value="janedoe",
            identifier_type=IdentifierType.HANDLE,
            service="GitHub",
            source="maigret",
            confidence=0.85,
        )
        assert i.service == "GitHub"
        assert i.linkage_strength == LinkageStrength.HIGH

    def test_medium_band_inferred_from_confidence(self):
        i = Identifier(
            value="jane.doe.82@gmail.com",
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            source="personal_pivot",
            confidence=0.55,
        )
        assert i.linkage_strength == LinkageStrength.MEDIUM

    def test_to_dict_round_trip(self):
        i = Identifier(
            value="janedoe",
            identifier_type=IdentifierType.HANDLE,
            service="GitHub",
            source="maigret",
            confidence=0.85,
            metadata={"url": "https://github.com/janedoe"},
        )
        d = i.to_dict()
        # JSON-safe.
        json.dumps(d)
        assert d["value"] == "janedoe"
        assert d["identifier_type"] == "handle"
        assert d["service"] == "GitHub"
        assert d["confidence"] == 0.85
        assert d["linkage_strength"] == "high"
        assert d["metadata"]["url"] == "https://github.com/janedoe"


# ──────────────────────────────────────────────────────────────────────
# CredentialExposure
# ──────────────────────────────────────────────────────────────────────


class TestCredentialExposure:
    def test_default_to_dict_redacts_value(self):
        """Anywhere a CredentialExposure could be persisted to disk or
        printed, the credential string must NOT appear in the
        serialised form by default. Pin this so a regression that
        drops the redaction default fails loud."""
        ce = CredentialExposure(
            breach_source="DeHashed:LinkedIn-2012",
            breach_date="2012-06-05",
            observed_at_identifier="jane.doe.82@gmail.com",
            credential_kind="password",
            credential_value="MarathonRunner!82",
            confidence=BreachConfidence.VERIFIED,
        )
        d = ce.to_dict()  # default redact=True
        assert d["credential_value"] == "[REDACTED]"
        # Other fields intact.
        assert d["breach_source"] == "DeHashed:LinkedIn-2012"
        assert d["confidence"] == "verified"

    def test_explicit_unredacted_returns_real_value(self):
        """The punch-list generator needs the real value. Verify the
        explicit opt-out path exposes it."""
        ce = CredentialExposure(
            breach_source="DeHashed:LinkedIn-2012",
            breach_date="2012-06-05",
            observed_at_identifier="jane.doe.82@gmail.com",
            credential_kind="password",
            credential_value="MarathonRunner!82",
            confidence=BreachConfidence.VERIFIED,
        )
        d = ce.to_dict(redact_value=False)
        assert d["credential_value"] == "MarathonRunner!82"

    def test_provenance_carries_through(self):
        ce = CredentialExposure(
            breach_source="HudsonRock:Vidar-2024-08",
            breach_date="2024-08-15",
            observed_at_identifier="jane.doe.82@gmail.com",
            credential_kind="password",
            credential_value="hunter2",
            confidence=BreachConfidence.VERIFIED,
            provenance={
                "captured_url": "login.example.com",
                "co_credentials": ["abc.com", "xyz.com"],
            },
        )
        d = ce.to_dict()
        assert d["provenance"]["captured_url"] == "login.example.com"


# ──────────────────────────────────────────────────────────────────────
# Identity
# ──────────────────────────────────────────────────────────────────────


class TestIdentityIdentifierDedup:
    def _i(self, value, type=IdentifierType.CORP_EMAIL, service=None,
            source="test", confidence=1.0, meta=None):
        return Identifier(
            value=value,
            identifier_type=type,
            service=service,
            source=source,
            confidence=confidence,
            metadata=meta or {},
        )

    def test_same_identifier_added_twice_dedups(self):
        identity = Identity(identity_id="x")
        identity.add_identifier(self._i("jane.doe@gitlab.com"))
        identity.add_identifier(self._i("jane.doe@gitlab.com"))
        assert len(identity.identifiers) == 1

    def test_dedup_key_includes_type(self):
        """Same string value as CORP_EMAIL and PERSONAL_EMAIL is two
        rows ── we can't tell them apart from the value alone."""
        identity = Identity(identity_id="x")
        identity.add_identifier(self._i("jane@example.com",
                                        type=IdentifierType.CORP_EMAIL))
        identity.add_identifier(self._i("jane@example.com",
                                        type=IdentifierType.PERSONAL_EMAIL))
        assert len(identity.identifiers) == 2

    def test_dedup_key_includes_service(self):
        """Same handle on GitHub and Twitter is two rows so the
        per-service confidence is tracked independently."""
        identity = Identity(identity_id="x")
        identity.add_identifier(self._i("janedoe", type=IdentifierType.HANDLE,
                                        service="GitHub", confidence=0.9))
        identity.add_identifier(self._i("janedoe", type=IdentifierType.HANDLE,
                                        service="Twitter", confidence=0.7))
        assert len(identity.identifiers) == 2

    def test_dedup_keeps_higher_confidence(self):
        """When the same identifier is added with two confidences,
        the higher one wins."""
        identity = Identity(identity_id="x")
        identity.add_identifier(self._i("jane.doe@gitlab.com", confidence=0.6))
        identity.add_identifier(self._i("jane.doe@gitlab.com", confidence=0.95))
        assert identity.identifiers[0].confidence == 0.95

    def test_dedup_merges_metadata(self):
        """Two sources surfacing the same identifier may carry
        complementary metadata ── neither should drop fields."""
        identity = Identity(identity_id="x")
        identity.add_identifier(self._i(
            "janedoe", type=IdentifierType.HANDLE, service="GitHub",
            source="maigret", meta={"url": "https://github.com/janedoe"},
        ))
        identity.add_identifier(self._i(
            "janedoe", type=IdentifierType.HANDLE, service="GitHub",
            source="github_recon", meta={"public_repos": 47},
        ))
        meta = identity.identifiers[0].metadata
        assert meta["url"] == "https://github.com/janedoe"
        assert meta["public_repos"] == 47

    def test_case_insensitive_dedup(self):
        identity = Identity(identity_id="x")
        identity.add_identifier(self._i("Jane.Doe@GitLab.com"))
        identity.add_identifier(self._i("jane.doe@gitlab.com"))
        assert len(identity.identifiers) == 1


class TestIdentityCredentialDedup:
    def test_same_credential_added_twice_dedups(self):
        identity = Identity(identity_id="x")
        ce = CredentialExposure(
            breach_source="DeHashed:LinkedIn-2012",
            breach_date="2012-06-05",
            observed_at_identifier="jane@example.com",
            credential_kind="password",
            credential_value="MarathonRunner!82",
            confidence=BreachConfidence.VERIFIED,
        )
        identity.add_credential_exposure(ce)
        identity.add_credential_exposure(ce)
        assert len(identity.credential_exposures) == 1

    def test_different_breach_sources_are_separate_rows(self):
        identity = Identity(identity_id="x")
        for src in ("DeHashed:LinkedIn-2012", "DeHashed:Adobe-2013"):
            identity.add_credential_exposure(CredentialExposure(
                breach_source=src,
                breach_date="2012-06-05",
                observed_at_identifier="jane@example.com",
                credential_kind="password",
                credential_value="x",
                confidence=BreachConfidence.VERIFIED,
            ))
        assert len(identity.credential_exposures) == 2


class TestIdentityQueryHelpers:
    def _build(self) -> Identity:
        identity = Identity(identity_id="x")
        identity.add_identifier(Identifier(
            value="jane.doe@gitlab.com",
            identifier_type=IdentifierType.CORP_EMAIL,
            source="hunter", confidence=1.0,
        ))
        identity.add_identifier(Identifier(
            value="jane.doe.82@gmail.com",
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            source="pivot", confidence=0.78,
        ))
        identity.add_identifier(Identifier(
            value="janedoe", identifier_type=IdentifierType.HANDLE,
            service="GitHub", source="maigret", confidence=0.85,
        ))
        identity.add_identifier(Identifier(
            value="janedoe", identifier_type=IdentifierType.HANDLE,
            service="Twitter", source="maigret", confidence=0.65,
        ))
        return identity

    def test_corp_emails_filter(self):
        identity = self._build()
        emails = identity.corp_emails()
        assert len(emails) == 1
        assert emails[0].value == "jane.doe@gitlab.com"

    def test_personal_emails_filter(self):
        identity = self._build()
        emails = identity.personal_emails()
        assert len(emails) == 1
        assert emails[0].value == "jane.doe.82@gmail.com"

    def test_handles_all(self):
        identity = self._build()
        handles = identity.handles()
        assert len(handles) == 2

    def test_handles_by_service(self):
        identity = self._build()
        github = identity.handles(service="GitHub")
        assert len(github) == 1
        assert github[0].value == "janedoe"
        # Case-insensitive.
        github_lower = identity.handles(service="github")
        assert len(github_lower) == 1

    def test_best_identifier_for(self):
        identity = self._build()
        best_email = identity.best_identifier_for(IdentifierType.CORP_EMAIL)
        assert best_email.value == "jane.doe@gitlab.com"
        # No phone in this identity.
        assert identity.best_identifier_for(IdentifierType.PHONE) is None


class TestHasActionableCredential:
    def test_no_exposures_returns_false(self):
        assert Identity(identity_id="x").has_actionable_credential() is False

    def test_presence_only_exposure_returns_false(self):
        """An HIBP-style 'this email is in N breaches' record without
        an actual password isn't actionable for credential testing."""
        identity = Identity(identity_id="x")
        identity.add_credential_exposure(CredentialExposure(
            breach_source="HIBP:LinkedIn-2012",
            breach_date="2012-06-05",
            observed_at_identifier="jane@example.com",
            credential_kind="presence_only",
            credential_value="",  # no value
            confidence=BreachConfidence.UNVERIFIED,
        ))
        assert identity.has_actionable_credential() is False

    def test_password_with_value_returns_true(self):
        identity = Identity(identity_id="x")
        identity.add_credential_exposure(CredentialExposure(
            breach_source="DeHashed:LinkedIn-2012",
            breach_date="2012-06-05",
            observed_at_identifier="jane@example.com",
            credential_kind="password",
            credential_value="MarathonRunner!82",
            confidence=BreachConfidence.VERIFIED,
        ))
        assert identity.has_actionable_credential() is True

    def test_redacted_string_doesnt_count_as_actionable(self):
        """If something stores a CredentialExposure with already-
        redacted value, treat it as presence-only ── operators won't
        be able to test the literal '[REDACTED]'."""
        identity = Identity(identity_id="x")
        identity.add_credential_exposure(CredentialExposure(
            breach_source="x", breach_date=None,
            observed_at_identifier="x", credential_kind="password",
            credential_value="[REDACTED]",
            confidence=BreachConfidence.VERIFIED,
        ))
        assert identity.has_actionable_credential() is False


# ──────────────────────────────────────────────────────────────────────
# derive_identity_id
# ──────────────────────────────────────────────────────────────────────


class TestDeriveIdentityId:
    def test_corp_email_wins_seed_priority(self):
        identifiers = [
            Identifier(value="janedoe", identifier_type=IdentifierType.HANDLE,
                       service="GitHub"),
            Identifier(value="jane.doe@gitlab.com",
                       identifier_type=IdentifierType.CORP_EMAIL),
        ]
        identity_id = derive_identity_id(identifiers)
        # Same person discovered via the corp email should always
        # produce the same id.
        identifiers_b = [
            Identifier(value="jane.doe@gitlab.com",
                       identifier_type=IdentifierType.CORP_EMAIL),
        ]
        assert derive_identity_id(identifiers_b) == identity_id

    def test_personal_email_used_when_no_corp(self):
        identifiers = [
            Identifier(value="jane@gmail.com",
                       identifier_type=IdentifierType.PERSONAL_EMAIL),
            Identifier(value="janedoe", identifier_type=IdentifierType.HANDLE,
                       service="GitHub"),
        ]
        # Same personal email → same id.
        other = [
            Identifier(value="jane@gmail.com",
                       identifier_type=IdentifierType.PERSONAL_EMAIL),
        ]
        assert derive_identity_id(identifiers) == derive_identity_id(other)

    def test_handle_with_service_used_when_no_email(self):
        identifiers = [
            Identifier(value="janedoe",
                       identifier_type=IdentifierType.HANDLE,
                       service="GitHub"),
        ]
        id1 = derive_identity_id(identifiers)
        # Same handle on a DIFFERENT service should produce a
        # different id ── two people might share a handle.
        identifiers_b = [
            Identifier(value="janedoe",
                       identifier_type=IdentifierType.HANDLE,
                       service="Twitter"),
        ]
        assert id1 != derive_identity_id(identifiers_b)

    def test_real_name_fallback(self):
        identifiers = [
            Identifier(value="Jane Doe",
                       identifier_type=IdentifierType.REAL_NAME),
        ]
        identity_id = derive_identity_id(identifiers)
        # Same name → same id.
        identifiers_b = [
            Identifier(value="Jane Doe",
                       identifier_type=IdentifierType.REAL_NAME),
        ]
        assert derive_identity_id(identifiers_b) == identity_id

    def test_empty_identifiers_returns_unique(self):
        """Empty list shouldn't crash ── produces a timestamp-based
        unique id."""
        id1 = derive_identity_id([])
        id2 = derive_identity_id([])
        # Both should be valid hex strings of length 16.
        assert len(id1) == 16 and len(id2) == 16
        # Parse as hex; raises if either is not a valid hex string.
        int(id1, 16)
        int(id2, 16)

    def test_case_insensitive_seed(self):
        a = derive_identity_id([Identifier(value="Jane.Doe@GitLab.com",
                                            identifier_type=IdentifierType.CORP_EMAIL)])
        b = derive_identity_id([Identifier(value="jane.doe@gitlab.com",
                                            identifier_type=IdentifierType.CORP_EMAIL)])
        assert a == b


# ──────────────────────────────────────────────────────────────────────
# IdentityGraph
# ──────────────────────────────────────────────────────────────────────


class TestIdentityGraph:
    def test_add_and_get(self):
        graph = IdentityGraph()
        identity = Identity(
            identity_id="abc",
            identifiers=[Identifier(value="x@y.com",
                                    identifier_type=IdentifierType.CORP_EMAIL)],
        )
        graph.add_identity(identity)
        assert len(graph) == 1
        assert graph.get("abc") is identity

    def test_by_identifier_reverse_lookup(self):
        graph = IdentityGraph()
        identity = Identity(
            identity_id="abc",
            identifiers=[Identifier(value="jane@gitlab.com",
                                    identifier_type=IdentifierType.CORP_EMAIL)],
        )
        graph.add_identity(identity)
        # Case-insensitive lookup.
        assert graph.by_identifier("JANE@gitlab.com") is identity
        assert graph.by_identifier("nobody@nowhere.com") is None

    def test_add_identity_merges_when_id_matches(self):
        """Adding an identity with the same id as an existing one
        should merge identifiers + exposures, not replace."""
        graph = IdentityGraph()
        a = Identity(
            identity_id="same-id",
            identifiers=[Identifier(value="jane@gitlab.com",
                                    identifier_type=IdentifierType.CORP_EMAIL)],
        )
        b = Identity(
            identity_id="same-id",
            identifiers=[Identifier(value="janedoe",
                                    identifier_type=IdentifierType.HANDLE,
                                    service="GitHub")],
        )
        graph.add_identity(a)
        graph.add_identity(b)
        assert len(graph) == 1
        merged = graph.get("same-id")
        assert len(merged.identifiers) == 2

    def test_add_identifier_to(self):
        graph = IdentityGraph()
        identity = Identity(
            identity_id="abc",
            identifiers=[Identifier(value="x@y.com",
                                    identifier_type=IdentifierType.CORP_EMAIL)],
        )
        graph.add_identity(identity)
        graph.add_identifier_to("abc", Identifier(
            value="janedoe",
            identifier_type=IdentifierType.HANDLE,
            service="GitHub",
        ))
        assert len(graph.get("abc").identifiers) == 2
        assert graph.by_identifier("janedoe") is graph.get("abc")

    def test_add_identifier_to_unknown_raises(self):
        graph = IdentityGraph()
        with pytest.raises(KeyError):
            graph.add_identifier_to("does-not-exist", Identifier(
                value="x", identifier_type=IdentifierType.HANDLE,
            ))

    def test_identities_with_credentials_filter(self):
        graph = IdentityGraph()
        # Identity A has a credential, B doesn't.
        a = Identity(identity_id="a")
        a.add_credential_exposure(CredentialExposure(
            breach_source="DeHashed:x", breach_date=None,
            observed_at_identifier="a@x.com",
            credential_kind="password", credential_value="real-password",
            confidence=BreachConfidence.VERIFIED,
        ))
        b = Identity(identity_id="b")
        graph.add_identity(a)
        graph.add_identity(b)
        with_creds = graph.identities_with_credentials()
        assert len(with_creds) == 1
        assert with_creds[0].identity_id == "a"

    def test_identities_with_personal_email_filter(self):
        graph = IdentityGraph()
        # A has a confident personal email; B has a low-confidence one;
        # C has no personal email.
        a = Identity(identity_id="a", identifiers=[Identifier(
            value="jane@gmail.com",
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            confidence=0.75,
        )])
        b = Identity(identity_id="b", identifiers=[Identifier(
            value="bob@gmail.com",
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            confidence=0.4,  # below the 0.6 actionable threshold
        )])
        c = Identity(identity_id="c", identifiers=[Identifier(
            value="c@corp.com",
            identifier_type=IdentifierType.CORP_EMAIL,
        )])
        for idn in (a, b, c):
            graph.add_identity(idn)
        result = graph.identities_with_personal_email()
        ids = {i.identity_id for i in result}
        assert ids == {"a"}


# ──────────────────────────────────────────────────────────────────────
# Round-trip serialisation
# ──────────────────────────────────────────────────────────────────────


class TestSerialisationRoundTrip:
    def test_to_dict_from_dict_round_trip(self):
        """The campaign-resume path persists the IdentityGraph to disk
        and reloads it. Verify the round-trip preserves every field."""
        graph = IdentityGraph()
        identity = Identity(
            identity_id="abc",
            primary_label="Jane Doe (VP Engineering, GitLab)",
            identifiers=[
                Identifier(value="jane.doe@gitlab.com",
                           identifier_type=IdentifierType.CORP_EMAIL,
                           source="hunter", confidence=1.0,
                           metadata={"position": "VP Engineering"}),
                Identifier(value="janedoe", identifier_type=IdentifierType.HANDLE,
                           service="GitHub", source="maigret", confidence=0.85),
            ],
            credential_exposures=[CredentialExposure(
                breach_source="DeHashed:LinkedIn-2012",
                breach_date="2012-06-05",
                observed_at_identifier="jane@gmail.com",
                credential_kind="password",
                credential_value="MarathonRunner!82",
                confidence=BreachConfidence.VERIFIED,
                provenance={"co_credentials": ["spotify"]},
            )],
            related_to=[RelationshipEdge(
                target_identity_id="def",
                interaction_type="co-author",
                strength=0.8,
                sources=["github"],
            )],
            metadata={"department": "engineering"},
        )
        graph.add_identity(identity)

        # Round-trip WITHOUT redaction (operator-side persistence path).
        serialised = graph.to_dict(redact_credentials=False)
        # JSON-safe.
        json.dumps(serialised)
        restored = IdentityGraph.from_dict(serialised)

        assert len(restored) == 1
        r = restored.get("abc")
        assert r.primary_label == identity.primary_label
        assert len(r.identifiers) == 2
        assert len(r.credential_exposures) == 1
        assert r.credential_exposures[0].credential_value == "MarathonRunner!82"
        assert len(r.related_to) == 1
        assert r.related_to[0].interaction_type == "co-author"
        assert r.metadata["department"] == "engineering"

    def test_to_dict_with_redaction_omits_credential_values(self):
        graph = IdentityGraph()
        identity = Identity(identity_id="abc")
        identity.add_credential_exposure(CredentialExposure(
            breach_source="DeHashed:x", breach_date=None,
            observed_at_identifier="jane@gmail.com",
            credential_kind="password", credential_value="real-password",
            confidence=BreachConfidence.VERIFIED,
        ))
        graph.add_identity(identity)
        serialised = graph.to_dict()  # default redact=True
        ce_dict = serialised["identities"][0]["credential_exposures"][0]
        assert ce_dict["credential_value"] == "[REDACTED]"


# ──────────────────────────────────────────────────────────────────────
# build_from_email_intel adapter
# ──────────────────────────────────────────────────────────────────────


class TestBuildFromEmailIntel:
    def test_basic_corp_email_becomes_identity(self):
        email_intel = {
            "emails": {
                "jane.doe@gitlab.com": {
                    "source": "hunter",
                    "first_name": "Jane",
                    "last_name": "Doe",
                    "position": "VP Engineering",
                },
            },
        }
        graph = build_from_email_intel(email_intel)
        assert len(graph) == 1
        identity = graph.by_identifier("jane.doe@gitlab.com")
        assert identity is not None
        # Real name extracted.
        real_names = [i for i in identity.identifiers
                      if i.identifier_type == IdentifierType.REAL_NAME]
        assert len(real_names) == 1
        assert real_names[0].value == "Jane Doe"
        # Position in label.
        assert "VP Engineering" in identity.primary_label

    def test_maigret_accounts_become_handle_identifiers(self):
        email_intel = {
            "emails": {
                "jane.doe@gitlab.com": {
                    "source": "hunter",
                    "maigret_accounts": [
                        {
                            "username": "janedoe",
                            "service": "GitHub",
                            "confidence": 0.85,
                            "confidence_rationale": "exact derivation, Tier 1",
                            "url": "https://github.com/janedoe",
                        },
                        {
                            "username": "janedoe",
                            "service": "Reddit",
                            "confidence": 0.35,  # below actionable
                            "confidence_rationale": "common handle",
                        },
                    ],
                },
            },
        }
        graph = build_from_email_intel(email_intel)
        identity = graph.by_identifier("jane.doe@gitlab.com")
        # Only the actionable (>= 0.6) maigret hit is promoted.
        handles = identity.handles()
        assert len(handles) == 1
        assert handles[0].value == "janedoe"
        assert handles[0].service == "GitHub"
        # Rationale carried into metadata.
        assert "Tier 1" in handles[0].metadata.get("rationale", "")

    def test_empty_email_intel_returns_empty_graph(self):
        graph = build_from_email_intel({})
        assert len(graph) == 0
        graph = build_from_email_intel({"emails": {}})
        assert len(graph) == 0

    def test_malformed_record_skipped_safely(self):
        """A record that isn't a dict should be skipped without
        crashing the whole adapter."""
        email_intel = {
            "emails": {
                "good@example.com": {"source": "hunter"},
                "bad@example.com": "not a dict",
                "also_bad": None,
            },
        }
        graph = build_from_email_intel(email_intel)
        # Only good@example.com made it through.
        assert len(graph) == 1
        assert graph.by_identifier("good@example.com") is not None

    def test_holehe_service_registrations_recorded(self):
        email_intel = {
            "emails": {
                "jane.doe@gitlab.com": {
                    "registered_services": [
                        {"service": "Adobe"},
                        {"service": "Lastfm"},
                    ],
                },
            },
        }
        graph = build_from_email_intel(email_intel)
        identity = graph.by_identifier("jane.doe@gitlab.com")
        # Two holehe markers for the corp email at Adobe + Lastfm.
        holehe_ids = [
            i for i in identity.identifiers
            if i.metadata.get("holehe_registered") is True
        ]
        assert len(holehe_ids) == 2
        services = {i.service for i in holehe_ids}
        assert services == {"Adobe", "Lastfm"}
