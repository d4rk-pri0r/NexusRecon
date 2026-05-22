"""Integration tests for D3 personal_pivot_tool.

Mocks the registry's ``execute`` so we exercise the orchestration
logic without firing real maigret / HIBP / IntelX subprocesses or
HTTP calls. The tool's scoring math + identity-extension assembly
are the real targets here."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from nexusrecon.core.identity_graph import (
    BreachConfidence,
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
)
from nexusrecon.tools.base import ToolResult
from nexusrecon.tools.identity.personal_pivot_tool import (
    PersonalPivotTool,
    _extract_credential_exposures,
    _summarise_breach_data,
    apply_extensions_to_graph,
)

# ──────────────────────────────────────────────────────────────────────
# Probe disabled: pure orchestration logic
# ──────────────────────────────────────────────────────────────────────


class TestProbeDisabledModes:
    async def test_no_probes_returns_candidates_only(self):
        """With both probes disabled, the tool returns the derived
        candidates without hitting any external service."""
        tool = PersonalPivotTool()
        result = await tool.run(
            "jane.doe@gitlab.com",
            name="Jane Doe",
            probe_handles=False,
            probe_emails=False,
        )
        assert result.success is True
        assert result.data["corp_identifier"] == "jane.doe@gitlab.com"
        assert len(result.data["handle_candidates"]) > 0
        assert len(result.data["email_candidates"]) > 0
        # No probes fired ── no hits, no extensions.
        assert result.data["handle_hits"] == []
        assert result.data["email_hits"] == []
        assert result.data["identity_extensions"] == []
        assert result.data["cross_domain_score"] == 0.0

    async def test_requires_name_kwarg(self):
        tool = PersonalPivotTool()
        result = await tool.run("jane.doe@gitlab.com")
        assert result.success is False
        assert "name" in result.error

    async def test_passes_context_to_derivation(self):
        """Context kwargs (age_range, interests, location) should
        widen the candidate set ── the test exercises the wiring,
        not the derivation itself (that's D2's tests)."""
        tool = PersonalPivotTool()
        await tool.run(
            "j@x.com", name="Jane Doe",
            probe_handles=False, probe_emails=False,
        )
        result_rich = await tool.run(
            "j@x.com", name="Jane Doe",
            age_range=(40, 45),
            interests=["Running"],
            location="San Francisco",
            max_handle_candidates=80,  # large cap to expose all patterns
            probe_handles=False, probe_emails=False,
        )
        rich_handles = {c["value"] for c in result_rich.data["handle_candidates"]}
        # Year + hobby + geo suffixes should produce values that
        # don't exist in the bare candidate set.
        assert any("running" in v or "marathon" in v or "knit" in v
                   for v in rich_handles)
        assert any("sf" in v or "sanfrancisco" in v
                   for v in rich_handles)


# ──────────────────────────────────────────────────────────────────────
# Handle probing
# ──────────────────────────────────────────────────────────────────────


class TestHandleProbing:
    async def test_handle_probe_invokes_maigret_via_registry(self):
        """``probe_handles=True`` should fire maigret on each derived
        candidate via the registry."""
        tool = PersonalPivotTool()

        # Mock the registry returned by get_registry().
        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(return_value=ToolResult(
            success=True, source="maigret",
            data={
                "registered_services": [
                    {"username": "jane.doe", "service": "Reddit",
                     "url": "https://reddit.com/u/jane.doe",
                     "confidence": 0.7,
                     "confidence_rationale": "tier 2"},
                ],
            },
            result_count=1,
        ))

        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=mock_registry,
        ):
            result = await tool.run(
                "jane@gitlab.com", name="Jane Doe",
                probe_handles=True, probe_emails=False,
                max_handle_candidates=3,
            )

        # Maigret should have been invoked for each candidate.
        assert mock_registry.execute.await_count >= 1
        # Hits should appear in the result.
        assert result.data["handle_hits"]
        # Each hit gets a pivot-candidate provenance field.
        first = result.data["handle_hits"][0]
        assert "pivot_candidate_pattern" in first
        assert "pivot_candidate_quality" in first

    async def test_handle_hit_failures_dont_crash_pivot(self):
        """If maigret throws on a candidate, the pivot keeps going
        for the remaining candidates."""
        tool = PersonalPivotTool()

        async def _flaky(*args, **kwargs):
            if "jane" in args[1]:
                raise RuntimeError("maigret crashed")
            return ToolResult(success=True, source="maigret",
                              data={"registered_services": []})

        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(side_effect=_flaky)

        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=mock_registry,
        ):
            result = await tool.run(
                "jane@gitlab.com", name="Jane Doe",
                probe_handles=True, probe_emails=False,
                max_handle_candidates=3,
            )

        # Tool succeeded despite the per-candidate errors.
        assert result.success is True


# ──────────────────────────────────────────────────────────────────────
# Email probing
# ──────────────────────────────────────────────────────────────────────


class TestEmailProbing:
    async def test_email_probe_runs_breach_tools(self):
        """All four breach tools (breach_lookup/HIBP, intelx,
        hudsonrock, dehashed) should be attempted per email
        candidate."""
        tool = PersonalPivotTool()

        seen_tool_names: list = []

        async def _fake_execute(tool_name, target, target_type, **kw):
            seen_tool_names.append(tool_name)
            return ToolResult(
                success=False, source=tool_name,
                error=f"{tool_name} prereqs not met",
            )

        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(side_effect=_fake_execute)

        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=mock_registry,
        ):
            await tool.run(
                "jane@gitlab.com", name="Jane Doe",
                probe_handles=False, probe_emails=True,
                max_email_candidates=2,
            )

        # All four breach tools should have been tried per candidate.
        unique = set(seen_tool_names)
        assert "breach_lookup" in unique
        assert "intelx" in unique
        assert "hudsonrock" in unique
        assert "dehashed" in unique

    async def test_hibp_hit_produces_presence_only_exposure(self):
        """A successful HIBP hit (with a breaches list, no passwords)
        should produce a presence_only CredentialExposure record."""
        tool = PersonalPivotTool()

        async def _fake_execute(tool_name, target, target_type, **kw):
            if tool_name == "breach_lookup":
                return ToolResult(
                    success=True, source="breach_lookup",
                    data={"breaches": [{"Name": "LinkedIn",
                                        "BreachDate": "2012-06-05"}]},
                    result_count=1,
                )
            return ToolResult(success=False, source=tool_name,
                              error=f"{tool_name} prereqs not met")

        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(side_effect=_fake_execute)

        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=mock_registry,
        ):
            result = await tool.run(
                "jane@gitlab.com", name="Jane Doe",
                probe_handles=False, probe_emails=True,
                max_email_candidates=2,
            )

        # Credential exposures from HIBP should appear (redacted in
        # the tool result).
        assert result.data["credential_exposures"]
        # All redacted.
        assert all(ce["credential_value"] == "[REDACTED]"
                   for ce in result.data["credential_exposures"])
        # Presence-only kind.
        assert any(ce["credential_kind"] == "presence_only"
                   for ce in result.data["credential_exposures"])
        # Breach source labelled properly.
        sources = {ce["breach_source"]
                   for ce in result.data["credential_exposures"]}
        assert any("HIBP:" in s for s in sources)

    async def test_dehashed_hit_produces_verified_password_exposure(self):
        """A DeHashed entry with a plaintext password should produce
        a VERIFIED-confidence record. The credential value gets
        redacted in the ToolResult per the privacy default."""
        tool = PersonalPivotTool()

        async def _fake_execute(tool_name, target, target_type, **kw):
            if tool_name == "dehashed":
                return ToolResult(
                    success=True, source="dehashed",
                    data={"entries": [{
                        "database": "LinkedIn-2012",
                        "password": "MarathonRunner!82",
                        "breach_date": "2012-06-05",
                    }]},
                    result_count=1,
                )
            return ToolResult(success=False, source=tool_name,
                              error=f"{tool_name} prereqs not met")

        mock_registry = MagicMock()
        mock_registry.execute = AsyncMock(side_effect=_fake_execute)

        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=mock_registry,
        ):
            result = await tool.run(
                "jane@gitlab.com", name="Jane Doe",
                probe_handles=False, probe_emails=True,
                max_email_candidates=1,
            )

        # At least one VERIFIED password exposure.
        pwd_exposures = [
            ce for ce in result.data["credential_exposures"]
            if ce["credential_kind"] == "password"
        ]
        assert pwd_exposures
        assert pwd_exposures[0]["confidence"] == "verified"
        # Redacted in the tool result.
        assert pwd_exposures[0]["credential_value"] == "[REDACTED]"


# ──────────────────────────────────────────────────────────────────────
# Scoring math
# ──────────────────────────────────────────────────────────────────────


class TestCrossDomainScoring:
    def test_score_handle_hit_handles_missing_fields(self):
        """An empty hit should produce a defensible score (not
        explode)."""
        score = PersonalPivotTool._score_handle_hit({}, {})
        assert 0.0 <= score <= 1.0

    def test_score_handle_hit_cross_service_convergence_bonus(self):
        """Same handle on 3+ services should outscore the same handle
        appearing only once, holding the other factors constant."""
        single = PersonalPivotTool._score_handle_hit(
            {"username": "jane.doe", "service": "Reddit",
             "pivot_candidate_quality": 0.5, "confidence": 0.5},
            {"jane.doe": 1},
        )
        triple = PersonalPivotTool._score_handle_hit(
            {"username": "jane.doe", "service": "Reddit",
             "pivot_candidate_quality": 0.5, "confidence": 0.5},
            {"jane.doe": 3},
        )
        assert triple > single

    def test_score_handle_hit_personal_tier_boost(self):
        """A personal-tier service (Reddit) should outscore an
        unrelated service (an unknown forum) for the same candidate +
        confidence."""
        personal = PersonalPivotTool._score_handle_hit(
            {"username": "jane.doe", "service": "Reddit",
             "pivot_candidate_quality": 0.5, "confidence": 0.5},
            {"jane.doe": 1},
        )
        unknown = PersonalPivotTool._score_handle_hit(
            {"username": "jane.doe", "service": "RandomForum.example",
             "pivot_candidate_quality": 0.5, "confidence": 0.5},
            {"jane.doe": 1},
        )
        assert personal > unknown

    def test_score_email_hit_tool_trust_dominates(self):
        """DeHashed hits should outscore HIBP hits ── DeHashed
        returns real credentials, HIBP is presence-only."""
        dehashed = PersonalPivotTool._score_email_hit({
            "tool": "dehashed", "candidate_quality": 0.8,
            "result_count": 1,
        })
        hibp = PersonalPivotTool._score_email_hit({
            "tool": "breach_lookup", "candidate_quality": 0.8,
            "result_count": 1,
        })
        assert dehashed > hibp


# ──────────────────────────────────────────────────────────────────────
# Graph extension
# ──────────────────────────────────────────────────────────────────────


class TestApplyExtensionsToGraph:
    def test_extensions_attach_to_existing_identity(self):
        graph = IdentityGraph()
        identity = Identity(
            identity_id="abc",
            identifiers=[Identifier(value="jane.doe@gitlab.com",
                                    identifier_type=IdentifierType.CORP_EMAIL)],
        )
        graph.add_identity(identity)

        pivot_result = {
            "identity_extensions": [
                {
                    "value": "jane.doe",
                    "identifier_type": IdentifierType.HANDLE.value,
                    "service": "Reddit",
                    "source": "personal_pivot:maigret",
                    "confidence": 0.78,
                    "metadata": {"pattern": "name.dotted"},
                },
                {
                    "value": "jane.doe.82@gmail.com",
                    "identifier_type": IdentifierType.PERSONAL_EMAIL.value,
                    "source": "personal_pivot:dehashed",
                    "confidence": 0.85,
                    "metadata": {},
                },
            ],
            "credential_exposures": [
                {
                    "breach_source": "DeHashed:LinkedIn-2012",
                    "breach_date": "2012-06-05",
                    "observed_at_identifier": "jane.doe.82@gmail.com",
                    "credential_kind": "password",
                    "credential_value": "[REDACTED]",
                    "confidence": "verified",
                    "provenance": {},
                },
            ],
        }
        apply_extensions_to_graph(graph, "abc", pivot_result)

        identity = graph.get("abc")
        # Original corp email + 2 extensions = 3 identifiers.
        assert len(identity.identifiers) == 3
        # Handle and personal email both present.
        types = {i.identifier_type for i in identity.identifiers}
        assert IdentifierType.CORP_EMAIL in types
        assert IdentifierType.HANDLE in types
        assert IdentifierType.PERSONAL_EMAIL in types
        # Credential exposure attached.
        assert len(identity.credential_exposures) == 1
        assert identity.credential_exposures[0].breach_source == "DeHashed:LinkedIn-2012"

    def test_apply_to_unknown_identity_silently_noops(self):
        graph = IdentityGraph()
        # Identity not added; apply should not raise.
        apply_extensions_to_graph(graph, "does-not-exist", {
            "identity_extensions": [{"value": "x", "identifier_type": "handle"}],
        })
        # Graph still empty.
        assert len(graph) == 0


# ──────────────────────────────────────────────────────────────────────
# Adapter helpers
# ──────────────────────────────────────────────────────────────────────


class TestCredentialExposureExtraction:
    def test_summarise_breach_data_non_dict(self):
        assert _summarise_breach_data(None) == {}
        assert _summarise_breach_data("not a dict") == {}

    def test_summarise_breach_data_counts(self):
        s = _summarise_breach_data({
            "result_count": 5,
            "breaches": [{"Name": "A"}, {"Name": "B"}],
            "stealers": [{}],
            "compromised": True,
        })
        assert s["result_count"] == 5
        assert s["breach_count"] == 2
        assert s["stealer_count"] == 1
        assert s["compromised"] is True

    def test_extract_credentials_unknown_tool_returns_empty(self):
        out = _extract_credential_exposures(
            tool_name="unknown_tool",
            email="jane@gmail.com",
            data={"anything": []},
        )
        assert out == []

    def test_extract_credentials_hibp_presence_only(self):
        out = _extract_credential_exposures(
            tool_name="breach_lookup",
            email="jane@gmail.com",
            data={"breaches": [{"Name": "LinkedIn",
                                "BreachDate": "2012-06-05"}]},
        )
        assert len(out) == 1
        assert out[0].credential_kind == "presence_only"
        assert out[0].credential_value == ""
        assert "HIBP:LinkedIn" in out[0].breach_source

    def test_extract_credentials_dehashed_with_password(self):
        out = _extract_credential_exposures(
            tool_name="dehashed",
            email="jane@gmail.com",
            data={"entries": [{
                "database": "LinkedIn-2012",
                "password": "MarathonRunner!82",
                "breach_date": "2012-06-05",
            }]},
        )
        assert len(out) == 1
        assert out[0].credential_kind == "password"
        assert out[0].credential_value == "MarathonRunner!82"
        assert out[0].confidence == BreachConfidence.VERIFIED

    def test_extract_credentials_dehashed_with_hash_only(self):
        out = _extract_credential_exposures(
            tool_name="dehashed",
            email="jane@gmail.com",
            data={"entries": [{
                "database": "Adobe-2013",
                "hashed_password": "5f4dcc3b5aa765d61d8327deb882cf99",
                "breach_date": "2013-10-04",
            }]},
        )
        assert len(out) == 1
        assert out[0].credential_kind == "hash"
        assert "5f4dcc" in out[0].credential_value

    def test_extract_credentials_hudsonrock_compromised(self):
        """Community-tier domain check: stealer without captured_credentials
        produces one presence_only record per stealer session."""
        out = _extract_credential_exposures(
            tool_name="hudsonrock",
            email="jane@gmail.com",
            data={
                "compromised": True,
                "stealers": [{
                    "stealer_family": "RedLine",
                    "date_compromised": "2024-08-15",
                    "computer_name": "DESKTOP-XYZ",
                    "operating_system": "Windows 10",
                }],
            },
        )
        assert len(out) == 1
        assert out[0].credential_kind == "presence_only"
        assert "RedLine" in out[0].breach_source
        # Provenance carries the stealer metadata for the audit trail.
        assert out[0].provenance["computer_name"] == "DESKTOP-XYZ"

    def test_extract_credentials_hudsonrock_paid_tier_email_check(self):
        """D6: paid-tier email check exposes ``captured_credentials`` —
        each entry must become a password CredentialExposure."""
        out = _extract_credential_exposures(
            tool_name="hudsonrock",
            email="jane@gmail.com",
            data={
                "compromised": True,
                "stealer_family": "Vidar",
                "date_compromised": "2024-06-01",
                "computer_name": "LAPTOP-A",
                "operating_system": "Windows 11",
                "external_ip": "1.2.3.4",
                "captured_credentials": [
                    {
                        "url": "https://mail.corp.com/owa/",
                        "username": "jane.doe@corp.com",
                        "password": "Summer2024!",
                    },
                    {
                        "url": "https://github.com/login",
                        "username": "janedoe82",
                        "password": "GitHub#456",
                    },
                ],
            },
        )
        assert len(out) == 2
        assert all(e.credential_kind == "password" for e in out)
        values = {e.credential_value for e in out}
        assert "Summer2024!" in values
        assert "GitHub#456" in values
        # Each carries the captured URL in provenance for D4 targeting.
        urls = {e.provenance.get("captured_url") for e in out}
        assert "https://mail.corp.com/owa/" in urls
        assert "https://github.com/login" in urls
        # Confidence escalated to VERIFIED for paid-tier passwords.
        assert all(e.confidence == BreachConfidence.VERIFIED for e in out)

    def test_extract_credentials_hudsonrock_paid_tier_domain_check(self):
        """D6: paid-tier domain check — per-stealer captured_credentials lifted."""
        out = _extract_credential_exposures(
            tool_name="hudsonrock",
            email="corp.com",
            data={
                "compromised": True,
                "stealers": [
                    {
                        "stealer_family": "RedLine",
                        "date_compromised": "2024-05-01",
                        "computer_name": "PC-1",
                        "operating_system": "Windows 10",
                        "captured_credentials": [
                            {
                                "url": "https://adfs.corp.com/adfs/ls",
                                "username": "alice@corp.com",
                                "password": "AlicePass!",
                            },
                        ],
                    },
                    {
                        "stealer_family": "Vidar",
                        "date_compromised": "2024-06-01",
                        "computer_name": "PC-2",
                        "operating_system": "Windows 11",
                        # No credentials array → presence_only fallback
                    },
                ],
            },
        )
        # Two records: one password (PC-1) + one presence_only (PC-2)
        assert len(out) == 2
        passwords = [e for e in out if e.credential_kind == "password"]
        presence = [e for e in out if e.credential_kind == "presence_only"]
        assert len(passwords) == 1
        assert len(presence) == 1
        assert passwords[0].credential_value == "AlicePass!"
        assert passwords[0].provenance["captured_url"] == "https://adfs.corp.com/adfs/ls"

    def test_extract_credentials_hudsonrock_empty_password_is_presence(self):
        """A captured_credentials entry with empty password → presence_only,
        not password — confidence drops to LIKELY since we have URL+username."""
        out = _extract_credential_exposures(
            tool_name="hudsonrock",
            email="jane@gmail.com",
            data={
                "compromised": True,
                "stealer_family": "Raccoon",
                "date_compromised": "2024-01-01",
                "captured_credentials": [
                    {
                        "url": "https://service.example.com/login",
                        "username": "janedoe",
                        "password": "",  # cleared by the stealer logger
                    },
                ],
            },
        )
        assert len(out) == 1
        assert out[0].credential_kind == "presence_only"
        assert out[0].credential_value == ""
        assert out[0].confidence == BreachConfidence.LIKELY

    def test_extract_credentials_intelx_with_password(self):
        out = _extract_credential_exposures(
            tool_name="intelx",
            email="jane@gmail.com",
            data={"records": [{
                "bucket": "leaks",
                "password": "MarathonRunner!82",
                "date": "2019-12-01",
            }]},
        )
        assert len(out) == 1
        assert out[0].credential_kind == "password"
        assert out[0].credential_value == "MarathonRunner!82"
        assert out[0].confidence == BreachConfidence.LIKELY
