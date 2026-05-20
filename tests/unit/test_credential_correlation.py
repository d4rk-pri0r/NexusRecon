"""Tests for nexusrecon.core.credential_correlation (D4)."""
from __future__ import annotations

import pytest

from nexusrecon.core.credential_correlation import (
    AuthEndpoint,
    CredentialSprayCandidate,
    _classify_url,
    _domain_from_key,
    _domain_from_url,
    _recency_bonus,
    _score,
    correlate_credentials,
    extract_auth_endpoints,
    summarise_punch_list,
)
from nexusrecon.core.identity_graph import (
    BreachConfidence,
    CredentialExposure,
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    derive_identity_id,
)


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _make_identity(
    email: str = "jane.doe@corp.com",
    name: str = "Jane Doe",
    exposures: list[CredentialExposure] | None = None,
) -> Identity:
    idents = [
        Identifier(
            value=email,
            identifier_type=IdentifierType.CORP_EMAIL,
            source="test",
            confidence=1.0,
        ),
        Identifier(
            value=name,
            identifier_type=IdentifierType.REAL_NAME,
            source="test",
            confidence=0.9,
        ),
    ]
    ident_id = derive_identity_id(idents)
    identity = Identity(
        identity_id=ident_id,
        primary_label=f"{name} (VP, Corp)",
        identifiers=idents,
        credential_exposures=exposures or [],
    )
    return identity


def _make_exposure(
    kind: str = "password",
    confidence: BreachConfidence = BreachConfidence.VERIFIED,
    breach_source: str = "DeHashed:LinkedIn-2012",
    observed_at: str = "jane.doe.82@gmail.com",
    breach_date: str | None = "2023-01-15",
    value: str = "hunter2",
) -> CredentialExposure:
    return CredentialExposure(
        breach_source=breach_source,
        breach_date=breach_date,
        observed_at_identifier=observed_at,
        credential_kind=kind,
        credential_value=value,
        confidence=confidence,
    )


def _make_graph(identities: list[Identity]) -> IdentityGraph:
    g = IdentityGraph()
    for i in identities:
        g.add_identity(i)
    return g


def _make_cloud_intel(
    domain: str = "corp.com",
    is_federated: bool = True,
    mfa: bool = False,
) -> dict:
    data: dict = {
        "user_realm": {
            "found": True,
            "is_federated": is_federated,
        },
    }
    if is_federated:
        data["user_realm"]["auth_url"] = f"https://sts.{domain}/adfs/ls"
    if mfa:
        data["mfa_enforced"] = True
    return {f"azure/{domain}": data}


# ──────────────────────────────────────────────────────────────────────
# URL helpers
# ──────────────────────────────────────────────────────────────────────


class TestURLHelpers:
    def test_classify_adfs_path(self):
        assert _classify_url("https://sts.corp.com/adfs/ls") == "adfs"

    def test_classify_adfs_subdomain(self):
        assert _classify_url("https://adfs.corp.com/") == "adfs"

    def test_classify_owa(self):
        assert _classify_url("https://mail.corp.com/owa/") == "owa"

    def test_classify_o365_managed(self):
        assert _classify_url("https://login.microsoftonline.com/common/oauth2/token") == "o365_managed"

    def test_classify_vpn_subdomain(self):
        assert _classify_url("https://vpn.corp.com/") == "vpn"

    def test_classify_unknown_returns_none(self):
        assert _classify_url("https://api.someservice.com/v1/auth") is None

    def test_domain_from_key(self):
        assert _domain_from_key("azure/gitlab.com") == "gitlab.com"
        assert _domain_from_key("aws/corp.com") == "corp.com"
        assert _domain_from_key("domain_only") == "domain_only"

    def test_domain_from_url(self):
        assert _domain_from_url("https://sts.corp.com/adfs/") == "corp.com"
        assert _domain_from_url("https://login.microsoftonline.com/common/") == "microsoftonline.com"


# ──────────────────────────────────────────────────────────────────────
# Auth endpoint extraction
# ──────────────────────────────────────────────────────────────────────


class TestExtractAuthEndpoints:
    def test_federated_adfs_extracts_endpoint(self):
        cloud_intel = _make_cloud_intel("corp.com", is_federated=True)
        eps = extract_auth_endpoints(cloud_intel)
        assert any(ep.endpoint_type == "adfs" for ep in eps)
        assert any("adfs" in ep.url for ep in eps)

    def test_managed_o365_extracts_token_endpoint(self):
        cloud_intel = _make_cloud_intel("corp.com", is_federated=False)
        eps = extract_auth_endpoints(cloud_intel)
        assert any(ep.endpoint_type == "o365_managed" for ep in eps)
        assert any("microsoftonline.com" in ep.url for ep in eps)

    def test_mfa_flag_propagated(self):
        cloud_intel = _make_cloud_intel("corp.com", is_federated=True, mfa=True)
        eps = extract_auth_endpoints(cloud_intel)
        adfs_eps = [ep for ep in eps if ep.endpoint_type == "adfs"]
        assert adfs_eps
        assert adfs_eps[0].mfa_expected is True

    def test_owa_url_field_extracted(self):
        cloud_intel = {
            "azure/corp.com": {
                "user_realm": {"found": True, "is_federated": False},
                "owa_url": "https://mail.corp.com/owa/",
            },
        }
        eps = extract_auth_endpoints(cloud_intel)
        owa = [ep for ep in eps if ep.endpoint_type == "owa"]
        assert owa
        assert "mail.corp.com" in owa[0].url

    def test_captured_urls_from_hudson_rock(self):
        cloud_intel = {
            "hudsonrock/corp.com": {
                "all_captured_urls": [
                    "https://sts.corp.com/adfs/ls",
                    "https://mail.corp.com/owa/",
                ],
            },
        }
        eps = extract_auth_endpoints(cloud_intel)
        url_types = {ep.endpoint_type for ep in eps}
        assert "adfs" in url_types or "owa" in url_types

    def test_empty_cloud_intel_returns_empty(self):
        assert extract_auth_endpoints({}) == []

    def test_dedup_same_url_added_twice(self):
        cloud_intel = {
            "a/corp.com": {
                "user_realm": {"found": True, "is_federated": True,
                                "auth_url": "https://sts.corp.com/adfs/ls"},
            },
            "b/corp.com": {
                "user_realm": {"found": True, "is_federated": True,
                                "auth_url": "https://sts.corp.com/adfs/ls"},
            },
        }
        eps = extract_auth_endpoints(cloud_intel)
        urls = [ep.url for ep in eps]
        # Should appear only once despite being in two intel entries.
        assert urls.count("https://sts.corp.com/adfs/ls") == 1


# ──────────────────────────────────────────────────────────────────────
# Scoring
# ──────────────────────────────────────────────────────────────────────


class TestScoring:
    def _ep(self, ep_type: str = "adfs", mfa: bool = False) -> AuthEndpoint:
        return AuthEndpoint(
            url=f"https://sts.corp.com/{ep_type}/",
            endpoint_type=ep_type,
            domain="corp.com",
            mfa_expected=mfa,
        )

    def test_password_verified_highest_base(self):
        exp = _make_exposure("password", BreachConfidence.VERIFIED)
        score = _score(exp, self._ep("adfs"))
        assert score >= 0.80

    def test_presence_only_lowest_base(self):
        exp = _make_exposure("presence_only", BreachConfidence.UNVERIFIED)
        score = _score(exp, self._ep("adfs"))
        assert score <= 0.30

    def test_mfa_penalty_reduces_score(self):
        exp = _make_exposure("password", BreachConfidence.VERIFIED)
        no_mfa = _score(exp, self._ep("adfs", mfa=False))
        with_mfa = _score(exp, self._ep("adfs", mfa=True))
        assert with_mfa < no_mfa

    def test_hash_scores_between_password_and_presence(self):
        exp_pwd = _make_exposure("password", BreachConfidence.VERIFIED)
        exp_hash = _make_exposure("hash", BreachConfidence.VERIFIED)
        exp_pres = _make_exposure("presence_only", BreachConfidence.UNVERIFIED)
        ep = self._ep("adfs")
        assert _score(exp_pwd, ep) > _score(exp_hash, ep) > _score(exp_pres, ep)

    def test_score_clamped_to_01(self):
        exp = _make_exposure("password", BreachConfidence.VERIFIED)
        score = _score(exp, self._ep("adfs"))
        assert 0.0 <= score <= 1.0

    def test_recency_bonus_applied_for_recent_breach(self):
        from datetime import datetime
        recent = datetime.now().strftime("%Y")
        old = "2010"
        ep = self._ep("adfs")
        exp_recent = _make_exposure("password", BreachConfidence.VERIFIED, breach_date=recent)
        exp_old = _make_exposure("password", BreachConfidence.VERIFIED, breach_date=old)
        # Recent should score same or higher (recency bonus)
        assert _score(exp_recent, ep) >= _score(exp_old, ep)

    def test_recency_bonus_zero_for_old_breach(self):
        bonus = _recency_bonus("2010-01-01")
        assert bonus == 0.0

    def test_recency_bonus_positive_for_recent(self):
        from datetime import datetime
        # Use a date within the past 2 years relative to today
        recent_year = str(datetime.now().year)
        bonus = _recency_bonus(recent_year)
        assert bonus > 0.0

    def test_recency_bonus_zero_for_none(self):
        assert _recency_bonus(None) == 0.0


# ──────────────────────────────────────────────────────────────────────
# Full correlation
# ──────────────────────────────────────────────────────────────────────


class TestCorrelateCredentials:
    def test_empty_graph_returns_empty(self):
        g = IdentityGraph()
        result = correlate_credentials(g, {})
        assert result == []

    def test_identity_without_corp_email_skipped(self):
        idents = [Identifier("janedoe", IdentifierType.HANDLE, service="GitHub",
                              source="test", confidence=0.9)]
        identity = Identity(
            identity_id=derive_identity_id(idents),
            identifiers=idents,
            credential_exposures=[_make_exposure()],
        )
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel())
        assert result == []

    def test_password_exposure_produces_candidate(self):
        identity = _make_identity(exposures=[_make_exposure("password")])
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        assert len(result) > 0
        assert result[0].credential_kind == "password"

    def test_candidates_sorted_by_confidence_descending(self):
        exps = [
            _make_exposure("password", BreachConfidence.VERIFIED, breach_source="A"),
            _make_exposure("presence_only", BreachConfidence.UNVERIFIED, breach_source="B"),
        ]
        identity = _make_identity(exposures=exps)
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        confs = [c.confidence for c in result]
        assert confs == sorted(confs, reverse=True)

    def test_presence_only_excluded_by_default(self):
        identity = _make_identity(exposures=[_make_exposure("presence_only")])
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        assert not any(c.credential_kind == "presence_only" for c in result)

    def test_presence_only_included_when_flag_set(self):
        identity = _make_identity(
            exposures=[_make_exposure("presence_only", BreachConfidence.UNVERIFIED)]
        )
        g = _make_graph([identity])
        result = correlate_credentials(
            g, _make_cloud_intel("corp.com"),
            include_presence_only=True,
        )
        assert any(c.credential_kind == "presence_only" for c in result)

    def test_max_candidates_respected(self):
        exps = [
            _make_exposure("password", BreachConfidence.VERIFIED,
                           breach_source=f"Source-{i}")
            for i in range(20)
        ]
        identity = _make_identity(exposures=exps)
        g = _make_graph([identity])
        result = correlate_credentials(
            g, _make_cloud_intel("corp.com"), max_candidates=5
        )
        assert len(result) <= 5

    def test_do_not_execute_always_true(self):
        identity = _make_identity(exposures=[_make_exposure("password")])
        g = _make_graph([identity])
        for c in correlate_credentials(g, _make_cloud_intel("corp.com")):
            assert c.do_not_execute is True

    def test_no_cloud_intel_synthesises_fallback_endpoint(self):
        """Without cloud_intel, a fallback O365 endpoint is synthesised."""
        identity = _make_identity(
            email="jane@corp.com",
            exposures=[_make_exposure("password")],
        )
        g = _make_graph([identity])
        result = correlate_credentials(g, {})
        # Should still produce at least one candidate via the fallback.
        assert len(result) > 0
        assert result[0].endpoint_type == "o365_managed"

    def test_mfa_flag_propagated_to_candidate(self):
        identity = _make_identity(exposures=[_make_exposure("password")])
        g = _make_graph([identity])
        cloud_intel = _make_cloud_intel("corp.com", is_federated=True, mfa=True)
        result = correlate_credentials(g, cloud_intel)
        assert result
        assert result[0].mfa_expected is True
        assert "mfa_expected" in result[0].risk_flags

    def test_risk_flags_always_include_lockout(self):
        identity = _make_identity(exposures=[_make_exposure("password")])
        g = _make_graph([identity])
        for c in correlate_credentials(g, _make_cloud_intel("corp.com")):
            assert "account_lockout_risk" in c.risk_flags

    def test_hash_candidate_includes_cracking_flag(self):
        identity = _make_identity(exposures=[_make_exposure("hash")])
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        assert result
        assert "hash_requires_cracking_or_relay" in result[0].risk_flags

    def test_mitre_techniques_populated(self):
        identity = _make_identity(exposures=[_make_exposure("password")])
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        assert result
        assert result[0].mitre_techniques  # non-empty
        # T1110.003 (Password Spraying) should always appear for password candidates.
        assert "T1110.003" in result[0].mitre_techniques

    def test_recommendation_non_empty_and_contains_corp_email(self):
        identity = _make_identity(
            email="jane.doe@corp.com",
            exposures=[_make_exposure("password")],
        )
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        assert result
        assert "jane.doe@corp.com" in result[0].recommendation

    def test_cross_domain_match_preferred(self):
        """Endpoints matching the corp email domain should be used first."""
        identity = _make_identity(
            email="jane.doe@corp.com",
            exposures=[_make_exposure("password")],
        )
        g = _make_graph([identity])
        cloud_intel = {
            "azure/corp.com": {
                "user_realm": {
                    "found": True, "is_federated": True,
                    "auth_url": "https://sts.corp.com/adfs/ls",
                },
            },
            "azure/othercorp.com": {
                "user_realm": {
                    "found": True, "is_federated": True,
                    "auth_url": "https://sts.othercorp.com/adfs/ls",
                },
            },
        }
        result = correlate_credentials(g, cloud_intel)
        # corp.com endpoint should appear first (domain match).
        if result:
            assert "corp.com" in result[0].test_endpoint_url


# ──────────────────────────────────────────────────────────────────────
# Serialisation
# ──────────────────────────────────────────────────────────────────────


class TestSerialization:
    def test_to_dict_redacts_value_by_default(self):
        import json
        identity = _make_identity(exposures=[_make_exposure("password", value="s3cr3t")])
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        assert result
        d = result[0].to_dict()
        assert d["credential_value"] == "[REDACTED]"
        # JSON-serialisable
        json.dumps(d)

    def test_to_dict_exposes_value_when_explicitly_requested(self):
        identity = _make_identity(exposures=[_make_exposure("password", value="s3cr3t")])
        g = _make_graph([identity])
        result = correlate_credentials(g, _make_cloud_intel("corp.com"))
        assert result
        d = result[0].to_dict(redact_value=False)
        assert d["credential_value"] == "s3cr3t"

    def test_auth_endpoint_to_dict(self):
        import json
        ep = AuthEndpoint(
            url="https://sts.corp.com/adfs/ls",
            endpoint_type="adfs",
            domain="corp.com",
            mfa_expected=True,
        )
        d = ep.to_dict()
        assert d["endpoint_type"] == "adfs"
        assert d["mfa_expected"] is True
        json.dumps(d)


# ──────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────


class TestSummarisePunchList:
    def test_empty_returns_zeros(self):
        s = summarise_punch_list([])
        assert s["total_candidates"] == 0
        assert s["by_credential_kind"] == {}

    def test_counts_credential_kinds(self):
        identity = _make_identity(
            exposures=[
                _make_exposure("password"),
                _make_exposure("hash"),
                _make_exposure("hash"),
            ]
        )
        g = _make_graph([identity])
        candidates = correlate_credentials(g, _make_cloud_intel("corp.com"))
        s = summarise_punch_list(candidates)
        assert s["by_credential_kind"].get("password", 0) >= 1
        assert s["by_credential_kind"].get("hash", 0) >= 2

    def test_confidence_bands_populated(self):
        identity = _make_identity(
            exposures=[_make_exposure("password", BreachConfidence.VERIFIED)]
        )
        g = _make_graph([identity])
        candidates = correlate_credentials(g, _make_cloud_intel("corp.com"))
        s = summarise_punch_list(candidates)
        total = (
            s["by_confidence_band"]["high"]
            + s["by_confidence_band"]["medium"]
            + s["by_confidence_band"]["low"]
        )
        assert total == len(candidates)

    def test_mfa_count_correct(self):
        identity = _make_identity(
            exposures=[_make_exposure("password")]
        )
        g = _make_graph([identity])
        cloud_intel = _make_cloud_intel("corp.com", is_federated=True, mfa=True)
        candidates = correlate_credentials(g, cloud_intel)
        s = summarise_punch_list(candidates)
        assert s["mfa_exposure_count"] == len(candidates)
