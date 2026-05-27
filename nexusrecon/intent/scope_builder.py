"""Translate an :class:`IntentRecord` into a scope.yaml stub.

The output is a Python ``dict`` shaped to match what
:func:`ScopeModel.from_yaml` consumes. Callers serialise with
``yaml.safe_dump`` to write the file. We deliberately do
NOT call ``yaml.safe_dump`` here so callers can edit the dict
(add headers, inline comments) before writing.

What's filled in
- ``engagement`` placeholders the operator MUST replace
  before running. We refuse to invent authorization markers.
- ``scope.in_scope.domains`` from the extracted targets.
- ``constraints.max_tier`` and ``constraints.stealth_profile``
  from the intent.
- ``constraints.max_llm_cost_usd`` from the extracted
  constraints, or a conservative default (5 USD).

What's NOT filled in
- ``signed_sow_hash`` — placeholder ``"sha256:" + "0"*64``.
- Dates — placeholders the operator must fix.
- Out-of-scope lists — the operator's call; we don't guess.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from nexusrecon.intent.intent_parser import IntentRecord


def build_scope_stub(intent: IntentRecord) -> dict[str, Any]:
    """Produce a scope.yaml-compatible dict from ``intent``.

    The dict round-trips through :func:`yaml.safe_dump` and
    is parseable by :func:`ScopeModel.from_yaml`. Operators
    should review the placeholders BEFORE running the
    resulting scope through a campaign."""
    today = datetime.now(UTC).date()
    end = today + timedelta(days=30)

    stub: dict[str, Any] = {
        # Comments-as-data: a header field the writer surfaces
        # as YAML comments. Callers strip + re-emit as
        # comments when serialising; we keep it on the dict
        # so the structure stays JSON-safe.
        "_generated_by": (
            "nexusrecon intent planner — REVIEW BEFORE RUNNING"
        ),
        "_intent_rationale": intent.rationale,
        "_intent_confidence": intent.confidence,
        "_intent_raw": intent.raw_sentence,
        "engagement": {
            "client": "REPLACE_ME",
            "engagement_id": (
                f"INTENT-{today.strftime('%Y%m%d')}"
            ),
            "authorized_by": "REPLACE_ME",
            "authorization_date": today.isoformat(),
            "signed_sow_hash": "sha256:" + "0" * 64,
            "start_date": today.isoformat(),
            "end_date": end.isoformat(),
        },
        "scope": {
            "in_scope": {
                "domains": list(intent.targets) or ["REPLACE_ME.example"],
            },
        },
        "constraints": {
            "max_tier": intent.max_tier,
            "stealth_profile": intent.stealth_profile,
            "allow_breach_db_lookup": (
                "credentials" in intent.intent_categories
            ),
            "allow_paid_apis": bool(intent.constraints.get(
                "allow_paid_apis", False,
            )),
            "max_llm_cost_usd": float(intent.constraints.get(
                "max_llm_cost_usd", 5.0,
            )),
        },
    }
    return stub
