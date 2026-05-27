"""Action policy — what to do with a graded trigger.

Locked-in policy from the architecture decisions ("tiered"):

  - ``low``    → append alert.
  - ``medium`` → append alert + append notification.
  - ``high``   → append alert + append notification + queue
                 micro-campaign request.

Why three append-only logs and not a notification BUS
- Auditability First (METASPLOIT_PLAN §1): every escalation
  point should produce a tamper-evident record before the
  side-effect fires. Live channels (Slack, email) sit
  downstream of the JSONL — an operator's external tail can
  forward, but the record exists either way.
- Composability: the operator's monitoring tool already has
  opinions about delivery. We don't want to bake them in.

Micro-campaign queuing
- ``high`` severity writes a structured record to
  ``micro_campaigns.jsonl`` containing the seed entities,
  the watch_id, and a suggested phase set.
- v1 does NOT auto-execute. The operator reviews + runs
  ``nexusrecon run`` against the queued payload manually
  (or pipes the JSONL into a SOAR). A future PR can layer
  auto-dispatch behind a per-watch opt-in flag.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from nexusrecon.watch.severity import GraphDiff, Severity
from nexusrecon.watch.storage import WatchAlert, WatchStorage


@dataclass
class Action:
    """The action policy's verdict for one graded trigger."""

    severity: str
    alerted: bool
    notified: bool
    micro_campaign_queued: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "alerted": self.alerted,
            "notified": self.notified,
            "micro_campaign_queued": self.micro_campaign_queued,
            "reason": self.reason,
        }


@dataclass
class ActionResult:
    """Side effects produced by :func:`apply_action`. Holds
    the alert record for the caller to surface in CLI
    output."""

    action: Action
    alert: WatchAlert | None = None
    notification: dict[str, Any] | None = None
    micro_campaign: dict[str, Any] | None = None


def apply_action(
    storage: WatchStorage,
    *,
    severity: Severity | str,
    reason: str,
    sensor_id: str,
    sensor_kind: str,
    changed_entity_ids: list[str],
    diff: GraphDiff | None,
    watch_id: str,
    campaign_id: str,
) -> ActionResult:
    """Apply the tiered policy. Writes alerts +
    notifications + micro_campaign records to ``storage``
    per severity, returns an :class:`ActionResult`."""
    sev_str = severity.value if isinstance(severity, Severity) else str(severity)
    timestamp = datetime.now(UTC).isoformat()

    alert = WatchAlert(
        timestamp=timestamp,
        sensor_id=sensor_id,
        sensor_kind=sensor_kind,
        severity=sev_str,
        reason=reason,
        changed_entity_ids=list(changed_entity_ids),
        diff=diff.to_dict() if diff is not None else {},
    )
    storage.append_alert(alert)

    notified = False
    notification: dict[str, Any] | None = None
    if sev_str in ("medium", "high"):
        notification = {
            "timestamp": timestamp,
            "watch_id": watch_id,
            "severity": sev_str,
            "sensor_id": sensor_id,
            "reason": reason,
        }
        storage.append_notification(notification)
        notified = True

    micro_campaign_queued = False
    micro_campaign: dict[str, Any] | None = None
    if sev_str == "high":
        micro_campaign = {
            "timestamp": timestamp,
            "watch_id": watch_id,
            "campaign_id": campaign_id,
            "sensor_id": sensor_id,
            "seed_entity_ids": list(changed_entity_ids),
            "rationale": reason,
            # Suggested follow-up phase set: passive recon +
            # correlation. Conservative starting point;
            # operators can swap in a richer template via
            # a future Strategy hook.
            "suggested_phases": [
                "phase1", "phase2", "phase4", "phase9",
            ],
            "status": "queued",
        }
        storage.append_micro_campaign(micro_campaign)
        micro_campaign_queued = True

    return ActionResult(
        action=Action(
            severity=sev_str,
            alerted=True,
            notified=notified,
            micro_campaign_queued=micro_campaign_queued,
            reason=reason,
        ),
        alert=alert,
        notification=notification,
        micro_campaign=micro_campaign,
    )
