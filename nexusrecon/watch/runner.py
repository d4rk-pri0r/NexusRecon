"""Watch runner — loads a watch, runs its sensors once, fires
the action policy.

Public entry points
- :func:`tick(watch_id)` — run one pass.
- :func:`list_watches()` — enumerate configured watches.

The runner deliberately does NOT loop. The operator either
calls ``tick`` from cron / systemd timer (the typical
deployment) or wraps it in a sleep loop themselves. Keeping
this synchronous + one-shot means tests can exercise the
full path without time.sleep.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from nexusrecon.watch.actions import (
    ActionResult,
    apply_action,
)
from nexusrecon.watch.sensors import SensorFingerprint
from nexusrecon.watch.severity import (
    SeverityConfig,
    classify_diff,
    diff_graphs,
)
from nexusrecon.watch.storage import (
    Watch,
    WatchStorage,
    resolve_watch_dir,
)

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Result type
# ──────────────────────────────────────────────────────────────────────


@dataclass
class TickResult:
    """One full tick across all sensors in a watch."""

    watch_id: str
    timestamp: str
    sensors_evaluated: int = 0
    sensors_fired: int = 0
    actions: list[ActionResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "watch_id": self.watch_id,
            "timestamp": self.timestamp,
            "sensors_evaluated": self.sensors_evaluated,
            "sensors_fired": self.sensors_fired,
            "actions": [a.action.to_dict() for a in self.actions],
            "errors": list(self.errors),
        }


# ──────────────────────────────────────────────────────────────────────
# tick
# ──────────────────────────────────────────────────────────────────────


def tick(
    watch_id: str,
    *,
    watch_root: Path | str | None = None,
    graph_loader: Any | None = None,
    severity_config: SeverityConfig | None = None,
    now: datetime | None = None,
) -> TickResult:
    """Run one pass of the watch's sensors.

    ``graph_loader`` is an injectable callable
    ``(campaign_id) -> EntityGraph`` so tests can swap in a
    fake without touching the campaign filesystem.
    Production callers leave it ``None`` to use the default
    state.json loader.
    """
    now = now or datetime.now(UTC)
    storage = WatchStorage(watch_id, root=watch_root)
    result = TickResult(
        watch_id=watch_id,
        timestamp=now.isoformat(),
    )

    try:
        watch = storage.load_watch()
    except FileNotFoundError as exc:
        result.errors.append(str(exc))
        return result

    try:
        graph = (graph_loader or _default_graph_loader)(watch.campaign_id)
    except Exception as exc:
        result.errors.append(
            f"graph load failed for campaign "
            f"{watch.campaign_id!r}: {exc}"
        )
        storage.append_tick_log(result.errors[-1])
        return result

    for sensor in watch.sensors:
        result.sensors_evaluated += 1
        previous = storage.load_fingerprint(sensor.sensor_id)
        try:
            trigger = sensor.evaluate(graph, previous, now)
        except Exception as exc:
            result.errors.append(
                f"sensor {sensor.sensor_id!r} raised: {exc}"
            )
            storage.append_tick_log(result.errors[-1])
            continue

        # Persist the new fingerprint regardless of whether
        # the sensor fired — operators rely on the
        # fingerprint history when troubleshooting "why
        # didn't this fire?".
        storage.save_fingerprint(trigger.fingerprint)

        if not trigger.fired:
            storage.append_tick_log(
                f"sensor={sensor.sensor_id} no_fire reason={trigger.reason}"
            )
            continue

        result.sensors_fired += 1

        # Build the diff + grade severity. Timed sensors
        # don't produce a graph diff — they get a stub diff
        # that's still useful for the alert.
        diff = diff_graphs(
            trigger.changed_entity_ids,
            graph,
            previous_entity_ids=(
                previous.entity_ids if previous is not None else None
            ),
        )
        severity, reason = classify_diff(
            diff, graph, config=severity_config,
        )
        # For timed sensors with no graph diff, the
        # classifier returns LOW + "minor update". Override
        # with a clearer message.
        if trigger.sensor_kind == "timed" and not diff.added \
                and not diff.removed and not diff.in_place_changes:
            reason = f"scheduled fire — {trigger.reason}"

        full_reason = f"{trigger.reason}; {reason}"

        action_result = apply_action(
            storage,
            severity=severity, reason=full_reason,
            sensor_id=sensor.sensor_id,
            sensor_kind=trigger.sensor_kind,
            changed_entity_ids=trigger.changed_entity_ids,
            diff=diff,
            watch_id=watch_id,
            campaign_id=watch.campaign_id,
        )
        result.actions.append(action_result)
        storage.append_tick_log(
            f"sensor={sensor.sensor_id} fired severity={severity} "
            f"reason={full_reason}"
        )

    storage.append_tick_log(
        f"tick complete evaluated={result.sensors_evaluated} "
        f"fired={result.sensors_fired}"
    )
    return result


# ──────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────


def list_watches(
    watch_root: Path | str | None = None,
) -> list[Watch]:
    """Enumerate every configured watch."""
    root = resolve_watch_dir(watch_root)
    if not root.exists():
        return []
    watches: list[Watch] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        if not (entry / "config.yaml").exists():
            continue
        storage = WatchStorage(entry.name, root=root)
        try:
            watches.append(storage.load_watch())
        except Exception as exc:
            log.warning(
                "Watch: malformed config skipped",
                watch_id=entry.name, error=str(exc),
            )
    return watches


# ──────────────────────────────────────────────────────────────────────
# Default graph loader
# ──────────────────────────────────────────────────────────────────────


def _default_graph_loader(campaign_id: str):
    """Default loader used in production: walks the campaign
    output dir for the matching state.json, rebuilds the
    EntityGraph via from_state."""
    import json

    from nexusrecon.core.config import get_config
    from nexusrecon.core.entity_graph import EntityGraph

    config = get_config()
    output_dir = Path(config.output_dir)
    state_path: Path | None = None
    for candidate in output_dir.rglob(campaign_id):
        if candidate.is_dir():
            sp = candidate / "state.json"
            if sp.exists():
                state_path = sp
                break
    if state_path is None:
        raise FileNotFoundError(
            f"campaign {campaign_id!r} state.json not found"
        )
    data = json.loads(state_path.read_text(encoding="utf-8"))
    return EntityGraph.from_state(
        data,
        campaign_id=data.get("campaign_id", ""),
        engagement_id=data.get("engagement_id", ""),
    )
