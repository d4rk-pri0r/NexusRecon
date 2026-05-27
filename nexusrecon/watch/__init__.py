"""Watch Mode — Phase 5 PR A.

Continuous monitoring: long-running sensors watch a
campaign's :class:`EntityGraph` (or a scope subset) and
trigger actions when material change occurs. Closes the gap
between "single campaign run" and "ongoing intelligence
posture" — operators get alerted on new findings without
having to remember to re-run.

Architecture
- **Sensors** (``watch/sensors.py``) define WHAT to watch.
  Three flavors ship in PR A:
    * :class:`EntitySensor` — single entity by id.
    * :class:`ScopeSensor` — entities matching a scope
      filter (e.g. "all subdomains of acme.com").
    * :class:`TimedSensor` — fires on a polling schedule
      regardless of graph state; meant for re-running a
      passive recon footprint on a cadence.
- **Diff + severity** (``watch/severity.py``) compute what
  changed since the last tick and grade it.
- **Actions** (``watch/actions.py``) decide what to do with
  graded changes — append an alert, send a notification,
  or launch a micro-campaign.
- **Storage** (``watch/storage.py``) persists watch configs +
  fingerprints + alert history under
  ``~/.nexusrecon/watch/<watch-id>/``.
- **Runner** (``watch/runner.py``) ties everything together.
  ``tick(watch_id)`` runs one pass; ``run(watch_id)``
  loops with sleep.

Sensor activation modes (locked in by architecture
decisions: "both")
- Diff-driven: compute a fingerprint of the watched
  entities; trigger when the fingerprint changes.
- Polling: re-run a specified footprint on a cadence
  regardless of graph state.

Action policy (locked in: "tiered")
- ``low`` severity → alert (append to ``alerts.jsonl``).
- ``medium`` severity → alert + notification (a
  notification file the operator can tail or pipe).
- ``high`` severity → alert + notification + queue a
  micro-campaign that targets the changed entity.

What's NOT in PR A
- Signed receipts (deferred per the architecture choice —
  PR B candidate).
- Multi-modal reasoning (Phase 5 follow-up).
- Live notification channels (Slack / email / webhook).
  v1 writes a ``notifications.jsonl`` the operator's
  external tooling tails.
"""
from nexusrecon.watch.actions import (
    Action,
    ActionResult,
    apply_action,
)
from nexusrecon.watch.runner import (
    TickResult,
    list_watches,
    tick,
)
from nexusrecon.watch.sensors import (
    EntitySensor,
    ScopeSensor,
    Sensor,
    SensorFingerprint,
    TimedSensor,
)
from nexusrecon.watch.severity import (
    GraphDiff,
    Severity,
    classify_diff,
    diff_graphs,
)
from nexusrecon.watch.storage import (
    Watch,
    WatchAlert,
    WatchStorage,
    resolve_watch_dir,
)

__all__ = [
    "Action",
    "ActionResult",
    "EntitySensor",
    "GraphDiff",
    "ScopeSensor",
    "Sensor",
    "SensorFingerprint",
    "Severity",
    "TickResult",
    "TimedSensor",
    "Watch",
    "WatchAlert",
    "WatchStorage",
    "apply_action",
    "classify_diff",
    "diff_graphs",
    "list_watches",
    "resolve_watch_dir",
    "tick",
]
