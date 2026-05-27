"""Persistence for watches.

Each watch lives under ``<watch_root>/<watch_id>/``:

  - ``config.yaml`` — watch definition (campaign id, sensors,
    severity overrides, micro-campaign template).
  - ``fingerprints/<sensor_id>.json`` — last-known fingerprint
    per sensor.
  - ``alerts.jsonl`` — chronological alert history.
  - ``notifications.jsonl`` — operator-visible notifications
    (medium + high severity). An external tool can tail this
    file and forward to Slack / email / a SOAR.
  - ``micro_campaigns.jsonl`` — queued micro-campaign
    requests (high-severity only). The runner doesn't
    auto-execute them; operators review + dispatch via
    ``nexusrecon run`` with the queued scope subset.
  - ``tick.log`` — short text log of per-tick activity for
    debugging.

``<watch_root>`` defaults to ``~/.nexusrecon/watch/``;
overridable via ``NEXUSRECON_WATCH_DIR`` env var or per-call.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
import yaml

from nexusrecon.watch.sensors import (
    Sensor,
    SensorFingerprint,
)

log = structlog.get_logger(__name__)


DEFAULT_WATCH_DIR_ENV = "NEXUSRECON_WATCH_DIR"
DEFAULT_WATCH_DIR = "~/.nexusrecon/watch"


def resolve_watch_dir(explicit: Path | str | None = None) -> Path:
    """Resolve the watch root. Precedence: explicit arg →
    env var → default."""
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    env_val = os.environ.get(DEFAULT_WATCH_DIR_ENV)
    if env_val:
        return Path(env_val).expanduser().resolve()
    return Path(DEFAULT_WATCH_DIR).expanduser().resolve()


# ──────────────────────────────────────────────────────────────────────
# Record types
# ──────────────────────────────────────────────────────────────────────


@dataclass
class WatchAlert:
    """One entry in ``alerts.jsonl``."""

    timestamp: str
    sensor_id: str
    sensor_kind: str
    severity: str
    reason: str
    changed_entity_ids: list[str] = field(default_factory=list)
    diff: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "sensor_id": self.sensor_id,
            "sensor_kind": self.sensor_kind,
            "severity": self.severity,
            "reason": self.reason,
            "changed_entity_ids": list(self.changed_entity_ids),
            "diff": dict(self.diff),
        }


@dataclass
class Watch:
    """Operator-authored watch config.

    Loaded from ``config.yaml`` on disk; mutated in tests via
    construction directly."""

    watch_id: str
    campaign_id: str
    sensors: list[Sensor]
    description: str = ""
    auto_dispatch_micro_campaigns: bool = False
    """When True, the runner doesn't just queue high-severity
    micro-campaign requests — it also writes a launch script
    operators can ``sh`` to run them. Defaults False so the
    operator stays in the loop. v1 stays conservative;
    auto-launch can come in a follow-up PR once the
    micro-campaign template format settles."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "watch_id": self.watch_id,
            "campaign_id": self.campaign_id,
            "description": self.description,
            "auto_dispatch_micro_campaigns": (
                self.auto_dispatch_micro_campaigns
            ),
            "sensors": [s.to_dict() for s in self.sensors],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Watch:
        return cls(
            watch_id=str(raw["watch_id"]),
            campaign_id=str(raw["campaign_id"]),
            description=str(raw.get("description", "")),
            auto_dispatch_micro_campaigns=bool(
                raw.get("auto_dispatch_micro_campaigns", False),
            ),
            sensors=[
                Sensor.from_dict(s)
                for s in raw.get("sensors", [])
            ],
        )


# ──────────────────────────────────────────────────────────────────────
# WatchStorage
# ──────────────────────────────────────────────────────────────────────


class WatchStorage:
    """File-backed store for one watch.

    The runner instantiates this with ``WatchStorage(watch_id,
    root=watch_root)`` + uses it to load the config, load /
    save fingerprints, append alerts."""

    def __init__(
        self,
        watch_id: str,
        *,
        root: Path | str | None = None,
    ):
        self.watch_id = watch_id
        self.root = resolve_watch_dir(root)
        self.watch_dir = self.root / watch_id
        self.config_path = self.watch_dir / "config.yaml"
        self.fingerprints_dir = self.watch_dir / "fingerprints"
        self.alerts_path = self.watch_dir / "alerts.jsonl"
        self.notifications_path = self.watch_dir / "notifications.jsonl"
        self.micro_campaigns_path = self.watch_dir / "micro_campaigns.jsonl"
        self.tick_log_path = self.watch_dir / "tick.log"

    # ── Watch lifecycle ──────────────────────────────────────

    def exists(self) -> bool:
        return self.config_path.exists()

    def save_watch(self, watch: Watch) -> None:
        """Persist a new (or updated) watch config."""
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.fingerprints_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            yaml.safe_dump(
                watch.to_dict(), sort_keys=False,
                default_flow_style=False,
            ),
            encoding="utf-8",
        )

    def load_watch(self) -> Watch:
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"no watch config at {self.config_path}"
            )
        raw = yaml.safe_load(self.config_path.read_text())
        return Watch.from_dict(raw)

    def delete(self) -> bool:
        """Remove the entire watch directory. Returns True
        on success."""
        import shutil
        if not self.watch_dir.exists():
            return False
        shutil.rmtree(self.watch_dir)
        return True

    # ── Fingerprint persistence ──────────────────────────────

    def load_fingerprint(
        self, sensor_id: str,
    ) -> SensorFingerprint | None:
        path = self.fingerprints_dir / f"{sensor_id}.json"
        if not path.exists():
            return None
        try:
            return SensorFingerprint.from_dict(
                json.loads(path.read_text(encoding="utf-8")),
            )
        except Exception as exc:
            log.warning(
                "Watch: corrupt fingerprint",
                sensor_id=sensor_id, error=str(exc),
            )
            return None

    def save_fingerprint(self, fingerprint: SensorFingerprint) -> None:
        self.fingerprints_dir.mkdir(parents=True, exist_ok=True)
        path = self.fingerprints_dir / f"{fingerprint.sensor_id}.json"
        path.write_text(
            json.dumps(fingerprint.to_dict(), indent=2),
            encoding="utf-8",
        )

    # ── Append-only logs ─────────────────────────────────────

    def append_alert(self, alert: WatchAlert) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        with open(self.alerts_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

    def append_notification(self, record: dict[str, Any]) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        with open(self.notifications_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def append_micro_campaign(self, record: dict[str, Any]) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        with open(self.micro_campaigns_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def append_tick_log(self, line: str) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).isoformat()
        with open(self.tick_log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {line}\n")

    # ── Read paths ───────────────────────────────────────────

    def read_alerts(self) -> list[dict[str, Any]]:
        if not self.alerts_path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.alerts_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out
