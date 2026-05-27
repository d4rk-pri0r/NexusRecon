"""Tests for Phase 5 PR A: Watch Mode.

PR A introduces ``nexusrecon/watch/`` — continuous
monitoring built around per-sensor fingerprints + a tiered
action policy:

  - Diff-driven sensors (:class:`EntitySensor`,
    :class:`ScopeSensor`) compare a watched set's
    fingerprint against the previous tick.
  - Polling sensor (:class:`TimedSensor`) fires on a
    configurable cadence regardless of graph state.
  - :func:`tick` runs every sensor once, grades the fired
    triggers, applies the action policy (low → alert,
    medium → +notification, high → +micro-campaign queue).

Coverage
- Each sensor produces a stable fingerprint; identical
  state → identical digest → no fire.
- A change in confidence / sources / edges flips the digest
  and fires the sensor.
- ScopeSensor honors entity_type + parent_domain +
  value_contains filters (AND semantics).
- TimedSensor's cadence respects the interval.
- Severity classifier upgrades high-confidence additions,
  vuln-source additions, and CITES-cascade edges.
- Action policy writes alerts.jsonl always, notifications
  on medium+, micro-campaigns on high.
- Watch storage round-trips through ``config.yaml`` (load /
  save / delete).
- ``list_watches`` enumerates configured watches.
- End-to-end: create a watch, mutate the graph between two
  ticks, confirm the second tick fires + grades correctly.
"""
from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.models.entities import (
    DomainEntity,
    LeadEntity,
    RelationshipType,
    SubdomainEntity,
)
from nexusrecon.watch import (
    EntitySensor,
    ScopeSensor,
    Sensor,
    SensorFingerprint,
    TimedSensor,
    Watch,
    WatchStorage,
    apply_action,
    classify_diff,
    diff_graphs,
    list_watches,
    tick,
)
from nexusrecon.watch.severity import Severity, SeverityConfig


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def watch_root(tmp_path: Path) -> Path:
    return tmp_path / "watch-root"


@pytest.fixture
def graph() -> EntityGraph:
    return EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")


def _seed_graph(g: EntityGraph) -> None:
    g.add_domain("acme.com", source="scope", confidence=0.95)
    g.add_subdomain("api.acme.com", "acme.com", "subfinder", confidence=0.85)
    g.add_subdomain("admin.acme.com", "acme.com", "subfinder", confidence=0.7)


# ──────────────────────────────────────────────────────────────────────
# Sensor fingerprints
# ──────────────────────────────────────────────────────────────────────


class TestEntitySensor:
    def test_no_fire_on_initial_capture(self, graph: EntityGraph):
        _seed_graph(graph)
        sensor = EntitySensor(
            sensor_id="api-watch", entity_id=graph.get_entity_id(
                _entity_type_enum("subdomain"), "api.acme.com",
            ),
        )
        trigger = sensor.evaluate(graph, None, datetime.now(UTC))
        assert trigger.fired is False
        assert "initial" in trigger.reason

    def test_no_fire_on_unchanged_state(self, graph: EntityGraph):
        _seed_graph(graph)
        eid = graph.get_entity_id(_entity_type_enum("subdomain"), "api.acme.com")
        sensor = EntitySensor(sensor_id="s", entity_id=eid)
        fp = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        # Re-evaluate with the captured fingerprint — same
        # state, no fire.
        trigger = sensor.evaluate(graph, fp, datetime.now(UTC))
        assert trigger.fired is False

    def test_fires_on_confidence_change(self, graph: EntityGraph):
        _seed_graph(graph)
        eid = graph.get_entity_id(_entity_type_enum("subdomain"), "api.acme.com")
        sensor = EntitySensor(sensor_id="s", entity_id=eid)
        fp = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        # Mutate confidence via the proper setter so the
        # mutation hook fires (matters for downstream
        # verifiers + this test).
        graph.set_confidence(eid, 0.5, reason="test", source="manual")
        trigger = sensor.evaluate(graph, fp, datetime.now(UTC))
        assert trigger.fired is True
        assert eid in trigger.changed_entity_ids

    def test_fires_on_new_source(self, graph: EntityGraph):
        _seed_graph(graph)
        eid = graph.get_entity_id(_entity_type_enum("subdomain"), "api.acme.com")
        sensor = EntitySensor(sensor_id="s", entity_id=eid)
        fp = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        graph.add_subdomain(
            "api.acme.com", "acme.com", "crtsh",
            confidence=0.85,
        )
        trigger = sensor.evaluate(graph, fp, datetime.now(UTC))
        assert trigger.fired is True

    def test_handles_missing_entity_gracefully(self, graph: EntityGraph):
        sensor = EntitySensor(sensor_id="s", entity_id="ghost")
        trigger = sensor.evaluate(graph, None, datetime.now(UTC))
        # Initial capture of a missing entity should not fire.
        assert trigger.fired is False


class TestScopeSensor:
    def test_requires_at_least_one_filter(self):
        with pytest.raises(ValueError):
            ScopeSensor(sensor_id="s")

    def test_matches_by_entity_type(self, graph: EntityGraph):
        _seed_graph(graph)
        sensor = ScopeSensor(
            sensor_id="s", entity_type="subdomain",
        )
        fp = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        assert len(fp.entity_ids) == 2

    def test_matches_by_parent_domain(self, graph: EntityGraph):
        _seed_graph(graph)
        sensor = ScopeSensor(
            sensor_id="s", parent_domain="acme.com",
        )
        fp = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        # All subdomains have parent_domain = "acme.com".
        assert len(fp.entity_ids) == 2

    def test_fires_on_added_member(self, graph: EntityGraph):
        _seed_graph(graph)
        sensor = ScopeSensor(
            sensor_id="s", entity_type="subdomain",
        )
        first = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        graph.add_subdomain(
            "new.acme.com", "acme.com", "subfinder",
            confidence=0.9,
        )
        trigger = sensor.evaluate(graph, first, datetime.now(UTC))
        assert trigger.fired is True
        # The added entity surfaces in changed_entity_ids.
        new_id = graph.get_entity_id(
            _entity_type_enum("subdomain"), "new.acme.com",
        )
        assert new_id in trigger.changed_entity_ids
        assert "+1 entity" in trigger.reason

    def test_value_contains_filter(self, graph: EntityGraph):
        _seed_graph(graph)
        sensor = ScopeSensor(
            sensor_id="s",
            entity_type="subdomain",
            value_contains="admin",
        )
        fp = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        # Only admin.acme.com matches.
        assert len(fp.entity_ids) == 1


class TestTimedSensor:
    def test_fires_on_initial_call(self, graph: EntityGraph):
        sensor = TimedSensor(
            sensor_id="t", interval_seconds=3600,
            description="hourly",
        )
        trigger = sensor.evaluate(graph, None, datetime.now(UTC))
        assert trigger.fired is True
        assert "initial timed fire" in trigger.reason

    def test_does_not_fire_within_cadence(self, graph: EntityGraph):
        sensor = TimedSensor(
            sensor_id="t", interval_seconds=3600,
        )
        fp = sensor.evaluate(graph, None, datetime.now(UTC)).fingerprint
        # Same time → cadence not elapsed.
        trigger = sensor.evaluate(graph, fp, datetime.now(UTC))
        assert trigger.fired is False

    def test_fires_after_cadence_elapses(self, graph: EntityGraph):
        now = datetime.now(UTC)
        sensor = TimedSensor(
            sensor_id="t", interval_seconds=10,
        )
        fp = sensor.evaluate(graph, None, now).fingerprint
        later = now + timedelta(seconds=20)
        trigger = sensor.evaluate(graph, fp, later)
        assert trigger.fired is True
        assert "cadence elapsed" in trigger.reason


# ──────────────────────────────────────────────────────────────────────
# Severity classifier
# ──────────────────────────────────────────────────────────────────────


class TestSeverityClassifier:
    def test_low_for_minor_edge_change(self, graph: EntityGraph):
        diff = diff_graphs([], graph, previous_entity_ids=[])
        severity, reason = classify_diff(diff, graph)
        assert severity == Severity.LOW

    def test_high_for_new_high_confidence_entity(self, graph: EntityGraph):
        _seed_graph(graph)
        eid = graph.get_entity_id(
            _entity_type_enum("subdomain"), "api.acme.com",
        )
        diff = diff_graphs(
            [eid], graph, previous_entity_ids=[],
        )
        severity, reason = classify_diff(diff, graph)
        assert severity == Severity.HIGH
        assert "high-confidence" in reason

    def test_high_for_vuln_source(self, graph: EntityGraph):
        sub_id = graph.add_subdomain(
            "vuln.acme.com", "acme.com",
            "imported_from:nuclei",
            confidence=0.7,
        )
        diff = diff_graphs(
            [sub_id], graph, previous_entity_ids=[],
        )
        severity, reason = classify_diff(diff, graph)
        assert severity == Severity.HIGH
        assert "vuln-source" in reason

    def test_high_for_cascade_into_lead(self, graph: EntityGraph):
        # Build a lead + an evidence entity + a CITES edge.
        ev_id = graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.7,
        )
        lead_id = graph.add_lead(
            "Exposed API surface",
            source="correlation",
            confidence=0.7,
        )
        graph.relate(
            lead_id, ev_id,
            rel_type=RelationshipType.CITES,
            confidence=0.85,
            source_tool="correlation",
        )
        diff = diff_graphs(
            [lead_id], graph, previous_entity_ids=[],
        )
        severity, reason = classify_diff(diff, graph)
        assert severity == Severity.HIGH
        assert "CITES" in reason

    def test_medium_for_low_confidence_addition(self, graph: EntityGraph):
        sub_id = graph.add_subdomain(
            "wip.acme.com", "acme.com", "subfinder",
            confidence=0.4,
        )
        diff = diff_graphs(
            [sub_id], graph, previous_entity_ids=[],
        )
        severity, _ = classify_diff(diff, graph)
        # Not high (confidence too low), but additions → medium.
        assert severity == Severity.MEDIUM


# ──────────────────────────────────────────────────────────────────────
# Action policy
# ──────────────────────────────────────────────────────────────────────


class TestActionPolicy:
    def test_low_writes_alert_only(self, watch_root: Path):
        storage = WatchStorage("w1", root=watch_root)
        storage.watch_dir.mkdir(parents=True, exist_ok=True)
        result = apply_action(
            storage,
            severity=Severity.LOW, reason="r",
            sensor_id="s", sensor_kind="entity",
            changed_entity_ids=[],
            diff=None, watch_id="w1", campaign_id="c1",
        )
        assert result.action.alerted is True
        assert result.action.notified is False
        assert result.action.micro_campaign_queued is False

    def test_medium_alerts_and_notifies(self, watch_root: Path):
        storage = WatchStorage("w1", root=watch_root)
        storage.watch_dir.mkdir(parents=True, exist_ok=True)
        result = apply_action(
            storage,
            severity=Severity.MEDIUM, reason="r",
            sensor_id="s", sensor_kind="scope",
            changed_entity_ids=[],
            diff=None, watch_id="w1", campaign_id="c1",
        )
        assert result.action.notified is True
        assert result.action.micro_campaign_queued is False
        assert storage.notifications_path.exists()

    def test_high_queues_micro_campaign(self, watch_root: Path):
        storage = WatchStorage("w1", root=watch_root)
        storage.watch_dir.mkdir(parents=True, exist_ok=True)
        result = apply_action(
            storage,
            severity=Severity.HIGH, reason="big change",
            sensor_id="s", sensor_kind="scope",
            changed_entity_ids=["e1", "e2"],
            diff=None, watch_id="w1", campaign_id="c1",
        )
        assert result.action.micro_campaign_queued is True
        assert storage.micro_campaigns_path.exists()
        loaded = json.loads(
            storage.micro_campaigns_path.read_text().strip(),
        )
        assert loaded["seed_entity_ids"] == ["e1", "e2"]
        assert loaded["status"] == "queued"
        assert "phase1" in loaded["suggested_phases"]


# ──────────────────────────────────────────────────────────────────────
# Storage
# ──────────────────────────────────────────────────────────────────────


class TestWatchStorage:
    def test_save_load_roundtrip(self, watch_root: Path):
        storage = WatchStorage("w1", root=watch_root)
        sensors: list[Sensor] = [
            ScopeSensor(sensor_id="s.scope", parent_domain="acme.com"),
            TimedSensor(sensor_id="s.timed", interval_seconds=3600),
        ]
        watch = Watch(
            watch_id="w1", campaign_id="c1",
            sensors=sensors, description="t",
        )
        storage.save_watch(watch)
        loaded = storage.load_watch()
        assert loaded.watch_id == "w1"
        assert loaded.campaign_id == "c1"
        assert len(loaded.sensors) == 2
        assert isinstance(loaded.sensors[0], ScopeSensor)
        assert isinstance(loaded.sensors[1], TimedSensor)

    def test_delete(self, watch_root: Path):
        storage = WatchStorage("w1", root=watch_root)
        storage.save_watch(Watch(
            watch_id="w1", campaign_id="c1",
            sensors=[
                ScopeSensor(sensor_id="s", parent_domain="acme.com"),
            ],
        ))
        assert storage.exists()
        assert storage.delete() is True
        assert not storage.exists()

    def test_fingerprint_roundtrip(self, watch_root: Path):
        storage = WatchStorage("w1", root=watch_root)
        storage.watch_dir.mkdir(parents=True, exist_ok=True)
        fp = SensorFingerprint(
            sensor_id="s", entity_ids=["a", "b"],
            digest="abc", captured_at="2026-05-27T00:00:00+00:00",
        )
        storage.save_fingerprint(fp)
        loaded = storage.load_fingerprint("s")
        assert loaded is not None
        assert loaded.digest == "abc"
        assert loaded.entity_ids == ["a", "b"]


# ──────────────────────────────────────────────────────────────────────
# Runner — end-to-end
# ──────────────────────────────────────────────────────────────────────


class TestRunner:
    def test_list_watches_enumerates_configs(self, watch_root: Path):
        WatchStorage("w1", root=watch_root).save_watch(Watch(
            watch_id="w1", campaign_id="c1",
            sensors=[ScopeSensor(
                sensor_id="s", parent_domain="acme.com",
            )],
        ))
        WatchStorage("w2", root=watch_root).save_watch(Watch(
            watch_id="w2", campaign_id="c2",
            sensors=[ScopeSensor(
                sensor_id="s", entity_type="domain",
            )],
        ))
        watches = list_watches(watch_root=watch_root)
        ids = {w.watch_id for w in watches}
        assert ids == {"w1", "w2"}

    def test_full_tick_lifecycle(self, watch_root: Path, graph: EntityGraph):
        """Full end-to-end: create a watch, run a first tick
        that just captures fingerprints, mutate the graph,
        run a second tick that fires + writes alerts."""
        _seed_graph(graph)
        # Create the watch.
        storage = WatchStorage("w1", root=watch_root)
        storage.save_watch(Watch(
            watch_id="w1", campaign_id="cmp-test",
            sensors=[ScopeSensor(
                sensor_id="subs", entity_type="subdomain",
            )],
        ))

        # Mutable graph reference; runner will be fed via
        # injectable loader.
        def loader(cid: str):
            return graph

        # First tick: initial fingerprint, no fire.
        r1 = tick("w1", watch_root=watch_root, graph_loader=loader)
        assert r1.sensors_evaluated == 1
        assert r1.sensors_fired == 0

        # Add a new subdomain at HIGH confidence so the
        # diff classifier raises severity to high.
        graph.add_subdomain(
            "fresh.acme.com", "acme.com", "subfinder",
            confidence=0.9,
        )

        # Second tick: fires + grades as high.
        r2 = tick("w1", watch_root=watch_root, graph_loader=loader)
        assert r2.sensors_fired == 1
        assert r2.actions[0].action.severity == "high"
        assert r2.actions[0].action.micro_campaign_queued is True

        # Alert + micro-campaign records persisted.
        assert storage.alerts_path.exists()
        alerts = storage.read_alerts()
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "high"
        assert storage.micro_campaigns_path.exists()

    def test_tick_missing_watch_returns_error(self, watch_root: Path):
        result = tick("ghost", watch_root=watch_root, graph_loader=lambda c: None)
        assert result.sensors_evaluated == 0
        assert any("no watch config" in e for e in result.errors)

    def test_graph_loader_failure_recorded(self, watch_root: Path):
        WatchStorage("w1", root=watch_root).save_watch(Watch(
            watch_id="w1", campaign_id="cmp-missing",
            sensors=[ScopeSensor(
                sensor_id="s", entity_type="domain",
            )],
        ))

        def boom(cid: str):
            raise RuntimeError("no such campaign")

        result = tick(
            "w1", watch_root=watch_root, graph_loader=boom,
        )
        assert any("graph load failed" in e for e in result.errors)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _entity_type_enum(value: str):
    from nexusrecon.models.entities import EntityType
    return EntityType(value)
