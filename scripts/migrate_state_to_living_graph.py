"""Migrate pre-Phase-0 ``state.json`` files to the new
Living Graph format.

Phase 0 of ARCHITECTURE.md §13-22 reshaped
``state["entity_graph"]`` from a truncated 500-entry name-list
dict (``{"subdomains": [...], "emails": [...]}``) to the real
serialised :class:`LivingGraph` carrying every entity surfaced
by the campaign, plus the unified person/relationship data
ingested from the Phase D ``IdentityGraph`` + Phase E
``RelationshipGraph``.

Old ``state.json`` files don't break on read — the new code
path tolerates the truncated format and rebuilds from the flat
buckets on the next phase4 invocation. This script does the
same rebuild EAGERLY so an operator can:

  - resume a partial campaign with the new graph already
    populated (instead of waiting for phase4 to re-run);
  - run reports off the new graph without re-running any
    phase;
  - inspect what the graph looks like for an old campaign
    without launching the TUI.

Usage:

    # Dry-run: report what would change without writing.
    python scripts/migrate_state_to_living_graph.py \\
        --campaign-dir campaigns/acme.com/2026-01-15T14-30-00

    # Apply: backup the existing state.json, write the
    # migrated version in place.
    python scripts/migrate_state_to_living_graph.py \\
        --campaign-dir campaigns/acme.com/2026-01-15T14-30-00 \\
        --apply

    # Bulk: walk every campaign under campaigns/.
    python scripts/migrate_state_to_living_graph.py \\
        --root campaigns/ --apply

The migration is idempotent — running it twice on the same
file produces the same result (the second pass detects the
graph is already up-to-date and reports "no changes").
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _summarise_old_graph(eg: dict[str, Any]) -> str:
    """Human-readable summary of what the old entity_graph
    field held. Used by --dry-run output so the operator can
    see what's being migrated."""
    if not isinstance(eg, dict):
        return "(missing/invalid)"
    if "nodes" in eg and "edges" in eg:
        return f"already new format ({len(eg['nodes'])} nodes, {len(eg['edges'])} edges)"
    subs = len(eg.get("subdomains", []) or [])
    emails = len(eg.get("emails", []) or [])
    return f"truncated name-list ({subs} subdomains, {emails} emails)"


def _migrate_one(
    state_path: Path,
    *,
    apply: bool,
) -> dict[str, Any]:
    """Migrate a single state.json file. Returns a report dict
    with the keys the CLI uses to print status lines."""
    if not state_path.exists():
        return {
            "path": str(state_path),
            "status": "missing",
            "message": "state.json not found",
        }

    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "path": str(state_path),
            "status": "error",
            "message": f"could not parse: {exc}",
        }

    # Import here so the script also works as a standalone
    # entry point without polluting other code paths.
    from nexusrecon.core.entity_graph import (
        GRAPH_SCHEMA_VERSION,
        EntityGraph,
    )

    old_eg = state.get("entity_graph") or {}
    old_summary = _summarise_old_graph(old_eg)

    # Is the graph already the new format AND at the current
    # schema version? Skip with "no changes" then.
    if (
        isinstance(old_eg, dict)
        and "nodes" in old_eg
        and "edges" in old_eg
        and old_eg.get("schema_version") == GRAPH_SCHEMA_VERSION
    ):
        return {
            "path": str(state_path),
            "status": "already_current",
            "message": f"entity_graph already at schema {GRAPH_SCHEMA_VERSION}",
            "old_summary": old_summary,
        }

    # Rebuild via the canonical from_state path. This is the
    # same code phase4 calls — so the migrated graph matches
    # what a fresh phase4 invocation would produce.
    try:
        eg = EntityGraph.from_state(
            state,
            campaign_id=state.get("campaign_id", ""),
            engagement_id=state.get("engagement_id", ""),
        )
    except Exception as exc:
        return {
            "path": str(state_path),
            "status": "error",
            "message": f"rebuild failed: {exc}",
        }

    new_eg_dict = eg.to_dict()
    # Stamp the schema version so future migrations can
    # detect at-current vs needs-upgrade in O(1).
    new_eg_dict["schema_version"] = GRAPH_SCHEMA_VERSION

    new_summary = (
        f"{len(new_eg_dict['nodes'])} nodes, "
        f"{len(new_eg_dict['edges'])} edges"
    )

    if not apply:
        return {
            "path": str(state_path),
            "status": "would_migrate",
            "message": f"would rewrite entity_graph: "
                       f"{old_summary} → {new_summary}",
            "old_summary": old_summary,
            "new_summary": new_summary,
        }

    # Apply: backup the existing state.json next to itself, write
    # the migrated state. Atomic-as-possible: write to .tmp then
    # rename.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = state_path.with_suffix(f".pre-migrate-{timestamp}.json")
    shutil.copy2(state_path, backup)

    state["entity_graph"] = new_eg_dict
    tmp_path = state_path.with_suffix(".json.tmp")
    tmp_path.write_text(
        json.dumps(state, default=str, indent=2),
        encoding="utf-8",
    )
    tmp_path.replace(state_path)

    return {
        "path": str(state_path),
        "status": "migrated",
        "message": f"entity_graph rewritten: {old_summary} → {new_summary}",
        "backup": str(backup),
        "old_summary": old_summary,
        "new_summary": new_summary,
    }


def _discover(root: Path) -> list[Path]:
    """Walk ``root`` for every ``state.json`` it contains."""
    return list(root.rglob("state.json"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--campaign-dir", type=Path,
        help="Single campaign directory containing state.json. "
             "Mutually exclusive with --root.",
    )
    parser.add_argument(
        "--root", type=Path,
        help="Root directory; the script walks every state.json under it. "
             "Mutually exclusive with --campaign-dir.",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Actually write the migrated state.json. Default is "
             "dry-run: report what would change without touching disk.",
    )
    args = parser.parse_args(argv)

    if bool(args.campaign_dir) == bool(args.root):
        parser.error(
            "exactly one of --campaign-dir or --root is required",
        )

    if args.campaign_dir:
        targets = [args.campaign_dir / "state.json"]
    else:
        targets = _discover(args.root)
        if not targets:
            print(f"No state.json files found under {args.root}",
                  file=sys.stderr)
            return 1

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] migrating {len(targets)} state.json file(s)")
    print()

    totals: dict[str, int] = {
        "would_migrate": 0,
        "migrated": 0,
        "already_current": 0,
        "missing": 0,
        "error": 0,
    }
    for state_path in targets:
        report = _migrate_one(state_path, apply=args.apply)
        status = report["status"]
        totals[status] = totals.get(status, 0) + 1
        marker = {
            "would_migrate": "→",
            "migrated": "✓",
            "already_current": "·",
            "missing": "?",
            "error": "✗",
        }.get(status, "?")
        print(f"  {marker}  {report['path']}")
        print(f"     {report['message']}")
        if report.get("backup"):
            print(f"     backup: {report['backup']}")
        print()

    print("Summary:")
    for status, count in totals.items():
        if count:
            print(f"  {status:18s} {count}")

    return 0 if totals.get("error", 0) == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
