"""Maltego CSV export — entity CSV compatible with Maltego import."""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any


def export_maltego_csv(state: dict[str, Any], output_dir: Path) -> str:
    """Export entities in Maltego-compatible CSV format."""
    path = output_dir / "maltego_export.csv"
    rows = []

    # Subdomains
    for sub, info in state.get("subdomain_intel", {}).items():
        rows.append({
            "Entity Type": "Domain",
            "Value": sub,
            "Sources": "|".join(info.get("sources", [])) if isinstance(info, dict) else "unknown",
            "Confidence": info.get("confidence", 1.0) if isinstance(info, dict) else 1.0,
            "Tags": "subdomain",
            "First Seen": "",
            "Last Seen": datetime.utcnow().isoformat(),
        })

    # Emails
    for em, info in state.get("email_intel", {}).get("emails", {}).items():
        rows.append({
            "Entity Type": "Email",
            "Value": em,
            "Sources": info.get("source", "unknown") if isinstance(info, dict) else "unknown",
            "Confidence": 0.8,
            "Tags": "email",
            "First Seen": "",
            "Last Seen": datetime.utcnow().isoformat(),
        })

    with open(path, "w", newline="", encoding="utf-8") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    return str(path)
