"""Wizard helper functions (TUI-4): validators, preset loader,
cost estimator.

Each helper is pure Python and unit-testable in isolation. The
Textual wizard screen wires them into the live form via
:class:`Input.Changed` handlers and selection callbacks.
"""
from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ──────────────────────────────────────────────────────────────────────
# Validators
# ──────────────────────────────────────────────────────────────────────

# Pattern shared with the wizard module — keep in sync.
_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_WILDCARD_RE = re.compile(r"^(\*\.|)([a-z0-9-]+\.)+[a-z]{2,}$")


@dataclass(frozen=True)
class FieldStatus:
    """Result of validating a single wizard field.

    Used by the live validation indicators next to each Input. The
    ``icon`` field is what the small status widget renders; the
    ``hint`` is the single-line tooltip shown on focus.
    """

    valid: bool
    icon: str
    hint: str = ""

    @classmethod
    def ok(cls, hint: str = "") -> FieldStatus:
        return cls(valid=True, icon="✓", hint=hint)

    @classmethod
    def bad(cls, hint: str) -> FieldStatus:
        return cls(valid=False, icon="✗", hint=hint)

    @classmethod
    def pending(cls, hint: str = "") -> FieldStatus:
        """Field is empty but not yet attempted — neutral, no error."""
        return cls(valid=False, icon="…", hint=hint)


def validate_required_text(value: str, *, label: str) -> FieldStatus:
    """Field must be non-empty after stripping whitespace."""
    if not value or not value.strip():
        return FieldStatus.pending(f"{label} is required")
    return FieldStatus.ok()


def validate_domain(value: str) -> FieldStatus:
    """Single-domain text input."""
    text = (value or "").strip().lower()
    if not text:
        return FieldStatus.pending("domain is required")
    if _DOMAIN_RE.match(text):
        return FieldStatus.ok()
    return FieldStatus.bad("doesn't look like a valid domain")


def validate_domain_list(value: str) -> FieldStatus:
    """Comma-separated list of fully-qualified domains (no wildcards)."""
    text = (value or "").strip()
    if not text:
        return FieldStatus.ok("(optional)")
    bad: list[str] = []
    count = 0
    for entry in text.split(","):
        entry = entry.strip().lower()
        if not entry:
            continue
        count += 1
        if not _DOMAIN_RE.match(entry):
            bad.append(entry)
    if bad:
        return FieldStatus.bad(f"invalid: {', '.join(bad[:3])}")
    return FieldStatus.ok(f"{count} domain(s)")


def validate_wildcard_list(value: str) -> FieldStatus:
    """Comma-separated list of FQDNs OR ``*.domain`` wildcards."""
    text = (value or "").strip()
    if not text:
        return FieldStatus.ok("(optional)")
    bad: list[str] = []
    count = 0
    for entry in text.split(","):
        entry = entry.strip().lower()
        if not entry:
            continue
        count += 1
        if not _WILDCARD_RE.match(entry):
            bad.append(entry)
    if bad:
        return FieldStatus.bad(f"invalid: {', '.join(bad[:3])}")
    return FieldStatus.ok(f"{count} pattern(s)")


def validate_iso_date(value: str) -> FieldStatus:
    """YYYY-MM-DD format."""
    text = (value or "").strip()
    if not text:
        return FieldStatus.pending("date is required")
    try:
        _dt.date.fromisoformat(text)
        return FieldStatus.ok()
    except Exception:
        return FieldStatus.bad("expected YYYY-MM-DD")


def validate_sow_hash(value: str) -> FieldStatus:
    """64-hex-char SHA-256 OR the literal ``placeholder`` token."""
    text = (value or "").strip()
    if not text:
        return FieldStatus.pending("required (or 'placeholder')")
    if text.lower() == "placeholder":
        return FieldStatus.ok("(test mode)")
    if _HEX64_RE.match(text):
        return FieldStatus.ok()
    if len(text) < 64:
        return FieldStatus.bad(f"{len(text)}/64 hex chars")
    return FieldStatus.bad("must be 64 hex chars")


def validate_positive_float(value: str, *, label: str) -> FieldStatus:
    """Numeric input that must parse + be strictly positive."""
    text = (value or "").strip()
    if not text:
        return FieldStatus.pending(f"{label} is required")
    try:
        n = float(text)
    except ValueError:
        return FieldStatus.bad("must be a number")
    if n <= 0:
        return FieldStatus.bad("must be positive")
    return FieldStatus.ok()


# ──────────────────────────────────────────────────────────────────────
# Scope-file presets
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ScopePreset:
    """A named pre-fill for the wizard's form fields.

    The ``fields`` dict maps wizard ``self.data`` keys directly to
    their starting values. Each preset can supply any subset; fields
    it doesn't mention retain their default.
    """

    id: str
    name: str
    description: str
    fields: dict[str, Any] = field(default_factory=dict)


#: Built-in presets that ship with the framework. Operators can
#: override by name by dropping a YAML with the same ``id`` field
#: into ``~/.nexusrecon/scope-presets/``.
BUILTIN_PRESETS: list[ScopePreset] = [
    ScopePreset(
        id="oss-recon",
        name="Open-source project recon",
        description=(
            "Wide-net OSINT against an OSS project: GitHub-heavy, "
            "no breach lookups, low-cost LLM."
        ),
        fields={
            "max_tier": "T1",
            "stealth": "normal",
            "max_cost_usd": "5.0",
            "allow_breach": False,
            "allow_paid": False,
            "mode": "medium",
            "dispatch_mode": "lite",
        },
    ),
    ScopePreset(
        id="corp-m365",
        name="M365 / Azure enterprise",
        description=(
            "Office365 + Azure-focused engagement. Conservative "
            "stealth, breach lookups enabled for credential context."
        ),
        fields={
            "max_tier": "T2",
            "stealth": "high",
            "max_cost_usd": "30.0",
            "allow_breach": True,
            "allow_paid": True,
            "mode": "deep",
            "dispatch_mode": "lite",
        },
    ),
    ScopePreset(
        id="aws-startup",
        name="AWS-native startup",
        description=(
            "Cloud-first SaaS startup: AWS + GitHub + brief identity "
            "pivot. Medium budget, normal stealth."
        ),
        fields={
            "max_tier": "T2",
            "stealth": "normal",
            "max_cost_usd": "15.0",
            "allow_breach": True,
            "allow_paid": True,
            "mode": "medium",
            "dispatch_mode": "lite",
        },
    ),
    ScopePreset(
        id="bug-bounty",
        name="Bug-bounty quick sweep",
        description=(
            "Bug-bounty target: low cost, fast iteration, no paid APIs, "
            "no breach lookups (out of program scope)."
        ),
        fields={
            "max_tier": "T1",
            "stealth": "normal",
            "max_cost_usd": "3.0",
            "allow_breach": False,
            "allow_paid": False,
            "mode": "light",
            "dispatch_mode": "off",
        },
    ),
]


def load_presets() -> list[ScopePreset]:
    """Return built-in + operator-defined presets.

    User presets live in ``~/.nexusrecon/scope-presets/*.yaml`` and
    each yaml is parsed as a single ScopePreset. An operator preset
    with the same ``id`` as a built-in OVERRIDES the built-in (the
    operator file wins).

    Defensive: returns the built-in set on any user-preset parse
    error. Adding a malformed file shouldn't break the wizard.
    """
    presets: dict[str, ScopePreset] = {p.id: p for p in BUILTIN_PRESETS}
    user_dir = Path.home() / ".nexusrecon" / "scope-presets"
    if not user_dir.exists():
        return list(presets.values())
    try:
        for path in sorted(user_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                if not isinstance(data, dict):
                    continue
                if "id" not in data or "name" not in data:
                    continue
                preset = ScopePreset(
                    id=str(data["id"]),
                    name=str(data["name"]),
                    description=str(data.get("description", "")),
                    fields=dict(data.get("fields", {})),
                )
                presets[preset.id] = preset
            except Exception:
                continue
    except Exception:
        pass
    return list(presets.values())


def preset_by_id(preset_id: str) -> ScopePreset | None:
    """Return the named preset, or None if it doesn't exist."""
    for p in load_presets():
        if p.id == preset_id:
            return p
    return None


# ──────────────────────────────────────────────────────────────────────
# Cost preview
# ──────────────────────────────────────────────────────────────────────


@dataclass
class CostPreview:
    """Estimated LLM spend for the campaign about to launch.

    The numbers are heuristics, not measurements: they exist to give
    the operator an order-of-magnitude sense ("am I about to spend
    $2 or $200?") rather than a precise prediction. The bounds widen
    as confidence drops (deep mode + full dispatch is the noisiest).
    """

    low_usd: float
    mid_usd: float
    high_usd: float
    rationale: str = ""

    def fits_budget(self, budget_usd: float) -> bool:
        """Is the upper estimate within the operator's budget?"""
        return self.high_usd <= budget_usd


def estimate_campaign_cost(
    *,
    mode: str,
    dispatch_mode: str,
    max_tier: str,
    stealth: str,
    seed_count: int,
    additional_count: int = 0,
    generate_phishing: bool = False,
) -> CostPreview:
    """Heuristic LLM cost estimate.

    The model behind these numbers:
      - Each campaign runs N phases (8 base + 2 conditional). The
        per-phase cost scales with the synthesis work the LLM does;
        ``deep`` mode roughly doubles the spend of ``medium``,
        ``light`` is roughly half.
      - Dispatch mode adds per-trigger LLM calls. ``lite`` fires
        after 3 phases (1/4/7); ``full`` fires after every phase;
        ``off`` skips it. Each fire costs ~$0.05–0.20 depending on
        context.
      - Tier ``T3`` rarely correlates with cost (already-found
        evidence drives the synthesis); we ignore it.
      - More domains = more attack-surface synthesis. Roughly
        linear in ``seed + additional``.
      - Phishing-draft generation adds ~$0.10–0.50 per target.

    Output: a 3-point estimate (low, mid, high) in USD that the
    review pane can render as a gauge.
    """
    domains = max(1, seed_count + additional_count)

    # Base cost per phase by mode (mid estimate).
    per_phase_mid = {
        "light": 0.05,
        "medium": 0.15,
        "deep": 0.40,
        "monitor": 0.10,
    }.get(mode, 0.15)
    phases = 8  # base count; phase 2.5 + 7.5 are conditional
    base_mid = per_phase_mid * phases * (1 + 0.2 * (domains - 1))

    # Dispatch overhead.
    dispatch_fires = {"off": 0, "lite": 3, "full": phases}.get(dispatch_mode, 3)
    dispatch_mid = dispatch_fires * 0.10

    # Phishing-draft overhead (assume ~5 targets default).
    phishing_mid = (5 * 0.25) if generate_phishing else 0.0

    mid = base_mid + dispatch_mid + phishing_mid

    # Spread: ±50% for low/high, but mode "deep" widens to ±70%.
    spread = 0.7 if mode == "deep" else 0.5
    low = max(0.01, mid * (1 - spread))
    high = mid * (1 + spread)

    rationale_parts = [
        f"{phases} phases × ${per_phase_mid:.2f} ({mode})",
        f"{domains} domain(s)",
    ]
    if dispatch_fires:
        rationale_parts.append(f"{dispatch_fires} dispatch fires")
    if generate_phishing:
        rationale_parts.append("phishing drafts ~5 targets")

    return CostPreview(
        low_usd=round(low, 2),
        mid_usd=round(mid, 2),
        high_usd=round(high, 2),
        rationale=" · ".join(rationale_parts),
    )


# ──────────────────────────────────────────────────────────────────────
# Summary pane rendering
# ──────────────────────────────────────────────────────────────────────


def render_summary(data: dict[str, Any]) -> str:
    """Sticky right-side summary contents for the wizard.

    Renders every field the operator has entered so far across all
    five steps, formatted as a compact key-value list. Empty fields
    appear as ``(not set)`` in dim — the operator can see at a
    glance what still needs attention before pressing Save & Run.
    """
    sections: list[tuple[str, list[tuple[str, str]]]] = [
        ("Engagement", [
            ("Client", data.get("client", "")),
            ("Engagement ID", data.get("engagement_id", "")),
            ("Authorized by", data.get("authorized_by", "")),
            ("Auth date", data.get("authorization_date", "")),
            ("Start", data.get("start_date", "")),
            ("End", data.get("end_date", "")),
            ("SOW", _shorten(data.get("sow_hash", ""), 12)),
        ]),
        ("Scope", [
            ("Seed", data.get("seed_domain", "")),
            ("Extra", _shorten(data.get("additional_domains", ""), 22)),
            ("Out of scope", _shorten(data.get("out_of_scope", ""), 22)),
        ]),
        ("Constraints", [
            ("Max tier", data.get("max_tier", "")),
            ("Stealth", data.get("stealth", "")),
            ("Budget", f"${data.get('max_cost_usd', '?')}"),
            ("Breach", "yes" if data.get("allow_breach") else "no"),
            ("Paid", "yes" if data.get("allow_paid") else "no"),
        ]),
        ("Run", [
            ("Mode", data.get("mode", "")),
            ("Dispatch", data.get("dispatch_mode", "")),
            ("Validate creds", "yes" if data.get("validate_creds") else "no"),
            ("Phishing", "yes" if data.get("generate_phishing") else "no"),
        ]),
    ]
    lines: list[str] = []
    for section_name, rows in sections:
        lines.append(f"[bold $primary]{section_name}[/bold $primary]")
        for k, v in rows:
            if v in ("", None):
                v_render = "[dim](not set)[/dim]"
            else:
                v_render = str(v)
            lines.append(f"  [dim]{k:<14}[/dim] {v_render}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _shorten(value: str, max_chars: int) -> str:
    if not value:
        return ""
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 1] + "…"


# ──────────────────────────────────────────────────────────────────────
# Apply preset to wizard data
# ──────────────────────────────────────────────────────────────────────


def apply_preset(data: dict[str, Any], preset: ScopePreset) -> None:
    """Merge preset fields into the wizard's data dict in place.

    Only the keys the preset explicitly mentions are overwritten;
    operator-entered values for other keys (Engagement ID, dates,
    etc.) are preserved. Boolean values pass through unchanged.
    """
    for k, v in preset.fields.items():
        data[k] = v


def known_preset_ids() -> Iterable[str]:
    return [p.id for p in load_presets()]
