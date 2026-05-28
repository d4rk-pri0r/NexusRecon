"""Email format inference tool with confidence scoring."""
from __future__ import annotations

import re
from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

# Patterns are matched against the ``@``-stripped local part of an
# email (e.g. ``alice.smith`` from ``alice.smith@example.com``).
# Order matters: the first regex to match wins, so more-specific
# patterns are listed first to prevent the catch-all ``first`` pattern
# from swallowing structured ones like ``first.last``.
#
# The trailing ``$`` anchor is essential — without it, ``^([a-z]+)``
# would match the leading letters of every local part regardless of
# what comes after, and every input would resolve to ``"first"``.
#
# Some patterns are textually ambiguous (``smith.j`` could be
# ``last.f`` or ``first.last`` depending on cultural naming order;
# ``jsmith`` could be ``flast`` or ``firstlast``). For ties the order
# below favours the convention most common in US corporate email
# directories. A ``last_first`` regex was present in earlier revisions
# but was identical to ``first.last`` — dropped because it could
# never win on text alone.
KNOWN_PATTERNS = {
    # 3-token dot-separated — most specific, tried first
    "first_middle_last": r'^([a-z]+)\.([a-z]+)\.([a-z]+)$',  # alice.b.smith
    # 2-token forms with a single-letter component — must come before
    # the generic ``first.last`` so e.g. ``j.smith`` matches ``f.last``
    # instead of being eaten by ``first.last`` (which also matches).
    "f.last":            r'^([a-z])\.([a-z]+)$',             # j.smith
    "last.f":            r'^([a-z]+)\.([a-z])$',             # smith.j
    "f_last":            r'^([a-z])_([a-z]+)$',              # j_smith
    "first_l":           r'^([a-z]+)_([a-z])$',              # smith_j
    # Generic 2-token dot form
    "first.last":        r'^([a-z]+)\.([a-z]+)$',            # alice.smith
    # Single-token forms — tried last because they match anything 1+
    # lowercase letters and would otherwise eat the structured patterns.
    "flast":             r'^([a-z])([a-z]+)$',               # jsmith (init + last)
    "firstlast":         r'^([a-z]+)([a-z]+)$',              # alicesmith
    "first":             r'^([a-z]+)$',                      # alice
}


@register_tool
class EmailFormatTool(OSINTTool):
    name = "email_format"
    tier = Tier.T0
    category = Category.EMAIL
    requires_keys = []
    description = "Email format inference with confidence scoring from observed samples"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        emails: list[str] = kwargs.get("emails", [])
        # F-B5: drop obviously synthetic/test addresses before inferring the
        # naming convention. A single junk address (e.g. abcfoo@) otherwise
        # skews the pattern distribution and the headline confidence.
        from nexusrecon.core.identity_hygiene import filter_test_identities
        emails, dropped = filter_test_identities(emails)
        if not emails:
            return ToolResult(
                success=True, source=self.name,
                data={"error": "No emails to analyze", "dropped_test_identities": dropped},
                result_count=0,
            )

        patterns_found: dict[str, int] = {}
        parsed = []

        for email in emails:
            email_lower = email.lower().strip()
            if "@" not in email_lower:
                continue
            local = email_lower.split("@")[0]

            matched_pattern = None
            for pattern_name, regex in KNOWN_PATTERNS.items():
                if re.match(regex, local):
                    matched_pattern = pattern_name
                    break

            if matched_pattern:
                patterns_found[matched_pattern] = patterns_found.get(matched_pattern, 0) + 1

            parsed.append({"email": email_lower, "local": local, "pattern": matched_pattern})

        # Calculate confidence scores
        total = len(emails)
        pattern_scores = {}
        for pattern, count in patterns_found.items():
            confidence = count / total if total > 0 else 0
            pattern_scores[pattern] = {
                "count": count,
                "confidence": round(confidence, 3),
            }

        # Determine most likely pattern
        likely_pattern = max(patterns_found, key=patterns_found.get) if patterns_found else "unknown"
        likely_confidence = patterns_found.get(likely_pattern, 0) / total if total > 0 else 0

        return ToolResult(
            success=True, source=self.name,
            data={
                "total_emails": total,
                "parsed_emails": parsed,
                "pattern_distribution": pattern_scores,
                "most_likely_pattern": likely_pattern,
                "most_likely_confidence": round(likely_confidence, 3),
                "recommendation": self._recommendation(likely_pattern, likely_confidence),
                "dropped_test_identities": dropped,
            },
            result_count=total,
        )

    @staticmethod
    def _recommendation(pattern: str, confidence: float) -> str:
        if confidence > 0.8:
            return f"High confidence ({confidence:.0%}) for '{pattern}' — safe for email generation"
        elif confidence > 0.5:
            return f"Moderate confidence ({confidence:.0%}) for '{pattern}' — verify with more samples"
        else:
            return f"Low confidence ({confidence:.0%}) for '{pattern}' — need more email samples for reliable pattern detection"
