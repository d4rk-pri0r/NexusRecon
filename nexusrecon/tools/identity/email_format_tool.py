"""Email format inference tool with confidence scoring."""
from __future__ import annotations
import re
from collections import Counter
from typing import Any, Dict, List, Optional
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

KNOWN_PATTERNS = {
    "flast": r'^([a-z])([a-z]+)@',
    "first.last": r'^([a-z]+)\.([a-z]+)@',
    "firstlast": r'^([a-z]+)([a-z]+)@',
    "f.last": r'^([a-z])\.([a-z]+)@',
    "first": r'^([a-z]+)@',
    "first_l": r'^([a-z]+)_([a-z])@',
    "f_last": r'^([a-z])_([a-z]+)@',
    "first_middle_last": r'^([a-z]+)\.([a-z]+)\.([a-z]+)@',
    "last_first": r'^([a-z]+)\.([a-z]+)@',
    "last.f": r'^([a-z]+)\.([a-z])@',
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
        emails: List[str] = kwargs.get("emails", [])
        if not emails:
            return ToolResult(success=True, source=self.name, data={"error": "No emails to analyze"}, result_count=0)

        patterns_found: Dict[str, int] = {}
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
