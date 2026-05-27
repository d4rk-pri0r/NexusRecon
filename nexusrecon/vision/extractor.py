"""Vision extractor — orchestrates the full pipeline.

One :class:`VisionExtractor` per campaign. Public surface:

  - :meth:`scan_image(image_bytes, mime_type, source_label,
    graph, state)` — single image.
  - :meth:`scan_file(path, source_label, graph, state)` —
    dispatch by extension to image / PDF.
  - :meth:`scan_pdf(path, source_label, graph, state)` —
    explicit PDF entry.

For each scan, the extractor:

  1. Consults the cost gate; SKIPS the LLM call when the
     vision_calls budget is 0 or exhausted (still tries QR
     decoding, which costs nothing).
  2. Calls the backend with a strict-JSON prompt that asks
     for structured entities + a narrative description.
  3. Parses the response, emits entities through the
     standard graph builders with
     ``imported_from:vision`` source tag.
  4. Adds a Hypothesis carrying the narrative description
     + CITES edges to the extracted entities.
  5. Audit-logs the scan with metadata about which budget
     was consulted + how many entities resulted.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog

from nexusrecon.vision.backend import (
    NoopVisionBackend,
    VisionBackend,
)
from nexusrecon.vision.cost import CostGate, CostGateDecision
from nexusrecon.vision.preprocess import (
    decode_qr_codes,
    extract_pdf_pages,
    guess_mime_type,
    is_supported_image,
    is_supported_pdf,
)

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Prompt
# ──────────────────────────────────────────────────────────────────────


_SYSTEM_PROMPT = """\
You are a multi-modal OSINT analyst. Examine the provided
visual artifact and return a STRICT JSON object with two
top-level keys:

{
  "description": "1-3 sentence narrative summary",
  "entities": {
    "urls": ["https://...", ...],
    "emails": ["user@host", ...],
    "persons": ["First Last", ...],
    "organizations": ["Acme Corp", ...],
    "brands": ["Brand Name", ...],
    "technologies": ["nginx", "AWS", ...],
    "domains": ["acme.com", ...]
  }
}

Rules:
- Return ONLY the JSON object, no prose around it.
- Use empty lists for keys you have no information about.
- Surface only things you can actually see — no
  speculation, no guessing.
- For brands / logos, return the brand NAME you identify
  (e.g. "Slack", "GitHub"). Skip if uncertain.
- For domain / URL extraction, copy text verbatim.
- A page may also be a phishing kit / malware UI — surface
  the impersonated brand without endorsing the content.
"""


_PDF_TEXT_SYSTEM_PROMPT = """\
You are an OSINT analyst reading a single PDF page's
extracted text. Same output contract as a vision call —
return a STRICT JSON object with `description` (1-3
sentences) + `entities` (dict of lists: urls, emails,
persons, organizations, brands, technologies, domains).
Return ONLY the JSON.
"""


# ──────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────


@dataclass
class VisionResult:
    """Aggregate outcome of one ``scan_*`` call."""

    source_label: str
    backend_used: str
    cost_decision: CostGateDecision
    description: str = ""
    entities_added: int = 0
    entity_counts: dict[str, int] = field(default_factory=dict)
    qr_decodes: list[dict[str, Any]] = field(default_factory=list)
    hypothesis_id: str = ""
    skipped: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_label": self.source_label,
            "backend_used": self.backend_used,
            "cost_decision": self.cost_decision.to_dict(),
            "description": self.description,
            "entities_added": self.entities_added,
            "entity_counts": dict(self.entity_counts),
            "qr_decodes": list(self.qr_decodes),
            "hypothesis_id": self.hypothesis_id,
            "skipped": self.skipped,
            "error": self.error,
        }


# ──────────────────────────────────────────────────────────────────────
# Extractor
# ──────────────────────────────────────────────────────────────────────


class VisionExtractor:
    """Orchestrates preprocessing → cost gate → backend call
    → entity emission. One instance per campaign."""

    def __init__(
        self,
        backend: VisionBackend | None = None,
        *,
        cost_gate: CostGate | None = None,
        system_prompt: str = _SYSTEM_PROMPT,
    ) -> None:
        self.backend: VisionBackend = backend or NoopVisionBackend()
        self.cost_gate = cost_gate or CostGate()
        self.system_prompt = system_prompt

    # ── Entry points ─────────────────────────────────────────

    def scan_image(
        self,
        image_bytes: bytes,
        *,
        mime_type: str,
        source_label: str,
        graph: Any,
        state: dict[str, Any],
    ) -> VisionResult:
        """Scan a single image. Cost gate consulted first."""
        # QR decoding ALWAYS runs (no LLM cost). Results are
        # emitted regardless of the budget decision.
        qr_hits = decode_qr_codes(image_bytes)
        qr_added = self._emit_qr_entities(graph, qr_hits, source_label)

        decision = self.cost_gate.consult(state)
        result = VisionResult(
            source_label=source_label,
            backend_used=self.backend.name,
            cost_decision=decision,
            qr_decodes=[q.to_dict() for q in qr_hits],
        )
        if qr_added:
            result.entity_counts["url_from_qr"] = qr_added
            result.entities_added += qr_added

        if not decision.allowed:
            result.skipped = True
            self.cost_gate.record_skip(
                state, source=source_label, decision=decision,
            )
            return result

        try:
            raw = self.backend.describe_image(
                image_bytes,
                mime_type=mime_type,
                prompt=self.system_prompt,
            )
        except Exception as exc:
            result.error = f"backend error: {exc}"
            return result

        self.cost_gate.record_call(state)
        parsed = _parse_response(raw)
        result.description = str(parsed.get("description", "")).strip()
        counts, ids = self._emit_entities(
            graph, parsed.get("entities") or {}, source_label,
        )
        for k, v in counts.items():
            result.entity_counts[k] = result.entity_counts.get(k, 0) + v
            result.entities_added += v

        # Narrative note — Hypothesis citing the extracted
        # entities. Empty descriptions skip the hypothesis to
        # avoid graph clutter.
        if result.description:
            hyp_id = graph.add_hypothesis(
                result.description,
                source=f"imported_from:vision",
                cites=ids,
                confidence=0.6,
                generated_by=f"vision/{self.backend.name}",
            )
            result.hypothesis_id = hyp_id

        _append_audit(state, result)
        return result

    def scan_file(
        self,
        path: Path | str,
        *,
        graph: Any,
        state: dict[str, Any],
        source_label: str | None = None,
    ) -> VisionResult | list[VisionResult]:
        """Dispatch by extension. PDFs return a LIST of
        results (one per page); images return a single
        result."""
        p = Path(path).expanduser().resolve()
        label = source_label or p.name
        if is_supported_image(p):
            return self.scan_image(
                p.read_bytes(),
                mime_type=guess_mime_type(p),
                source_label=label,
                graph=graph,
                state=state,
            )
        if is_supported_pdf(p):
            return self.scan_pdf(
                p, graph=graph, state=state,
                source_label=label,
            )
        # Unsupported extension → emit a no-op result so
        # callers can keep going.
        return VisionResult(
            source_label=label,
            backend_used=self.backend.name,
            cost_decision=CostGateDecision(
                allowed=False, budget=0, used=0,
                reason=f"unsupported file extension: {p.suffix!r}",
            ),
            skipped=True,
            error=f"unsupported file extension: {p.suffix!r}",
        )

    def scan_pdf(
        self,
        path: Path | str,
        *,
        graph: Any,
        state: dict[str, Any],
        source_label: str | None = None,
    ) -> list[VisionResult]:
        """One result per page. Pages with meaningful text
        get the text-only backend call (cheaper); pages
        without text are skipped in v1 with a warning
        (operator pre-renders for vision)."""
        p = Path(path).expanduser().resolve()
        label = source_label or p.name
        extraction = extract_pdf_pages(p)
        if not extraction.extractor_available:
            return [VisionResult(
                source_label=label,
                backend_used=self.backend.name,
                cost_decision=CostGateDecision(
                    allowed=False, budget=0, used=0,
                    reason=(
                        "pypdf not installed — PDF text "
                        "extraction unavailable. Install "
                        "pypdf or pre-export pages as images."
                    ),
                ),
                skipped=True,
                error="pypdf not installed",
            )]
        results: list[VisionResult] = []
        for page in extraction.pages:
            page_label = f"{label}#page={page.page_number}"
            if not page.has_meaningful_text:
                results.append(VisionResult(
                    source_label=page_label,
                    backend_used=self.backend.name,
                    cost_decision=CostGateDecision(
                        allowed=False, budget=0, used=0,
                        reason="image-only page (no extracted text)",
                    ),
                    skipped=True,
                    error="no extractable text on this page",
                ))
                continue
            results.append(
                self._scan_pdf_text_page(
                    page.text, source_label=page_label,
                    graph=graph, state=state,
                ),
            )
        return results

    # ── Internal helpers ─────────────────────────────────────

    def _scan_pdf_text_page(
        self,
        text: str,
        *,
        source_label: str,
        graph: Any,
        state: dict[str, Any],
    ) -> VisionResult:
        decision = self.cost_gate.consult(state)
        result = VisionResult(
            source_label=source_label,
            backend_used=self.backend.name,
            cost_decision=decision,
        )
        if not decision.allowed:
            result.skipped = True
            self.cost_gate.record_skip(
                state, source=source_label, decision=decision,
            )
            return result
        try:
            raw = self.backend.describe_text(
                text, prompt=_PDF_TEXT_SYSTEM_PROMPT,
            )
        except NotImplementedError:
            result.error = (
                "backend does not implement text-mode; "
                "PDF text path skipped"
            )
            result.skipped = True
            return result
        except Exception as exc:
            result.error = f"backend error: {exc}"
            return result
        self.cost_gate.record_call(state)
        parsed = _parse_response(raw)
        result.description = str(parsed.get("description", "")).strip()
        counts, ids = self._emit_entities(
            graph, parsed.get("entities") or {}, source_label,
        )
        for k, v in counts.items():
            result.entity_counts[k] = result.entity_counts.get(k, 0) + v
            result.entities_added += v
        if result.description:
            hyp_id = graph.add_hypothesis(
                result.description,
                source=f"imported_from:vision",
                cites=ids,
                confidence=0.6,
                generated_by=f"vision/{self.backend.name}",
            )
            result.hypothesis_id = hyp_id
        _append_audit(state, result)
        return result

    def _emit_qr_entities(
        self,
        graph: Any,
        qr_hits: list[Any],
        source_label: str,
    ) -> int:
        """Decoded QR strings → URL entities (when URL-shaped)
        or skipped (plain text). Returns count emitted."""
        added = 0
        for qr in qr_hits:
            data = qr.data if hasattr(qr, "data") else str(qr)
            if "://" in data:
                # URL-looking — emit URL entity.
                from nexusrecon.models.entities import URLEntity
                graph.add_entity(URLEntity(
                    value=data,
                    sources=[f"imported_from:vision:qr"],
                    confidence=0.85,
                ))
                added += 1
        return added

    def _emit_entities(
        self,
        graph: Any,
        entities: dict[str, Any],
        source_label: str,
    ) -> tuple[dict[str, int], list[str]]:
        """Map the LLM's structured output → graph entities.
        Returns (per-type counts, list of emitted entity_ids)
        so the caller can attach them to the narrative
        hypothesis."""
        counts: dict[str, int] = {}
        emitted_ids: list[str] = []
        source = "imported_from:vision"
        for url in _list(entities.get("urls")):
            from nexusrecon.models.entities import URLEntity
            eid = graph.add_entity(URLEntity(
                value=url, sources=[source], confidence=0.7,
            ))
            emitted_ids.append(eid)
            counts["url"] = counts.get("url", 0) + 1
        for email in _list(entities.get("emails")):
            if "@" not in email:
                continue
            eid = graph.add_email(email, source=source, confidence=0.7)
            emitted_ids.append(eid)
            counts["email"] = counts.get("email", 0) + 1
        for domain in _list(entities.get("domains")):
            if "." not in domain:
                continue
            if domain.count(".") >= 2:
                eid = graph.add_subdomain(
                    domain,
                    parent=".".join(domain.split(".")[-2:]),
                    source=source, confidence=0.7,
                )
                counts["subdomain"] = counts.get("subdomain", 0) + 1
            else:
                eid = graph.add_domain(
                    domain, source=source, confidence=0.7,
                )
                counts["domain"] = counts.get("domain", 0) + 1
            emitted_ids.append(eid)
        for person in _list(entities.get("persons")):
            from nexusrecon.models.entities import PersonEntity
            eid = graph.add_entity(PersonEntity(
                value=person, sources=[source], confidence=0.6,
            ))
            emitted_ids.append(eid)
            counts["person"] = counts.get("person", 0) + 1
        for org in _list(entities.get("organizations")):
            from nexusrecon.models.entities import OrganizationEntity
            eid = graph.add_entity(OrganizationEntity(
                value=org, sources=[source], confidence=0.6,
            ))
            emitted_ids.append(eid)
            counts["organization"] = counts.get("organization", 0) + 1
        for brand in _list(entities.get("brands")):
            # Brands land as Organization entities tagged with
            # a "brand" label — operators routinely treat
            # brand vs. legal-entity-name as distinct.
            from nexusrecon.models.entities import OrganizationEntity
            eid = graph.add_entity(OrganizationEntity(
                value=brand,
                sources=[source],
                tags=["brand"],
                confidence=0.55,
            ))
            emitted_ids.append(eid)
            counts["brand"] = counts.get("brand", 0) + 1
        for tech in _list(entities.get("technologies")):
            eid = graph.add_technology(
                tech, source=source, confidence=0.6,
            )
            emitted_ids.append(eid)
            counts["technology"] = counts.get("technology", 0) + 1
        return counts, emitted_ids


# ──────────────────────────────────────────────────────────────────────
# Parsing + helpers
# ──────────────────────────────────────────────────────────────────────


def _parse_response(raw: str) -> dict[str, Any]:
    """Extract the JSON object from the model's response.
    Returns ``{}`` on any failure — the extractor falls
    back to entity-less behavior."""
    if not raw:
        return {}
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _list(value: Any) -> list[str]:
    """Coerce to a list of trimmed non-empty strings."""
    if isinstance(value, list):
        return [str(v).strip() for v in value if v and str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _append_audit(state: dict[str, Any], result: VisionResult) -> None:
    """Append the scan to ``state["vision_audit_log"]``."""
    audit_log = list(state.get("vision_audit_log") or [])
    audit_log.append({
        "timestamp": datetime.now(UTC).isoformat(),
        **result.to_dict(),
    })
    state["vision_audit_log"] = audit_log
