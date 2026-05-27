"""Tests for Phase 5 PR D: multi-modal vision pipeline.

PR D ships ``nexusrecon/vision/`` — a backend protocol +
default langchain-driven implementation, image / PDF / QR
preprocessing helpers, a cost gate keyed to the Phase 1
Strategy's ``tool_budgets["vision_calls"]``, and the
:class:`VisionExtractor` that orchestrates the whole pipeline.

Coverage
- Backend protocol: a fake substituting cleanly for
  :class:`LangChainVisionBackend`.
- Cost gate: blocks when budget=0, blocks when exhausted,
  passes within budget; per-decision skip records land in
  ``state["vision_skip_log"]``; successful calls increment
  ``state["vision_call_count"]``.
- Preprocess helpers: image/PDF extension detection;
  ``extract_pdf_pages`` graceful-skip when pypdf missing;
  ``decode_qr_codes`` graceful-skip when pyzbar missing.
- VisionExtractor: scans an image with a fake backend
  returning structured JSON → entities + Hypothesis +
  audit log entry. Skips backend call when budget=0 but
  still attempts QR decoding. Surfaces backend errors
  cleanly. Routes by extension via ``scan_file``.
- Bad JSON from the backend produces an empty extraction
  with no crash.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.vision import (
    CostGate,
    CostGateDecision,
    NoopVisionBackend,
    VisionBackend,
    VisionExtractor,
    decode_qr_codes,
    extract_pdf_pages,
    is_supported_image,
    is_supported_pdf,
)
from nexusrecon.vision.extractor import _list, _parse_response


# ──────────────────────────────────────────────────────────────────────
# Fixtures + test doubles
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def graph() -> EntityGraph:
    return EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")


def _state_with_budget(n: int) -> dict[str, Any]:
    return {
        "strategy": {"tool_budgets": {"vision_calls": n}},
    }


@dataclass
class _FakeBackend:
    """Scripted backend. Returns whatever string the test
    configured. Records every call for assertion."""

    image_response: str = '{"description": "noop", "entities": {}}'
    text_response: str = '{"description": "noop", "entities": {}}'
    raise_on_image: Exception | None = None
    raise_on_text: Exception | None = None
    name: str = "fake"
    image_calls: list[dict[str, Any]] = field(default_factory=list)
    text_calls: list[dict[str, Any]] = field(default_factory=list)

    def describe_image(
        self, image_bytes, *, mime_type, prompt, max_tokens=1024,
    ):
        self.image_calls.append({
            "size": len(image_bytes),
            "mime_type": mime_type,
            "prompt_excerpt": prompt[:80],
        })
        if self.raise_on_image:
            raise self.raise_on_image
        return self.image_response

    def describe_text(
        self, text, *, prompt, max_tokens=1024,
    ):
        self.text_calls.append({
            "len": len(text),
            "prompt_excerpt": prompt[:80],
        })
        if self.raise_on_text:
            raise self.raise_on_text
        return self.text_response


# ──────────────────────────────────────────────────────────────────────
# Backend protocol
# ──────────────────────────────────────────────────────────────────────


class TestBackendProtocol:
    def test_fake_satisfies_protocol(self):
        # `runtime_checkable` Protocol → isinstance works.
        fake = _FakeBackend()
        assert isinstance(fake, VisionBackend)

    def test_noop_returns_empty_extraction(self):
        backend = NoopVisionBackend()
        assert "entities" in backend.describe_image(
            b"x", mime_type="image/png", prompt="p",
        )


# ──────────────────────────────────────────────────────────────────────
# Cost gate
# ──────────────────────────────────────────────────────────────────────


class TestCostGate:
    def test_no_strategy_means_zero_budget(self):
        gate = CostGate()
        decision = gate.consult({})
        assert decision.allowed is False
        assert decision.budget == 0

    def test_zero_budget_blocks(self):
        gate = CostGate()
        state = _state_with_budget(0)
        assert gate.consult(state).allowed is False

    def test_budget_exhausted_blocks(self):
        gate = CostGate()
        state = _state_with_budget(2)
        state["vision_call_count"] = 2
        assert gate.consult(state).allowed is False

    def test_within_budget_allows(self):
        gate = CostGate()
        state = _state_with_budget(5)
        decision = gate.consult(state)
        assert decision.allowed is True
        assert decision.budget == 5
        assert decision.used == 0

    def test_record_call_increments(self):
        gate = CostGate()
        state = _state_with_budget(5)
        gate.record_call(state)
        gate.record_call(state)
        assert state["vision_call_count"] == 2

    def test_record_skip_appends_log(self):
        gate = CostGate()
        state = _state_with_budget(0)
        decision = gate.consult(state)
        gate.record_skip(state, source="img.png", decision=decision)
        log = state.get("vision_skip_log", [])
        assert len(log) == 1
        assert log[0]["source"] == "img.png"


# ──────────────────────────────────────────────────────────────────────
# Preprocess helpers
# ──────────────────────────────────────────────────────────────────────


class TestPreprocess:
    def test_is_supported_image(self):
        assert is_supported_image("a.png")
        assert is_supported_image(Path("a.jpg"))
        assert is_supported_image("a.WEBP")  # case insensitive
        assert not is_supported_image("a.txt")

    def test_is_supported_pdf(self):
        assert is_supported_pdf("doc.pdf")
        assert not is_supported_pdf("doc.png")

    def test_extract_pdf_pages_missing_file(self, tmp_path: Path):
        result = extract_pdf_pages(tmp_path / "nope.pdf")
        # Either no pages OR extractor unavailable — both
        # are acceptable graceful outcomes.
        assert result.pages == []

    def test_decode_qr_codes_handles_missing_pyzbar(self):
        # Even when pyzbar isn't installed, the function
        # returns [] rather than raising.
        out = decode_qr_codes(b"not really an image")
        assert isinstance(out, list)


# ──────────────────────────────────────────────────────────────────────
# Parsing helpers
# ──────────────────────────────────────────────────────────────────────


class TestParseHelpers:
    def test_parse_response_extracts_json(self):
        text = (
            "Some preamble.\n"
            '{"description": "a", "entities": {"urls": ["https://x"]}}\n'
            "trailing"
        )
        parsed = _parse_response(text)
        assert parsed["description"] == "a"
        assert parsed["entities"]["urls"] == ["https://x"]

    def test_parse_response_handles_bad_json(self):
        assert _parse_response("not JSON") == {}

    def test_parse_response_handles_empty(self):
        assert _parse_response("") == {}

    def test_list_helper(self):
        assert _list(["a", "", " b "]) == ["a", "b"]
        assert _list("single") == ["single"]
        assert _list(None) == []
        assert _list([]) == []


# ──────────────────────────────────────────────────────────────────────
# Extractor — image path
# ──────────────────────────────────────────────────────────────────────


class TestVisionExtractorImage:
    def test_skips_when_budget_zero(self, graph: EntityGraph):
        backend = _FakeBackend()
        extractor = VisionExtractor(backend=backend)
        state: dict[str, Any] = {}  # no strategy → budget=0
        result = extractor.scan_image(
            b"image-bytes",
            mime_type="image/png",
            source_label="screen.png",
            graph=graph, state=state,
        )
        assert result.skipped is True
        assert backend.image_calls == []
        # Skip recorded.
        assert state.get("vision_skip_log")

    def test_full_extraction_with_budget(self, graph: EntityGraph):
        backend = _FakeBackend(image_response=json.dumps({
            "description": "A login page for acme.com",
            "entities": {
                "urls": ["https://acme.com/login"],
                "emails": ["admin@acme.com"],
                "persons": ["Jane Smith"],
                "organizations": ["Acme Corp"],
                "brands": ["Acme"],
                "technologies": ["nginx"],
                "domains": ["api.acme.com"],
            },
        }))
        extractor = VisionExtractor(backend=backend)
        state = _state_with_budget(5)
        result = extractor.scan_image(
            b"image-bytes", mime_type="image/png",
            source_label="login.png",
            graph=graph, state=state,
        )
        assert result.skipped is False
        assert result.description.startswith("A login page")
        # Hypothesis was added + cites the extracted entities.
        assert result.hypothesis_id
        # Counter incremented.
        assert state["vision_call_count"] == 1
        # Audit log has one entry.
        assert len(state["vision_audit_log"]) == 1
        # Per-type counts.
        assert result.entity_counts.get("url", 0) == 1
        assert result.entity_counts.get("email", 0) == 1
        assert result.entity_counts.get("person", 0) == 1
        assert result.entity_counts.get("organization", 0) >= 1
        # api.acme.com → subdomain bucket.
        assert result.entity_counts.get("subdomain", 0) == 1
        assert result.entity_counts.get("technology", 0) == 1

    def test_bad_json_response_no_crash(self, graph: EntityGraph):
        backend = _FakeBackend(image_response="garbage not JSON")
        extractor = VisionExtractor(backend=backend)
        state = _state_with_budget(5)
        result = extractor.scan_image(
            b"x", mime_type="image/png",
            source_label="img.png",
            graph=graph, state=state,
        )
        # Call still counted (budget consumed).
        assert state["vision_call_count"] == 1
        # No entities emitted; no Hypothesis.
        assert result.entities_added == 0
        assert result.hypothesis_id == ""

    def test_backend_exception_surfaces_in_result(
        self, graph: EntityGraph,
    ):
        backend = _FakeBackend(
            raise_on_image=RuntimeError("transient API hiccup"),
        )
        extractor = VisionExtractor(backend=backend)
        state = _state_with_budget(5)
        result = extractor.scan_image(
            b"x", mime_type="image/png",
            source_label="img.png",
            graph=graph, state=state,
        )
        assert "transient API hiccup" in result.error
        # Budget NOT consumed on a failed call.
        assert state.get("vision_call_count", 0) == 0

    def test_skip_records_qr_decodes_only(
        self, graph: EntityGraph,
    ):
        """Even with budget=0, the QR decode pass should run
        — it costs nothing."""
        backend = _FakeBackend()
        extractor = VisionExtractor(backend=backend)
        # No pyzbar likely present in CI → decode returns []
        # but the QR decode path still ran without raising.
        state: dict[str, Any] = {}
        result = extractor.scan_image(
            b"image-bytes",
            mime_type="image/png",
            source_label="qr.png",
            graph=graph, state=state,
        )
        assert result.skipped is True
        assert isinstance(result.qr_decodes, list)


# ──────────────────────────────────────────────────────────────────────
# Extractor — scan_file dispatch
# ──────────────────────────────────────────────────────────────────────


class TestScanFileDispatch:
    def test_image_path_routes_to_scan_image(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        backend = _FakeBackend(image_response=json.dumps({
            "description": "x", "entities": {},
        }))
        extractor = VisionExtractor(backend=backend)
        state = _state_with_budget(2)
        img = tmp_path / "shot.png"
        img.write_bytes(b"fake png bytes")
        result = extractor.scan_file(
            img, graph=graph, state=state,
        )
        # Single image → single result, not a list.
        assert not isinstance(result, list)
        assert backend.image_calls

    def test_unsupported_extension_returns_skipped(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        extractor = VisionExtractor(backend=_FakeBackend())
        state = _state_with_budget(5)
        weird = tmp_path / "x.exe"
        weird.write_bytes(b"x")
        result = extractor.scan_file(
            weird, graph=graph, state=state,
        )
        assert result.skipped is True
        assert "unsupported" in result.error

    def test_pdf_routes_to_scan_pdf(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        extractor = VisionExtractor(backend=_FakeBackend())
        state = _state_with_budget(5)
        # Fake PDF file — pypdf will either fail to parse or
        # not be installed. Either way scan_pdf returns a
        # LIST of results.
        pdf = tmp_path / "doc.pdf"
        pdf.write_bytes(b"%PDF-1.4 fake")
        result = extractor.scan_file(pdf, graph=graph, state=state)
        assert isinstance(result, list)
