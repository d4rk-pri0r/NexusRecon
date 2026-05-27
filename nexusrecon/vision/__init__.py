"""Multi-modal reasoning — Phase 5 PR D.

Lets a campaign absorb visual artifacts (screenshots, leaked
documents, slide decks, brand logos, QR codes) into the
Living Graph. The pipeline is opt-in per-campaign via the
Phase 1 Strategy's ``tool_budgets["vision_calls"]`` — no
vision calls fire without an explicit budget.

Artifact support (locked-in: "all of the above")
- PNG / JPG / GIF / WEBP screenshots — main path, vision
  LLM extracts structured entities + a narrative note.
- PDF documents — pypdf-based text extraction (optional
  dep, graceful skip if missing). Per-page text feeds a
  text-mode LLM call rather than a vision call (cheaper);
  scanned PDFs whose text extraction yields ~nothing fall
  back to vision when the operator's budget permits.
- Logos / brand marks — same path as screenshots; the
  vision prompt is shaped to surface brand-recognition
  guesses.
- QR codes / barcodes — decoded via pyzbar (optional dep,
  graceful skip). No LLM cost; URLs / text get added as
  URL / hypothesis entities directly.

Backend choice (locked-in: "multi-provider")
- :class:`VisionBackend` Protocol — minimal contract any
  vision-capable LLM can satisfy.
- :class:`LangChainVisionBackend` — default implementation
  that takes a configured langchain chat model
  (ChatAnthropic / ChatOpenAI) and invokes it with
  multi-modal content. Picks up whichever provider the
  operator's config selected.
- Pluggable: community packs can ship a custom backend
  (e.g. Ollama with a local vision model) and operators
  wire it via ``state["vision_backend"]``.

Graph integration (locked-in: "structured + narrative")
- The vision prompt asks for STRICT JSON containing
  URLs, emails, person names, organization names, brand
  / product names, technologies. Each entity flows through
  the standard graph builders with an
  ``imported_from:vision`` source tag.
- A free-form narrative description ALSO lands as a
  HypothesisEntity citing the extracted entities — keeps
  the audit trail human-readable.

Cost control (locked-in: "strategy-driven")
- :class:`CostGate` consults
  ``state["strategy"]["tool_budgets"]["vision_calls"]`` and
  ``state["vision_call_count"]``. Skips with a warning
  when the budget is exhausted or never set.
- Default budget is 0 — operators MUST set it in their
  Strategy. The intent planner (Phase 4 PR A) populates
  it automatically when the operator's NL goal mentions
  screenshots / visual analysis.
"""
from nexusrecon.vision.backend import (
    LangChainVisionBackend,
    NoopVisionBackend,
    VisionBackend,
)
from nexusrecon.vision.cost import (
    CostGate,
    CostGateDecision,
)
from nexusrecon.vision.extractor import (
    VisionExtractor,
    VisionResult,
)
from nexusrecon.vision.preprocess import (
    decode_qr_codes,
    extract_pdf_pages,
    is_supported_image,
    is_supported_pdf,
)

__all__ = [
    "CostGate",
    "CostGateDecision",
    "LangChainVisionBackend",
    "NoopVisionBackend",
    "VisionBackend",
    "VisionExtractor",
    "VisionResult",
    "decode_qr_codes",
    "extract_pdf_pages",
    "is_supported_image",
    "is_supported_pdf",
]
