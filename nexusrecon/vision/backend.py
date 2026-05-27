"""Vision backend protocol + default langchain-driven impl.

The backend is the seam between the extractor and whichever
vision-capable LLM the operator configured. Anything that
implements :class:`VisionBackend` works — bundled
:class:`LangChainVisionBackend` covers Anthropic + OpenAI
(via langchain), and community packs can ship custom
backends (Ollama-local-vision, Replicate, etc.) that get
wired through the ``state["vision_backend"]`` slot.

Contract
- :meth:`describe_image(image_bytes, mime_type, prompt)`
  → raw text response from the model. The extractor is
  responsible for prompt construction + JSON parsing.
- :meth:`describe_text(text, prompt)` → text-mode call
  for the PDF text-extraction path (vision unnecessary when
  the PDF already has searchable text).
- :meth:`name` — operator-readable identifier surfaced in
  audit log entries.

Why two methods instead of one
- The PDF flow extracts text directly when present (much
  cheaper than vision). A backend that wraps a vision-only
  model can either route the text call to its text mode or
  raise NotImplementedError, in which case the extractor
  skips the text path and goes straight to vision.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import structlog

log = structlog.get_logger(__name__)


@runtime_checkable
class VisionBackend(Protocol):
    """Minimal contract."""

    name: str

    def describe_image(
        self,
        image_bytes: bytes,
        *,
        mime_type: str,
        prompt: str,
        max_tokens: int = 1024,
    ) -> str:
        """Return raw model output. Extractor parses."""
        ...

    def describe_text(
        self,
        text: str,
        *,
        prompt: str,
        max_tokens: int = 1024,
    ) -> str:
        """Text-only completion. Backends that only support
        vision can raise :class:`NotImplementedError`."""
        ...


# ──────────────────────────────────────────────────────────────────────
# LangChain-driven default
# ──────────────────────────────────────────────────────────────────────


@dataclass
class LangChainVisionBackend:
    """Default backend. Takes a configured langchain chat
    model + invokes it with multi-modal content. Works for
    any provider whose langchain integration supports the
    standard ``image_url`` content type.

    The ``llm`` argument is the same object returned by
    :func:`nexusrecon.graph.agent_executor.get_llm_from_config`
    — so the operator's existing LLM configuration drives the
    vision path automatically.
    """

    llm: Any
    name: str = "langchain"

    def describe_image(
        self,
        image_bytes: bytes,
        *,
        mime_type: str,
        prompt: str,
        max_tokens: int = 1024,
    ) -> str:
        b64 = base64.b64encode(image_bytes).decode("ascii")
        data_url = f"data:{mime_type};base64,{b64}"
        try:
            from langchain_core.messages import HumanMessage
        except ImportError as exc:
            raise RuntimeError(
                "langchain_core is required for the default "
                "vision backend"
            ) from exc
        message = HumanMessage(content=[
            {"type": "text", "text": prompt},
            {
                "type": "image_url",
                "image_url": {"url": data_url},
            },
        ])
        response = self.llm.invoke([message])
        return _extract_response_text(response)

    def describe_text(
        self,
        text: str,
        *,
        prompt: str,
        max_tokens: int = 1024,
    ) -> str:
        try:
            from langchain_core.messages import HumanMessage
        except ImportError as exc:
            raise RuntimeError(
                "langchain_core is required for the default "
                "vision backend"
            ) from exc
        message = HumanMessage(content=prompt + "\n\n---\n\n" + text)
        response = self.llm.invoke([message])
        return _extract_response_text(response)


def _extract_response_text(response: Any) -> str:
    """LangChain message responses come back as objects with
    .content or as plain strings depending on the model.
    Normalise so the extractor sees one shape."""
    if response is None:
        return ""
    if hasattr(response, "content"):
        content = response.content
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            # Multi-part content (some models). Join text
            # parts.
            parts: list[str] = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parts.append(str(part.get("text", "")))
                elif isinstance(part, str):
                    parts.append(part)
            return "\n".join(parts)
    return str(response)


# ──────────────────────────────────────────────────────────────────────
# No-op backend for tests + dry-runs
# ──────────────────────────────────────────────────────────────────────


@dataclass
class NoopVisionBackend:
    """No-op backend. Returns an empty JSON-shaped string so
    the extractor's parser produces an empty extraction
    record. Useful for ``--dry-run`` and for the test path
    where we don't want to call any LLM."""

    name: str = "noop"

    def describe_image(
        self,
        image_bytes: bytes,
        *,
        mime_type: str,
        prompt: str,
        max_tokens: int = 1024,
    ) -> str:
        return '{"description": "noop backend", "entities": {}}'

    def describe_text(
        self,
        text: str,
        *,
        prompt: str,
        max_tokens: int = 1024,
    ) -> str:
        return '{"description": "noop backend", "entities": {}}'
