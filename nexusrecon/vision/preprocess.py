"""Image + PDF + QR preprocessing.

Three small helpers feed the extractor:

  - :func:`is_supported_image` — extension/MIME detection.
  - :func:`extract_pdf_pages` — optional pypdf dependency.
    Returns page-by-page text + a render hint (when text
    extraction yields ~nothing the caller falls back to a
    vision call on the page's image, if a renderer is
    available).
  - :func:`decode_qr_codes` — optional pyzbar dependency.
    Returns the decoded strings (URLs, plain text) found
    in the image. No LLM cost.

Optional deps
- ``pypdf`` is widely installed (transitive of many tools)
  but not required. When missing, ``extract_pdf_pages``
  returns an empty list + logs a debug warning.
- ``pyzbar`` requires the native ``zbar`` library to be
  installed; same graceful-degrade behavior when absent.
- The extractor checks both and adjusts its flow
  accordingly. Operators on stripped-down systems still get
  the screenshot path.
"""
from __future__ import annotations

import mimetypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


_IMAGE_EXTS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp",
})
_PDF_EXTS: frozenset[str] = frozenset({".pdf"})


# ──────────────────────────────────────────────────────────────────────
# Type detection
# ──────────────────────────────────────────────────────────────────────


def is_supported_image(path: Path | str) -> bool:
    """True when the file extension is one of the supported
    image formats."""
    return Path(path).suffix.lower() in _IMAGE_EXTS


def is_supported_pdf(path: Path | str) -> bool:
    return Path(path).suffix.lower() in _PDF_EXTS


def guess_mime_type(path: Path | str) -> str:
    """Returns a MIME type suitable for the vision backend's
    ``data:`` URL. Falls back to ``application/octet-stream``
    only if mimetypes can't guess — at which point the caller
    probably shouldn't be calling us anyway."""
    mt, _ = mimetypes.guess_type(str(path))
    if mt:
        return mt
    ext = Path(path).suffix.lower()
    return {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".gif": "image/gif",
        ".webp": "image/webp", ".bmp": "image/bmp",
    }.get(ext, "application/octet-stream")


# ──────────────────────────────────────────────────────────────────────
# PDF
# ──────────────────────────────────────────────────────────────────────


@dataclass
class PDFPageText:
    """One extracted page."""

    page_number: int  # 1-based
    text: str
    """Raw page text. Empty / whitespace-only when the page
    is image-only (scanned)."""

    @property
    def has_meaningful_text(self) -> bool:
        return len(self.text.strip()) >= 40


@dataclass
class PDFExtractionResult:
    pages: list[PDFPageText] = field(default_factory=list)
    extractor_available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "page_count": len(self.pages),
            "extractor_available": self.extractor_available,
            "pages_with_text": sum(
                1 for p in self.pages if p.has_meaningful_text
            ),
        }


def extract_pdf_pages(path: Path | str) -> PDFExtractionResult:
    """Read PDF pages with pypdf. Returns an empty list + a
    debug log message when pypdf isn't installed.

    The caller decides what to do with image-only pages:
    skip them, or queue them for vision-mode rasterization
    (the latter is out of scope for v1 — operators
    pre-export the page images for now)."""
    p = Path(path).expanduser()
    if not p.exists():
        return PDFExtractionResult(extractor_available=True)
    try:
        from pypdf import PdfReader  # noqa: F401
    except ImportError:
        log.debug("pypdf not installed — PDF text extraction skipped")
        return PDFExtractionResult(extractor_available=False)
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(p))
    except Exception as exc:
        log.warning("PDF read failed", path=str(p), error=str(exc))
        return PDFExtractionResult(extractor_available=True)

    result = PDFExtractionResult()
    for i, page in enumerate(reader.pages, 1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:
            log.debug(
                "Per-page PDF extract failed",
                page=i, error=str(exc),
            )
            text = ""
        result.pages.append(PDFPageText(page_number=i, text=text))
    return result


# ──────────────────────────────────────────────────────────────────────
# QR / barcode
# ──────────────────────────────────────────────────────────────────────


@dataclass
class QRDecode:
    """One decoded QR / barcode."""
    data: str
    kind: str  # "QRCODE" | "EAN13" | ...

    def to_dict(self) -> dict[str, Any]:
        return {"data": self.data, "kind": self.kind}


def decode_qr_codes(image_bytes: bytes) -> list[QRDecode]:
    """Decode every QR / barcode in ``image_bytes`` via
    pyzbar. Returns an empty list when pyzbar (or its
    underlying ``zbar`` native library) isn't installed."""
    try:
        from io import BytesIO
        from PIL import Image  # noqa: F401
        from pyzbar.pyzbar import decode  # type: ignore[import-not-found]
    except ImportError:
        log.debug("pyzbar / Pillow not installed — QR decoding skipped")
        return []
    try:
        from io import BytesIO
        from PIL import Image
        from pyzbar.pyzbar import decode  # type: ignore[import-not-found]
        img = Image.open(BytesIO(image_bytes))
        out: list[QRDecode] = []
        for hit in decode(img):
            try:
                data = hit.data.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                continue
            kind = getattr(hit, "type", "").upper() or "UNKNOWN"
            out.append(QRDecode(data=data, kind=kind))
        return out
    except Exception as exc:
        log.warning("QR decode raised", error=str(exc))
        return []
