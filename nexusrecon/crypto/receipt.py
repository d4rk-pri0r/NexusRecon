"""Receipt envelope — pairs a bundle hash with a signature.

The on-disk shape::

    {
      "version": "1.0",
      "signed_at": "2026-05-27T12:00:00.000Z",
      "signer": {
        "key_id": "corp-red-team-2026",
        "fingerprint": "sha256:abc..."
      },
      "bundle": {
        "filename": "stix2-bundle.json",
        "hash_algorithm": "sha256",
        "hash": "sha256:def..."
      },
      "signature_algorithm": "ed25519",
      "signature": "base64url-encoded-signature"
    }

Versioning
- ``version`` is the receipt schema. v1.0 ships in PR B.
  Future schema changes bump the major so older verifiers
  fail closed rather than silently miss fields.

Stability promise
- The verifier — both ``nexusrecon verify`` and the
  standalone script — depends ONLY on the field names
  above. Future PRs can add fields without breaking old
  receipts as long as the verifier ignores unknowns.

Bundle hashing
- We hash the bundle's BYTES on disk, not a canonical
  re-serialisation. The signature attests to the EXACT
  file contents — re-emitting the same logical bundle with
  different JSON whitespace would fail to verify, and that
  is the correct behavior (the signed artifact is the
  delivered file).
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


RECEIPT_VERSION: str = "1.0"


@dataclass
class Receipt:
    """Receipt envelope produced by :func:`sign_bundle` and
    consumed by :func:`verify_bundle`."""

    signer_key_id: str
    signer_fingerprint: str
    bundle_filename: str
    bundle_hash: str
    signature: str
    """Base64url-encoded signature bytes (no padding)."""
    signed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    version: str = RECEIPT_VERSION
    bundle_hash_algorithm: str = "sha256"
    signature_algorithm: str = "ed25519"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "signed_at": self.signed_at,
            "signer": {
                "key_id": self.signer_key_id,
                "fingerprint": self.signer_fingerprint,
            },
            "bundle": {
                "filename": self.bundle_filename,
                "hash_algorithm": self.bundle_hash_algorithm,
                "hash": self.bundle_hash,
            },
            "signature_algorithm": self.signature_algorithm,
            "signature": self.signature,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def signature_bytes(self) -> bytes:
        """Decode the base64url-encoded signature back to
        raw bytes for verification."""
        # ``+= "=" * 4`` pads back to a length the base64
        # library accepts.
        padded = self.signature + "=" * (-len(self.signature) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Receipt:
        version = str(raw.get("version", ""))
        if not version:
            raise ValueError("receipt missing 'version'")
        if not version.startswith("1."):
            raise ValueError(
                f"receipt schema {version!r} not supported "
                f"by this verifier (expected 1.x)"
            )
        signer = raw.get("signer") or {}
        bundle = raw.get("bundle") or {}
        return cls(
            version=version,
            signed_at=str(raw.get("signed_at", "")),
            signer_key_id=str(signer.get("key_id", "")),
            signer_fingerprint=str(signer.get("fingerprint", "")),
            bundle_filename=str(bundle.get("filename", "")),
            bundle_hash=str(bundle.get("hash", "")),
            bundle_hash_algorithm=str(
                bundle.get("hash_algorithm", "sha256"),
            ),
            signature_algorithm=str(
                raw.get("signature_algorithm", "ed25519"),
            ),
            signature=str(raw.get("signature", "")),
        )

    @classmethod
    def from_json_file(cls, path: Path | str) -> Receipt:
        p = Path(path).expanduser()
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))


def compute_bundle_hash(path: Path | str) -> str:
    """SHA-256 over the bundle file's bytes. Prefixed
    ``sha256:`` to match the receipt format."""
    p = Path(path).expanduser()
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"
