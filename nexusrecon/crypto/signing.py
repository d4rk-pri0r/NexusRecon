"""Bundle signing + verification.

Public surface
- :func:`sign_bundle(bundle_path, keypair, output_receipt_path=None)`
  → writes a ``<bundle>.receipt.json`` next to the bundle
  and returns the :class:`Receipt`.
- :func:`verify_bundle(bundle_path, receipt_path, public_key_path)`
  → re-hashes the bundle, loads the receipt + public key,
  validates the signature. Raises :class:`VerificationError`
  with a useful message on any mismatch.

Why hash + sign and not sign-the-file-directly
- Ed25519 over arbitrary data is fine, but small fixed-size
  inputs (a 32-byte SHA-256 digest prefixed with the
  algorithm tag) keep the signature operation
  constant-time across bundle sizes + simplify the
  standalone verifier's data plumbing.
- Verifier needs to read the bundle, hash it, compare —
  same work either way.

What the signature actually covers
- The signed message is the bytes of
  ``"<algorithm>|<bundle_hash>"`` (UTF-8).
- Including the algorithm tag in the signed payload
  prevents algorithm-substitution attacks (a future
  verifier accepting both ed25519 and a weaker algorithm
  couldn't be tricked by re-labelling).
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from nexusrecon.crypto.keys import KeyPair, load_public_key
from nexusrecon.crypto.receipt import Receipt, compute_bundle_hash

log = structlog.get_logger(__name__)


class SigningError(RuntimeError):
    """Raised when ``sign_bundle`` can't complete."""


class VerificationError(RuntimeError):
    """Raised when ``verify_bundle`` rejects.

    The message describes which specific check failed
    (hash mismatch, signature mismatch, fingerprint
    mismatch). Verifiers report this verbatim."""


# ──────────────────────────────────────────────────────────────────────
# Signing
# ──────────────────────────────────────────────────────────────────────


def _signed_message(bundle_hash: str, algorithm: str = "ed25519") -> bytes:
    """Construct the canonical message the signature
    covers. Tagging with the algorithm name short-circuits
    algorithm-substitution attacks in future multi-algorithm
    verifiers."""
    return f"{algorithm}|{bundle_hash}".encode("utf-8")


def sign_bundle(
    bundle_path: Path | str,
    keypair: KeyPair,
    *,
    output_receipt_path: Path | str | None = None,
) -> Receipt:
    """Sign a STIX bundle (or any file) with an Ed25519
    keypair. Writes a sidecar ``<bundle>.receipt.json`` next
    to the bundle unless ``output_receipt_path`` overrides.
    Returns the :class:`Receipt` so the CLI can print it."""
    if not keypair.can_sign:
        raise SigningError(
            "keypair has no private key — cannot sign "
            "(was it loaded with ``load_public_key``?)"
        )

    bundle = Path(bundle_path).expanduser().resolve()
    if not bundle.exists():
        raise SigningError(f"bundle not found: {bundle}")

    bundle_hash = compute_bundle_hash(bundle)
    message = _signed_message(bundle_hash)
    raw_signature = keypair.private_key.sign(message)  # type: ignore[union-attr]
    signature_b64 = base64.urlsafe_b64encode(
        raw_signature,
    ).decode("ascii").rstrip("=")

    receipt = Receipt(
        signer_key_id=keypair.metadata.key_id,
        signer_fingerprint=keypair.metadata.fingerprint,
        bundle_filename=bundle.name,
        bundle_hash=bundle_hash,
        signature=signature_b64,
        signed_at=datetime.now(UTC).isoformat(),
    )

    if output_receipt_path is None:
        out = bundle.with_name(bundle.name + ".receipt.json")
    else:
        out = Path(output_receipt_path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(receipt.to_json(), encoding="utf-8")

    log.info(
        "Bundle signed",
        bundle=str(bundle), key_id=keypair.metadata.key_id,
    )
    return receipt


# ──────────────────────────────────────────────────────────────────────
# Verification
# ──────────────────────────────────────────────────────────────────────


def verify_bundle(
    bundle_path: Path | str,
    receipt_path: Path | str,
    public_key_path: Path | str,
    *,
    expected_key_id: str | None = None,
    expected_fingerprint: str | None = None,
) -> Receipt:
    """Verify a signed bundle against its receipt + a public
    key. Returns the loaded :class:`Receipt` on success;
    raises :class:`VerificationError` with a descriptive
    message on any failure.

    Optional ``expected_key_id`` / ``expected_fingerprint``
    pin the verifier to a specific signer — useful when an
    auditor knows which key SHOULD have signed and wants
    a substitution attempt to fail loudly."""
    bundle = Path(bundle_path).expanduser().resolve()
    if not bundle.exists():
        raise VerificationError(f"bundle not found: {bundle}")
    receipt = Receipt.from_json_file(receipt_path)
    public_key, computed_fingerprint = load_public_key(public_key_path)
    return _verify_with_public_key(
        bundle, receipt, public_key, computed_fingerprint,
        expected_key_id=expected_key_id,
        expected_fingerprint=expected_fingerprint,
    )


def _verify_with_public_key(
    bundle_path: Path,
    receipt: Receipt,
    public_key: Ed25519PublicKey,
    computed_fingerprint: str,
    *,
    expected_key_id: str | None = None,
    expected_fingerprint: str | None = None,
) -> Receipt:
    """Internal: factored so the standalone verifier can
    use the same path without re-implementing the checks."""
    # Algorithm check — receipts the verifier doesn't
    # understand fail closed.
    if receipt.signature_algorithm != "ed25519":
        raise VerificationError(
            f"unsupported signature algorithm "
            f"{receipt.signature_algorithm!r}"
        )
    if receipt.bundle_hash_algorithm != "sha256":
        raise VerificationError(
            f"unsupported bundle hash algorithm "
            f"{receipt.bundle_hash_algorithm!r}"
        )

    # Fingerprint check — the public key the operator
    # provided must match what the receipt claims signed it.
    if receipt.signer_fingerprint != computed_fingerprint:
        raise VerificationError(
            f"public key fingerprint mismatch: receipt "
            f"claims {receipt.signer_fingerprint!r}, public "
            f"key computes to {computed_fingerprint!r}"
        )

    # Optional pinned-identity checks.
    if expected_key_id and receipt.signer_key_id != expected_key_id:
        raise VerificationError(
            f"key_id mismatch: receipt is from "
            f"{receipt.signer_key_id!r}, expected "
            f"{expected_key_id!r}"
        )
    if (
        expected_fingerprint
        and computed_fingerprint != expected_fingerprint
    ):
        raise VerificationError(
            f"public key fingerprint mismatch: "
            f"{computed_fingerprint!r} vs expected "
            f"{expected_fingerprint!r}"
        )

    # Bundle hash check.
    actual_hash = compute_bundle_hash(bundle_path)
    if actual_hash != receipt.bundle_hash:
        raise VerificationError(
            f"bundle hash mismatch: file hashes to "
            f"{actual_hash!r}, receipt claims "
            f"{receipt.bundle_hash!r}"
        )

    # Signature check.
    message = _signed_message(receipt.bundle_hash)
    try:
        public_key.verify(receipt.signature_bytes(), message)
    except InvalidSignature as exc:
        raise VerificationError(
            "signature does not verify against the supplied "
            "public key"
        ) from exc

    return receipt
