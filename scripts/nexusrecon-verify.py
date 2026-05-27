#!/usr/bin/env python3
"""Standalone verifier for NexusRecon signed STIX bundles.

Depends ONLY on the `cryptography` Python library — does not
import any `nexusrecon.*` module. Distribute this file
alongside a signed bundle so auditors who don't have
NexusRecon installed can still verify the chain of custody.

Usage:
    python nexusrecon-verify.py \\
        --bundle stix2-bundle.json \\
        --receipt stix2-bundle.json.receipt.json \\
        --public-key signer-pubkey.pem
    [--expected-key-id corp-red-team-2026]
    [--expected-fingerprint sha256:...]

Exit codes
    0  signature verifies + identity matches (if pinned)
    1  any verification failure

The format is fixed by NexusRecon's Receipt v1.x schema —
this script handles every v1.x receipt. Major-version bumps
will require an updated verifier (the script refuses
schemas it doesn't understand).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "ERROR: this verifier needs the `cryptography` "
        "Python package.\n"
        f"      install with: pip install cryptography\n"
        f"      (underlying import error: {exc})\n"
    )
    sys.exit(1)


def _fail(msg: str) -> "None":
    sys.stderr.write(f"VERIFICATION FAILED: {msg}\n")
    sys.exit(1)


def _ok(msg: str) -> None:
    sys.stdout.write(f"OK: {msg}\n")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def _fingerprint_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _signed_message(bundle_hash: str) -> bytes:
    # MUST match nexusrecon.crypto.signing._signed_message.
    return f"ed25519|{bundle_hash}".encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument(
        "--expected-key-id", default=None,
        help="Fail if the receipt's signer key_id differs from this.",
    )
    parser.add_argument(
        "--expected-fingerprint", default=None,
        help="Fail if the public key's fingerprint differs from this.",
    )
    args = parser.parse_args(argv)

    # ── Existence ───────────────────────────────────────────
    for label, path in (
        ("bundle", args.bundle),
        ("receipt", args.receipt),
        ("public-key", args.public_key),
    ):
        if not path.exists():
            _fail(f"{label} not found: {path}")

    # ── Receipt ─────────────────────────────────────────────
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"receipt is not valid JSON: {exc}")
    if not isinstance(receipt, dict):
        _fail("receipt root is not a JSON object")

    version = str(receipt.get("version", ""))
    if not version.startswith("1."):
        _fail(
            f"receipt schema {version!r} not supported by "
            f"this verifier (expected 1.x)"
        )

    sig_algo = str(receipt.get("signature_algorithm", "")).lower()
    if sig_algo != "ed25519":
        _fail(f"unsupported signature algorithm: {sig_algo!r}")

    bundle_block = receipt.get("bundle") or {}
    bundle_hash_algo = str(
        bundle_block.get("hash_algorithm", "")
    ).lower()
    if bundle_hash_algo != "sha256":
        _fail(f"unsupported bundle hash algorithm: {bundle_hash_algo!r}")

    receipt_bundle_hash = str(bundle_block.get("hash", ""))
    if not receipt_bundle_hash.startswith("sha256:"):
        _fail("receipt's bundle hash is malformed")

    signer = receipt.get("signer") or {}
    receipt_key_id = str(signer.get("key_id", ""))
    receipt_fingerprint = str(signer.get("fingerprint", ""))
    sig_b64 = str(receipt.get("signature", ""))
    if not sig_b64:
        _fail("receipt has no signature field")

    # ── Public key ─────────────────────────────────────────
    try:
        public_key = serialization.load_pem_public_key(
            args.public_key.read_bytes(),
        )
    except Exception as exc:
        _fail(f"could not load public key: {exc}")
    if not isinstance(public_key, Ed25519PublicKey):
        _fail("public key is not Ed25519")
    computed_fp = _fingerprint_public_key(public_key)

    # Fingerprint match: receipt's claimed fingerprint vs the
    # public key the operator supplied.
    if receipt_fingerprint != computed_fp:
        _fail(
            f"public-key fingerprint mismatch: receipt "
            f"claims {receipt_fingerprint!r}, supplied key "
            f"computes to {computed_fp!r}"
        )

    # Optional pinned checks.
    if args.expected_key_id and receipt_key_id != args.expected_key_id:
        _fail(
            f"key_id pin mismatch: receipt {receipt_key_id!r} "
            f"vs expected {args.expected_key_id!r}"
        )
    if (
        args.expected_fingerprint
        and computed_fp != args.expected_fingerprint
    ):
        _fail(
            f"fingerprint pin mismatch: computed {computed_fp!r} "
            f"vs expected {args.expected_fingerprint!r}"
        )

    # ── Bundle hash ────────────────────────────────────────
    actual_bundle_hash = _sha256_file(args.bundle)
    if actual_bundle_hash != receipt_bundle_hash:
        _fail(
            f"bundle hash mismatch: file hashes to "
            f"{actual_bundle_hash!r}, receipt claims "
            f"{receipt_bundle_hash!r}"
        )

    # ── Signature ──────────────────────────────────────────
    # Decode base64url with padding tolerance.
    padded = sig_b64 + "=" * (-len(sig_b64) % 4)
    try:
        sig_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        _fail(f"signature is not valid base64url: {exc}")

    try:
        public_key.verify(sig_bytes, _signed_message(receipt_bundle_hash))
    except InvalidSignature:
        _fail("signature does not verify against the supplied public key")

    _ok(
        f"bundle '{args.bundle.name}' signed by "
        f"key_id={receipt_key_id!r} "
        f"fingerprint={computed_fp}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
