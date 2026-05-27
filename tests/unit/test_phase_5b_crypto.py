"""Tests for Phase 5 PR B: provenance cryptography.

PR B ships ``nexusrecon/crypto/`` — Ed25519 keypair lifecycle,
bundle signing, verification, receipt envelope, and a
standalone verifier script.

Coverage
- Keypair generation produces an encrypted PEM that round-
  trips with the correct passphrase and FAILS with the
  wrong one.
- Fingerprints are stable + deterministic for a given
  public key.
- ``sign_bundle`` writes a sidecar receipt next to the
  bundle; the receipt JSON parses cleanly.
- ``verify_bundle`` accepts the freshly-signed receipt and
  REJECTS:
  * a bundle whose content was modified post-signing
  * a swapped public key
  * a tampered receipt (signature field flipped)
  * a wrong key_id pin
- The standalone verifier script (``scripts/nexusrecon-
  verify.py``) accepts the same artifacts and exits 0 on
  success / 1 on any failure.
- Receipt schema rejects unknown major versions (forward-
  compat refusal).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from nexusrecon.crypto import (
    KeyMetadata,
    VerificationError,
    compute_bundle_hash,
    generate_keypair,
    list_keypairs,
    load_keypair,
    load_public_key,
    sign_bundle,
    verify_bundle,
)
from nexusrecon.crypto.receipt import Receipt


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def key_dir(tmp_path: Path) -> Path:
    return tmp_path / "keys"


@pytest.fixture
def bundle_path(tmp_path: Path) -> Path:
    """A tiny STIX-ish bundle for signing."""
    path = tmp_path / "stix2-bundle.json"
    path.write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000000",
        "objects": [],
    }))
    return path


# ──────────────────────────────────────────────────────────────────────
# Key generation + load
# ──────────────────────────────────────────────────────────────────────


class TestKeyGeneration:
    def test_creates_files_on_disk(self, key_dir: Path):
        kp = generate_keypair(
            "test-key", "correct-passphrase",
            label="test", key_dir=key_dir,
        )
        target = key_dir / "test-key"
        assert (target / "private.pem").exists()
        assert (target / "public.pem").exists()
        assert (target / "metadata.json").exists()
        assert kp.metadata.fingerprint.startswith("sha256:")
        # Both keys present in memory.
        assert kp.can_sign is True

    def test_refuses_duplicate(self, key_dir: Path):
        generate_keypair("k1", "p", key_dir=key_dir)
        with pytest.raises(FileExistsError):
            generate_keypair("k1", "p", key_dir=key_dir)

    def test_overwrite_allows_replacement(self, key_dir: Path):
        kp1 = generate_keypair("k1", "p", key_dir=key_dir)
        kp2 = generate_keypair(
            "k1", "p", key_dir=key_dir, overwrite=True,
        )
        # New keypair has a DIFFERENT fingerprint than the
        # one it replaced — confirms regeneration happened.
        assert kp2.metadata.fingerprint != kp1.metadata.fingerprint

    def test_empty_key_id_rejected(self, key_dir: Path):
        with pytest.raises(ValueError, match="key_id"):
            generate_keypair("", "p", key_dir=key_dir)

    def test_empty_passphrase_rejected(self, key_dir: Path):
        with pytest.raises(ValueError, match="passphrase"):
            generate_keypair("k1", "", key_dir=key_dir)


class TestKeyLoad:
    def test_correct_passphrase_succeeds(self, key_dir: Path):
        original = generate_keypair("k1", "secret123", key_dir=key_dir)
        loaded = load_keypair("k1", "secret123", key_dir=key_dir)
        assert loaded.metadata.fingerprint == original.metadata.fingerprint
        assert loaded.can_sign is True

    def test_wrong_passphrase_raises(self, key_dir: Path):
        generate_keypair("k1", "secret123", key_dir=key_dir)
        with pytest.raises(ValueError, match="passphrase"):
            load_keypair("k1", "wrong", key_dir=key_dir)

    def test_missing_key_raises(self, key_dir: Path):
        with pytest.raises(FileNotFoundError):
            load_keypair("ghost", "p", key_dir=key_dir)


class TestListKeypairs:
    def test_enumerates_metadata(self, key_dir: Path):
        generate_keypair("a", "p", key_dir=key_dir)
        generate_keypair("b", "p", key_dir=key_dir, label="another")
        items = list_keypairs(key_dir=key_dir)
        ids = {m.key_id for m in items}
        assert ids == {"a", "b"}

    def test_empty_returns_empty(self, key_dir: Path):
        assert list_keypairs(key_dir=key_dir) == []


# ──────────────────────────────────────────────────────────────────────
# Fingerprints
# ──────────────────────────────────────────────────────────────────────


class TestFingerprints:
    def test_load_public_key_matches_metadata(self, key_dir: Path):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        _, fp = load_public_key(key_dir / "k1" / "public.pem")
        assert fp == kp.metadata.fingerprint


# ──────────────────────────────────────────────────────────────────────
# Sign + verify
# ──────────────────────────────────────────────────────────────────────


class TestSignVerify:
    def test_sign_writes_receipt(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        receipt = sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        assert receipt_path.exists()
        # Receipt JSON parses + has expected structure.
        loaded = json.loads(receipt_path.read_text())
        assert loaded["version"].startswith("1.")
        assert loaded["signature_algorithm"] == "ed25519"
        assert loaded["bundle"]["hash"] == receipt.bundle_hash

    def test_verify_accepts_fresh_signature(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        public_key_path = key_dir / "k1" / "public.pem"
        # Should not raise.
        receipt = verify_bundle(
            bundle_path, receipt_path, public_key_path,
        )
        assert receipt.signer_key_id == "k1"

    def test_verify_rejects_modified_bundle(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        public_key_path = key_dir / "k1" / "public.pem"

        # Tamper with the bundle AFTER signing.
        bundle_path.write_text(
            bundle_path.read_text() + "\n# extra content\n",
        )

        with pytest.raises(VerificationError, match="bundle hash mismatch"):
            verify_bundle(bundle_path, receipt_path, public_key_path)

    def test_verify_rejects_wrong_public_key(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp_a = generate_keypair("ka", "p", key_dir=key_dir)
        kp_b = generate_keypair("kb", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp_a)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        # Try to verify with the WRONG public key.
        wrong_pub = key_dir / "kb" / "public.pem"
        with pytest.raises(VerificationError, match="fingerprint mismatch"):
            verify_bundle(bundle_path, receipt_path, wrong_pub)

    def test_verify_rejects_tampered_signature(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        # Flip a single character in the signature field.
        receipt_dict = json.loads(receipt_path.read_text())
        sig = receipt_dict["signature"]
        # Mutate the first character via a small ASCII roll.
        if sig[0] == "A":
            sig = "B" + sig[1:]
        else:
            sig = "A" + sig[1:]
        receipt_dict["signature"] = sig
        receipt_path.write_text(json.dumps(receipt_dict))

        with pytest.raises(VerificationError, match="signature"):
            verify_bundle(
                bundle_path, receipt_path,
                key_dir / "k1" / "public.pem",
            )

    def test_pinned_key_id_mismatch_rejected(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        with pytest.raises(VerificationError, match="key_id"):
            verify_bundle(
                bundle_path, receipt_path,
                key_dir / "k1" / "public.pem",
                expected_key_id="someone-else",
            )

    def test_pinned_fingerprint_match(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        # Pinned to the correct fingerprint — succeeds.
        verify_bundle(
            bundle_path, receipt_path,
            key_dir / "k1" / "public.pem",
            expected_fingerprint=kp.metadata.fingerprint,
        )


# ──────────────────────────────────────────────────────────────────────
# Receipt schema
# ──────────────────────────────────────────────────────────────────────


class TestReceiptSchema:
    def test_unknown_major_version_rejected(self):
        with pytest.raises(ValueError, match="schema"):
            Receipt.from_dict({
                "version": "2.0",
                "signer": {"key_id": "k", "fingerprint": "sha256:abc"},
                "bundle": {
                    "filename": "x", "hash_algorithm": "sha256",
                    "hash": "sha256:abc",
                },
                "signature_algorithm": "ed25519",
                "signature": "",
            })

    def test_missing_version_rejected(self):
        with pytest.raises(ValueError, match="version"):
            Receipt.from_dict({})

    def test_bundle_hash_computation_stable(self, bundle_path: Path):
        a = compute_bundle_hash(bundle_path)
        b = compute_bundle_hash(bundle_path)
        assert a == b
        # Modifying the file changes the hash.
        bundle_path.write_text(bundle_path.read_text() + "\nmore\n")
        c = compute_bundle_hash(bundle_path)
        assert c != a


# ──────────────────────────────────────────────────────────────────────
# Standalone verifier script
# ──────────────────────────────────────────────────────────────────────


SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "scripts" / "nexusrecon-verify.py"
)


def _run_script(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True, text=True, check=False,
    )


class TestStandaloneVerifier:
    def test_script_exists(self):
        assert SCRIPT_PATH.exists(), (
            f"standalone verifier missing at {SCRIPT_PATH}"
        )

    def test_accepts_fresh_signature(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        result = _run_script([
            "--bundle", str(bundle_path),
            "--receipt", str(receipt_path),
            "--public-key", str(key_dir / "k1" / "public.pem"),
        ])
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_rejects_modified_bundle(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        bundle_path.write_text(bundle_path.read_text() + "\n# tamper\n")
        result = _run_script([
            "--bundle", str(bundle_path),
            "--receipt", str(receipt_path),
            "--public-key", str(key_dir / "k1" / "public.pem"),
        ])
        assert result.returncode == 1
        assert "bundle hash mismatch" in result.stderr

    def test_rejects_wrong_public_key(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp_a = generate_keypair("ka", "p", key_dir=key_dir)
        generate_keypair("kb", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp_a)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        result = _run_script([
            "--bundle", str(bundle_path),
            "--receipt", str(receipt_path),
            "--public-key", str(key_dir / "kb" / "public.pem"),
        ])
        assert result.returncode == 1
        assert "fingerprint" in result.stderr

    def test_pinned_key_id_mismatch_rejected(
        self, key_dir: Path, bundle_path: Path,
    ):
        kp = generate_keypair("k1", "p", key_dir=key_dir)
        sign_bundle(bundle_path, kp)
        receipt_path = bundle_path.with_name(
            bundle_path.name + ".receipt.json",
        )
        result = _run_script([
            "--bundle", str(bundle_path),
            "--receipt", str(receipt_path),
            "--public-key", str(key_dir / "k1" / "public.pem"),
            "--expected-key-id", "different-signer",
        ])
        assert result.returncode == 1
        assert "key_id" in result.stderr
