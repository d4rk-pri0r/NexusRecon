"""Provenance cryptography — Phase 5 PR B.

Signed receipts for STIX exports. Closes a long-standing
audit gap: today's audit log is tamper-evident *within* a
campaign (hash-chained, Phase 1 PR D), but a downstream
auditor with only the exported STIX bundle has no way to
prove the bundle came from a specific NexusRecon instance at
a specific time. PR B fixes that.

Architecture decisions (locked in)
- **Algorithm**: Ed25519. Small keys, fast verify, modern.
  Uses the ``cryptography`` library (already a transitive
  dep at v46+).
- **Signing scope**: BUNDLES. Sign the entire STIX export
  at campaign end — one signature, one verification step.
  Per-finding receipts + audit-chain signatures stay
  candidates for follow-up PRs.
- **Key storage**: PEM file with passphrase encryption under
  ``~/.nexusrecon/keys/``. Operator enters the passphrase
  when signing. Public keys live alongside (unencrypted)
  for easy distribution.
- **Verifier**: BOTH CLI (``nexusrecon verify``) AND a
  standalone single-file Python script
  (``scripts/nexusrecon-verify.py``) so auditors with no
  NexusRecon install can still verify.

Receipt envelope
- Sidecar JSON file next to the signed bundle.
- Carries: bundle hash, signature, signer metadata
  (key_id + public key fingerprint), timestamp, algorithm
  version markers.
- Stable schema so future verifier versions stay
  backwards-compatible.

What's deliberately NOT here
- Sigstore / transparency log integration — biggest scope;
  deferred until community demand justifies the deps.
- HSM / cloud KMS signing — file-based keys cover the
  common case; KMS support can layer on later via a
  ``SigningBackend`` protocol that the high-level API
  already accepts.
- Per-finding receipts — bundle signing covers the
  attestation case. Per-finding adds complexity that
  isn't justified until at least one operator asks.
"""
from nexusrecon.crypto.keys import (
    KeyMetadata,
    KeyPair,
    generate_keypair,
    list_keypairs,
    load_keypair,
    load_public_key,
    resolve_key_dir,
)
from nexusrecon.crypto.receipt import (
    Receipt,
    compute_bundle_hash,
)
from nexusrecon.crypto.signing import (
    SigningError,
    VerificationError,
    sign_bundle,
    verify_bundle,
)

__all__ = [
    "KeyMetadata",
    "KeyPair",
    "Receipt",
    "SigningError",
    "VerificationError",
    "compute_bundle_hash",
    "generate_keypair",
    "list_keypairs",
    "load_keypair",
    "load_public_key",
    "resolve_key_dir",
    "sign_bundle",
    "verify_bundle",
]
