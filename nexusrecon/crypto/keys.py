"""Ed25519 keypair lifecycle.

Files on disk (under ``<key_dir>/<name>/``)
- ``private.pem`` — PEM-encrypted (PKCS8) private key.
  Passphrase required to decrypt.
- ``public.pem`` — Plain PEM-encoded public key. Distributed
  to verifiers freely.
- ``metadata.json`` — created_at, key_id, fingerprint, label.

Filesystem permissions
- The key dir is created with mode 0o700 (operator only).
- The private key file is written with mode 0o600.
- On Windows the modes are best-effort (Python sets the
  bits but Windows ignores POSIX modes); operators on
  Windows should rely on NTFS ACLs.

Identity
- A keypair's ``key_id`` is operator-supplied (e.g.
  ``corp-red-team-2026``). Fingerprint is SHA-256 of the
  raw public key bytes, prefixed ``sha256:`` to match the
  audit-log hash format.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

log = structlog.get_logger(__name__)


DEFAULT_KEY_DIR_ENV = "NEXUSRECON_KEY_DIR"
DEFAULT_KEY_DIR = "~/.nexusrecon/keys"


def resolve_key_dir(explicit: Path | str | None = None) -> Path:
    """Resolve the key root directory. Precedence: explicit
    arg → ``NEXUSRECON_KEY_DIR`` env → default."""
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    env_val = os.environ.get(DEFAULT_KEY_DIR_ENV)
    if env_val:
        return Path(env_val).expanduser().resolve()
    return Path(DEFAULT_KEY_DIR).expanduser().resolve()


# ──────────────────────────────────────────────────────────────────────
# Metadata + KeyPair record
# ──────────────────────────────────────────────────────────────────────


@dataclass
class KeyMetadata:
    """Carries the human-meaningful identity attached to a
    keypair on disk. Sits alongside the PEM files so the CLI
    can render ``keys list`` without decrypting anything."""

    key_id: str
    fingerprint: str
    created_at: str
    label: str = ""
    algorithm: str = "ed25519"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "label": self.label,
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> KeyMetadata:
        return cls(
            key_id=str(raw["key_id"]),
            fingerprint=str(raw["fingerprint"]),
            created_at=str(raw["created_at"]),
            label=str(raw.get("label", "")),
            algorithm=str(raw.get("algorithm", "ed25519")),
        )


@dataclass
class KeyPair:
    """In-memory holder. Returned by :func:`generate_keypair`
    + :func:`load_keypair`. Carries the live cryptography
    objects so callers can sign without re-loading."""

    metadata: KeyMetadata
    private_key: Ed25519PrivateKey | None
    public_key: Ed25519PublicKey

    @property
    def can_sign(self) -> bool:
        return self.private_key is not None


# ──────────────────────────────────────────────────────────────────────
# Public-key fingerprint
# ──────────────────────────────────────────────────────────────────────


def _fingerprint_public_key(public_key: Ed25519PublicKey) -> str:
    """SHA-256 over the raw 32-byte public key. Prefixed
    ``sha256:`` so the format matches the rest of the
    codebase's hashes."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw).hexdigest()
    return f"sha256:{digest}"


# ──────────────────────────────────────────────────────────────────────
# Generate
# ──────────────────────────────────────────────────────────────────────


def generate_keypair(
    key_id: str,
    passphrase: str,
    *,
    label: str = "",
    key_dir: Path | str | None = None,
    overwrite: bool = False,
) -> KeyPair:
    """Generate a new Ed25519 keypair and persist it.

    Raises ``FileExistsError`` if a keypair with ``key_id``
    already exists, unless ``overwrite=True``. The passphrase
    encrypts the private key in PKCS8 PEM format.
    """
    if not key_id:
        raise ValueError("key_id must not be empty")
    if not passphrase:
        raise ValueError(
            "passphrase must not be empty — "
            "encrypted keys require it"
        )

    root = resolve_key_dir(key_dir)
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        # Best effort on Windows.
        pass

    target_dir = root / key_id
    if target_dir.exists() and not overwrite:
        raise FileExistsError(
            f"keypair {key_id!r} already exists at {target_dir}"
        )
    target_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    fingerprint = _fingerprint_public_key(public_key)
    created_at = datetime.now(UTC).isoformat()

    # Private key: PKCS8 PEM, passphrase-encrypted with the
    # cryptography library's BestAvailableEncryption (which
    # picks an appropriate KDF + cipher under the hood).
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase.encode("utf-8"),
        ),
    )
    private_path = target_dir / "private.pem"
    private_path.write_bytes(private_pem)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    # Public key: plain PEM.
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (target_dir / "public.pem").write_bytes(public_pem)

    # Metadata file.
    metadata = KeyMetadata(
        key_id=key_id,
        fingerprint=fingerprint,
        created_at=created_at,
        label=label,
    )
    (target_dir / "metadata.json").write_text(
        json.dumps(metadata.to_dict(), indent=2),
        encoding="utf-8",
    )

    log.info(
        "Generated keypair",
        key_id=key_id, fingerprint=fingerprint[:24],
    )
    return KeyPair(
        metadata=metadata,
        private_key=private_key,
        public_key=public_key,
    )


# ──────────────────────────────────────────────────────────────────────
# Load
# ──────────────────────────────────────────────────────────────────────


def load_keypair(
    key_id: str,
    passphrase: str,
    *,
    key_dir: Path | str | None = None,
) -> KeyPair:
    """Load a keypair from disk.

    Raises ``FileNotFoundError`` if missing, ``ValueError``
    if the passphrase is wrong (the underlying
    cryptography library raises ``InvalidKey`` /
    ``ValueError`` and we normalise)."""
    root = resolve_key_dir(key_dir)
    target_dir = root / key_id
    if not (target_dir / "private.pem").exists():
        raise FileNotFoundError(f"keypair {key_id!r} not found")

    metadata = _load_metadata(target_dir)
    private_pem = (target_dir / "private.pem").read_bytes()
    try:
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=passphrase.encode("utf-8"),
        )
    except Exception as exc:
        # Surface a uniform error so callers can render a
        # friendly message without inspecting the underlying
        # library's exception classes.
        raise ValueError(
            f"could not load keypair {key_id!r} — bad passphrase?"
        ) from exc

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(
            f"keypair {key_id!r} is not an Ed25519 key"
        )

    public_key = private_key.public_key()
    return KeyPair(
        metadata=metadata,
        private_key=private_key,
        public_key=public_key,
    )


def load_public_key(
    path: Path | str,
) -> tuple[Ed25519PublicKey, str]:
    """Load a public key from a PEM file. Returns the key
    object + its fingerprint string. Used by verifiers that
    don't have access to the metadata file."""
    pem_path = Path(path).expanduser().resolve()
    if not pem_path.exists():
        raise FileNotFoundError(f"public key not found: {pem_path}")
    public_key = serialization.load_pem_public_key(pem_path.read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError(
            f"{pem_path} is not an Ed25519 public key"
        )
    return public_key, _fingerprint_public_key(public_key)


# ──────────────────────────────────────────────────────────────────────
# List
# ──────────────────────────────────────────────────────────────────────


def list_keypairs(
    key_dir: Path | str | None = None,
) -> list[KeyMetadata]:
    """Enumerate every configured keypair (metadata only —
    private keys stay encrypted on disk)."""
    root = resolve_key_dir(key_dir)
    if not root.exists():
        return []
    out: list[KeyMetadata] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        try:
            out.append(_load_metadata(entry))
        except Exception as exc:
            log.debug(
                "Skipped malformed key dir",
                path=str(entry), error=str(exc),
            )
    return out


def _load_metadata(target_dir: Path) -> KeyMetadata:
    path = target_dir / "metadata.json"
    if not path.exists():
        raise FileNotFoundError(
            f"metadata.json missing in {target_dir}"
        )
    return KeyMetadata.from_dict(
        json.loads(path.read_text(encoding="utf-8")),
    )
