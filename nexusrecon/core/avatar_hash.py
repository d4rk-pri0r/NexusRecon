"""
Cross-service avatar similarity hashing (Phase C item C1).

If Jane Doe uses the same selfie on her GitHub, Twitter, and LinkedIn
profiles, those are very likely the same person ── stronger evidence
than any text-based signal short of a cryptographic linked-account
proof. This module fetches profile avatars, computes perceptual hashes,
and clusters images that look the same across services.

The signal complements but does not replace the linked-account graph:

  - A linked-account reference is *attested* identity ── one service's
    bio claims another service's handle. Strongest when present.
  - An avatar match is *observed* identity ── two services
    independently expose the same image. Weaker but doesn't require
    either profile to mention the other.

Together they catch identity even when both bios are minimal:
the avatar match confirms what the bio doesn't say.

## Mechanic

  - Each fetched ProfileData carries an ``avatar_url`` (when the
    service exposes one). The Phase B profile_fetcher fills it for
    GitHub, GitLab, Reddit, Stack Exchange; generic HTML fallback
    reads ``<meta og:image>``.
  - For HIGH/MEDIUM band hits, this module fetches the image and
    computes a perceptual hash (dHash from the imagehash library,
    64-bit by default).
  - Hashes are compared via Hamming distance. Distance <= 8 means
    likely the same image; <= 4 means very high confidence.
  - The result is a list of "avatar clusters" ── groups of hits whose
    avatars match. A hit appearing in a cluster of size >= 2 gets a
    confidence boost.

## Limitations

This is "same image" detection, not "same person." Two unrelated
humans using the same anime character avatar would falsely cluster.
Mitigations:

  - **Identicon filter**: many services serve auto-generated default
    avatars (GitHub identicons, Gravatar monsterids, Reddit snoo
    variants). The module heuristically detects these and excludes
    them from cluster scoring ── otherwise every default-avatar user
    on a service would cluster together meaninglessly.
  - **Threshold tuning**: distance threshold of 8 catches the common
    case while leaving room for cropping/format differences. Operators
    can tighten by passing ``threshold=4`` for high-precision mode.

## Optional dependency

Requires ``Pillow`` and ``imagehash``. Both are widely-available and
pure-Python (Pillow has C extensions for image decode). If either
import fails, the module's functions become no-ops returning
empty results ── the framework continues without avatar hashing
rather than crashing.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from nexusrecon.opsec.context import proxy_kwargs
from nexusrecon.opsec.useragent import random_ua

log = structlog.get_logger(__name__)


# Lazy-import Pillow + imagehash so the module loads even when the
# optional deps are missing. Operators without the deps get clean
# no-ops; operators with them get full functionality.
try:
    import imagehash
    from PIL import Image
    _AVATAR_HASH_AVAILABLE = True
except ImportError:
    Image = None  # type: ignore[assignment]
    imagehash = None  # type: ignore[assignment]
    _AVATAR_HASH_AVAILABLE = False


def avatar_hash_available() -> bool:
    """Return True when Pillow + imagehash are both importable.

    Tests and callers should branch on this instead of catching
    exceptions ── lets the rest of the framework keep working when
    the optional deps aren't installed."""
    return _AVATAR_HASH_AVAILABLE


# Distance threshold for "likely same image". 64-bit dHash with
# Hamming distance <= 8 typically means same image with possible
# cropping / format / quality differences.
_DEFAULT_DISTANCE_THRESHOLD = 8

# Maximum image size we'll download. Avatars are typically <200KB;
# anything larger is probably a service serving full resolution by
# mistake or pointing at a non-avatar URL.
_MAX_AVATAR_BYTES = 5 * 1024 * 1024  # 5MB

# Hash bit length. 64-bit is the default for ``imagehash.dhash``;
# longer hashes (16x16=256-bit) catch more detail but are slower and
# more sensitive to compression artifacts.
_HASH_SIZE = 8  # → 8x8 = 64-bit hash


# Identicon / default-avatar URL patterns. Avatars matching these are
# excluded from cluster scoring because they don't represent a chosen
# user-uploaded image.
_IDENTICON_PATTERNS = [
    re.compile(r"/identicons?/", re.IGNORECASE),
    re.compile(r"[?&]d=identicon\b", re.IGNORECASE),
    re.compile(r"[?&]d=monsterid\b", re.IGNORECASE),
    re.compile(r"[?&]d=wavatar\b", re.IGNORECASE),
    re.compile(r"[?&]d=retro\b", re.IGNORECASE),
    re.compile(r"[?&]d=robohash\b", re.IGNORECASE),
    re.compile(r"/default[_-]avatar", re.IGNORECASE),
    re.compile(r"/avatars/default/", re.IGNORECASE),
    re.compile(r"/snoo_avatars/", re.IGNORECASE),  # Reddit default
    # GitHub identicon URLs: gravatar.com/avatar/HASH?d=identicon
    re.compile(r"avatar\.png\?_=avatar", re.IGNORECASE),
]


@dataclass
class AvatarFingerprint:
    """Perceptual hash of one fetched avatar plus metadata.

    Attributes:
        service: Service the avatar came from (e.g. ``"GitHub"``).
        username: Handle on that service.
        image_url: The URL we fetched.
        phash: Hex string of the perceptual hash. Empty when fetch
            failed.
        is_identicon: True when ``image_url`` matched a known
            identicon pattern. Identicons are excluded from cluster
            scoring.
        error: Failure message when fetch / hash failed; ``None`` on
            success.
    """

    service: str
    username: str
    image_url: str
    phash: str
    is_identicon: bool = False
    error: str | None = None

    @property
    def fetched(self) -> bool:
        return bool(self.phash) and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "username": self.username,
            "image_url": self.image_url,
            "phash": self.phash,
            "is_identicon": self.is_identicon,
            "error": self.error,
        }


def is_identicon_url(url: str) -> bool:
    """Heuristically detect auto-generated default avatars by URL.

    Doesn't catch every identicon (some services serve user-uploaded
    images from the same URL pattern as defaults) but catches the
    common cases: Gravatar with ``d=identicon``, GitHub identicons,
    Reddit snoo defaults, etc."""
    if not url:
        return True
    for pattern in _IDENTICON_PATTERNS:
        if pattern.search(url):
            return True
    return False


async def fetch_and_hash_avatar(
    service: str,
    username: str,
    image_url: str,
    timeout: float = 8.0,
) -> AvatarFingerprint:
    """Fetch an avatar image and compute its perceptual hash.

    Returns an :class:`AvatarFingerprint` with ``phash=""`` and an
    ``error`` field set when:

      - The optional deps (Pillow, imagehash) aren't installed.
      - The URL is empty.
      - The HTTP fetch fails (non-200, timeout, connection error).
      - The image decode fails (corrupt, unsupported format, too big).

    The fetch routes through the campaign proxy via ``proxy_kwargs``
    and uses a rotated UA. Errors never raise ── one failed avatar
    fetch can't crash the batch.
    """
    if not _AVATAR_HASH_AVAILABLE:
        return AvatarFingerprint(
            service=service, username=username, image_url=image_url,
            phash="", error="Pillow / imagehash not installed",
        )
    if not image_url:
        return AvatarFingerprint(
            service=service, username=username, image_url="",
            phash="", error="empty avatar URL",
        )

    identicon = is_identicon_url(image_url)

    headers = {
        "User-Agent": random_ua(),
        "Accept": "image/*",
    }
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, headers=headers,
            **proxy_kwargs(),
        ) as client:
            resp = await client.get(image_url)
            if resp.status_code != 200:
                return AvatarFingerprint(
                    service=service, username=username,
                    image_url=image_url, phash="",
                    is_identicon=identicon,
                    error=f"image fetch returned HTTP {resp.status_code}",
                )
            content = resp.content
            if len(content) > _MAX_AVATAR_BYTES:
                return AvatarFingerprint(
                    service=service, username=username,
                    image_url=image_url, phash="",
                    is_identicon=identicon,
                    error=f"image too large ({len(content)} bytes)",
                )
    except Exception as exc:
        return AvatarFingerprint(
            service=service, username=username,
            image_url=image_url, phash="",
            is_identicon=identicon,
            error=f"image fetch failed: {exc}",
        )

    # Decode + hash. Wrap in a thread executor because Pillow's
    # image decoding is CPU-bound (not async). Tiny avatars are
    # negligibly fast but a 5MB upload-by-mistake JPEG could block
    # the event loop briefly without this.
    try:
        loop = asyncio.get_event_loop()
        phash = await loop.run_in_executor(None, _decode_and_hash, content)
    except Exception as exc:
        return AvatarFingerprint(
            service=service, username=username,
            image_url=image_url, phash="",
            is_identicon=identicon,
            error=f"image decode/hash failed: {exc}",
        )

    return AvatarFingerprint(
        service=service, username=username,
        image_url=image_url, phash=phash,
        is_identicon=identicon,
    )


def _decode_and_hash(content: bytes) -> str:
    """Pillow + imagehash CPU work, wrapped in a sync function so we
    can run it in an executor without blocking the event loop.

    Uses ``dhash`` (difference hash) ── slightly more robust than
    ``ahash`` (average hash) for cropping and lighting changes, and
    faster than ``phash`` (perceptual hash via DCT). For avatar
    matching the trade-off favours dhash."""
    from io import BytesIO
    with Image.open(BytesIO(content)) as img:
        # Convert to greyscale for deterministic hashing across
        # services that may serve different color profiles.
        img = img.convert("L")
        return str(imagehash.dhash(img, hash_size=_HASH_SIZE))


async def fetch_and_hash_batch(
    avatars: list[tuple[str, str, str]],
    max_concurrent: int = 5,
) -> list[AvatarFingerprint]:
    """Fetch + hash a batch of avatars concurrently.

    Args:
        avatars: list of ``(service, username, image_url)`` tuples.
        max_concurrent: cap on simultaneous fetches (be polite to
            service CDNs ── 5 is a safe default).

    Returns:
        Fingerprints in the same order as input.
    """
    if not _AVATAR_HASH_AVAILABLE:
        return [
            AvatarFingerprint(
                service=s, username=u, image_url=url, phash="",
                error="Pillow / imagehash not installed",
            )
            for s, u, url in avatars
        ]

    sem = asyncio.Semaphore(max_concurrent)

    async def _one(item: tuple[str, str, str]) -> AvatarFingerprint:
        service, username, url = item
        async with sem:
            return await fetch_and_hash_avatar(service, username, url)

    return await asyncio.gather(*(_one(a) for a in avatars))


def hamming_distance(hex_a: str, hex_b: str) -> int:
    """Hamming distance between two hex-string perceptual hashes.

    Both inputs should be the same length (output of ``dhash`` with
    the same hash_size). Returns a large sentinel value when the
    inputs are malformed ── lets callers treat parse errors the same
    way as "definitely different image"."""
    if not hex_a or not hex_b:
        return 10**6
    try:
        a = int(hex_a, 16)
        b = int(hex_b, 16)
    except ValueError:
        return 10**6
    return bin(a ^ b).count("1")


def find_avatar_clusters(
    fingerprints: Sequence[AvatarFingerprint],
    threshold: int = _DEFAULT_DISTANCE_THRESHOLD,
) -> list[list[AvatarFingerprint]]:
    """Group fingerprints whose hashes are within ``threshold``
    Hamming distance of each other.

    Excludes identicons and failed fetches from cluster construction
    ── only successfully-fetched user-uploaded images can cluster.

    The clustering is a simple greedy single-link: start with the
    first fingerprint, attach any subsequent fingerprint within
    threshold, repeat. This is O(N²) but N is small (10s of hits
    per campaign) so it's fine.

    Returns a list of clusters, each containing 2+ fingerprints.
    Singletons (an image with no matches) are omitted because they
    carry no cross-service signal.
    """
    candidates = [
        fp for fp in fingerprints
        if fp.fetched and not fp.is_identicon
    ]
    if len(candidates) < 2:
        return []

    visited: list[bool] = [False] * len(candidates)
    clusters: list[list[AvatarFingerprint]] = []

    for i, fp_i in enumerate(candidates):
        if visited[i]:
            continue
        cluster = [fp_i]
        visited[i] = True
        for j in range(i + 1, len(candidates)):
            if visited[j]:
                continue
            if hamming_distance(fp_i.phash, candidates[j].phash) <= threshold:
                cluster.append(candidates[j])
                visited[j] = True
        if len(cluster) >= 2:
            clusters.append(cluster)

    return clusters


def annotate_hits_with_avatar_clusters(
    hits: list[dict[str, Any]],
    clusters: list[list[AvatarFingerprint]],
) -> None:
    """Mutate ``hits`` in place, attaching ``avatar_cluster_id`` and
    ``avatar_cluster_size`` to each hit whose fingerprint participated
    in a cluster.

    Hits are matched to fingerprints by ``(service, username)`` ──
    same key as :func:`extract_linked_accounts.cross_reference_with_hits`.
    """
    # Build a (service, username) → cluster_id mapping.
    lookup: dict[tuple[str, str], tuple[int, int]] = {}
    for cluster_id, cluster in enumerate(clusters):
        for fp in cluster:
            key = (fp.service.lower(), fp.username.lower())
            lookup[key] = (cluster_id, len(cluster))

    for hit in hits:
        key = (
            (hit.get("service") or "").lower(),
            (hit.get("username") or "").lower(),
        )
        if key in lookup:
            cluster_id, cluster_size = lookup[key]
            hit["avatar_cluster_id"] = cluster_id
            hit["avatar_cluster_size"] = cluster_size
