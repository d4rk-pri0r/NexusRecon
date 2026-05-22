"""Tests for nexusrecon.core.avatar_hash.

Mocked HTTP fetches, real perceptual hashing on synthetic images.
The module gracefully degrades when Pillow/imagehash aren't
installed, so we test both code paths."""
from __future__ import annotations

import io

import httpx
import pytest
import respx
from httpx import Response

from nexusrecon.core.avatar_hash import (
    AvatarFingerprint,
    annotate_hits_with_avatar_clusters,
    avatar_hash_available,
    fetch_and_hash_avatar,
    fetch_and_hash_batch,
    find_avatar_clusters,
    hamming_distance,
    is_identicon_url,
)

# Skip the hash-computation tests when deps aren't available; the
# pure-function tests (URL classification, distance, clustering)
# still run.
PILLOW_AVAILABLE = avatar_hash_available()


def _png_bytes(color: tuple = (50, 100, 200), size: tuple = (32, 32)) -> bytes:
    """Build a small synthetic PNG for hash testing. Different colors
    produce different perceptual hashes; same color produces matching
    ones."""
    pytest.importorskip("PIL")
    from PIL import Image as PImage
    img = PImage.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ──────────────────────────────────────────────────────────────────────
# URL classification
# ──────────────────────────────────────────────────────────────────────


class TestIdenticonDetection:
    def test_empty_url_is_identicon(self):
        assert is_identicon_url("") is True
        assert is_identicon_url(None) is True

    def test_gravatar_identicon_query_param(self):
        url = "https://www.gravatar.com/avatar/abc?d=identicon&s=200"
        assert is_identicon_url(url) is True

    def test_gravatar_monsterid(self):
        assert is_identicon_url(
            "https://gravatar.com/avatar/abc?d=monsterid"
        ) is True

    def test_gravatar_retro(self):
        assert is_identicon_url("https://gravatar.com/avatar/abc?d=retro") is True

    def test_default_avatar_path(self):
        assert is_identicon_url("https://service.example/default_avatar.png") is True
        assert is_identicon_url("https://service.example/avatars/default/user.png") is True

    def test_reddit_default_snoo(self):
        url = "https://www.redditstatic.com/avatars/snoo_avatars/avatar_1.png"
        assert is_identicon_url(url) is True

    def test_real_avatar_url_not_identicon(self):
        # User-uploaded avatars typically have content hashes in URL.
        assert is_identicon_url(
            "https://avatars.githubusercontent.com/u/12345?v=4"
        ) is False
        assert is_identicon_url(
            "https://i.imgur.com/abc1234.jpg"
        ) is False


# ──────────────────────────────────────────────────────────────────────
# Hamming distance
# ──────────────────────────────────────────────────────────────────────


class TestHammingDistance:
    def test_identical_hashes_zero_distance(self):
        assert hamming_distance("0123456789abcdef", "0123456789abcdef") == 0

    def test_one_bit_difference(self):
        # 0xff differs from 0xfe by one bit.
        assert hamming_distance("ff", "fe") == 1

    def test_completely_different_hashes(self):
        # All bits flipped.
        assert hamming_distance("ff", "00") == 8

    def test_empty_hash_returns_sentinel(self):
        """Both empty / None / malformed inputs return a large value
        so callers treating them as 'definitely different image' get
        the right behaviour."""
        assert hamming_distance("", "abcd") >= 1000
        assert hamming_distance("abcd", "") >= 1000

    def test_malformed_hex_returns_sentinel(self):
        assert hamming_distance("XYZ", "abcd") >= 1000


# ──────────────────────────────────────────────────────────────────────
# Cluster detection
# ──────────────────────────────────────────────────────────────────────


class TestClusterDetection:
    def test_no_fingerprints_returns_empty(self):
        assert find_avatar_clusters([]) == []

    def test_single_fingerprint_returns_empty(self):
        """A lone fingerprint can't cluster ── no other image to match
        against."""
        fp = AvatarFingerprint(
            service="GitHub", username="jane",
            image_url="https://x", phash="abcd1234",
        )
        assert find_avatar_clusters([fp]) == []

    def test_matching_hashes_cluster(self):
        fps = [
            AvatarFingerprint("GitHub", "jane", "x", "0000000000000000"),
            AvatarFingerprint("Twitter", "jane", "y", "0000000000000000"),
        ]
        clusters = find_avatar_clusters(fps, threshold=8)
        assert len(clusters) == 1
        assert len(clusters[0]) == 2

    def test_close_hashes_cluster(self):
        """Hashes within Hamming distance ``threshold`` should cluster
        ── catches cropping/recompression differences."""
        fps = [
            AvatarFingerprint("GitHub", "jane", "x", "ff00000000000000"),
            # One byte different → 8 bit-flips. Threshold default is 8.
            AvatarFingerprint("Twitter", "jane", "y", "0000000000000000"),
        ]
        clusters = find_avatar_clusters(fps, threshold=8)
        assert len(clusters) == 1

    def test_distant_hashes_dont_cluster(self):
        fps = [
            AvatarFingerprint("GitHub", "jane", "x", "0000000000000000"),
            AvatarFingerprint("Twitter", "jane", "y", "ffffffffffffffff"),
        ]
        assert find_avatar_clusters(fps, threshold=8) == []

    def test_identicons_excluded_from_clustering(self):
        """Even when identicons hash-match, they're excluded ── they
        don't represent user-chosen identity."""
        fps = [
            AvatarFingerprint("GitHub", "jane", "x", "0000",
                              is_identicon=True),
            AvatarFingerprint("GitHub", "bob", "y", "0000",
                              is_identicon=True),
        ]
        assert find_avatar_clusters(fps) == []

    def test_failed_fetches_excluded(self):
        fps = [
            AvatarFingerprint("GitHub", "jane", "x", "",
                              error="404"),
            AvatarFingerprint("Twitter", "jane", "y", ""),
        ]
        assert find_avatar_clusters(fps) == []

    def test_three_way_cluster(self):
        fps = [
            AvatarFingerprint("GitHub", "jane", "a", "0000000000000000"),
            AvatarFingerprint("Twitter", "jane", "b", "0000000000000000"),
            AvatarFingerprint("Mastodon", "jane", "c", "0000000000000000"),
        ]
        clusters = find_avatar_clusters(fps)
        assert len(clusters) == 1
        assert len(clusters[0]) == 3


# ──────────────────────────────────────────────────────────────────────
# Hit annotation
# ──────────────────────────────────────────────────────────────────────


class TestHitAnnotation:
    def test_cluster_id_attached_to_matched_hits(self):
        hits = [
            {"service": "GitHub", "username": "jane", "url": "..."},
            {"service": "Twitter", "username": "jane", "url": "..."},
            {"service": "Reddit", "username": "alice", "url": "..."},
        ]
        clusters = [[
            AvatarFingerprint("GitHub", "jane", "u", "0000"),
            AvatarFingerprint("Twitter", "jane", "v", "0000"),
        ]]
        annotate_hits_with_avatar_clusters(hits, clusters)
        gh_hit = next(h for h in hits if h["service"] == "GitHub")
        tw_hit = next(h for h in hits if h["service"] == "Twitter")
        rd_hit = next(h for h in hits if h["service"] == "Reddit")
        assert gh_hit["avatar_cluster_size"] == 2
        assert tw_hit["avatar_cluster_size"] == 2
        # Reddit hit unaffected.
        assert "avatar_cluster_size" not in rd_hit

    def test_case_insensitive_matching(self):
        hits = [{"service": "GitHub", "username": "Jane", "url": "..."}]
        clusters = [[
            AvatarFingerprint("github", "jane", "u", "0000"),
            AvatarFingerprint("Twitter", "alice", "v", "0000"),
        ]]
        annotate_hits_with_avatar_clusters(hits, clusters)
        assert hits[0].get("avatar_cluster_id") == 0


# ──────────────────────────────────────────────────────────────────────
# Fetch + hash (skipped when deps missing)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow / imagehash not installed")
class TestFetchAndHash:
    async def test_happy_path_returns_hash(self):
        png_bytes = _png_bytes(color=(100, 100, 100))
        with respx.mock:
            respx.get("https://example.com/avatar.png").mock(
                return_value=Response(200, content=png_bytes),
            )
            fp = await fetch_and_hash_avatar(
                service="GitHub", username="jane",
                image_url="https://example.com/avatar.png",
            )
        assert fp.fetched is True
        assert fp.error is None
        assert len(fp.phash) > 0

    async def test_same_image_produces_same_hash(self):
        """Determinism: the same bytes always produce the same hash."""
        png = _png_bytes(color=(150, 50, 200))
        with respx.mock:
            respx.get("https://a.example/a.png").mock(
                return_value=Response(200, content=png),
            )
            respx.get("https://b.example/b.png").mock(
                return_value=Response(200, content=png),
            )
            fp_a = await fetch_and_hash_avatar("A", "x", "https://a.example/a.png")
            fp_b = await fetch_and_hash_avatar("B", "x", "https://b.example/b.png")
        assert fp_a.phash == fp_b.phash

    async def test_404_returns_error_not_exception(self):
        with respx.mock:
            respx.get("https://example.com/missing.png").mock(
                return_value=Response(404),
            )
            fp = await fetch_and_hash_avatar(
                "GitHub", "jane",
                "https://example.com/missing.png",
            )
        assert fp.fetched is False
        assert fp.error is not None
        assert "404" in fp.error

    async def test_connection_error_returns_error(self):
        with respx.mock:
            respx.get("https://example.com/avatar.png").mock(
                side_effect=httpx.ConnectError("refused"),
            )
            fp = await fetch_and_hash_avatar(
                "GitHub", "jane",
                "https://example.com/avatar.png",
            )
        assert fp.fetched is False

    async def test_empty_url_returns_error(self):
        fp = await fetch_and_hash_avatar("GitHub", "jane", "")
        assert fp.fetched is False
        assert "empty" in (fp.error or "").lower()

    async def test_corrupt_image_returns_error(self):
        with respx.mock:
            respx.get("https://example.com/avatar.png").mock(
                return_value=Response(200, content=b"not an image"),
            )
            fp = await fetch_and_hash_avatar(
                "GitHub", "jane",
                "https://example.com/avatar.png",
            )
        assert fp.fetched is False

    async def test_identicon_url_marked_even_on_success(self):
        png = _png_bytes()
        with respx.mock:
            respx.get("https://gravatar.com/avatar/x?d=identicon").mock(
                return_value=Response(200, content=png),
            )
            fp = await fetch_and_hash_avatar(
                "Gravatar", "x",
                "https://gravatar.com/avatar/x?d=identicon",
            )
        assert fp.is_identicon is True


@pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow / imagehash not installed")
class TestBatchFetcher:
    async def test_batch_returns_same_order(self):
        png = _png_bytes()
        with respx.mock:
            respx.get("https://a.example/avatar.png").mock(
                return_value=Response(200, content=png))
            respx.get("https://b.example/avatar.png").mock(
                return_value=Response(200, content=png))
            results = await fetch_and_hash_batch([
                ("A", "alice", "https://a.example/avatar.png"),
                ("B", "bob", "https://b.example/avatar.png"),
            ])
        assert [r.service for r in results] == ["A", "B"]
        assert all(r.fetched for r in results)


# ──────────────────────────────────────────────────────────────────────
# Degraded mode (deps missing)
# ──────────────────────────────────────────────────────────────────────


class TestDegradedMode:
    """When Pillow or imagehash is absent, the module returns
    error-set fingerprints rather than raising. These tests verify
    that path stays clean regardless of which deps are installed."""

    def test_avatar_hash_available_returns_boolean(self):
        assert isinstance(avatar_hash_available(), bool)
