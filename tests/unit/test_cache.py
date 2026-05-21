"""Tests for core/cache.py — SQLite-backed TTL cache."""
import os
import tempfile
from pathlib import Path

import pytest

from nexusrecon.core.cache import DEFAULT_TTLS, Cache


@pytest.fixture
def cache() -> Cache:
    """Create a fresh isolated cache for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    c = Cache(db_path=path)
    yield c
    try:
        os.unlink(path)
    except OSError:
        pass


class TestCache:
    def test_init_in_memory(self):
        cache = Cache(db_path=":memory:")
        assert cache is not None

    def test_set_and_get(self, cache):
        cache.set("test_source", "query1", {"data": [1, 2, 3]})
        result = cache.get("test_source", "query1")
        assert result is not None
        assert result == {"data": [1, 2, 3]}

    def test_get_missing(self, cache):
        result = cache.get("unknown_source", "missing_query")
        assert result is None

    def test_overwrite(self, cache):
        cache.set("src", "q", "value1")
        cache.set("src", "q", "value2")
        result = cache.get("src", "q")
        assert result == "value2"

    def test_multiple_keys(self, cache):
        cache.set("src", "a", 1)
        cache.set("src", "b", 2)
        cache.set("src", "c", 3)
        assert cache.get("src", "a") == 1
        assert cache.get("src", "b") == 2
        assert cache.get("src", "c") == 3

    def test_stats(self, cache):
        cache.set("src1", "k1", "v1")
        cache.set("src1", "k2", "v2")
        cache.get("src1", "k1")
        cache.get("src1", "k1")
        cache.get("src1", "k2")
        stats = cache.stats()
        assert stats["total_entries"] == 2
        assert stats["active_entries"] == 2

    def test_stats_empty(self, cache):
        stats = cache.stats()
        assert stats["total_entries"] == 0

    def test_invalidate(self, cache):
        cache.set("src", "q", "data")
        assert cache.get("src", "q") is not None
        deleted = cache.invalidate("src", "q")
        assert deleted is True
        assert cache.get("src", "q") is None

    def test_invalidate_missing(self, cache):
        deleted = cache.invalidate("src", "nonexistent")
        assert deleted is False

    def test_invalidate_source(self, cache):
        cache.set("src1", "a", 1)
        cache.set("src1", "b", 2)
        cache.set("src2", "c", 3)
        count = cache.invalidate_source("src1")
        assert count == 2
        assert cache.get("src1", "a") is None
        assert cache.get("src2", "c") is not None

    def test_purge_expired(self, cache):
        cache.set("src", "q", "data", ttl=-1)
        count = cache.purge_expired()
        assert count >= 1
        assert cache.get("src", "q") is None

    def test_persistent_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            c1 = Cache(db_path=str(db_path))
            c1.set("src", "persisted", "stored")
            del c1
            c2 = Cache(db_path=str(db_path))
            result = c2.get("src", "persisted")
            assert result == "stored"

    def test_complex_data_types(self, cache):
        data = {
            "string": "hello",
            "number": 42,
            "list": [1, 2, 3],
            "dict": {"nested": "value"},
            "bool": True,
        }
        cache.set("src", "complex", data)
        result = cache.get("src", "complex")
        assert result == data
        assert result["list"] == [1, 2, 3]
        assert result["dict"]["nested"] == "value"

    def test_default_ttls(self):
        assert DEFAULT_TTLS["crtsh"] == 86400
        assert DEFAULT_TTLS["dns"] == 3600
        assert DEFAULT_TTLS["hibp"] == 604800
        assert DEFAULT_TTLS["default"] == 3600

    def test_ttl_expiration(self, cache):
        cache.set("src", "expires_soon", "data", ttl=0)
        import time
        time.sleep(0.01)
        result = cache.get("src", "expires_soon")
        assert result is None
