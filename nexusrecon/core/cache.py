"""
SQLite-backed TTL cache for tool results.

Cache key: sha256(source_name + "|" + canonical_query)
Separate TTL per source type:
  - crt.sh: 24 hours
  - Shodan: 6 hours
  - breach DB: 7 days
  - live DNS: 1 hour
  - news/jobs: 1 hour
  - GitHub: 2 hours
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Default TTLs in seconds
DEFAULT_TTLS: dict[str, int] = {
    "crtsh": 86400,           # 24h
    "shodan": 21600,          # 6h
    "censys": 21600,          # 6h
    "virustotal": 14400,      # 4h
    "greynoise": 3600,        # 1h
    "hibp": 604800,           # 7d
    "dehashed": 604800,       # 7d
    "intelx": 604800,         # 7d
    "securitytrails": 21600,  # 6h
    "dns": 3600,              # 1h
    "whois": 86400,           # 24h
    "wayback": 86400,         # 24h
    "github": 7200,           # 2h
    "hunter": 86400,          # 24h
    "urlscan": 21600,         # 6h
    "bgpview": 86400,         # 24h
    "news": 3600,             # 1h
    "jobs": 3600,             # 1h
    "nvd": 86400,             # 24h
    "kev": 86400,             # 24h
    "epss": 86400,            # 24h
    "default": 3600,          # 1h fallback
}


class Cache:
    """
    Thread-safe SQLite cache with per-source TTLs.

    Shared with the LangGraph state database (same SQLite file, separate table).
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        if self.db_path == ":memory:":
            self.db_path = "file::memory:?cache=shared"
        self._init_db()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_cache (
                cache_key TEXT PRIMARY KEY,
                source    TEXT NOT NULL,
                query     TEXT NOT NULL,
                result    TEXT NOT NULL,
                created   REAL NOT NULL,
                expires   REAL NOT NULL,
                hit_count INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_expires ON tool_cache(expires)
        """)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        # Table creation is handled in _conn() context manager
        pass

    @staticmethod
    def _make_key(source: str, query: Any) -> str:
        canonical = source + "|" + json.dumps(query, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def get(self, source: str, query: Any) -> Any | None:
        """Return cached result or None if missing/expired."""
        key = self._make_key(source, query)
        now = time.time()

        with self._conn() as conn:
            row = conn.execute(
                "SELECT result, expires FROM tool_cache WHERE cache_key = ?",
                (key,),
            ).fetchone()

            if row is None:
                return None

            if now > row["expires"]:
                conn.execute("DELETE FROM tool_cache WHERE cache_key = ?", (key,))
                return None

            conn.execute(
                "UPDATE tool_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
                (key,),
            )
            return json.loads(row["result"])

    def set(self, source: str, query: Any, result: Any, ttl: int | None = None) -> None:
        """Store a result in the cache."""
        if ttl is None:
            ttl = DEFAULT_TTLS.get(source.lower(), DEFAULT_TTLS["default"])

        key = self._make_key(source, query)
        now = time.time()

        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tool_cache
                    (cache_key, source, query, result, created, expires, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    key,
                    source,
                    json.dumps(query, sort_keys=True, default=str),
                    json.dumps(result, default=str),
                    now,
                    now + ttl,
                ),
            )

    def invalidate(self, source: str, query: Any) -> bool:
        """Remove a specific cache entry. Returns True if deleted."""
        key = self._make_key(source, query)
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM tool_cache WHERE cache_key = ?", (key,)
            )
            return cursor.rowcount > 0

    def invalidate_source(self, source: str) -> int:
        """Remove all cache entries for a source. Returns count deleted."""
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM tool_cache WHERE source = ?", (source,)
            )
            return cursor.rowcount

    def purge_expired(self) -> int:
        """Remove all expired entries. Returns count deleted."""
        now = time.time()
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM tool_cache WHERE expires < ?", (now,)
            )
            count = cursor.rowcount
        if count:
            log.info("Cache purged expired entries", count=count)
        return count

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM tool_cache").fetchone()[0]
            now = time.time()
            expired = conn.execute(
                "SELECT COUNT(*) FROM tool_cache WHERE expires < ?", (now,)
            ).fetchone()[0]
            hits = conn.execute(
                "SELECT SUM(hit_count) FROM tool_cache"
            ).fetchone()[0] or 0
            by_source = conn.execute(
                "SELECT source, COUNT(*) as cnt FROM tool_cache GROUP BY source"
            ).fetchall()

        return {
            "total_entries": total,
            "expired_entries": expired,
            "active_entries": total - expired,
            "total_hits": hits,
            "by_source": {r["source"]: r["cnt"] for r in by_source},
        }
