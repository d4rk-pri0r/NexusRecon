"""
Cross-campaign handle ubiquity tracking (Phase B item B3).

If `jdoe` shows up in every campaign you run, it's a common handle
pattern, not your specific target's identity. The Phase B common-
handles list and name-frequency tables catch the obvious cases (john,
smith, admin, mjohnson). This tracker catches the long tail: handles
that pass both Phase B checks but recur across many unrelated
campaigns because they're just popular handles.

Mechanic:
  - After maigret produces hits, the tool records each
    (handle, service, campaign_id) observation into a persistent
    sqlite database.
  - On future scoring runs, the attribution scorer reads the handle's
    cross-campaign campaign-count and contributes an additional
    uniqueness penalty proportional to that count.
  - Handles seen in 1 campaign get no penalty (no ubiquity signal
    yet). 4+ campaigns gets meaningful penalty. 10+ campaigns is
    treated as "definitely common."

## Privacy

Storing handles across campaigns is sensitive. A leaked DB would
disclose which handles an operator has investigated, which could
help target the operator or compromise engagement confidentiality.
Two mitigations:

  - **Salted SHA-256 hashing**: only the hash of the handle is
    stored, never the plaintext. The salt is generated once on first
    DB init and stored alongside the data. Same handle within an
    install hashes to the same value (so ubiquity counting works).
    Different installs use different salts (so collusion between
    operators' leaked DBs reveals nothing).
  - **Opt-in by default**: a campaign only records observations when
    a tracker is explicitly bound to the registry (via
    ``set_current_tracker`` or the campaign runner's setup). The
    framework ships with no tracker bound, so by default nothing
    persists.

## Default location

When opted-in, the DB lives at ``~/.nexusrecon/handle_ubiquity.db``
unless overridden via:

  - The ``db_path=`` constructor argument, OR
  - The ``NEXUS_UBIQUITY_DB_PATH`` env var.

Operators who want strict isolation per engagement should pass a
campaign-scoped DB path. Operators happy with cross-engagement
learning leave the default.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

# Default location ── ~/.nexusrecon/handle_ubiquity.db. Created on
# first init. The directory is created with mode 0o700 (owner-only).
_DEFAULT_DB_PATH = Path.home() / ".nexusrecon" / "handle_ubiquity.db"

# Ubiquity → commonness mapping. Tunable here so operators can see
# the curve without reading the scoring math.
#
# Seen in 1 campaign: no signal yet (could be the first time we see
# what turns out to be a common handle). 0.0 commonness.
# 2-3 campaigns: starting to look common. 0.30.
# 4-10 campaigns: very common across this operator's work. 0.60.
# 10+ campaigns: universal handle. 0.85.
_UBIQUITY_CURVE = (
    (1, 0.0),
    (3, 0.30),
    (10, 0.60),
    (10**9, 0.85),
)


class HandleUbiquityTracker:
    """SQLite-backed cross-campaign handle observation store.

    Thread-safe via a per-instance lock around connection use. Same
    instance can be shared across all phase nodes in one campaign
    process.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            override = os.environ.get("NEXUS_UBIQUITY_DB_PATH")
            db_path = Path(override) if override else _DEFAULT_DB_PATH
        self._db_path = Path(db_path)
        self._lock = threading.Lock()
        self._salt: bytes | None = None
        self._conn: sqlite3.Connection | None = None
        self._initialise()

    # ── Public API ───────────────────────────────────────────────────

    @property
    def db_path(self) -> Path:
        return self._db_path

    def record_observation(
        self,
        handle: str,
        service: str,
        campaign_id: str,
        engagement_id: str | None = None,
        confidence: float | None = None,
    ) -> None:
        """Record that we saw ``handle`` on ``service`` during the
        ``campaign_id`` campaign. Idempotent ── repeated observations
        of the same ``(handle, service, campaign_id)`` triple are
        absorbed by the primary key constraint.

        Errors are swallowed and logged ── tracker failures must not
        crash the recon loop.
        """
        if not handle or not service or not campaign_id:
            return
        try:
            handle_hash = self._hash_handle(handle)
            with self._lock:
                self._conn.execute(
                    "INSERT OR IGNORE INTO handle_observations "
                    "(handle_hash, service, campaign_id, engagement_id, confidence) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (handle_hash, service.lower(), campaign_id,
                     engagement_id, confidence),
                )
                self._conn.commit()
        except sqlite3.Error:
            pass

    def campaign_count(self, handle: str) -> int:
        """Return the number of distinct campaigns this handle has
        been observed in. Used by the attribution scorer to derive a
        ubiquity penalty.

        Returns 0 if the handle has never been observed (or on DB
        error ── ubiquity is a refinement signal, not a blocker)."""
        if not handle:
            return 0
        try:
            handle_hash = self._hash_handle(handle)
            with self._lock:
                cur = self._conn.execute(
                    "SELECT COUNT(DISTINCT campaign_id) "
                    "FROM handle_observations WHERE handle_hash = ?",
                    (handle_hash,),
                )
                row = cur.fetchone()
                return int(row[0]) if row else 0
        except sqlite3.Error:
            return 0

    def commonness_score(self, handle: str) -> float:
        """Convert the handle's cross-campaign count into a
        commonness score in ``[0, 1]`` per the documented curve.

        Returns 0.0 for handles seen in only one campaign (no signal
        yet) or never seen at all."""
        count = self.campaign_count(handle)
        return _commonness_for_count(count)

    def total_observations(self) -> int:
        """Diagnostic ── how many rows in the store. For health checks."""
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT COUNT(*) FROM handle_observations"
                )
                row = cur.fetchone()
                return int(row[0]) if row else 0
        except sqlite3.Error:
            return 0

    def close(self) -> None:
        """Close the underlying SQLite connection. Safe to call
        multiple times; safe to call before ``__del__``."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    def __enter__(self) -> HandleUbiquityTracker:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── Internals ────────────────────────────────────────────────────

    def _initialise(self) -> None:
        """Open the SQLite connection, create the schema on first run,
        and load (or generate) the per-install salt."""
        # Ensure parent directory exists with restrictive permissions.
        # Best-effort ── if we can't chmod, the DB still works.
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self._db_path.parent, 0o700)
            except OSError:
                pass
        except OSError:
            # Parent dir creation failed ── this happens in some CI
            # environments. Fall back to an in-memory DB so the
            # framework can still function.
            self._db_path = Path(":memory:")

        self._conn = sqlite3.connect(
            str(self._db_path),
            isolation_level=None,  # autocommit; we do manual commits
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")

        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS handle_observations (
                handle_hash TEXT NOT NULL,
                service TEXT NOT NULL,
                campaign_id TEXT NOT NULL,
                engagement_id TEXT,
                confidence REAL,
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (handle_hash, service, campaign_id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_handle_hash "
            "ON handle_observations(handle_hash)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_campaign "
            "ON handle_observations(campaign_id)"
        )

        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS install_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

        # Load or generate the per-install salt. The salt prevents
        # cross-install handle-hash collisions ── one operator's leaked
        # DB can't be combined with another's to confirm shared targets.
        cur = self._conn.execute(
            "SELECT value FROM install_metadata WHERE key = 'handle_salt'"
        )
        row = cur.fetchone()
        if row is None:
            salt_hex = secrets.token_hex(16)
            self._conn.execute(
                "INSERT INTO install_metadata (key, value) VALUES (?, ?)",
                ("handle_salt", salt_hex),
            )
            self._conn.commit()
            self._salt = bytes.fromhex(salt_hex)
        else:
            self._salt = bytes.fromhex(row[0])

    def _hash_handle(self, handle: str) -> str:
        """Return a salted SHA-256 hex digest of the normalised handle.

        Normalisation: case-folded + stripped. So ``Jane.Doe`` and
        ``jane.doe`` hash to the same value within an install ── this
        is necessary for ubiquity counting to work across the case-
        variation we see in real handle data."""
        normalised = handle.strip().lower().encode("utf-8")
        h = hashlib.sha256()
        if self._salt is not None:
            h.update(self._salt)
        h.update(normalised)
        return h.hexdigest()


def _commonness_for_count(count: int) -> float:
    """Map a campaign-count to a commonness score per the documented
    curve. Used by both the tracker and the attribution scorer."""
    if count <= 0:
        return 0.0
    for threshold, score in _UBIQUITY_CURVE:
        if count <= threshold:
            return score
    return _UBIQUITY_CURVE[-1][1]


# ──────────────────────────────────────────────────────────────────────
# Global tracker access via ContextVar
# ──────────────────────────────────────────────────────────────────────
#
# Attribution scoring is called from many places; passing a tracker
# instance through every call site is noisy. A ContextVar lets the
# campaign runner bind a tracker once and have all downstream scoring
# pick it up automatically. By default the var is None ── scoring
# happens without ubiquity input, matching the opt-in default.

_current_tracker: ContextVar[HandleUbiquityTracker | None] = ContextVar(
    "nexus_handle_ubiquity_tracker", default=None,
)


def get_current_tracker() -> HandleUbiquityTracker | None:
    """Return the tracker bound by the enclosing ``ubiquity_context``,
    or ``None`` if no tracker is active. Attribution and maigret_tool
    call this to find a tracker without explicit parameter passing."""
    return _current_tracker.get()


@contextmanager
def ubiquity_context(tracker: HandleUbiquityTracker | None) -> Iterator[None]:
    """Bind a tracker for the duration of the ``with`` block.

    Pattern from the campaign runner::

        tracker = HandleUbiquityTracker()
        with ubiquity_context(tracker):
            await run_workflow(state)
        tracker.close()

    Inside the block, ``get_current_tracker()`` returns the tracker;
    outside, it returns None. Passing ``None`` explicitly bypasses
    ubiquity for a section (useful in tests).
    """
    token = _current_tracker.set(tracker)
    try:
        yield
    finally:
        _current_tracker.reset(token)
