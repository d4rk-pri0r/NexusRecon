"""
Per-source rate limiter using token bucket algorithm.

Each source (Shodan, GitHub, crt.sh, etc.) gets its own bucket.
Global rate limits are also enforced.  Burst detection prevents
operator fingerprinting via rapid sequential requests.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

import structlog

log = structlog.get_logger(__name__)


class TokenBucket:
    """
    Thread/async-safe token bucket rate limiter.

    rate: tokens added per second
    capacity: max tokens in bucket (burst allowance)
    """

    def __init__(self, rate: float, capacity: Optional[float] = None) -> None:
        self.rate = rate
        self.capacity = capacity or max(rate * 2, 1.0)
        self._tokens = self.capacity
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_update = now

    async def acquire(self, count: float = 1.0) -> float:
        """Wait until count tokens are available. Returns wait time in seconds."""
        async with self._lock:
            self._refill()
            if self._tokens >= count:
                self._tokens -= count
                return 0.0
            # Need to wait
            deficit = count - self._tokens
            wait_time = deficit / self.rate
            self._tokens = 0.0
            await asyncio.sleep(wait_time)
            self._last_update = time.monotonic()
            return wait_time

    def acquire_sync(self, count: float = 1.0) -> float:
        """Synchronous version. Returns wait time in seconds."""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_update = now

        if self._tokens >= count:
            self._tokens -= count
            return 0.0

        deficit = count - self._tokens
        wait_time = deficit / self.rate
        self._tokens = 0.0
        time.sleep(wait_time)
        self._last_update = time.monotonic()
        return wait_time


class BurstDetector:
    """
    Sliding window burst detector.

    Tracks request timestamps in a window and self-throttles if
    too many requests happen within the window to avoid fingerprinting.
    """

    def __init__(self, threshold: int, window_sec: float) -> None:
        self.threshold = threshold
        self.window_sec = window_sec
        self._timestamps: Deque[float] = deque()

    def record_and_check(self) -> float:
        """
        Record a request and check for burst.
        Returns sleep time if burst detected, else 0.
        """
        now = time.monotonic()
        # Remove old entries outside window
        while self._timestamps and self._timestamps[0] < now - self.window_sec:
            self._timestamps.popleft()

        self._timestamps.append(now)

        if len(self._timestamps) > self.threshold:
            # Burst detected — sleep until window edge
            oldest = self._timestamps[0]
            sleep_time = oldest + self.window_sec - now
            if sleep_time > 0:
                log.warning("Burst detected, throttling", sleep_sec=round(sleep_time, 2))
                return sleep_time

        return 0.0


class SourceRateLimiter:
    """
    Per-source rate limiter.  Each source key gets its own TokenBucket.
    Optionally also applies burst detection.
    """

    def __init__(
        self,
        source_rates: Dict[str, float],
        burst_threshold: int = 10,
        burst_window_sec: float = 1.0,
        burst_detection_enabled: bool = True,
    ) -> None:
        self._rates = source_rates
        self._buckets: Dict[str, TokenBucket] = {}
        self._burst_detectors: Dict[str, BurstDetector] = {}
        self._burst_detection_enabled = burst_detection_enabled
        self._burst_threshold = burst_threshold
        self._burst_window_sec = burst_window_sec

    def _get_bucket(self, source: str) -> TokenBucket:
        if source not in self._buckets:
            rate = self._rates.get(source.lower(), self._rates.get("default", 1.0))
            self._buckets[source] = TokenBucket(rate=rate)
        return self._buckets[source]

    def _get_burst_detector(self, source: str) -> BurstDetector:
        if source not in self._burst_detectors:
            self._burst_detectors[source] = BurstDetector(
                self._burst_threshold, self._burst_window_sec
            )
        return self._burst_detectors[source]

    async def wait(self, source: str) -> None:
        """Async wait for rate limit on source."""
        bucket = self._get_bucket(source)
        await bucket.acquire()

        if self._burst_detection_enabled:
            detector = self._get_burst_detector(source)
            sleep_time = detector.record_and_check()
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

    def wait_sync(self, source: str) -> None:
        """Synchronous wait for rate limit on source."""
        bucket = self._get_bucket(source)
        bucket.acquire_sync()

        if self._burst_detection_enabled:
            detector = self._get_burst_detector(source)
            sleep_time = detector.record_and_check()
            if sleep_time > 0:
                time.sleep(sleep_time)

    def update_rate(self, source: str, rate: float) -> None:
        """Update rate for a source (e.g., after API key auth)."""
        self._rates[source.lower()] = rate
        if source in self._buckets:
            self._buckets[source].rate = rate


class RateLimiter(SourceRateLimiter):
    """
    Alias for SourceRateLimiter with convenience constructor from StealthProfile.
    """

    @classmethod
    def from_profile(cls, profile: "StealthProfile") -> "RateLimiter":  # type: ignore[name-defined]
        from nexusrecon.opsec.profiles import StealthProfile
        return cls(
            source_rates=profile.source_rates,
            burst_threshold=profile.burst_threshold,
            burst_window_sec=profile.burst_window_sec,
            burst_detection_enabled=profile.burst_detection_enabled,
        )
