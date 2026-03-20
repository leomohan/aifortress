"""
rate_limiter.py  —  Sliding-window and token-bucket rate limiting
AI Fortress · Chapter 5 · Code Sample 5.A

Two complementary algorithms:

  SlidingWindowRateLimiter  — counts requests in the last N seconds using a
    deque of timestamps. Simple, accurate, and resistant to boundary bursting
    (the failure mode of fixed-window limiters). Best for general request caps.

  TokenBucketRateLimiter  — refills tokens at a constant rate; allows short
    bursts up to bucket capacity while enforcing a long-run average. Best for
    APIs where occasional bursts are acceptable but sustained high rates are not.

Both support per-key limits (API key, IP address, user ID) with configurable
tiers (free / pro / enterprise) and emit Retry-After values for 429 responses.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional


class RateLimitExceeded(Exception):
    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = round(retry_after, 2)


@dataclass
class RateTier:
    name:                str
    requests_per_minute: int
    burst_multiplier:    float = 1.5   # token bucket burst = rpm * multiplier / 60


# Pre-built tiers
TIERS = {
    "free":       RateTier("free",       requests_per_minute=20),
    "pro":        RateTier("pro",        requests_per_minute=120),
    "enterprise": RateTier("enterprise", requests_per_minute=1200),
}


class SlidingWindowRateLimiter:
    """
    Per-key sliding-window rate limiter backed by in-memory deques.

    For production, replace the in-memory store with Redis using a Lua script
    to make the check-and-increment atomic across replicas.

    Parameters
    ----------
    requests_per_minute : Default limit (overridden per-key by key_tiers)
    window_seconds      : Window size (default 60)
    key_tiers           : Optional mapping of key → RateTier for per-key limits
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        window_seconds:      int = 60,
        key_tiers:           Optional[Dict[str, RateTier]] = None,
    ):
        self.default_rpm     = requests_per_minute
        self.window_seconds  = window_seconds
        self.key_tiers       = key_tiers or {}
        self._windows:       Dict[str, Deque[float]] = defaultdict(deque)
        self._lock           = threading.Lock()

    def check(self, key: str) -> None:
        """
        Record a request for `key`. Raises RateLimitExceeded if over limit.
        Thread-safe.
        """
        now  = time.monotonic()
        tier = self.key_tiers.get(key)
        rpm  = tier.requests_per_minute if tier else self.default_rpm
        limit = rpm  # requests per window_seconds (default window = 60s)

        with self._lock:
            window = self._windows[key]
            cutoff = now - self.window_seconds
            # Evict expired timestamps
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= limit:
                # Retry-After: time until oldest request leaves the window
                oldest      = window[0]
                retry_after = (oldest + self.window_seconds) - now
                raise RateLimitExceeded(
                    f"Rate limit exceeded for key '{key}': {limit} req/{self.window_seconds}s. "
                    f"Retry after {retry_after:.1f}s.",
                    retry_after=retry_after,
                )
            window.append(now)

    def current_count(self, key: str) -> int:
        """Return number of requests in the current window for a key."""
        now    = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            window = self._windows[key]
            return sum(1 for t in window if t >= cutoff)

    def reset(self, key: str) -> None:
        """Clear the rate limit window for a key (e.g. after key rotation)."""
        with self._lock:
            self._windows.pop(key, None)


class TokenBucketRateLimiter:
    """
    Per-key token-bucket rate limiter.

    Tokens refill at `refill_rate` tokens/second.
    Bucket capacity = `capacity` tokens (max burst).

    Parameters
    ----------
    capacity     : Bucket capacity in tokens (max burst)
    refill_rate  : Tokens added per second
    cost         : Tokens consumed per request (default 1)
    """

    def __init__(
        self,
        capacity:    float = 10.0,
        refill_rate: float = 1.0,
        cost:        float = 1.0,
    ):
        self.capacity    = capacity
        self.refill_rate = refill_rate
        self.cost        = cost
        self._buckets:   Dict[str, Dict] = defaultdict(
            lambda: {"tokens": capacity, "last_refill": time.monotonic()}
        )
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        """Consume `cost` tokens for `key`. Raises RateLimitExceeded if bucket empty."""
        with self._lock:
            bucket = self._buckets[key]
            now    = time.monotonic()

            # Refill
            elapsed = now - bucket["last_refill"]
            bucket["tokens"] = min(
                self.capacity,
                bucket["tokens"] + elapsed * self.refill_rate,
            )
            bucket["last_refill"] = now

            if bucket["tokens"] < self.cost:
                deficit     = self.cost - bucket["tokens"]
                retry_after = deficit / self.refill_rate
                raise RateLimitExceeded(
                    f"Token bucket empty for key '{key}'. "
                    f"Retry after {retry_after:.1f}s.",
                    retry_after=retry_after,
                )
            bucket["tokens"] -= self.cost

    def available_tokens(self, key: str) -> float:
        """Return current token count for a key (after refill)."""
        with self._lock:
            bucket  = self._buckets[key]
            now     = time.monotonic()
            elapsed = now - bucket["last_refill"]
            return min(self.capacity, bucket["tokens"] + elapsed * self.refill_rate)
