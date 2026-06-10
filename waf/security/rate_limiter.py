"""
waf.security.rate_limiter
~~~~~~~~~~~~~~~~~~~~~~~~~~

Sliding-window rate limiter with async-safe per-IP locking and LRU eviction.

Design decisions
----------------
* **Sliding window** (not fixed window) — more accurate than a token bucket
  for short-burst detection; each timestamp is stored individually and
  evicted once outside the configured window.
* **Per-IP ``asyncio.Lock``** — prevents race conditions when multiple
  concurrent coroutines check/update the same IP's history.  Using a
  single global lock would serialise all requests; per-IP locks allow
  true concurrency across distinct clients.
* **LRU eviction via ``collections.OrderedDict``** — bounds memory usage
  under sustained attack from many unique IPs.  When ``max_ips`` is
  reached, the least-recently-seen IP is evicted.  ``OrderedDict`` gives
  O(1) move-to-end and O(1) popitem(last=False) for LRU ordering.
* **Metrics attributes** — ``blocked_count`` and ``total_requests`` are
  plain integer counters that can be scraped by a Prometheus endpoint or
  logged by a health-check handler without introducing an external library.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict

import logging
from waf.utils.logger import get_logger

log: logging.Logger = get_logger(__name__)


class RateLimiter:
    """
    Sliding-window, per-IP rate limiter.

    Args:
        max_requests:  Maximum requests allowed within *window_seconds*.
        window_seconds: Duration of the sliding window in seconds.
        max_ips:       Maximum number of unique IPs tracked in memory
                       before LRU eviction removes the oldest entry.

    Example::

        limiter = RateLimiter(max_requests=30, window_seconds=60)
        is_ok = await limiter.is_allowed("203.0.113.1")
    """

    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: int = 60,
        max_ips: int = 100_000,
    ) -> None:
        if max_requests <= 0:
            raise ValueError(f"max_requests must be positive, got {max_requests}")
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        if max_ips <= 0:
            raise ValueError(f"max_ips must be positive, got {max_ips}")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_ips = max_ips

        # Ordered dict preserves insertion order for LRU eviction.
        # Values: list of float timestamps within the current window.
        self._store: OrderedDict[str, list[float]] = OrderedDict()

        # Per-IP asyncio locks — created lazily to avoid pre-allocating
        # locks for IPs that may never appear.
        self._locks: dict[str, asyncio.Lock] = {}
        # A single meta-lock guards the creation of per-IP locks to prevent
        # two coroutines from racing to create a lock for the same new IP.
        self._meta_lock = asyncio.Lock()

        # Metrics
        self.total_requests: int = 0
        self.blocked_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def is_allowed(self, ip: str) -> bool:
        """
        Check whether the request from *ip* is within the rate limit.

        Updates internal state atomically using a per-IP async lock.

        Args:
            ip: Client IP address string.

        Returns:
            ``True`` if the request is within the allowed rate;
            ``False`` if the client has exceeded the limit.
        """
        self.total_requests += 1
        lock = await self._get_or_create_lock(ip)

        async with lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds

            # Retrieve existing history or start fresh
            history = self._store.get(ip, [])

            # Evict timestamps outside the sliding window
            history = [ts for ts in history if ts > cutoff]

            if len(history) >= self.max_requests:
                # Store updated (cleaned) history and mark IP as recently seen
                self._store[ip] = history
                self._store.move_to_end(ip)
                self.blocked_count += 1
                return False

            # Record this request and update the store
            history.append(now)
            self._store[ip] = history
            self._store.move_to_end(ip)

            # LRU eviction: remove the oldest IP when capacity is exceeded
            if len(self._store) > self.max_ips:
                evicted_ip, _ = self._store.popitem(last=False)
                # Also remove its lock to free memory
                self._locks.pop(evicted_ip, None)
                log.debug("RateLimiter evicted LRU entry for IP %s", evicted_ip)

            return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_or_create_lock(self, ip: str) -> asyncio.Lock:
        """Return the per-IP lock, creating it atomically if absent."""
        # Fast path: lock already exists (no meta-lock needed)
        if ip in self._locks:
            return self._locks[ip]

        # Slow path: atomically create a new lock for this IP
        async with self._meta_lock:
            # Re-check after acquiring meta-lock (double-checked locking)
            if ip not in self._locks:
                self._locks[ip] = asyncio.Lock()
            return self._locks[ip]