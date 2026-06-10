"""
waf.security.ip_filter
~~~~~~~~~~~~~~~~~~~~~~~

IP blocklist filtering — loads a file of malicious IPs and CIDR ranges,
supports hot-reload, and performs O(n) lookup with ``ipaddress`` stdlib.

Design decisions
----------------
* Uses Python's stdlib ``ipaddress`` module — no third-party dependency.
* Supports both individual IPs (``192.168.1.1``) and CIDR ranges
  (``10.0.0.0/8``, ``2001:db8::/32``).
* Lines beginning with ``#`` and blank lines are ignored, making the
  blocklist file human-maintainable with comments.
* **Hot-reload** is implemented by checking the file's modification
  timestamp (``mtime``) on every call to ``is_blocked()``.  A stat()
  call is O(1) and negligible compared to network I/O; no background
  thread or inotify dependency is required.
* All network objects are stored in a ``frozenset`` so that the lookup
  iteration is over an immutable snapshot — thread-safe without locking.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

from waf.utils.logger import get_logger

log: logging.Logger = get_logger(__name__)

# Type alias for the set of network objects loaded from the blocklist file.
_NetworkSet = frozenset[ipaddress.IPv4Network | ipaddress.IPv6Network]


class IPFilter:
    """
    Checks whether a client IP address is on the blocklist.

    Args:
        blocklist_path: Path to a text file containing one IP or CIDR
                        range per line.  Relative paths are resolved
                        against the project root.
        hot_reload:     If ``True``, the blocklist file is re-read
                        whenever its modification time changes.
    """

    def __init__(self, blocklist_path: str | Path, *, hot_reload: bool = True) -> None:
        self._path = Path(blocklist_path).resolve()
        self._hot_reload = hot_reload
        self._networks: _NetworkSet = frozenset()
        self._last_mtime: float = 0.0
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_blocked(self, ip: str) -> bool:
        """
        Return ``True`` if *ip* is present in or overlapped by a blocklisted
        network, ``False`` otherwise.

        Performs a hot-reload check (stat only) before each evaluation
        when ``hot_reload=True`` was specified at construction time.

        Args:
            ip: Dotted-decimal or colon-separated IP address string.

        Returns:
            ``bool`` — ``True`` means the request should be blocked.
        """
        if self._hot_reload:
            self._reload_if_changed()

        try:
            client_addr = ipaddress.ip_address(ip)
        except ValueError:
            log.warning("IPFilter received unparseable IP address: %r", ip)
            return False  # Fail open — do not block on parse errors

        return any(client_addr in network for network in self._networks)

    @property
    def blocked_network_count(self) -> int:
        """Number of network entries currently loaded from the blocklist."""
        return len(self._networks)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Read the blocklist file and populate ``self._networks``."""
        if not self._path.exists():
            log.info(
                "Blocklist file not found at %s — IP filtering disabled.", self._path
            )
            self._networks = frozenset()
            return

        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        skipped = 0

        for lineno, line in enumerate(
            self._path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                # ``strict=False`` accepts host bits set in CIDR notation
                # (e.g. ``192.168.1.100/24`` is treated as ``192.168.1.0/24``).
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.warning(
                    "Blocklist line %d: invalid IP/CIDR %r — skipped.", lineno, entry
                )
                skipped += 1

        self._networks = frozenset(networks)
        try:
            self._last_mtime = self._path.stat().st_mtime
        except OSError:
            self._last_mtime = 0.0

        log.info(
            "IPFilter loaded %d entries from %s (%d skipped).",
            len(self._networks),
            self._path,
            skipped,
        )

    def _reload_if_changed(self) -> None:
        """Stat the blocklist file and reload only if its mtime has changed."""
        try:
            current_mtime = self._path.stat().st_mtime
        except OSError:
            return  # File disappeared — keep the last-known list
        if current_mtime != self._last_mtime:
            log.info("Blocklist file changed — reloading.")
            self._load()
