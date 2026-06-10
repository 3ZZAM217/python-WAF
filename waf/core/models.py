"""
waf.core.models
~~~~~~~~~~~~~~~

Typed domain objects for the WAF inspection pipeline.

Using dataclasses (stdlib, zero deps) ensures every component in the
inspection chain speaks the same typed contract rather than raw primitives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True, slots=True)
class InspectionContext:
    """
    Immutable snapshot of an incoming HTTP request.

    Constructed once per request in the proxy layer and passed through
    the entire inspection pipeline.  ``frozen=True`` prevents accidental
    mutation mid-pipeline; ``slots=True`` reduces per-instance memory.

    Attributes:
        ip:           Client IP address (post X-Forwarded-For resolution).
        method:       HTTP method (GET, POST, …).
        path:         URL path component (e.g. ``/login``).
        query_string: Raw query string (e.g. ``id=1&name=foo``).
        headers:      Request headers dict (lowercase keys).
        body:         Raw request body bytes.
    """

    ip: str
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body: bytes = field(default=b"", hash=False, compare=False)


@dataclass(frozen=True, slots=True)
class BlockDecision:
    """
    Result object returned by :class:`~waf.core.engine.WAFEngine.inspect`.

    Using a named dataclass (rather than a bare ``tuple[bool, str]``) makes
    callers explicit and prevents argument-order bugs.

    Attributes:
        allowed:  ``True`` if the request may be forwarded.
        reason:   Human-readable explanation of the decision.
        rule_id:  Machine-readable rule identifier (e.g. ``SQLI-001``),
                  empty string when ``allowed=True``.
    """

    allowed: bool
    reason: str
    rule_id: str = ""

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def allow(cls) -> "BlockDecision":
        """Factory: request passed all checks."""
        return cls(allowed=True, reason="Passed", rule_id="")

    @classmethod
    def block(cls, reason: str, rule_id: str) -> "BlockDecision":
        """Factory: request failed a security rule."""
        return cls(allowed=False, reason=reason, rule_id=rule_id)
