"""
waf.security.rules_sqli
~~~~~~~~~~~~~~~~~~~~~~~~

SQL Injection (SQLi) detection rule — Rule ID: SQLI-001.

Detection strategy
------------------
A defence-in-depth approach using three sequential normalisation passes
before pattern matching:

1. **URL decode** — converts ``%27`` → ``'``, ``%20`` → space, etc.
2. **Double URL decode** — handles double-encoded payloads such as
   ``%2527`` → ``%27`` → ``'`` that bypass single-decode filters.
3. **Regex match** against a comprehensive pattern set covering:

   * UNION-based injection (``UNION SELECT``, ``UNION ALL SELECT``)
   * Boolean-blind injection (``OR 1=1``, ``AND 1=2``, etc.)
   * Error-based injection (``EXTRACTVALUE``, ``UPDATEXML``)
   * Time-based blind injection (``SLEEP()``, ``WAITFOR DELAY``,
     ``BENCHMARK()``, ``PG_SLEEP()``)
   * Stacked / batched queries (``;DROP``, ``;INSERT``, etc.)
   * Comment-based filter evasion (``--``, ``#``, ``/**/``)
   * Tautology patterns (``' OR '1'='1``)
   * Hex-encoded string literals (``0x41424344``)
   * Information-schema probing (``information_schema.tables``)

Limitations
-----------
Regex-based WAF rules are a complementary control, not a complete
solution. They should be layered with parameterised queries at the
application layer and an ORM that enforces type safety.
"""

from __future__ import annotations

import re
import urllib.parse

# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------

RULE_ID = "SQLI-001"

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_SQLI_PATTERN = re.compile(
    r"""
    # UNION-based injection
    \bunion\b[\s\S]{0,20}\bselect\b           # UNION [ALL] SELECT

    # Boolean-blind tautologies / contradictions
    |  \bor\b\s+\d+\s*=\s*\d+                # OR 1=1
    |  \band\b\s+\d+\s*=\s*\d+               # AND 1=2
    |  '\s*or\s*'[^']*'\s*=\s*'              # ' OR 'a'='a
    |  '\s*or\s+\d+\s*=\s*\d+               # ' OR 1=1

    # Comment-based filter evasion
    |  --[\s\r\n]                            # standard SQL line comment
    |  --$                                   # trailing comment (end of string)
    |  \#[\s\r\n]                            # MySQL line comment
    |  /\*[\s\S]*?\*/                        # block comment  /* ... */

    # Stacked / batched queries
    |  ;\s*(drop|insert|update|delete|create|alter|truncate|exec)\b

    # Time-based blind injection
    |  \bsleep\s*\(                          # SLEEP(n)
    |  \bwaitfor\b\s+\bdelay\b              # WAITFOR DELAY '0:0:5'
    |  \bbenchmark\s*\(                      # BENCHMARK(n, expr)
    |  \bpg_sleep\s*\(                       # PG_SLEEP(n) — PostgreSQL

    # Error-based injection
    |  \bextractvalue\s*\(                   # MySQL EXTRACTVALUE()
    |  \bupdatexml\s*\(                      # MySQL UPDATEXML()

    # Information schema / system table probing
    |  \binformation_schema\b
    |  \bsysobjects\b                        # MSSQL
    |  \bsyscolumns\b

    # Hex-encoded string literals (common obfuscation)
    |  \b0x[0-9a-f]{4,}\b

    # Malicious DDL / DCL keywords that should never appear in user input
    |  \b(drop|truncate|grant|revoke)\b\s+\b(table|database|schema|user|role)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_sqli(payload: str) -> bool:
    """
    Return ``True`` if *payload* contains a SQL Injection pattern.

    Applies URL decoding twice to defeat double-encoded attack strings
    before running the compiled regex.

    Args:
        payload: Arbitrary string from an HTTP request surface (path,
                 query string, body, or header value).

    Returns:
        ``True`` if a SQLi pattern is detected; ``False`` otherwise.
    """
    if not payload:
        return False

    # Pass 1: standard URL decode  (%27 → ')
    decoded_once = urllib.parse.unquote(payload)

    # Pass 2: double-URL decode  (%2527 → %27 → ')
    decoded_twice = urllib.parse.unquote(decoded_once)

    return bool(_SQLI_PATTERN.search(decoded_twice))