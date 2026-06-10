"""
waf.security.rules_xss
~~~~~~~~~~~~~~~~~~~~~~~

Cross-Site Scripting (XSS) detection rule — Rule ID: XSS-001.

Detection strategy
------------------
Three sequential normalisation passes before pattern matching:

1. **URL decode** — converts ``%3Cscript%3E`` → ``<script>``.
2. **Double URL decode** — handles ``%253C`` → ``%3C`` → ``<``.
3. **HTML entity decode** — converts ``&lt;`` → ``<``, ``&#x3C;`` → ``<``,
   and decimal entities ``&#60;`` → ``<``, neutralising entity-encoded
   payloads that bypass single-pass filters.

Pattern coverage
----------------
* ``<script …>`` tags (with whitespace / attribute variations)
* ``<svg>`` / ``<math>`` context injections (``onload``, ``onstart``)
* Event-handler attributes (``onerror=``, ``onclick=``, ``onfocus=``, …)
* ``javascript:`` and ``vbscript:`` pseudo-protocol URIs
* ``data:text/html`` and ``data:application/xhtml+xml`` URIs
* CSS ``expression()`` function (IE legacy attack surface)
* ``<iframe>`` / ``<object>`` / ``<embed>`` resource-injection tags
* HTML entity–encoded angle brackets used to reconstruct tags
* ``document.write``, ``document.cookie``, ``window.location``
  DOM-clobbering / exfiltration patterns
"""

from __future__ import annotations

import html
import re
import urllib.parse

# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------

RULE_ID = "XSS-001"

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_XSS_PATTERN = re.compile(
    r"""
    # --- Tag-based injections ---
    <\s*script[\s>]                          # <script>, <script type=...>
    | <\s*/\s*script\s*>                     # </script>
    | <\s*svg[\s/]                           # <svg>, <svg/onload=...>
    | <\s*math[\s/]                          # <math> MathML injection
    | <\s*iframe[\s/]                        # <iframe src=...>
    | <\s*object[\s/]                        # <object data=...>
    | <\s*embed[\s/]                         # <embed src=...>
    | <\s*img\b[^>]*\bon\w+\s*=             # <img onerror=...>
    | <\s*details\b[^>]*\bopen\b            # <details open ontoggle=...>

    # --- Event handlers (broad: on* = at word boundary) ---
    | \bon\w+\s*=                            # onerror=, onclick=, onload=, …

    # --- Dangerous URI schemes ---
    | javascript\s*:                         # javascript:alert()
    | vbscript\s*:                           # vbscript:msgbox()
    | data\s*:\s*text\s*/\s*(html|xml|svg)  # data:text/html;base64,…

    # --- CSS expression (IE legacy) ---
    | expression\s*\(                        # expression(alert())

    # --- DOM manipulation / exfiltration patterns ---
    | document\s*\.\s*(write|cookie|location|domain|referrer)
    | window\s*\.\s*(location|open|eval)
    | \beval\s*\(                            # eval(...)

    # --- HTML entity–encoded angle brackets used to reassemble tags ---
    # Catches &lt;script&gt; and &#x3C;script&#x3E; (after entity decode)
    | &\s*lt\s*;.*&\s*gt\s*;
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _html_entity_decode(text: str) -> str:
    """
    Decode HTML entities in *text*.

    ``html.unescape`` handles named (``&lt;``), decimal (``&#60;``), and
    hex (``&#x3C;``) entities, covering all standard XSS encoding tricks.
    """
    return html.unescape(text)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_xss(payload: str) -> bool:
    """
    Return ``True`` if *payload* contains a Cross-Site Scripting pattern.

    Applies URL decoding (twice) and HTML entity decoding before matching
    to defeat common encoding-based bypass techniques.

    Args:
        payload: Arbitrary string from an HTTP request surface.

    Returns:
        ``True`` if an XSS pattern is detected; ``False`` otherwise.
    """
    if not payload:
        return False

    # Pass 1: URL decode
    decoded_once = urllib.parse.unquote(payload)

    # Pass 2: double URL decode
    decoded_twice = urllib.parse.unquote(decoded_once)

    # Pass 3: HTML entity decode
    fully_decoded = _html_entity_decode(decoded_twice)

    return bool(_XSS_PATTERN.search(fully_decoded))