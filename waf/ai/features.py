"""
waf.ai.features
~~~~~~~~~~~~~~~

Hand-crafted feature extraction for the AI threat classifier.

These features are computed *in addition to* TF-IDF character n-grams,
giving the model explicit signals that sparse n-gram counts alone would
not easily learn from small datasets.

Feature inventory
-----------------
* ``length``              — total character count
* ``entropy``             — Shannon entropy (high entropy → obfuscation)
* ``digit_ratio``         — proportion of digit chars
* ``alpha_ratio``         — proportion of alpha chars
* ``special_ratio``       — proportion of chars that are not alphanum/space
* ``space_ratio``         — proportion of space chars
* ``single_quote_count``  — raw count of ``'`` (SQLi tautology canary)
* ``double_quote_count``  — raw count of ``"``
* ``angle_bracket_count`` — raw count of ``<>`` (XSS canary)
* ``semicolon_count``     — raw count of ``;`` (stacked queries)
* ``dash_dash_count``     — raw count of ``--`` subsequences (SQL comment)
* ``slash_count``         — count of ``/``
* ``pct_encoded_count``   — count of ``%XX`` sequences (URL encoding)
* ``hex_token_count``     — count of ``0x[0-9a-f]+`` tokens (hex obfuscation)
* ``keyword_sqli``        — count of top SQLi keywords (union, select, …)
* ``keyword_xss``         — count of top XSS keywords (script, onerror, …)
* ``keyword_cmd``         — count of command-injection tokens (cmd, exec, …)
* ``keyword_path``        — count of path-traversal tokens (../, etc.)
* ``token_count``         — word token count after splitting on non-alnum

All features are returned as a plain Python dict so callers can pass them
to :func:`pandas.DataFrame` or a ``DictVectorizer`` / ``FeatureUnion``
without any scikit-learn import dependency in this module.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# ---------------------------------------------------------------------------
# Compiled helpers (module-level for performance)
# ---------------------------------------------------------------------------

_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_HEX_TOKEN_RE = re.compile(r"\b0x[0-9a-fA-F]+\b", re.IGNORECASE)
_TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9_]+")

# SQLi keyword set — single-word tokens only (multi-word are caught by regex)
_SQLI_KEYWORDS = frozenset(
    [
        "select", "union", "insert", "update", "delete", "drop",
        "create", "alter", "truncate", "exec", "execute", "grant",
        "revoke", "sleep", "benchmark", "waitfor", "delay",
        "extractvalue", "updatexml", "information_schema",
        "sysobjects", "syscolumns", "char", "cast", "convert",
        "load_file", "outfile", "dumpfile", "concat",
    ]
)

# XSS keyword set
_XSS_KEYWORDS = frozenset(
    [
        "script", "onerror", "onload", "onclick", "onfocus",
        "onmouseover", "alert", "confirm", "prompt", "eval",
        "document", "window", "location", "cookie", "iframe",
        "object", "embed", "svg", "math", "expression",
        "javascript", "vbscript", "data",
    ]
)

# Command injection keywords
_CMD_KEYWORDS = frozenset(
    [
        "cmd", "exec", "system", "passthru", "popen", "shell_exec",
        "proc_open", "bash", "sh", "powershell", "wget", "curl",
        "nc", "netcat", "ncat", "python", "perl", "ruby", "php",
        "base64", "chmod", "chown", "sudo", "su", "ls", "id",
    ]
)

# Path traversal tokens
_PATH_KEYWORDS = frozenset(
    ["..", "etc", "passwd", "shadow", "win", "system32", "boot.ini",
     "proc", "self", "environ"]
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_features(text: str) -> dict[str, float]:
    """
    Compute a feature dict for *text* (an HTTP request surface string).

    Args:
        text: Arbitrary string — URL path, query string, body snippet,
              or header value.  May be empty.

    Returns:
        A ``dict[str, float]`` with all features defined in this module.
        All values are numeric (int promoted to float for consistency).
    """
    if not text:
        return _zero_features()

    length = len(text)
    lower = text.lower()
    chars = Counter(text)

    # --- Character-level ratios ---
    alpha = sum(1 for c in text if c.isalpha())
    digit = sum(1 for c in text if c.isdigit())
    space = sum(1 for c in text if c == " ")
    special = length - alpha - digit - space

    # --- Shannon entropy ---
    entropy = _shannon_entropy(text)

    # --- Specific character counts ---
    single_quote = text.count("'")
    double_quote = text.count('"')
    angle_brackets = text.count("<") + text.count(">")
    semicolons = text.count(";")
    dash_dash = lower.count("--")
    slashes = text.count("/")

    # --- Encoded / obfuscated patterns ---
    pct_encoded = len(_PCT_RE.findall(text))
    hex_tokens = len(_HEX_TOKEN_RE.findall(text))

    # --- Keyword counts ---
    tokens = [t for t in _TOKEN_SPLIT_RE.split(lower) if t]
    token_counter = Counter(tokens)
    token_count = len(tokens)

    kw_sqli = sum(token_counter[k] for k in _SQLI_KEYWORDS if k in token_counter)
    kw_xss = sum(token_counter[k] for k in _XSS_KEYWORDS if k in token_counter)
    kw_cmd = sum(token_counter[k] for k in _CMD_KEYWORDS if k in token_counter)

    # Path traversal: count ".." occurrences and path keywords
    kw_path = lower.count("..") + lower.count("../") + lower.count("..\\")
    kw_path += sum(token_counter[k] for k in _PATH_KEYWORDS if k in token_counter)

    return {
        "length": float(length),
        "entropy": entropy,
        "alpha_ratio": alpha / length,
        "digit_ratio": digit / length,
        "space_ratio": space / length,
        "special_ratio": special / length,
        "single_quote_count": float(single_quote),
        "double_quote_count": float(double_quote),
        "angle_bracket_count": float(angle_brackets),
        "semicolon_count": float(semicolons),
        "dash_dash_count": float(dash_dash),
        "slash_count": float(slashes),
        "pct_encoded_count": float(pct_encoded),
        "hex_token_count": float(hex_tokens),
        "keyword_sqli": float(kw_sqli),
        "keyword_xss": float(kw_xss),
        "keyword_cmd": float(kw_cmd),
        "keyword_path": float(kw_path),
        "token_count": float(token_count),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(text: str) -> float:
    """
    Compute the Shannon entropy of *text* in bits per character.

    High entropy (> 4.5) is a strong signal of base64, hex encoding,
    or other obfuscation used to bypass signature-based filters.
    """
    if not text:
        return 0.0
    freq = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _zero_features() -> dict[str, float]:
    """Return a zeroed feature dict for empty inputs."""
    keys = [
        "length", "entropy", "alpha_ratio", "digit_ratio",
        "space_ratio", "special_ratio", "single_quote_count",
        "double_quote_count", "angle_bracket_count", "semicolon_count",
        "dash_dash_count", "slash_count", "pct_encoded_count",
        "hex_token_count", "keyword_sqli", "keyword_xss",
        "keyword_cmd", "keyword_path", "token_count",
    ]
    return {k: 0.0 for k in keys}
