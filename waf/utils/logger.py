"""
waf.utils.logger
~~~~~~~~~~~~~~~~

Structured JSON logging for the WAF.

Design decisions
----------------
* Uses Python's stdlib ``logging`` — no third-party dependency.
* ``RotatingFileHandler`` caps log files at 10 MB, keeps 5 backups;
  prevents unbounded disk growth in long-running deployments.
* Log records are emitted as newline-delimited JSON (NDJSON) for easy
  ingestion by log aggregators (Elasticsearch, Splunk, Loki, etc.).
* The log file path is resolved via the ``WAF_LOG_FILE`` environment
  variable, falling back to ``<project-root>/logs/waf_alerts.log``.
  An absolute path is always used so the file lands in a predictable
  location regardless of the process working directory.
* ``get_logger()`` is a thin factory that ensures every module gets a
  child logger inheriting this configuration without double-registering
  handlers on repeated imports.
"""

from __future__ import annotations

import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_LOG_FILE = _PROJECT_ROOT / "logs" / "waf_alerts.log"
_LOG_FILE = Path(os.getenv("WAF_LOG_FILE", str(_DEFAULT_LOG_FILE))).resolve()

_LOGGER_NAME = "python_shield_waf"
_MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file
_BACKUP_COUNT = 5


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    """Serialises log records as single-line JSON objects (NDJSON)."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: dict = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any extra fields injected via ``logger.info(..., extra={...})``
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------


def _build_root_logger() -> logging.Logger:
    """Initialise and return the root WAF logger (called once at import time)."""
    logger = logging.getLogger(_LOGGER_NAME)

    # Guard: only add handlers the first time this module is imported.
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # --- File handler (rotating JSON) ---
    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        _LOG_FILE,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(_JsonFormatter())

    # --- Console handler (human-readable for development) ---
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
    )

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    return logger


# Module-level root logger instance
_root_logger = _build_root_logger()


def get_logger(name: str = "") -> logging.Logger:
    """
    Return a child logger scoped to *name* under the WAF root logger.

    Usage::

        from waf.utils.logger import get_logger
        log = get_logger(__name__)
        log.info("Component ready")
    """
    if name:
        return _root_logger.getChild(name)
    return _root_logger


# ---------------------------------------------------------------------------
# Convenience audit helper
# ---------------------------------------------------------------------------


def log_blocked_request(
    *,
    ip: str,
    method: str,
    path: str,
    rule_id: str,
    reason: str,
) -> None:
    """
    Emit a structured WARN-level audit record for a blocked request.

    All parameters are keyword-only to prevent positional-order mistakes
    at call sites — a defensive practice for security-critical logging.
    """
    _root_logger.warning(
        "Request blocked",
        extra={
            "attacker_ip": ip,
            "http_method": method,
            "target_path": path,
            "rule_id": rule_id,
            "block_reason": reason,
        },
    )