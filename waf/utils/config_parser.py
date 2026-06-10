"""
waf.utils.config_parser
~~~~~~~~~~~~~~~~~~~~~~~~

YAML configuration loader for Python Shield WAF.

Design decisions
----------------
* Built entirely on stdlib (``pathlib``, ``dataclasses``, ``os``) plus
  ``PyYAML`` — the only non-stdlib dependency added for config parsing.
* Returns an immutable ``WAFConfig`` dataclass so that downstream code
  cannot accidentally mutate runtime configuration.
* Environment variables take precedence over file values for the two
  most commonly overridden settings (``TARGET_URL``, ``WAF_LOG_FILE``),
  following the 12-factor app convention.
* Raises ``ConfigurationError`` (a subclass of ``ValueError``) on invalid
  or missing required fields so that misconfiguration fails loudly at
  startup rather than silently at runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class ConfigurationError(ValueError):
    """Raised when the WAF configuration file is missing or malformed."""


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitConfig:
    max_requests: int = 30
    window_seconds: int = 60
    max_tracked_ips: int = 100_000


@dataclass(frozen=True)
class IPFilterConfig:
    blocklist_path: str = "config/malicious_ips.txt"
    hot_reload: bool = True


@dataclass(frozen=True)
class RulesConfig:
    sqli_detection: bool = True
    xss_detection: bool = True
    inspect_url_path: bool = True
    inspect_query_string: bool = True
    inspect_request_body: bool = True
    inspect_headers: bool = True
    max_body_inspect_bytes: int = 65_536  # 64 KB


@dataclass(frozen=True)
class AIConfig:
    """Configuration for the AI-powered threat detection layer (Rule 7)."""

    enabled: bool = True
    """Enable or disable the AI classifier entirely."""

    mode: str = "shadow"
    """
    Operating mode:
    * ``"shadow"`` — AI runs and logs its verdict but never blocks (safe default).
    * ``"block"``  — AI blocks requests it classifies as malicious.
    """

    confidence_threshold: float = 0.85
    """Minimum model confidence (0.0–1.0) required to treat a request as malicious."""

    model_path: str = "models/waf_ai_model.pkl"
    """Path to the serialised scikit-learn model artifact."""

    max_surface_bytes: int = 4096
    """Maximum bytes of the combined request surface sent to the AI model."""

    # --- Anomaly detection (Isolation Forest for zero-day attacks) ---

    anomaly_detection: bool = True
    """Enable the anomaly detector alongside the classifier."""

    anomaly_contamination: float = 0.05
    """Expected fraction of outliers in traffic (0.01–0.50). Lower = more conservative."""

    anomaly_model_path: str = "models/waf_anomaly_model.pkl"
    """Path to the serialised Isolation Forest anomaly model."""

    # --- Self-learning pipeline ---

    learning_enabled: bool = True
    """Enable automatic data collection and periodic retraining."""

    learning_data_dir: str = "data/learning"
    """Directory where the learner stores collected samples."""

    retrain_after_samples: int = 100
    """Auto-retrain when this many new samples have been collected."""

    retrain_interval_hours: int = 6
    """Maximum hours between auto-retrains (whichever triggers first)."""

    min_f1_for_deploy: float = 0.88
    """Safety gate: new model must achieve at least this F1 to replace the old one."""

    baseline_sample_rate: float = 0.10
    """Fraction of allowed (benign) requests to sample for baseline training data."""

    def validate(self) -> None:
        """Raise ``ConfigurationError`` on invalid values."""
        if self.mode not in {"shadow", "block"}:
            raise ConfigurationError(
                f"ai.mode must be 'shadow' or 'block', got '{self.mode}'."
            )
        if not 0.0 < self.confidence_threshold <= 1.0:
            raise ConfigurationError(
                f"ai.confidence_threshold must be in (0.0, 1.0], got {self.confidence_threshold}."
            )
        if not 0.001 <= self.anomaly_contamination <= 0.50:
            raise ConfigurationError(
                f"ai.anomaly_contamination must be in [0.001, 0.50], "
                f"got {self.anomaly_contamination}."
            )
        if not 0.0 < self.baseline_sample_rate <= 1.0:
            raise ConfigurationError(
                f"ai.baseline_sample_rate must be in (0.0, 1.0], "
                f"got {self.baseline_sample_rate}."
            )
        if not 0.0 < self.min_f1_for_deploy <= 1.0:
            raise ConfigurationError(
                f"ai.min_f1_for_deploy must be in (0.0, 1.0], "
                f"got {self.min_f1_for_deploy}."
            )


@dataclass(frozen=True)
class WAFConfig:
    """Validated, immutable representation of ``waf_config.yaml``."""

    # Target upstream
    target_url: str
    target_timeout: int

    # Rate limiting
    rate_limit: RateLimitConfig

    # IP filtering
    ip_filter: IPFilterConfig

    # Logging
    log_file: str
    log_level: str

    # Detection rules
    rules: RulesConfig

    # AI detection layer
    ai: AIConfig = field(default_factory=AIConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "config" / "waf_config.yaml"


def load_config(path: str | Path | None = None) -> WAFConfig:
    """
    Parse and validate the WAF YAML configuration file.

    Environment variables ``TARGET_URL`` and ``WAF_LOG_FILE`` override the
    corresponding file values when set.

    Args:
        path: Path to ``waf_config.yaml``.  Defaults to
              ``<project-root>/config/waf_config.yaml``.

    Returns:
        A validated, immutable :class:`WAFConfig` instance.

    Raises:
        ConfigurationError: If the file is missing, unreadable, or contains
            invalid values.
    """
    config_path = Path(path) if path else _DEFAULT_CONFIG_PATH

    if not config_path.exists():
        raise ConfigurationError(
            f"Configuration file not found: {config_path}. "
            "Ensure config/waf_config.yaml exists in the project root."
        )

    try:
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Failed to parse configuration YAML: {exc}") from exc

    # --- Target ---
    target_section = raw.get("target", {})
    target_url = os.getenv("TARGET_URL") or target_section.get("url", "http://localhost:5000")
    target_timeout = _validate_positive_int(
        target_section.get("timeout_seconds", 10), "target.timeout_seconds"
    )

    # --- Rate limit ---
    rl = raw.get("rate_limit", {})
    rate_limit = RateLimitConfig(
        max_requests=_validate_positive_int(rl.get("max_requests", 30), "rate_limit.max_requests"),
        window_seconds=_validate_positive_int(
            rl.get("window_seconds", 60), "rate_limit.window_seconds"
        ),
        max_tracked_ips=_validate_positive_int(
            rl.get("max_tracked_ips", 100_000), "rate_limit.max_tracked_ips"
        ),
    )

    # --- IP filter ---
    ipf = raw.get("ip_filter", {})
    ip_filter = IPFilterConfig(
        blocklist_path=str(ipf.get("blocklist_path", "config/malicious_ips.txt")),
        hot_reload=bool(ipf.get("hot_reload", True)),
    )

    # --- Logging ---
    log_section = raw.get("logging", {})
    log_file = os.getenv("WAF_LOG_FILE") or log_section.get(
        "log_file", "logs/waf_alerts.log"
    )
    log_level = log_section.get("level", "INFO").upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigurationError(
            f"Invalid logging.level '{log_level}'. "
            "Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL."
        )

    # --- Rules ---
    r = raw.get("rules", {})
    rules = RulesConfig(
        sqli_detection=bool(r.get("sqli_detection", True)),
        xss_detection=bool(r.get("xss_detection", True)),
        inspect_url_path=bool(r.get("inspect_url_path", True)),
        inspect_query_string=bool(r.get("inspect_query_string", True)),
        inspect_request_body=bool(r.get("inspect_request_body", True)),
        inspect_headers=bool(r.get("inspect_headers", True)),
        max_body_inspect_bytes=int(r.get("max_body_inspect_bytes", 65_536)),
    )

    # --- AI detection ---
    ai_section = raw.get("ai", {})
    learning_section = ai_section.get("learning", {})
    ai_config = AIConfig(
        enabled=bool(ai_section.get("enabled", True)),
        mode=str(ai_section.get("mode", "shadow")),
        confidence_threshold=float(ai_section.get("confidence_threshold", 0.85)),
        model_path=str(ai_section.get("model_path", "models/waf_ai_model.pkl")),
        max_surface_bytes=int(ai_section.get("max_surface_bytes", 4096)),
        # Anomaly detection
        anomaly_detection=bool(ai_section.get("anomaly_detection", True)),
        anomaly_contamination=float(ai_section.get("anomaly_contamination", 0.05)),
        anomaly_model_path=str(
            ai_section.get("anomaly_model_path", "models/waf_anomaly_model.pkl")
        ),
        # Self-learning
        learning_enabled=bool(learning_section.get("enabled", True)),
        learning_data_dir=str(learning_section.get("data_dir", "data/learning")),
        retrain_after_samples=int(learning_section.get("retrain_after_samples", 100)),
        retrain_interval_hours=int(learning_section.get("retrain_interval_hours", 6)),
        min_f1_for_deploy=float(learning_section.get("min_f1_for_deploy", 0.88)),
        baseline_sample_rate=float(learning_section.get("baseline_sample_rate", 0.10)),
    )
    ai_config.validate()

    return WAFConfig(
        target_url=target_url,
        target_timeout=target_timeout,
        rate_limit=rate_limit,
        ip_filter=ip_filter,
        log_file=log_file,
        log_level=log_level,
        rules=rules,
        ai=ai_config,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_positive_int(value: Any, field_name: str) -> int:
    """Coerce *value* to a positive integer or raise ``ConfigurationError``."""
    try:
        int_value = int(value)
    except (TypeError, ValueError):
        raise ConfigurationError(
            f"Configuration field '{field_name}' must be an integer, got {value!r}."
        )
    if int_value <= 0:
        raise ConfigurationError(
            f"Configuration field '{field_name}' must be a positive integer, got {int_value}."
        )
    return int_value
