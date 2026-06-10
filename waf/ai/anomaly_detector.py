"""
waf.ai.anomaly_detector
~~~~~~~~~~~~~~~~~~~~~~~

Isolation Forest anomaly detector for zero-day / unknown attack detection.

This module complements the supervised classifier (:mod:`waf.ai.classifier`)
with an **unsupervised** anomaly detection layer.  While the classifier asks
"what kind of attack is this?", the anomaly detector asks "does this request
look *normal* compared to the baseline traffic I've learned?"

Design decisions
----------------
* **Isolation Forest** — chosen because it does not need labeled attack data;
  it only needs examples of normal traffic.  It isolates anomalies by randomly
  partitioning features — outliers require fewer partitions to isolate, yielding
  a short average path length and a high anomaly score.

* **Same feature space** — uses :func:`waf.ai.features.extract_features` so
  both models share a consistent representation.  No additional feature
  engineering is needed for the anomaly detector.

* **Async-safe** — ``score_samples`` is offloaded to a thread via
  ``asyncio.to_thread`` to avoid blocking the FastAPI event loop.

* **Graceful degradation** — if the anomaly model is absent or corrupt,
  the detector returns ``None`` (skipped), and the classifier alone decides.

Why this catches zero-days
--------------------------
A novel attack technique (e.g. a new obfuscation encoding, a new verb-based
bypass) will have feature values that deviate from normal traffic — unusual
entropy, rare character ratios, anomalous keyword counts.  Even without a
labeled example of the attack, the Isolation Forest flags it as statistically
unlikely under the learned normal distribution.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from waf.ai.features import extract_features
from waf.ai.models import AIDecision, THREAT_ANOMALY, SOURCE_ANOMALY
from waf.utils.logger import get_logger

# Lazy sklearn imports
try:
    import joblib
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False

log: logging.Logger = get_logger(__name__)

_DEFAULT_ANOMALY_MODEL_PATH = Path("models/waf_anomaly_model.pkl")


class AnomalyDetector:
    """
    Unsupervised anomaly detector using Isolation Forest.

    Trained on feature vectors of **normal traffic only**.  At runtime,
    any request whose features deviate significantly from the learned
    normal distribution is flagged as a potential zero-day attack.

    Args:
        model_path:    Path to the serialised anomaly model artifact.
        contamination: Expected fraction of outliers (used as a scoring
                       reference, not for retraining at runtime).
    """

    def __init__(
        self,
        model_path: str | Path = _DEFAULT_ANOMALY_MODEL_PATH,
        contamination: float = 0.05,
    ) -> None:
        self._model_path = Path(model_path)
        self._contamination = contamination
        self._model: Any | None = None
        self._feature_names: list[str] = []
        self._available = False
        self._model_version = "unavailable"
        self._lock = asyncio.Lock() if _SKLEARN_AVAILABLE else None

        self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def score(self, text: str) -> AIDecision | None:
        """
        Score *text* for anomalousness.

        Args:
            text: Combined request surface string.

        Returns:
            ``AIDecision`` with ``threat_type="anomaly"`` if the request
            is flagged as anomalous, or ``None`` if the detector is
            unavailable or the request is normal.
        """
        if not self._available or not text:
            return None

        return await asyncio.to_thread(self._score_sync, text)

    @property
    def is_available(self) -> bool:
        """``True`` if the anomaly model loaded successfully."""
        return self._available

    @property
    def model_version(self) -> str:
        """Version string from the anomaly model artifact."""
        return self._model_version

    def reload_model(self, new_path: str | Path | None = None) -> bool:
        """
        Hot-reload the anomaly model from disk.

        Args:
            new_path: Optional new model path. If ``None``, reloads from
                      the original path.

        Returns:
            ``True`` if the new model loaded successfully.
        """
        if new_path is not None:
            self._model_path = Path(new_path)
        old_model = self._model
        old_version = self._model_version
        old_available = self._available

        self._load_model()

        if self._available:
            log.info(
                "Anomaly model hot-reloaded: %s → %s",
                old_version, self._model_version,
            )
            return True

        # Rollback on failure
        self._model = old_model
        self._model_version = old_version
        self._available = old_available
        log.warning("Anomaly model hot-reload failed — keeping previous model.")
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load the anomaly model artifact from disk."""
        if not _SKLEARN_AVAILABLE:
            log.warning(
                "scikit-learn / joblib not installed — anomaly detector disabled."
            )
            return

        if not self._model_path.exists():
            log.warning(
                "Anomaly model not found at %s — anomaly detector disabled. "
                "Run: python scripts/train_model.py",
                self._model_path,
            )
            return

        try:
            artifact = joblib.load(self._model_path)
            self._model = artifact["model"]
            self._feature_names = artifact.get("feature_names", [])
            self._model_version = artifact.get("model_version", "unknown")
            self._available = True
            log.info(
                "Anomaly detector loaded — model_version=%s | "
                "contamination=%.3f | path=%s",
                self._model_version,
                self._contamination,
                self._model_path,
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Failed to load anomaly model from %s: %s — "
                "anomaly detector disabled.",
                self._model_path, exc,
            )

    def _score_sync(self, text: str) -> AIDecision | None:
        """
        Synchronous scoring — called in a thread via asyncio.to_thread.

        Isolation Forest ``score_samples`` returns negative anomaly scores:
        * More negative = more anomalous
        * Scores near 0 or positive = normal

        We convert the raw score to a [0, 1] confidence value where
        higher = more confident the request is anomalous.
        """
        try:
            features = extract_features(text)

            # Build feature vector in the expected order
            if self._feature_names:
                feature_vector = [features.get(name, 0.0) for name in self._feature_names]
            else:
                feature_vector = list(features.values())

            X = np.array([feature_vector])

            # score_samples returns the anomaly score (more negative = more anomalous)
            raw_score = self._model.score_samples(X)[0]

            # predict returns -1 for anomalies, 1 for normal
            prediction = self._model.predict(X)[0]

            if prediction == -1:
                # Convert raw score to a confidence value
                # Isolation Forest scores are typically in [-1, 0] range
                # More negative = more anomalous
                confidence = min(1.0, max(0.0, -raw_score))

                # Extract which features contributed most to anomaly detection
                top_features = self._get_anomaly_features(features)

                return AIDecision.malicious(
                    confidence=confidence,
                    threat_type=THREAT_ANOMALY,
                    top_features=top_features,
                    model_version=self._model_version,
                    detection_source=SOURCE_ANOMALY,
                )

            # Normal — return None to indicate no anomaly
            return None

        except Exception as exc:  # noqa: BLE001
            log.error("Anomaly scoring error: %s — skipping.", exc)
            return None

    def _get_anomaly_features(self, features: dict[str, float]) -> list[str]:
        """
        Identify which features are most anomalous by comparing them
        to typical ranges.

        This is a heuristic explanation — Isolation Forest doesn't natively
        provide feature attributions, so we flag features that are extreme
        compared to simple thresholds.
        """
        anomalous: list[tuple[str, float]] = []

        # Flag features with suspiciously extreme values
        _thresholds = {
            "entropy": (0.0, 4.5),          # Normal text: 3.5–4.5
            "special_ratio": (0.0, 0.3),     # Normal: < 30% special chars
            "single_quote_count": (0.0, 2.0),
            "double_quote_count": (0.0, 2.0),
            "angle_bracket_count": (0.0, 2.0),
            "semicolon_count": (0.0, 2.0),
            "dash_dash_count": (0.0, 1.0),
            "pct_encoded_count": (0.0, 5.0),
            "hex_token_count": (0.0, 1.0),
            "keyword_sqli": (0.0, 1.0),
            "keyword_xss": (0.0, 1.0),
            "keyword_cmd": (0.0, 1.0),
            "keyword_path": (0.0, 1.0),
        }

        for feat_name, (low, high) in _thresholds.items():
            val = features.get(feat_name, 0.0)
            if val > high:
                deviation = (val - high) / max(high, 0.01)
                anomalous.append((feat_name, deviation))
            elif val < low:
                deviation = (low - val) / max(abs(low), 0.01)
                anomalous.append((feat_name, deviation))

        # Sort by deviation magnitude, return top feature names
        anomalous.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in anomalous[:10]]
