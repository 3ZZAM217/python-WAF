"""
waf.ai.classifier
~~~~~~~~~~~~~~~~~

Runtime AI threat classifier for Python Shield WAF.

This module provides :class:`AIClassifier` — a thin, async-safe wrapper
around a pre-trained ``scikit-learn`` pipeline.  The model is loaded once
at WAF startup (in the FastAPI lifespan) and reused across all requests.

Design decisions
----------------
* **Async-safe via asyncio.to_thread** — sklearn ``predict_proba`` is a
  pure CPU operation with no I/O.  We offload it to a thread so the
  FastAPI event loop is never blocked, even under high concurrency.

* **Single model load** — ``AIClassifier.__init__`` reads and deserialises
  the model artifact once.  Subsequent calls are in-memory operations.

* **Graceful degradation** — if the model file is absent or corrupt, the
  classifier falls back to ``AIDecision.benign()`` and logs a warning.
  This means a missing model file degrades gracefully (no AI protection)
  rather than crashing the WAF.

* **Explainability** — after every prediction the top *N* feature names
  with the highest absolute coefficients / feature importances are
  extracted and attached to the ``AIDecision``.  This powers the enriched
  audit log so analysts can see *why* a request was flagged.

* **Hot-swap support** — ``reload_model()`` allows the self-learning
  pipeline to replace the model at runtime without restarting the WAF.

* **No external API calls** — all inference is fully local.

Usage (in engine.py)::

    classifier = AIClassifier()  # called once at startup
    decision: AIDecision = await classifier.predict(payload_text)
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any

from waf.ai.features import extract_features
from waf.ai.models import AIDecision, THREAT_BENIGN, SOURCE_CLASSIFIER
from waf.utils.logger import get_logger

# Import sklearn lazily to avoid hard failure if not installed
try:
    import joblib
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False

log: logging.Logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Label map (int -> threat-type string) — authoritative copy for runtime inference
# ---------------------------------------------------------------------------

_LABEL_TO_THREAT = {
    0: "benign",
    1: "sqli",
    2: "xss",
    3: "cmdi",
    4: "path_traversal",
    5: "generic_attack",
}

_TOP_N_FEATURES = 10          # Max features to include in audit log
_DEFAULT_MODEL_PATH = Path("models/waf_ai_model.pkl")


class AIClassifier:
    """
    Async-safe wrapper around the scikit-learn WAF classification pipeline.

    Args:
        model_path:           Path to the ``joblib`` model artifact produced
                              by :mod:`waf.ai.trainer`.
        confidence_threshold: Minimum ``predict_proba`` probability for the
                              *malicious* class to trigger a block decision.
                              Requests below the threshold are treated as benign.

    Raises:
        RuntimeError: If ``scikit-learn`` or ``joblib`` are not installed and
                      the classifier is used in a context where it should block.
    """

    def __init__(
        self,
        model_path: str | Path = _DEFAULT_MODEL_PATH,
        confidence_threshold: float = 0.85,
    ) -> None:
        self._threshold = confidence_threshold
        self._model_path = Path(model_path)
        self._artifact: dict[str, Any] | None = None
        self._available = False
        self._model_version = "unavailable"
        # Thread-safe lock for hot-swap model replacement
        self._swap_lock = threading.Lock()

        self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def predict(self, text: str) -> AIDecision:
        """
        Classify *text* as benign or malicious.

        Offloads the CPU-bound sklearn inference to a thread pool so the
        asyncio event loop is never blocked.

        Args:
            text: Combined request surface string (path + query + body snippet).

        Returns:
            :class:`~waf.ai.models.AIDecision` with verdict, confidence,
            threat type, and top contributing features.
        """
        if not self._available or not text:
            return AIDecision.benign(model_version=self._model_version)

        return await asyncio.to_thread(self._predict_sync, text)

    @property
    def is_available(self) -> bool:
        """``True`` if the model loaded successfully and is ready to classify."""
        return self._available

    @property
    def model_version(self) -> str:
        """Version string from the model artifact metadata."""
        return self._model_version

    def reload_model(self, new_path: str | Path | None = None) -> bool:
        """
        Hot-reload the classifier model from disk.

        Thread-safe: uses a lock to prevent concurrent reads during swap.
        Called by :class:`~waf.ai.learner.WAFLearner` after retraining.

        Args:
            new_path: Optional new model path. If ``None``, reloads from
                      the original path.

        Returns:
            ``True`` if the new model loaded successfully.
        """
        if new_path is not None:
            self._model_path = Path(new_path)

        old_artifact = self._artifact
        old_version = self._model_version
        old_available = self._available

        self._load_model()

        if self._available:
            log.info(
                "Classifier hot-reloaded: %s → %s",
                old_version, self._model_version,
            )
            return True

        # Rollback on failure
        with self._swap_lock:
            self._artifact = old_artifact
            self._model_version = old_version
            self._available = old_available
        log.warning("Classifier hot-reload failed — keeping previous model.")
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load and validate the model artifact from disk."""
        if not _SKLEARN_AVAILABLE:
            log.warning(
                "scikit-learn / joblib not installed — AI classifier disabled. "
                "Run: pip install scikit-learn joblib numpy"
            )
            return

        if not self._model_path.exists():
            log.warning(
                "AI model artifact not found at %s — AI classifier disabled. "
                "Run: python scripts/train_model.py",
                self._model_path,
            )
            return

        try:
            artifact = joblib.load(self._model_path)
            with self._swap_lock:
                self._artifact = artifact
                self._model_version = artifact.get("model_version", "unknown")
                self._available = True
            log.info(
                "AI classifier loaded — model_version=%s | threshold=%.2f | path=%s",
                self._model_version,
                self._threshold,
                self._model_path,
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Failed to load AI model from %s: %s — AI classifier disabled.",
                self._model_path,
                exc,
            )

    def _predict_sync(self, text: str) -> AIDecision:
        """
        Synchronous prediction — called inside a thread via asyncio.to_thread.

        Returns AIDecision (benign or malicious) based on model output.
        """
        try:
            with self._swap_lock:
                artifact = self._artifact
                model_version = self._model_version

            if artifact is None:
                return AIDecision.benign(model_version=model_version)

            pipeline = artifact["pipeline"]
            label_map = artifact.get("label_map", _LABEL_TO_THREAT)

            # predict_proba returns shape (1, n_classes)
            proba = pipeline.predict_proba([text])[0]
            predicted_class = int(np.argmax(proba))
            max_confidence = float(proba[predicted_class])

            # Class 0 is benign; anything else is an attack
            if predicted_class == 0 or max_confidence < self._threshold:
                return AIDecision.benign(
                    confidence=float(proba[0]),
                    model_version=model_version,
                    detection_source=SOURCE_CLASSIFIER,
                )

            threat_type = label_map.get(predicted_class, "generic_attack")
            if isinstance(threat_type, str) is False:
                threat_type = str(threat_type)

            top_features = self._get_top_features(pipeline, text)

            return AIDecision.malicious(
                confidence=max_confidence,
                threat_type=threat_type,
                top_features=top_features,
                model_version=model_version,
                detection_source=SOURCE_CLASSIFIER,
            )

        except Exception as exc:  # noqa: BLE001
            log.error("AI prediction error: %s — defaulting to benign.", exc)
            return AIDecision.benign(model_version=self._model_version)

    def _get_top_features(self, pipeline: Any, text: str) -> list[str]:
        """
        Extract the top contributing feature names for *text*.

        Uses the classifier's ``feature_importances_`` (tree-based models)
        combined with the pipeline's feature names to produce a human-readable
        list for the audit log.
        """
        try:
            clf = pipeline.named_steps["clf"]
            feature_union = pipeline.named_steps["features"]

            if not hasattr(clf, "feature_importances_"):
                return []

            importances = clf.feature_importances_
            # Get feature names from the union
            feature_names: list[str] = []
            for _, transformer in feature_union.transformer_list:
                if hasattr(transformer, "get_feature_names_out"):
                    feature_names.extend(transformer.get_feature_names_out().tolist())
                elif hasattr(transformer, "named_steps"):
                    vec = transformer.named_steps.get("vectorize")
                    if vec and hasattr(vec, "feature_names_"):
                        feature_names.extend(vec.feature_names_)

            if len(feature_names) != len(importances):
                return []

            top_indices = np.argsort(importances)[::-1][:_TOP_N_FEATURES]
            return [str(feature_names[i]) for i in top_indices if importances[i] > 0]

        except Exception:  # noqa: BLE001
            return []
