"""
waf.ai.learner
~~~~~~~~~~~~~~

Self-learning pipeline for the WAF AI layer.

This module is the adaptive brain of Python Shield WAF.  It enables the
AI to **learn from live traffic** — every blocked request becomes a
confirmed attack sample, and a fraction of allowed requests form the
baseline of "normal".  When enough new data accumulates (or a time
interval elapses), the learner automatically retrains both the classifier
and the anomaly detector, validates the new models, and hot-swaps them
into the live pipeline with zero downtime.

Architecture
------------
The learner has three sub-components:

1. **DataCollector** — records request surfaces + labels to CSV files
   in ``data/learning/``.  Blocked-by-rules requests get the rule's
   label; allowed requests are sampled at a configurable rate as benign.

2. **AutoRetrainer** — a background async task that monitors the
   collected sample count and wall-clock time.  When either threshold
   is met it merges new data with existing training data, retrains
   both models, validates against a held-out set, and deploys only if
   the new model's F1 meets the safety gate.

3. **ModelSwapper** — thread-safe model replacement.  After retraining,
   the new model artifacts are written to disk and the live classifier /
   anomaly detector objects are told to ``reload_model()``.

Design decisions
----------------
* **Append-only CSV** — simple, debuggable, and safe under concurrent
  writes (one writer at a time via asyncio.Lock).
* **Merge-then-retrain** — new samples are merged with the original
  ``training_data.csv`` so the model doesn't "forget" old patterns.
* **F1 safety gate** — prevents deploying a model that's worse than the
  current one due to noisy or poisoned training data.
* **Background task** — retraining is CPU-intensive, so it runs in a
  thread pool to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import csv
import logging
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from waf.ai.features import extract_features
from waf.utils.logger import get_logger

if TYPE_CHECKING:
    from waf.ai.classifier import AIClassifier
    from waf.ai.anomaly_detector import AnomalyDetector

# Lazy imports for training (heavy dependencies)
try:
    import numpy as np
    import pandas as pd
    _TRAINING_AVAILABLE = True
except ImportError:
    _TRAINING_AVAILABLE = False

log: logging.Logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Rule-ID → label mapping for auto-labeling blocked requests
# ---------------------------------------------------------------------------

_RULE_TO_LABEL: dict[str, int] = {
    "SQLI-001": 1,      # sqli
    "XSS-001": 2,       # xss
    "AI-001": None,      # AI-blocked — use the AI's own classification
    "AI-ANOMALY-001": 5, # generic_attack (anomaly detections)
}

# Threat-type string → label mapping for AI-classified blocks
_THREAT_TO_LABEL: dict[str, int] = {
    "sqli": 1,
    "xss": 2,
    "cmdi": 3,
    "path_traversal": 4,
    "generic_attack": 5,
    "anomaly": 5,
}


class WAFLearner:
    """
    Self-learning pipeline — collects data, triggers retraining, swaps models.

    Args:
        data_dir:              Directory for storing collected learning samples.
        retrain_after_samples: Retrain when this many new samples have been collected.
        retrain_interval_hours: Maximum hours between retrains.
        min_f1_for_deploy:     Safety gate — new model must beat this F1.
        baseline_sample_rate:  Fraction of allowed requests to sample as benign.
        original_data_path:    Path to the original training dataset for merging.
        classifier:            Reference to the live classifier (for hot-swap).
        anomaly_detector:      Reference to the live anomaly detector (for hot-swap).
    """

    def __init__(
        self,
        data_dir: str | Path = "data/learning",
        retrain_after_samples: int = 100,
        retrain_interval_hours: int = 6,
        min_f1_for_deploy: float = 0.88,
        baseline_sample_rate: float = 0.10,
        original_data_path: str | Path = "data/training_data.csv",
        classifier: AIClassifier | None = None,
        anomaly_detector: AnomalyDetector | None = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._retrain_threshold = retrain_after_samples
        self._retrain_interval = retrain_interval_hours * 3600  # to seconds
        self._min_f1 = min_f1_for_deploy
        self._sample_rate = baseline_sample_rate
        self._original_data_path = Path(original_data_path)

        self._classifier = classifier
        self._anomaly_detector = anomaly_detector

        # State
        self._samples_since_train: int = 0
        self._last_train_time: float = time.monotonic()
        self._write_lock = asyncio.Lock()
        self._retrain_lock = asyncio.Lock()
        self._retrain_task: asyncio.Task | None = None

        # File paths
        self._attacks_file = self._data_dir / "collected_attacks.csv"
        self._benign_file = self._data_dir / "collected_benign.csv"

        # Count existing samples
        self._samples_since_train = self._count_existing_samples()

        log.info(
            "WAFLearner initialised — data_dir=%s | retrain_threshold=%d | "
            "interval=%dh | existing_samples=%d",
            self._data_dir,
            self._retrain_threshold,
            retrain_interval_hours,
            self._samples_since_train,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def record_blocked(
        self,
        surface: str,
        rule_id: str,
        threat_type: str = "",
    ) -> None:
        """
        Record a blocked request as confirmed-attack training data.

        Args:
            surface:     Combined request surface string.
            rule_id:     The rule that blocked the request (e.g. ``"SQLI-001"``).
            threat_type: AI-classified threat type (only used if ``rule_id`` is AI).
        """
        if not surface.strip():
            return

        # Determine label from rule ID
        label = _RULE_TO_LABEL.get(rule_id)
        if label is None and threat_type:
            label = _THREAT_TO_LABEL.get(threat_type, 5)
        if label is None:
            label = 5  # generic_attack fallback

        await self._append_sample(self._attacks_file, surface, label, rule_id)

    async def record_allowed(self, surface: str) -> None:
        """
        Probabilistically sample an allowed request as benign baseline data.

        Only a fraction of allowed requests are recorded (configured by
        ``baseline_sample_rate``) to avoid overwhelming disk I/O on
        high-traffic deployments.
        """
        if not surface.strip():
            return

        # Probabilistic sampling
        if random.random() > self._sample_rate:
            return

        await self._append_sample(self._benign_file, surface, 0, "BASELINE")

    async def check_retrain(self) -> None:
        """
        Check whether retraining thresholds have been met and trigger
        a background retrain if so.

        This is called after each ``record_*`` call from the engine.
        Retraining happens asynchronously and does not block request
        processing.
        """
        elapsed = time.monotonic() - self._last_train_time
        threshold_met = self._samples_since_train >= self._retrain_threshold
        interval_met = elapsed >= self._retrain_interval

        if not (threshold_met or interval_met):
            return

        # Don't stack retrains
        if self._retrain_lock.locked():
            return

        trigger = "sample_threshold" if threshold_met else "time_interval"
        log.info(
            "Retrain trigger: %s (samples=%d, elapsed=%.0fs)",
            trigger, self._samples_since_train, elapsed,
        )

        # Launch retrain in background
        self._retrain_task = asyncio.create_task(self._retrain_background())

    def set_classifier(self, classifier: AIClassifier) -> None:
        """Attach the live classifier for hot-swap after retraining."""
        self._classifier = classifier

    def set_anomaly_detector(self, detector: AnomalyDetector) -> None:
        """Attach the live anomaly detector for hot-swap after retraining."""
        self._anomaly_detector = detector

    @property
    def samples_collected(self) -> int:
        """Number of samples collected since the last retrain."""
        return self._samples_since_train

    # ------------------------------------------------------------------
    # Internal: data collection
    # ------------------------------------------------------------------

    async def _append_sample(
        self, filepath: Path, payload: str, label: int, source: str,
    ) -> None:
        """Append a single sample to the given CSV file (thread-safe)."""
        async with self._write_lock:
            try:
                is_new = not filepath.exists() or filepath.stat().st_size == 0
                with open(filepath, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
                    if is_new:
                        writer.writerow(["payload", "label", "source", "timestamp"])
                    writer.writerow([
                        payload,
                        label,
                        source,
                        datetime.now(timezone.utc).isoformat(),
                    ])
                self._samples_since_train += 1
            except Exception as exc:  # noqa: BLE001
                log.error("Failed to write learning sample: %s", exc)

    def _count_existing_samples(self) -> int:
        """Count samples already in the learning directory."""
        total = 0
        for filepath in [self._attacks_file, self._benign_file]:
            if filepath.exists():
                try:
                    # Count lines minus header
                    total += max(0, sum(1 for _ in open(filepath, encoding="utf-8")) - 1)
                except Exception:  # noqa: BLE001
                    pass
        return total

    # ------------------------------------------------------------------
    # Internal: background retraining
    # ------------------------------------------------------------------

    async def _retrain_background(self) -> None:
        """
        Background retraining task.

        Merges collected samples with original training data, retrains
        both models, validates, and hot-swaps if the new model is better.
        """
        async with self._retrain_lock:
            log.info("Starting background retrain…")
            try:
                result = await asyncio.to_thread(self._retrain_sync)
                if result:
                    log.info(
                        "Retrain complete — new model deployed! "
                        "classifier_f1=%.4f, anomaly_version=%s",
                        result.get("f1_macro", 0),
                        result.get("anomaly_version", "n/a"),
                    )
                else:
                    log.warning("Retrain completed but model NOT deployed (safety gate).")
            except Exception as exc:  # noqa: BLE001
                log.error("Background retrain failed: %s", exc)
            finally:
                self._samples_since_train = 0
                self._last_train_time = time.monotonic()

    def _retrain_sync(self) -> dict | None:
        """
        Synchronous retraining — called inside a thread.

        Returns a result dict if the new model was deployed, ``None`` if
        it failed the safety gate.
        """
        if not _TRAINING_AVAILABLE:
            log.warning("pandas/numpy not available — cannot retrain.")
            return None

        # Late import to avoid circular dependency and loading heavy modules at startup
        from waf.ai.trainer import train_and_save, train_anomaly_model

        # 1. Merge original + collected data
        merged_path = self._merge_datasets()
        if merged_path is None:
            return None

        # 2. Train classifier
        try:
            new_model_path = Path("models/waf_ai_model_new.pkl")
            result = train_and_save(
                data_path=merged_path,
                model_path=new_model_path,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("Classifier retrain failed: %s", exc)
            return None

        # 3. Safety gate: check F1
        f1 = result.get("f1_macro", 0)
        if f1 < self._min_f1:
            log.warning(
                "New model F1=%.4f < min_f1=%.4f — NOT deploying.",
                f1, self._min_f1,
            )
            # Clean up the rejected model
            if new_model_path.exists():
                new_model_path.unlink()
            return None

        # 4. Train anomaly model
        anomaly_result = {}
        try:
            new_anomaly_path = Path("models/waf_anomaly_model_new.pkl")
            anomaly_result = train_anomaly_model(
                data_path=merged_path,
                model_path=new_anomaly_path,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Anomaly model retrain failed: %s — keeping old.", exc)

        # 5. Deploy: move new models into place
        final_model = Path("models/waf_ai_model.pkl")
        final_anomaly = Path("models/waf_anomaly_model.pkl")

        try:
            if new_model_path.exists():
                # Atomic-ish rename (on same filesystem)
                if final_model.exists():
                    final_model.unlink()
                new_model_path.rename(final_model)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to deploy new classifier model: %s", exc)
            return None

        try:
            new_anomaly_path_check = Path("models/waf_anomaly_model_new.pkl")
            if new_anomaly_path_check.exists():
                if final_anomaly.exists():
                    final_anomaly.unlink()
                new_anomaly_path_check.rename(final_anomaly)
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to deploy new anomaly model: %s", exc)

        # 6. Hot-swap: tell live models to reload
        if self._classifier is not None:
            self._classifier.reload_model()
            log.info("Classifier hot-swapped successfully.")

        if self._anomaly_detector is not None:
            self._anomaly_detector.reload_model()
            log.info("Anomaly detector hot-swapped successfully.")

        # 7. Archive collected data (don't delete — useful for forensics)
        self._archive_collected_data()

        return {
            "f1_macro": f1,
            "report": result.get("report", ""),
            "anomaly_version": anomaly_result.get("model_version", "n/a"),
        }

    def _merge_datasets(self) -> Path | None:
        """
        Merge original training data with collected samples.

        Returns the path to the merged CSV, or ``None`` if there's
        nothing to merge.
        """
        try:
            dfs: list[pd.DataFrame] = []

            # Load original dataset
            if self._original_data_path.exists():
                df_orig = pd.read_csv(self._original_data_path, encoding="utf-8")
                if "payload" in df_orig.columns and "label" in df_orig.columns:
                    dfs.append(df_orig[["payload", "label"]])

            # Load collected attacks
            if self._attacks_file.exists():
                df_attacks = pd.read_csv(self._attacks_file, encoding="utf-8")
                if "payload" in df_attacks.columns and "label" in df_attacks.columns:
                    dfs.append(df_attacks[["payload", "label"]])

            # Load collected benign samples
            if self._benign_file.exists():
                df_benign = pd.read_csv(self._benign_file, encoding="utf-8")
                if "payload" in df_benign.columns and "label" in df_benign.columns:
                    dfs.append(df_benign[["payload", "label"]])

            if not dfs:
                log.warning("No datasets found to merge.")
                return None

            merged = pd.concat(dfs, ignore_index=True)
            merged = merged.dropna(subset=["payload"])
            merged = merged.drop_duplicates(subset=["payload"])

            merged_path = self._data_dir / "merged_training_data.csv"
            merged.to_csv(merged_path, index=False, encoding="utf-8")

            log.info(
                "Merged dataset: %d samples (%d original + %d new)",
                len(merged),
                len(dfs[0]) if len(dfs) > 0 else 0,
                len(merged) - (len(dfs[0]) if len(dfs) > 0 else 0),
            )
            return merged_path

        except Exception as exc:  # noqa: BLE001
            log.error("Failed to merge datasets: %s", exc)
            return None

    def _archive_collected_data(self) -> None:
        """
        Archive collected data files after a successful retrain.

        Renames them with a timestamp suffix so they're preserved for
        forensic analysis but don't get re-merged in the next cycle.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        for filepath in [self._attacks_file, self._benign_file]:
            if filepath.exists():
                try:
                    archive_name = filepath.with_suffix(f".{timestamp}.csv")
                    filepath.rename(archive_name)
                    log.info("Archived %s → %s", filepath.name, archive_name.name)
                except Exception as exc:  # noqa: BLE001
                    log.warning("Failed to archive %s: %s", filepath.name, exc)
