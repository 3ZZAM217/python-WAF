#!/usr/bin/env python
"""
scripts/train_model.py
~~~~~~~~~~~~~~~~~~~~~~

CLI entry point for training the AI WAF classifier and anomaly detector.

Usage (from project root):

    python scripts/train_model.py
    python scripts/train_model.py --data data/training_data.csv --model models/waf_ai_model.pkl
    python scripts/train_model.py --skip-anomaly   # skip anomaly model training

The script will:
    1. Load the labeled dataset from --data (default: data/training_data.csv)
    2. Train the GradientBoosting + TF-IDF classifier pipeline
    3. Train the Isolation Forest anomaly detector on benign samples
    4. Print classification reports and F1 scores
    5. Save both model artifacts

Requirements:
    pip install scikit-learn joblib numpy pandas
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure the project root is on sys.path when running as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from waf.ai.trainer import train_and_save, train_anomaly_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the Python Shield WAF AI classifier and anomaly detector."
    )
    parser.add_argument(
        "--data",
        default="data/training_data.csv",
        help="Path to the labeled CSV dataset (default: data/training_data.csv)",
    )
    parser.add_argument(
        "--model",
        default="models/waf_ai_model.pkl",
        help="Output path for the classifier model (default: models/waf_ai_model.pkl)",
    )
    parser.add_argument(
        "--anomaly-model",
        default="models/waf_anomaly_model.pkl",
        help="Output path for the anomaly model (default: models/waf_anomaly_model.pkl)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of data to hold out for evaluation (default: 0.2)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Anomaly detector contamination parameter (default: 0.05)",
    )
    parser.add_argument(
        "--skip-anomaly",
        action="store_true",
        help="Skip training the anomaly detector",
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  Python Shield WAF — AI Model Training")
    print("=" * 60)

    # --- Train classifier ---
    print("\n[*] Phase 1: Training classifier...")
    result = train_and_save(
        data_path=args.data,
        model_path=args.model,
        test_size=args.test_size,
    )

    print("\n" + "-" * 60)
    print(f"  [OK] Classifier trained!")
    print(f"  [F1] Macro F1 Score : {result['f1_macro']:.4f}")
    print(f"  [>>] Model saved to : {args.model}")
    print("-" * 60)
    print("\nClassification Report:")
    print(result["report"])

    if result["f1_macro"] < 0.90:
        print(
            "[WARNING] F1 score is below 0.90. Consider adding more training data "
            "or tuning hyperparameters before deploying in block mode."
        )

    # --- Train anomaly detector ---
    if not args.skip_anomaly:
        print("\n[*] Phase 2: Training anomaly detector...")
        anomaly_result = train_anomaly_model(
            data_path=args.data,
            model_path=args.anomaly_model,
            contamination=args.contamination,
        )

        print("\n" + "-" * 60)
        print(f"  [OK] Anomaly detector trained!")
        print(f"  [>>] Model version  : {anomaly_result['model_version']}")
        print(f"  [>>] Training samples: {anomaly_result['n_samples']}")
        print(f"  [>>] Model saved to : {args.anomaly_model}")
        print("-" * 60)
    else:
        print("\n[SKIP] Skipping anomaly detector training (--skip-anomaly)")

    print("\n" + "=" * 60)
    print("  [OK] All models trained successfully!")
    print("=" * 60)

    if result["f1_macro"] < 0.90:
        sys.exit(1)


if __name__ == "__main__":
    main()
