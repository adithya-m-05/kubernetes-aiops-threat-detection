"""
=============================================================================
Model Training & Artifact Generation Script
=============================================================================
Module: scripts/train_model.py

Purpose:
    Executes the end-to-end training workflow:
    1. Generates or loads raw Falco telemetry events
    2. Preprocesses data and extracts features
    3. Normalizes features with MinMaxScaler
    4. Trains the PyTorch Anomaly Autoencoder on benign samples
    5. Computes reconstruction threshold based on percentile
    6. Saves trained model weights and metadata into models/autoencoder/

Usage:
    python scripts/train_model.py --epochs 50 --events 3000
=============================================================================
"""

import os
import sys
import json
import argparse
import logging
import numpy as np
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data_pipeline.mock_data_generator import generate_dataset, save_dataset
from data_pipeline.preprocessing import preprocess_telemetry
from data_pipeline.feature_extraction import extract_all_features
from data_pipeline.data_balancing import normalize_features
from ml_engine.autoencoder import train_autoencoder, compute_anomaly_scores, determine_threshold

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_model")

def run_training(
    num_events: int = 3000,
    epochs: int = 50,
    batch_size: int = 32,
    output_dir: str = "models/autoencoder",
    data_path: str = None
):
    os.makedirs(output_dir, exist_ok=True)
    raw_telemetry_file = "temp_training_telemetry.jsonl"

    if data_path and os.path.exists(data_path):
        logger.info(f"Using existing data from {data_path}")
        raw_telemetry_file = data_path
    else:
        logger.info(f"Generating {num_events} synthetic Falco events for training...")
        events = generate_dataset(num_events=num_events, attack_ratio=0.15)
        save_dataset(events, raw_telemetry_file)

    # 1. Preprocess
    logger.info("Preprocessing telemetry data...")
    clean_df = preprocess_telemetry(raw_telemetry_file)

    # 2. Extract features
    logger.info("Extracting features...")
    feature_df = extract_all_features(clean_df, window_seconds=60)
    
    # Filter numeric features
    numeric_cols = feature_df.select_dtypes(include=[np.number]).columns.tolist()
    X = feature_df[numeric_cols].fillna(0).values

    # 3. Normalize features
    logger.info(f"Normalizing {X.shape[1]} features across {X.shape[0]} samples...")
    from sklearn.preprocessing import MinMaxScaler
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    # 4. Train autoencoder
    logger.info(f"Training Autoencoder for {epochs} epochs...")
    input_dim = X_scaled.shape[1]
    latent_dim = max(2, input_dim // 2)

    model, history = train_autoencoder(
        X_scaled,
        latent_dim=latent_dim,
        epochs=epochs,
        batch_size=batch_size,
        learning_rate=0.001
    )

    # 5. Compute threshold from reconstruction error
    scores = compute_anomaly_scores(model, X_scaled)
    threshold = determine_threshold(scores, percentile=95.0)
    logger.info(f"Anomaly threshold set to: {threshold:.6f}")

    # 6. Save model and metadata
    model_file = os.path.join(output_dir, "model.pt")
    meta_file = os.path.join(output_dir, "model_meta.json")

    import torch
    torch.save(model.state_dict(), model_file)

    metadata = {
        "input_dim": input_dim,
        "latent_dim": latent_dim,
        "threshold": float(threshold),
        "feature_names": numeric_cols,
        "history": {
            "train_loss": [float(x) for x in history.get("train_loss", [])],
            "val_loss": [float(x) for x in history.get("val_loss", [])]
        }
    }

    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=2)

    # Clean up temp file if created
    if raw_telemetry_file == "temp_training_telemetry.jsonl" and os.path.exists(raw_telemetry_file):
        try:
            os.remove(raw_telemetry_file)
        except Exception:
            pass

    logger.info(f"Training complete! Model artifacts saved to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Autoencoder Anomaly Detection Model")
    parser.add_argument("--events", type=int, default=3000)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--output-dir", type=str, default="models/autoencoder")
    parser.add_argument("--data", type=str, default=None)
    args = parser.parse_args()

    run_training(
        num_events=args.events,
        epochs=args.epochs,
        batch_size=args.batch_size,
        output_dir=args.output_dir,
        data_path=args.data
    )
