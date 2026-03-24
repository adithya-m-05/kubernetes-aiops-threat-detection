"""
=============================================================================
Autoencoder — Unsupervised Anomaly Detection for Zero-Day Threats
=============================================================================
Module: ml_engine/autoencoder.py
Agent:  Agent 3 — "The Brain"

Purpose:
    Implements a PyTorch undercomplete autoencoder trained exclusively on
    benign traffic data. Anomalies (including zero-day attacks) are detected
    by measuring reconstruction error — events that the model cannot
    reconstruct well are flagged as anomalous.

Architecture:
    Encoder: input_dim → 128 → 64 → 32 (latent space)
    Decoder: 32 → 64 → 128 → input_dim

Why Autoencoders for Zero-Day Detection?
    Traditional supervised classifiers require labeled attack data, making
    them blind to novel (zero-day) attacks. Autoencoders learn the "normal"
    data manifold during training. Any input that deviates from this manifold
    produces high reconstruction error, effectively detecting attacks the
    model has never seen. This makes autoencoders ideal for zero-day
    detection in security applications (An & Cho, 2015).

Usage:
    python autoencoder.py --train --data features.csv --epochs 50
    python autoencoder.py --detect --data new_data.csv --model model.pt
=============================================================================
"""

import logging
import argparse
import os
import json
from typing import Tuple, Optional

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("autoencoder")


class AnomalyAutoencoder(nn.Module):
    """
    Undercomplete Autoencoder for anomaly detection.

    Architecture Design Rationale:
    - Undercomplete (bottleneck < input): Forces the network to learn a
      compressed representation of the input, capturing only the most
      important features of "normal" data.
    - Symmetric encoder/decoder: Standard practice ensuring balanced
      compression and reconstruction capability.
    - ReLU activation: Introduces non-linearity for learning complex
      patterns while avoiding vanishing gradients.
    - No dropout: We WANT the model to overfit to normal data — that's
      how it learns what "normal" looks like. Anomalies will then produce
      high reconstruction error precisely because the model expects normal.
    - Batch Normalization: Stabilizes training and accelerates convergence
      for the relatively small security datasets we work with.
    """

    def __init__(self, input_dim: int, latent_dim: int = 32):
        super(AnomalyAutoencoder, self).__init__()

        # Encoder: progressively compress input to latent space
        # input_dim → 128 → 64 → 32
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Linear(64, latent_dim),
            nn.BatchNorm1d(latent_dim),
            nn.ReLU(),
        )

        # Decoder: reconstruct input from latent representation
        # 32 → 64 → 128 → input_dim
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Linear(128, input_dim),
            # No activation on output — allow full reconstruction range
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass: encode then decode."""
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

    def get_latent(self, x: torch.Tensor) -> torch.Tensor:
        """Extract latent representation (useful for visualization)."""
        return self.encoder(x)


def train_autoencoder(
    X_train: np.ndarray,
    epochs: int = 50,
    batch_size: int = 64,
    learning_rate: float = 1e-3,
    latent_dim: int = 32,
    validation_split: float = 0.15,
    device: str = "auto"
) -> Tuple[AnomalyAutoencoder, dict]:
    """
    Train the autoencoder on benign-only data.

    Training Strategy:
    - Loss: MSE (Mean Squared Error) — measures per-feature reconstruction
      accuracy. Low MSE = good reconstruction = "normal" data.
    - Optimizer: Adam — adaptive learning rate handles the heterogeneous
      feature scales in security data.
    - Early stopping: Monitor validation loss to prevent overfitting to
      noise in the benign data (we want to learn structure, not noise).

    Args:
        X_train: Training data (benign events only)
        epochs: Number of training epochs
        batch_size: Mini-batch size
        learning_rate: Adam learning rate
        latent_dim: Bottleneck dimension
        validation_split: Fraction for validation
        device: "cpu", "cuda", or "auto"

    Returns:
        (trained model, training history dict)
    """
    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Training on device: {device}")

    # Split into train/validation
    X_tr, X_val = train_test_split(X_train, test_size=validation_split, random_state=42)

    # Convert to PyTorch tensors
    train_tensor = torch.FloatTensor(X_tr).to(device)
    val_tensor = torch.FloatTensor(X_val).to(device)
    train_loader = DataLoader(TensorDataset(train_tensor), batch_size=batch_size, shuffle=True)

    # Initialize model
    input_dim = X_train.shape[1]
    model = AnomalyAutoencoder(input_dim, latent_dim).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()

    history = {"train_loss": [], "val_loss": []}
    best_val_loss = float("inf")

    for epoch in range(epochs):
        # Training phase
        model.train()
        epoch_loss = 0
        for (batch,) in train_loader:
            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = criterion(reconstructed, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        avg_train_loss = epoch_loss / len(train_loader)

        # Validation phase
        model.eval()
        with torch.no_grad():
            val_recon = model(val_tensor)
            val_loss = criterion(val_recon, val_tensor).item()

        history["train_loss"].append(avg_train_loss)
        history["val_loss"].append(val_loss)

        if val_loss < best_val_loss:
            best_val_loss = val_loss

        if (epoch + 1) % 10 == 0:
            logger.info(f"  Epoch {epoch+1}/{epochs} — "
                        f"Train Loss: {avg_train_loss:.6f}, Val Loss: {val_loss:.6f}")

    logger.info(f"Training complete. Best val loss: {best_val_loss:.6f}")
    return model, history


def compute_anomaly_scores(
    model: AnomalyAutoencoder,
    X: np.ndarray,
    device: str = "auto"
) -> np.ndarray:
    """
    Compute per-sample reconstruction error as anomaly scores.

    The reconstruction error (MSE per sample) serves as the anomaly score:
    - Low error → model can reconstruct → normal data
    - High error → model cannot reconstruct → anomalous data

    This is the core detection mechanism. No attack labels are needed.
    """
    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"

    model.eval()
    with torch.no_grad():
        X_tensor = torch.FloatTensor(X).to(device)
        reconstructed = model(X_tensor)
        mse_per_sample = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
    return mse_per_sample.cpu().numpy()


def determine_threshold(
    scores: np.ndarray,
    percentile: float = 95.0
) -> float:
    """
    Determine the anomaly detection threshold.

    Strategy: Set threshold at the P-th percentile of reconstruction errors
    on the training set (benign data). Samples exceeding this threshold in
    production are flagged as anomalies.

    Default percentile=95 means 5% false positive rate on training data.
    This is tunable: lower percentile = more sensitive (more false positives),
    higher percentile = less sensitive (may miss subtle attacks).
    """
    threshold = np.percentile(scores, percentile)
    logger.info(f"Threshold (P{percentile}): {threshold:.6f}")
    return threshold


def detect_anomalies(
    model: AnomalyAutoencoder,
    X: np.ndarray,
    threshold: float,
    device: str = "auto"
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Detect anomalies in new data using the trained autoencoder.

    Returns:
        (anomaly_flags: bool array, anomaly_scores: float array)
    """
    scores = compute_anomaly_scores(model, X, device)
    flags = scores > threshold
    n_anomalies = flags.sum()
    logger.info(f"Detected {n_anomalies}/{len(scores)} anomalies "
                f"({n_anomalies/len(scores)*100:.1f}%)")
    return flags, scores


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Autoencoder Anomaly Detection")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--detect", action="store_true")
    parser.add_argument("--test", action="store_true", help="Run smoke test")
    parser.add_argument("--data", type=str, default=None)
    parser.add_argument("--model", type=str, default="autoencoder_model.pt")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--threshold-percentile", type=float, default=95.0)
    args = parser.parse_args()

    if args.test:
        # Smoke test with random data
        logger.info("Running autoencoder smoke test...")
        X_test = np.random.randn(500, 20).astype(np.float32)
        model, hist = train_autoencoder(X_test, epochs=10, batch_size=32)
        scores = compute_anomaly_scores(model, X_test)
        threshold = determine_threshold(scores, 95.0)
        flags, _ = detect_anomalies(model, X_test, threshold)
        logger.info(f"Smoke test passed. Anomalies: {flags.sum()}")
    elif args.train and args.data:
        df = pd.read_csv(args.data)
        X = df.select_dtypes(include=[np.number]).values.astype(np.float32)
        model, hist = train_autoencoder(X, epochs=args.epochs)
        torch.save(model.state_dict(), args.model)
        scores = compute_anomaly_scores(model, X)
        threshold = determine_threshold(scores, args.threshold_percentile)
        meta = {"threshold": float(threshold), "input_dim": int(X.shape[1]), "history": hist}
        with open(args.model + ".meta.json", "w") as f:
            json.dump(meta, f, indent=2)
        logger.info(f"Model saved to {args.model}")
