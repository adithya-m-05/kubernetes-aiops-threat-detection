"""
=============================================================================
Data Balancing — Normalization, PCA, and SMOTE
=============================================================================
Module: data_pipeline/data_balancing.py
Agent:  Agent 2 — "The Cleaner"

Purpose:
    Normalizes features, reduces dimensionality via PCA, and addresses
    class imbalance via SMOTE for security telemetry ML training.

Dependencies: pandas, numpy, scikit-learn, imbalanced-learn
=============================================================================
"""

import logging
from typing import Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.decomposition import PCA
from imblearn.over_sampling import SMOTE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("data_balancing")


def normalize_features(X, method="minmax", feature_range=(0, 1)):
    """
    Normalize feature values to a common scale.

    Methods:
    1. Min-Max: X_norm = (X - X_min) / (X_max - X_min) -> [0, 1]
       Best when distributions are uniform and scale matters.
    2. Z-Score: X_norm = (X - mu) / sigma -> mean=0, std=1
       Best for Gaussian distributions; penalizes outliers.

    Why normalize? ML algorithms using distance/gradient optimization are
    sensitive to feature scale. Without it, large-range features (port
    numbers 0-65535) dominate small-range features (entropy 0-5).
    """
    logger.info(f"Normalizing features with method='{method}'...")
    if method == "minmax":
        scaler = MinMaxScaler(feature_range=feature_range)
    elif method == "zscore":
        scaler = StandardScaler()
    else:
        raise ValueError(f"Unknown method: {method}. Use 'minmax' or 'zscore'.")

    X_norm = pd.DataFrame(scaler.fit_transform(X), columns=X.columns, index=X.index)
    logger.info(f"  Output range: [{X_norm.min().min():.4f}, {X_norm.max().max():.4f}]")
    return X_norm, scaler


def apply_pca(X, n_components=None, variance_threshold=0.95):
    """
    PCA for dimensionality reduction.

    Finds orthogonal directions maximizing variance. Reduces correlated
    features (e.g., unique_dst_ips, unique_dst_ports, port_entropy all
    measure "network diversity") into independent components.

    Component selection: If n_components is None, auto-select minimum k
    where cumulative explained variance >= threshold (Jolliffe, 2002).
    """
    logger.info("Applying PCA for dimensionality reduction...")
    if n_components is None:
        pca_full = PCA(n_components=min(X.shape[0], X.shape[1]))
        pca_full.fit(X)
        cum_var = np.cumsum(pca_full.explained_variance_ratio_)
        n_components = int(np.argmax(cum_var >= variance_threshold) + 1)
        logger.info(f"  Auto-selected {n_components} components (>={variance_threshold*100:.0f}% var)")

    pca = PCA(n_components=n_components)
    X_pca = pca.fit_transform(X)
    pc_cols = [f"PC{i+1}" for i in range(n_components)]
    X_pca_df = pd.DataFrame(X_pca, columns=pc_cols, index=X.index)

    analysis = {
        "n_components": n_components,
        "original_dimensions": X.shape[1],
        "explained_variance_ratio": pca.explained_variance_ratio_.tolist(),
        "cumulative_variance": np.cumsum(pca.explained_variance_ratio_).tolist(),
        "total_explained_variance": sum(pca.explained_variance_ratio_),
    }
    logger.info(f"  PCA: {X.shape[1]} -> {n_components} dims, var={analysis['total_explained_variance']:.4f}")
    return X_pca_df, pca, analysis


def apply_smote(X, y, sampling_strategy="auto", k_neighbors=5, random_state=42):
    """
    SMOTE (Chawla et al., 2002) for class imbalance handling.

    Generates synthetic minority samples by interpolating between existing
    minority samples and their k nearest neighbors. Unlike random oversampling,
    SMOTE creates novel interpolated samples that help classifiers learn
    generalizable attack patterns instead of memorizing specific instances.

    Security datasets are heavily imbalanced (~99% benign, ~1% malicious).
    Without resampling, classifiers learn to always predict "benign".
    """
    logger.info("Applying SMOTE for class imbalance handling...")
    class_before = y.value_counts().to_dict()
    logger.info(f"  Before: {class_before}")

    min_count = y.value_counts().min()
    if min_count <= k_neighbors:
        k_neighbors = max(1, min_count - 1)
        logger.warning(f"  Reduced k_neighbors to {k_neighbors}")

    smote = SMOTE(sampling_strategy=sampling_strategy, k_neighbors=k_neighbors,
                  random_state=random_state)
    X_res, y_res = smote.fit_resample(X, y)
    X_res = pd.DataFrame(X_res, columns=X.columns)
    y_res = pd.Series(y_res, name=y.name)

    class_after = y_res.value_counts().to_dict()
    stats = {
        "class_distribution_before": class_before,
        "class_distribution_after": class_after,
        "samples_before": len(y), "samples_after": len(y_res),
        "synthetic_created": len(y_res) - len(y),
    }
    logger.info(f"  After: {class_after} (+{stats['synthetic_created']} synthetic)")
    return X_res, y_res, stats


def balance_pipeline(X, y, normalization_method="minmax", n_pca_components=None,
                     pca_variance_threshold=0.95, apply_smote_flag=True,
                     smote_k_neighbors=5, random_state=42):
    """
    Full pipeline: Normalize -> PCA -> SMOTE.

    Order is deliberate:
    1. Normalize FIRST: PCA needs equal-scale features for meaningful variance.
    2. PCA SECOND: Reduce dims before SMOTE to avoid curse of dimensionality.
    3. SMOTE LAST: Synthesize in reduced space where distances are meaningful.
    """
    logger.info("=" * 60)
    logger.info("Starting Data Balancing Pipeline")
    logger.info("=" * 60)

    stats = {}
    X_norm, scaler = normalize_features(X, method=normalization_method)
    stats["normalization"] = normalization_method

    X_pca, pca, pca_stats = apply_pca(X_norm, n_pca_components, pca_variance_threshold)
    stats["pca"] = pca_stats

    if apply_smote_flag and y is not None:
        X_final, y_final, smote_stats = apply_smote(X_pca, y, k_neighbors=smote_k_neighbors,
                                                     random_state=random_state)
        stats["smote"] = smote_stats
    else:
        X_final, y_final = X_pca, y

    logger.info(f"Pipeline complete. Final shape: {X_final.shape}")
    return X_final, y_final, stats
