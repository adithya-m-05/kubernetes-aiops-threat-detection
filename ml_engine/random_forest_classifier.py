"""
=============================================================================
Random Forest Classifier — Known Attack Vector Identification
=============================================================================
Module: ml_engine/random_forest_classifier.py
Agent:  Agent 3 — "The Brain"

Purpose:
    Implements a Scikit-learn pipeline for multi-class classification of
    known attack types using Random Forest, a robust ensemble method.

Why Random Forest for known attack classification?
    1. Ensemble of decision trees — resistant to overfitting
    2. Handles mixed feature types (numeric + categorical) naturally
    3. Provides feature importance rankings for academic analysis
    4. Works well with imbalanced classes via class_weight='balanced'
    5. No feature scaling required (tree-based splits are scale-invariant)
    6. Interpretable: individual trees can be visualized for reporting

Attack Classes:
    - benign: Normal container operations
    - ddos: Distributed Denial of Service flood attacks
    - exfiltration: Data exfiltration to external hosts
    - lateral_movement: Internal network scanning and pivot
    - crypto_mining: Unauthorized cryptocurrency mining

Usage:
    python random_forest_classifier.py --train --data features.csv
    python random_forest_classifier.py --test  # smoke test
=============================================================================
"""

import logging
import argparse
import os
import json
import pickle
from typing import Tuple, Dict

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import (cross_val_score, StratifiedKFold,
                                      train_test_split)
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score, f1_score)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("random_forest_classifier")

# Attack class labels
ATTACK_CLASSES = ["benign", "ddos", "exfiltration", "lateral_movement", "crypto_mining"]


def build_pipeline(n_estimators=200, max_depth=None, class_weight="balanced",
                   random_state=42):
    """
    Build the classification pipeline: StandardScaler → RandomForest.

    Why StandardScaler before Random Forest?
        Technically, tree-based models don't need feature scaling. However,
        including StandardScaler in the pipeline ensures consistent
        preprocessing if the pipeline is swapped with a distance-based
        model (e.g., SVM, k-NN) during experimentation. It also makes the
        pipeline self-contained — no external preprocessing needed.

    Why class_weight='balanced'?
        Automatically adjusts class weights inversely proportional to
        class frequencies: w_c = n_samples / (n_classes * n_c).
        This penalizes misclassification of minority classes more heavily,
        complementing SMOTE's synthetic oversampling.

    Parameters:
        n_estimators=200: More trees = more stable predictions. 200 is a
            good balance between accuracy and training time for our dataset.
        max_depth=None: Allow full tree growth. Pruning is handled by the
            ensemble averaging (bagging) which prevents overfitting.
    """
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight=class_weight,
            random_state=random_state,
            n_jobs=-1,        # Use all CPU cores
            oob_score=True,   # Out-of-bag score as built-in validation
            verbose=0,
        ))
    ])
    return pipeline


def train_and_evaluate(X, y, test_size=0.2, cv_folds=5, random_state=42):
    """
    Train the Random Forest pipeline with cross-validation and evaluation.

    Evaluation Metrics:
    - Accuracy: Overall correctness (can be misleading for imbalanced data)
    - F1-Score: Harmonic mean of precision and recall (better for imbalance)
    - Confusion Matrix: Shows per-class error patterns
    - Feature Importance: Which features drive classification decisions
    - Cross-Validation: 5-fold stratified CV for robust performance estimate

    Returns pipeline, metrics dict, and label encoder.
    """
    logger.info("Training Random Forest classifier...")

    # Encode string labels to integers
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # Train/test split (stratified to preserve class ratios)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=test_size, stratify=y_encoded, random_state=random_state)

    # Build and train pipeline
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    # Evaluate on test set
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True)

    # Cross-validation for robust estimate
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    cv_scores = cross_val_score(pipeline, X, y_encoded, cv=cv, scoring="f1_macro")

    # Feature importance analysis
    rf_model = pipeline.named_steps["classifier"]
    feature_importance = dict(zip(
        [f"feature_{i}" for i in range(X.shape[1])] if not hasattr(X, "columns") else X.columns,
        rf_model.feature_importances_
    ))
    top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]

    metrics = {
        "accuracy": accuracy,
        "f1_macro": f1_macro,
        "f1_weighted": f1_weighted,
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "cv_f1_scores": cv_scores.tolist(),
        "cv_f1_mean": cv_scores.mean(),
        "cv_f1_std": cv_scores.std(),
        "oob_score": rf_model.oob_score_,
        "top_features": top_features,
    }

    logger.info(f"  Test Accuracy:    {accuracy:.4f}")
    logger.info(f"  Test F1 (macro):  {f1_macro:.4f}")
    logger.info(f"  CV F1 (macro):    {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    logger.info(f"  OOB Score:        {rf_model.oob_score_:.4f}")
    logger.info(f"  Top 5 Features:   {top_features[:5]}")

    return pipeline, metrics, le


def predict_threats(pipeline, X, label_encoder):
    """Predict threat labels and probabilities for new data."""
    predictions = pipeline.predict(X)
    probabilities = pipeline.predict_proba(X)
    labels = label_encoder.inverse_transform(predictions)
    return labels, probabilities


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Random Forest Threat Classifier")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--test", action="store_true", help="Smoke test with mock data")
    parser.add_argument("--data", type=str, default=None)
    parser.add_argument("--model", type=str, default="rf_model.pkl")
    args = parser.parse_args()

    if args.test:
        logger.info("Running Random Forest smoke test...")
        np.random.seed(42)
        n_samples, n_features = 1000, 15
        X = np.random.randn(n_samples, n_features)
        y = np.random.choice(ATTACK_CLASSES, size=n_samples,
                             p=[0.6, 0.1, 0.1, 0.1, 0.1])
        X = pd.DataFrame(X, columns=[f"f{i}" for i in range(n_features)])
        y = pd.Series(y, name="label")

        pipeline, metrics, le = train_and_evaluate(X, y)
        logger.info(f"Smoke test passed. Accuracy: {metrics['accuracy']:.4f}")
        print("\nClassification Report:")
        print(json.dumps(metrics["classification_report"], indent=2))

    elif args.train and args.data:
        df = pd.read_csv(args.data)
        y = df["label"]
        X = df.drop(columns=["label"])
        pipeline, metrics, le = train_and_evaluate(X, y)
        with open(args.model, "wb") as f:
            pickle.dump({"pipeline": pipeline, "label_encoder": le, "metrics": metrics}, f)
        logger.info(f"Model saved to {args.model}")
