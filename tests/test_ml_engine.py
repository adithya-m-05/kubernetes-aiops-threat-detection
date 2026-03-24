"""
Unit tests for the ML engine modules.
Tests: Autoencoder, Random Forest, Bayesian predictor, MITRE mapping.
"""
import sys
import os
import pytest
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAutoencoder:
    def test_model_forward_pass(self):
        from ml_engine.autoencoder import AnomalyAutoencoder
        import torch
        model = AnomalyAutoencoder(input_dim=20, latent_dim=8)
        x = torch.randn(32, 20)
        output = model(x)
        assert output.shape == (32, 20), "Output shape must match input"

    def test_latent_space(self):
        from ml_engine.autoencoder import AnomalyAutoencoder
        import torch
        model = AnomalyAutoencoder(input_dim=15, latent_dim=4)
        x = torch.randn(10, 15)
        latent = model.get_latent(x)
        assert latent.shape == (10, 4), "Latent dim must match config"

    def test_training(self):
        from ml_engine.autoencoder import train_autoencoder, compute_anomaly_scores
        X = np.random.randn(200, 10).astype(np.float32)
        model, history = train_autoencoder(X, epochs=5, batch_size=32)
        assert len(history["train_loss"]) == 5
        scores = compute_anomaly_scores(model, X)
        assert scores.shape == (200,)

    def test_anomaly_detection(self):
        from ml_engine.autoencoder import (
            train_autoencoder, detect_anomalies, determine_threshold)
        X_normal = np.random.randn(300, 10).astype(np.float32)
        model, _ = train_autoencoder(X_normal, epochs=10, batch_size=32)
        from ml_engine.autoencoder import compute_anomaly_scores
        scores = compute_anomaly_scores(model, X_normal)
        threshold = determine_threshold(scores, 95.0)
        # Anomalous data (different distribution)
        X_anomaly = np.random.randn(50, 10).astype(np.float32) + 5
        flags, scores = detect_anomalies(model, X_anomaly, threshold)
        assert flags.sum() > 0, "Should detect some anomalies in shifted data"


class TestRandomForest:
    def test_pipeline_build(self):
        from ml_engine.random_forest_classifier import build_pipeline
        pipeline = build_pipeline()
        assert pipeline is not None

    def test_train_and_evaluate(self):
        from ml_engine.random_forest_classifier import train_and_evaluate
        np.random.seed(42)
        X = pd.DataFrame(np.random.randn(200, 10),
                         columns=[f"f{i}" for i in range(10)])
        y = pd.Series(np.random.choice(
            ["benign", "ddos", "exfiltration"], 200,
            p=[0.6, 0.2, 0.2]), name="label")
        pipeline, metrics, le = train_and_evaluate(X, y)
        assert 0 <= metrics["accuracy"] <= 1
        assert len(le.classes_) == 3

    def test_predictions(self):
        from ml_engine.random_forest_classifier import (
            train_and_evaluate, predict_threats)
        np.random.seed(42)
        X = pd.DataFrame(np.random.randn(200, 5),
                         columns=[f"f{i}" for i in range(5)])
        y = pd.Series(np.random.choice(["benign", "attack"], 200), name="label")
        pipeline, _, le = train_and_evaluate(X, y)
        labels, probs = predict_threats(pipeline, X[:10], le)
        assert len(labels) == 10
        assert probs.shape[0] == 10


class TestBayesianPredictor:
    def test_initialization(self):
        from ml_engine.bayesian_attack_predictor import AttackPredictor
        predictor = AttackPredictor()
        assert len(predictor.STAGES) == 9

    def test_prediction(self):
        from ml_engine.bayesian_attack_predictor import AttackPredictor
        predictor = AttackPredictor()
        predictions = predictor.predict_next_stage(
            {"execution": 1, "discovery": 1})
        assert len(predictions) > 0
        assert all("probability" in p for p in predictions)

    def test_threat_assessment(self):
        from ml_engine.bayesian_attack_predictor import AttackPredictor
        predictor = AttackPredictor()
        assessment = predictor.get_threat_assessment(
            {"execution": 1, "privilege_escalation": 1})
        assert "risk_level" in assessment
        assert "predictions" in assessment
        assert assessment["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TestMITREMapping:
    def test_technique_lookup(self):
        from ml_engine.mitre_attack_mapping import get_technique_info
        info = get_technique_info("T1611")
        assert info["name"] == "Escape to Host"
        assert info["tactic"] == "privilege_escalation"

    def test_anomaly_mapping(self):
        from ml_engine.mitre_attack_mapping import map_anomaly_to_techniques
        techniques = map_anomaly_to_techniques("container_escape")
        assert len(techniques) > 0
        assert any(t["id"] == "T1611" for t in techniques)

    def test_kill_chain_stage(self):
        from ml_engine.mitre_attack_mapping import get_tactic_stage
        stage = get_tactic_stage("T1611")
        assert stage == 3  # privilege_escalation is stage 3
