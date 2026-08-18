"""
Unit tests for the ML engine modules.
Tests: Autoencoder, MITRE mapping, Runtime Pipeline.
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

    def test_tactic_stage(self):
        from ml_engine.mitre_attack_mapping import get_tactic_stage
        stage = get_tactic_stage("T1611")
        assert stage == 3


class TestRuntimePipeline:
    def test_pipeline_passthrough_event(self):
        from ml_engine.pipeline import ThreatDetectionPipeline
        pipeline = ThreatDetectionPipeline(model_dir=None, dry_run=True)
        event = {
            "pod": "api-backend-ghi56",
            "namespace": "aiops-security",
            "severity": "CRITICAL",
            "event_type": "container_escape",
            "syscall": "setns",
            "process": "nsenter",
            "network_metadata": {"dst_port": 4443, "dst_ip": "203.0.113.10"}
        }
        res = pipeline.process_event(event)
        assert res["status"] == "processed"
        assert res["pod"] == "api-backend-ghi56"
        assert "anomaly_score" in res
        assert "risk_level" in res
        assert len(res["mitre_techniques"]) > 0
