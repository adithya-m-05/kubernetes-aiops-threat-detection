"""
Integration tests for the complete threat detection pipeline.
Tests end-to-end flow: Raw event -> Preprocessing -> Feature Extraction -> Autoencoder -> MITRE Mapping -> Webhook.
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_engine.pipeline import ThreatDetectionPipeline


def test_full_detection_pipeline():
    pipeline = ThreatDetectionPipeline(model_dir="models/autoencoder", dry_run=True)
    
    benign_event = {
        "event_id": "test-benign-001",
        "pod": "web-frontend-abc12",
        "namespace": "aiops-security",
        "severity": "LOW",
        "event_type": "process_execution",
        "syscall": "read",
        "process": "nginx",
        "network_metadata": {"dst_port": 80, "dst_ip": "10.244.0.5"}
    }
    
    benign_res = pipeline.process_event(benign_event)
    assert benign_res["status"] == "processed"
    assert benign_res["pod"] == "web-frontend-abc12"
    assert "anomaly_score" in benign_res
    
    attack_event = {
        "event_id": "test-attack-001",
        "pod": "api-backend-ghi56",
        "namespace": "aiops-security",
        "severity": "CRITICAL",
        "event_type": "container_escape",
        "syscall": "setns",
        "process": "nsenter",
        "network_metadata": {"dst_port": 4443, "dst_ip": "203.0.113.10"}
    }
    
    attack_res = pipeline.process_event(attack_event)
    assert attack_res["status"] == "processed"
    assert attack_res["anomaly_score"] > 0
    assert len(attack_res["mitre_techniques"]) > 0
    assert attack_res["mitre_techniques"][0]["id"] == "T1611"
