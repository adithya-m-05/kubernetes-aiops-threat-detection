"""
Unit tests for the data preprocessing pipeline.
Tests: JSON ingestion, feature extraction, normalization, PCA, SMOTE.
"""
import sys
import os
import json
import tempfile
import uuid
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def sample_telemetry_file(tmp_path):
    """Create a temporary NDJSON telemetry file with sample events."""
    events = []
    base_time = datetime(2026, 3, 23, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(50):
        event = {
            "timestamp": (base_time + timedelta(seconds=i * 2)).isoformat(),
            "source": "falco",
            "event_id": str(uuid.uuid4()),
            "pod": f"test-pod-{i % 3}",
            "namespace": "aiops-security",
            "container_id": f"containerd://{uuid.uuid4().hex[:12]}",
            "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
            "event_type": ["process_execution", "file_access",
                           "network_connection", "shell_execution"][i % 4],
            "syscall": ["read", "write", "execve", "connect"][i % 4],
            "process": "python",
            "network_metadata": {
                "src_ip": "10.244.0.5",
                "dst_ip": "10.244.0.6",
                "src_port": 30000 + i,
                "dst_port": [80, 443, 8080, 6379][i % 4],
                "protocol": "TCP"
            },
            "mitre_technique": ["T1609", None, "T1611", "T1046"][i % 4],
            "raw_event": {}
        }
        events.append(event)

    filepath = str(tmp_path / "test_telemetry.jsonl")
    with open(filepath, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    return filepath


@pytest.fixture
def sample_dataframe():
    """Create a sample cleaned DataFrame for feature extraction tests."""
    np.random.seed(42)
    n = 100
    base_time = pd.Timestamp("2026-03-23 10:00:00", tz="UTC")
    return pd.DataFrame({
        "timestamp": [base_time + pd.Timedelta(seconds=i * 2) for i in range(n)],
        "event_id": [str(uuid.uuid4()) for _ in range(n)],
        "pod": [f"pod-{i % 3}" for i in range(n)],
        "namespace": ["aiops-security"] * n,
        "source": ["falco"] * n,
        "severity": np.random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], n),
        "severity_numeric": np.random.randint(0, 4, n),
        "event_type": np.random.choice(
            ["process_execution", "shell_execution", "network_connection"], n),
        "syscall": np.random.choice(["read", "write", "execve", "connect"], n),
        "process": np.random.choice(["python", "nginx", "bash"], n),
        "net_dst_ip": [f"10.244.0.{i % 10}" for i in range(n)],
        "net_dst_port": np.random.choice([80, 443, 8080, 22, 3306], n),
        "net_src_ip": ["10.244.0.5"] * n,
        "net_src_port": np.random.randint(30000, 65535, n),
        "net_protocol": ["TCP"] * n,
        "container_id": ["test-container"] * n,
        "mitre_technique": np.random.choice(["T1609", "T1611", "", None], n),
    })


# =============================================================================
# Tests: Preprocessing
# =============================================================================
class TestPreprocessing:
    def test_ingest_telemetry(self, sample_telemetry_file):
        from data_pipeline.preprocessing import ingest_telemetry
        df = ingest_telemetry(sample_telemetry_file)
        assert len(df) == 50
        assert "net_dst_port" in df.columns  # Flattened network metadata
        assert "raw_event" not in df.columns  # Removed for memory

    def test_validate_schema(self, sample_telemetry_file):
        from data_pipeline.preprocessing import ingest_telemetry, validate_schema
        df = ingest_telemetry(sample_telemetry_file)
        df = validate_schema(df)
        assert "severity_numeric" in df.columns
        assert df["timestamp"].dtype == "datetime64[ns, UTC]"

    def test_handle_missing_data(self, sample_telemetry_file):
        from data_pipeline.preprocessing import (
            ingest_telemetry, validate_schema, handle_missing_data)
        df = ingest_telemetry(sample_telemetry_file)
        df = validate_schema(df)
        df = handle_missing_data(df)
        # No NaN values in string columns
        assert df["pod"].isna().sum() == 0

    def test_full_pipeline(self, sample_telemetry_file):
        from data_pipeline.preprocessing import preprocess_telemetry
        df = preprocess_telemetry(sample_telemetry_file)
        assert len(df) == 50
        assert df.isna().sum().sum() == 0  # No missing values


# =============================================================================
# Tests: Feature Extraction
# =============================================================================
class TestFeatureExtraction:
    def test_temporal_features(self, sample_dataframe):
        from data_pipeline.feature_extraction import extract_temporal_features
        features = extract_temporal_features(sample_dataframe, window_seconds=60)
        assert "session_duration" in features.columns
        assert "event_rate" in features.columns
        assert len(features) > 0

    def test_traffic_features(self, sample_dataframe):
        from data_pipeline.feature_extraction import extract_traffic_features
        features = extract_traffic_features(sample_dataframe, window_seconds=60)
        assert "unique_dst_ips" in features.columns or len(features) == 0

    def test_behavioral_features(self, sample_dataframe):
        from data_pipeline.feature_extraction import extract_behavioral_features
        features = extract_behavioral_features(sample_dataframe, window_seconds=60)
        assert "severity_mean" in features.columns
        assert len(features) > 0

    def test_full_extraction(self, sample_dataframe):
        from data_pipeline.feature_extraction import extract_all_features
        features = extract_all_features(sample_dataframe, window_seconds=60)
        assert features.shape[1] >= 5  # At least 5 features
        assert features.isna().sum().sum() == 0  # No NaN after fill


# =============================================================================
# Tests: Data Balancing
# =============================================================================
class TestDataBalancing:
    def test_normalize_minmax(self):
        from data_pipeline.data_balancing import normalize_features
        X = pd.DataFrame(np.random.randn(100, 5), columns=[f"f{i}" for i in range(5)])
        X_norm, scaler = normalize_features(X, method="minmax")
        assert X_norm.min().min() >= -0.001  # Allow small float errors
        assert X_norm.max().max() <= 1.001

    def test_normalize_zscore(self):
        from data_pipeline.data_balancing import normalize_features
        X = pd.DataFrame(np.random.randn(100, 5), columns=[f"f{i}" for i in range(5)])
        X_norm, scaler = normalize_features(X, method="zscore")
        assert abs(X_norm.mean().mean()) < 0.1  # Near-zero mean

    def test_pca_variance(self):
        from data_pipeline.data_balancing import apply_pca
        X = pd.DataFrame(np.random.randn(100, 10), columns=[f"f{i}" for i in range(10)])
        X_pca, pca, analysis = apply_pca(X, variance_threshold=0.90)
        assert analysis["total_explained_variance"] >= 0.85
        assert X_pca.shape[1] <= 10

    def test_smote_balancing(self):
        from data_pipeline.data_balancing import apply_smote
        X = pd.DataFrame(np.random.randn(100, 5), columns=[f"f{i}" for i in range(5)])
        y = pd.Series(["benign"] * 80 + ["attack"] * 20, name="label")
        X_bal, y_bal, stats = apply_smote(X, y)
        assert y_bal.value_counts()["benign"] == y_bal.value_counts()["attack"]
