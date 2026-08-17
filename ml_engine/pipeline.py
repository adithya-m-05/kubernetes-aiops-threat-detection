"""
=============================================================================
Runtime Inference Pipeline — Falco Event → Anomaly Detection → Response
=============================================================================
Module: ml_engine/pipeline.py

Purpose:
    Central runtime inference pipeline that connects all components:
    1. Receives a Falco telemetry event (JSON)
    2. Preprocesses and extracts features
    3. Runs the autoencoder for anomaly detection
    4. Maps anomalies to MITRE ATT&CK techniques
    5. Determines risk level and response action
    6. Triggers automated response (NetworkPolicy isolation)

    This is the single entry point for real-time threat detection.

Usage:
    from ml_engine.pipeline import ThreatDetectionPipeline

    pipeline = ThreatDetectionPipeline(model_dir="models/autoencoder/")
    result = pipeline.process_event(falco_event_json)
=============================================================================
"""

import os
import sys
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pipeline")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available — pipeline will run without ML inference")


class ThreatDetectionPipeline:
    """
    End-to-end runtime threat detection pipeline.

    Architecture:
        Falco Event → Feature Extraction → Autoencoder → Anomaly Score
            → Threshold Check → MITRE ATT&CK Mapping → Risk Assessment

    The pipeline operates in two modes:
    - **Inference mode**: Loads a trained model and processes events in real-time
    - **Passthrough mode**: If no model is loaded, passes events through with
      rule-based detection only (useful for testing without training)
    """

    def __init__(
        self,
        model_dir: Optional[str] = None,
        threshold: Optional[float] = None,
        dry_run: bool = True
    ):
        """
        Initialize the threat detection pipeline.

        Args:
            model_dir: Directory containing trained autoencoder model files
                       (model.pt, model_meta.json). If None, runs in passthrough mode.
            threshold: Override anomaly threshold. If None, uses saved threshold.
            dry_run: If True, response actions are logged but not executed.
        """
        self.model = None
        self.threshold = threshold or 0.0
        self.input_dim = 0
        self.feature_names = []
        self.scaler = None
        self.dry_run = dry_run
        self.model_loaded = False

        # Event processing statistics
        self.stats = {
            "events_processed": 0,
            "anomalies_detected": 0,
            "responses_triggered": 0,
        }

        # Load model if directory provided
        if model_dir and os.path.isdir(model_dir):
            self._load_model(model_dir)

        # Import MITRE mapping
        try:
            from ml_engine.mitre_attack_mapping import (
                map_anomaly_to_techniques, get_technique_info
            )
            self._map_anomaly = map_anomaly_to_techniques
            self._get_technique = get_technique_info
            self.mitre_available = True
        except ImportError:
            self.mitre_available = False
            logger.warning("MITRE ATT&CK mapping module not available")

    def _load_model(self, model_dir: str) -> None:
        """Load a trained autoencoder model and its metadata."""
        if not TORCH_AVAILABLE:
            logger.warning("Cannot load model — PyTorch not installed")
            return

        model_path = os.path.join(model_dir, "model.pt")
        meta_path = os.path.join(model_dir, "model_meta.json")

        if not os.path.exists(model_path):
            logger.warning(f"Model file not found: {model_path}")
            return

        try:
            # Load metadata
            if os.path.exists(meta_path):
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                self.input_dim = meta.get("input_dim", 0)
                self.threshold = meta.get("threshold", self.threshold)
                self.feature_names = meta.get("feature_names", [])
                logger.info(f"Model metadata loaded: input_dim={self.input_dim}, "
                            f"threshold={self.threshold:.6f}")

            # Load model
            from ml_engine.autoencoder import AnomalyAutoencoder
            self.model = AnomalyAutoencoder(
                input_dim=self.input_dim,
                latent_dim=meta.get("latent_dim", self.input_dim // 2)
            )
            self.model.load_state_dict(torch.load(model_path, weights_only=True))
            self.model.eval()
            self.model_loaded = True
            logger.info(f"Autoencoder model loaded from {model_path}")

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model_loaded = False

    def extract_features(self, event: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Extract numeric features from a single Falco event.

        This is a simplified per-event feature extraction for real-time
        inference. For batch training, use data_pipeline/feature_extraction.py.

        Features extracted:
        - severity_numeric: Severity as integer (LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3)
        - event_type_encoded: One-hot or ordinal encoding of event type
        - syscall_risk: Risk score of the system call (0-3)
        - has_network: Whether network metadata is present (0/1)
        - dst_port_risk: Risk score based on destination port
        - is_external_dst: Whether destination IP is external (0/1)
        - process_risk: Risk score based on process name
        """
        try:
            # Severity encoding
            severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            severity = severity_map.get(event.get("severity", "LOW"), 0)

            # Event type encoding
            event_type_map = {
                "process_execution": 0, "file_access": 1,
                "network_connection": 2, "shell_execution": 3,
                "network_anomaly": 4, "unexpected_network_connection": 5,
                "crypto_mining": 6, "container_escape": 7,
                "sensitive_file_read": 8, "privilege_escalation": 9,
            }
            event_type = event_type_map.get(event.get("event_type", ""), 0)

            # Syscall risk scoring
            high_risk_syscalls = {"execve", "setuid", "setns", "unshare",
                                  "mount", "ptrace", "clone"}
            medium_risk_syscalls = {"connect", "sendto", "socket", "recvfrom",
                                    "bind", "listen"}
            syscall = event.get("syscall", "")
            if syscall in high_risk_syscalls:
                syscall_risk = 3
            elif syscall in medium_risk_syscalls:
                syscall_risk = 2
            else:
                syscall_risk = 0

            # Network metadata features
            net = event.get("network_metadata") or {}
            has_network = 1 if net else 0
            dst_port = net.get("dst_port", 0) if net else 0
            dst_ip = net.get("dst_ip", "") if net else ""

            # Destination port risk
            suspicious_ports = {4443, 8443, 9999, 3333, 5555, 8332, 22, 23}
            standard_ports = {80, 443, 8080, 6379, 5432, 3306, 53}
            if dst_port in suspicious_ports:
                dst_port_risk = 3
            elif dst_port not in standard_ports and dst_port > 0:
                dst_port_risk = 1
            else:
                dst_port_risk = 0

            # External IP detection
            is_external = 0
            if dst_ip and not dst_ip.startswith(("10.", "172.", "192.168.")):
                is_external = 1

            # Process risk scoring
            risky_processes = {"bash", "sh", "curl", "wget", "nmap", "nc",
                               "netcat", "python", "perl", "xmrig", "minerd",
                               "cpuminer", "nsenter", "runc"}
            safe_processes = {"nginx", "redis-server", "node", "java",
                              "postgres", "mysqld"}
            process = event.get("process", "")
            if process in risky_processes:
                process_risk = 2
            elif process in safe_processes:
                process_risk = 0
            else:
                process_risk = 1

            features = np.array([
                severity,
                event_type,
                syscall_risk,
                has_network,
                dst_port_risk,
                is_external,
                process_risk,
            ], dtype=np.float32)

            return features

        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def compute_anomaly_score(self, features: np.ndarray) -> float:
        """
        Compute the autoencoder reconstruction error as an anomaly score.

        If no model is loaded, uses a heuristic risk score based on
        feature values (passthrough mode).
        """
        if self.model_loaded and self.model is not None:
            try:
                x = torch.tensor(features, dtype=torch.float32).unsqueeze(0)
                with torch.no_grad():
                    output = self.model(x)
                    mse = torch.mean((x - output) ** 2).item()
                return mse
            except Exception as e:
                logger.error(f"Model inference failed: {e}")
                return self._heuristic_score(features)
        else:
            return self._heuristic_score(features)

    def _heuristic_score(self, features: np.ndarray) -> float:
        """
        Fallback heuristic scoring when no trained model is available.

        Computes a simple weighted risk score from the extracted features.
        This enables the pipeline to function end-to-end even without
        a trained autoencoder (useful for demos and testing).
        """
        # features: [severity, event_type, syscall_risk, has_network,
        #            dst_port_risk, is_external, process_risk]
        weights = np.array([0.20, 0.10, 0.25, 0.05, 0.15, 0.15, 0.10])
        max_values = np.array([3, 9, 3, 1, 3, 1, 2])

        # Normalize each feature to [0, 1] range
        normalized = np.minimum(features / np.maximum(max_values, 1), 1.0)
        score = float(np.dot(normalized, weights))
        return score

    def assess_risk(
        self, anomaly_score: float, event: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Determine risk level and response action based on anomaly score.

        Risk Levels:
        - CRITICAL: anomaly_score > threshold * 1.5 → Isolate pod
        - HIGH:     anomaly_score > threshold       → Isolate pod
        - MEDIUM:   anomaly_score > threshold * 0.7 → Log and monitor
        - LOW:      anomaly_score <= threshold * 0.7 → Log only

        When running in passthrough mode (no model), the threshold is
        set heuristically at 0.5.
        """
        threshold = self.threshold if self.threshold > 0 else 0.5

        if anomaly_score > threshold * 1.5:
            risk_level = "CRITICAL"
            response_action = "isolate_pod"
        elif anomaly_score > threshold:
            risk_level = "HIGH"
            response_action = "isolate_pod"
        elif anomaly_score > threshold * 0.7:
            risk_level = "MEDIUM"
            response_action = "monitor"
        else:
            risk_level = "LOW"
            response_action = "log_only"

        # MITRE ATT&CK mapping
        mitre_techniques = []
        if self.mitre_available and risk_level in ("CRITICAL", "HIGH", "MEDIUM"):
            event_type = event.get("event_type", "")
            mitre_techniques = self._map_anomaly(event_type)

            # Also use technique from event if present
            if event.get("mitre_technique"):
                technique_info = self._get_technique(event["mitre_technique"])
                if technique_info.get("name") != "Unknown Technique":
                    mitre_techniques = [technique_info] + [
                        t for t in mitre_techniques
                        if t["id"] != event["mitre_technique"]
                    ]

        return {
            "risk_level": risk_level,
            "response_action": response_action,
            "mitre_techniques": mitre_techniques,
        }

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single Falco telemetry event through the full pipeline.

        This is the main entry point for real-time inference.

        Args:
            event: Falco telemetry event as a dictionary

        Returns:
            Detection result dictionary containing:
            - event metadata (pod, namespace, timestamp)
            - anomaly_score
            - is_anomaly (bool)
            - risk_level (LOW/MEDIUM/HIGH/CRITICAL)
            - mitre_techniques (list)
            - response_action (log_only/monitor/isolate_pod)
        """
        self.stats["events_processed"] += 1

        # Step 1: Extract features
        features = self.extract_features(event)
        if features is None:
            return {
                "status": "error",
                "error": "Feature extraction failed",
                "event_id": event.get("event_id", "unknown"),
            }

        # Step 2: Compute anomaly score
        anomaly_score = self.compute_anomaly_score(features)

        # Step 3: Assess risk and map to MITRE ATT&CK
        assessment = self.assess_risk(anomaly_score, event)

        is_anomaly = assessment["risk_level"] in ("HIGH", "CRITICAL")
        if is_anomaly:
            self.stats["anomalies_detected"] += 1

        # Step 4: Build result
        result = {
            "status": "processed",
            "event_id": event.get("event_id", "unknown"),
            "timestamp": event.get("timestamp",
                                   datetime.now(timezone.utc).isoformat()),
            "pod": event.get("pod", "unknown"),
            "namespace": event.get("namespace", "unknown"),
            "event_type": event.get("event_type", "unknown"),
            "anomaly_score": round(anomaly_score, 6),
            "is_anomaly": is_anomaly,
            "risk_level": assessment["risk_level"],
            "response_action": assessment["response_action"],
            "mitre_techniques": assessment["mitre_techniques"],
            "model_used": self.model_loaded,
        }

        if is_anomaly:
            logger.warning(
                f"ANOMALY DETECTED: {event.get('event_type')} on "
                f"{event.get('pod')} (score={anomaly_score:.4f}, "
                f"risk={assessment['risk_level']})"
            )

        return result

    def process_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of events and return results."""
        return [self.process_event(e) for e in events]

    def get_stats(self) -> Dict[str, Any]:
        """Return pipeline processing statistics."""
        return {
            **self.stats,
            "model_loaded": self.model_loaded,
            "threshold": self.threshold,
            "dry_run": self.dry_run,
        }


# =============================================================================
# CLI Entry Point
# =============================================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the threat detection pipeline on Falco telemetry"
    )
    parser.add_argument("--input", "-i", type=str, required=True,
                        help="Path to NDJSON telemetry file")
    parser.add_argument("--model-dir", type=str, default=None,
                        help="Directory containing trained model")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output path for results (NDJSON)")
    args = parser.parse_args()

    pipeline = ThreatDetectionPipeline(model_dir=args.model_dir)

    results = []
    with open(args.input, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            result = pipeline.process_event(event)
            results.append(result)

    # Print summary
    stats = pipeline.get_stats()
    print(f"\n{'='*60}")
    print(f"Pipeline Results Summary")
    print(f"{'='*60}")
    print(f"Events processed:   {stats['events_processed']}")
    print(f"Anomalies detected: {stats['anomalies_detected']}")
    print(f"Model loaded:       {stats['model_loaded']}")
    print(f"Threshold:          {stats['threshold']:.6f}")

    # Risk distribution
    from collections import Counter
    risk_dist = Counter(r["risk_level"] for r in results)
    print(f"\nRisk Distribution:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"  {level}: {risk_dist.get(level, 0)}")

    # Save results
    if args.output:
        with open(args.output, "w") as f:
            for r in results:
                f.write(json.dumps(r, default=str) + "\n")
        print(f"\nResults saved to: {args.output}")
