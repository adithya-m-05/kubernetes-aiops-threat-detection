"""
=============================================================================
Webhook Server — Threat Alert Receiver and ML Inference API
=============================================================================
Module: response_engine/webhook_server.py

Purpose:
    Flask-based REST API that serves as the central hub for the threat
    detection system:
    1. Receives Falco telemetry events and processes them through the
       ML inference pipeline (autoencoder anomaly detection)
    2. Receives pre-formed threat alerts from external sources
    3. Triggers automated remediation (NetworkPolicy pod isolation)
    4. Serves detection results to the SOC dashboard

API Endpoints:
    POST /api/v1/alert     — Receive threat alert and trigger response
    POST /api/v1/event     — Process a raw Falco event through ML pipeline
    GET  /api/v1/status    — Health check and system status
    GET  /api/v1/history   — View recent alert history

Usage:
    python webhook_server.py --port 5000 --confidence-threshold 0.85
=============================================================================
"""

import logging
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any
from collections import deque

from flask import Flask, request, jsonify
from flask_cors import CORS

# Import response modules (graceful import for standalone testing)
try:
    from response_engine.network_policy_manager import NetworkPolicyManager
    RESPONSE_MODULES_AVAILABLE = True
except ImportError:
    RESPONSE_MODULES_AVAILABLE = False

# Import ML pipeline (graceful import)
try:
    from ml_engine.pipeline import ThreatDetectionPipeline
    ML_PIPELINE_AVAILABLE = True
except ImportError:
    ML_PIPELINE_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webhook_server")

# Flask application
app = Flask(__name__)
CORS(app)

# Configuration (can be overridden via environment variables)
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.85"))
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
MODEL_DIR = os.environ.get("MODEL_DIR", None)
MAX_HISTORY = 100

# In-memory alert history (bounded deque)
alert_history = deque(maxlen=MAX_HISTORY)

# ML Pipeline instance (initialized on first request or at startup)
ml_pipeline = None


def get_ml_pipeline():
    """Lazy-initialize the ML pipeline."""
    global ml_pipeline
    if ml_pipeline is None and ML_PIPELINE_AVAILABLE:
        ml_pipeline = ThreatDetectionPipeline(
            model_dir=MODEL_DIR,
            dry_run=DRY_RUN
        )
        logger.info(f"ML Pipeline initialized (model_loaded={ml_pipeline.model_loaded})")
    return ml_pipeline


# =============================================================================
# Response Action Mapping
# =============================================================================
# Maps risk levels to automated response actions.
# CRITICAL/HIGH: Network isolation (NetworkPolicy deny-all)
# MEDIUM: Monitoring enhancement (audit-only)
# LOW: Log only (no automated action)

RESPONSE_ACTIONS = {
    "CRITICAL": ["isolate_pod"],
    "HIGH":     ["isolate_pod"],
    "MEDIUM":   ["log_only"],
    "LOW":      ["log_only"],
}


def validate_alert(data: Dict[str, Any]) -> tuple:
    """
    Validate incoming alert payload against expected schema.

    Returns (is_valid, error_message) tuple.
    """
    required_fields = ["pod", "namespace", "threat_type", "confidence_score"]
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"

    if not isinstance(data["confidence_score"], (int, float)):
        return False, "confidence_score must be numeric"

    if not 0 <= data["confidence_score"] <= 1:
        return False, "confidence_score must be between 0 and 1"

    return True, ""


def execute_response(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute the automated response based on alert risk level.

    Response Protocol:
    1. Determine risk level from alert (default to threshold-based)
    2. Map risk level to response actions
    3. Execute each action sequentially
    4. Log results for audit trail

    The response is deliberately graduated:
    - We don't isolate pods for LOW/MEDIUM threats (false positive cost)
    - We DO isolate for HIGH/CRITICAL threats (attack in progress)
    """
    risk_level = alert.get("risk_level", "MEDIUM")
    actions = RESPONSE_ACTIONS.get(risk_level, ["log_only"])
    results = {"actions_taken": [], "success": True}

    pod = alert["pod"]
    namespace = alert["namespace"]

    for action in actions:
        try:
            if action == "isolate_pod" and RESPONSE_MODULES_AVAILABLE:
                npm = NetworkPolicyManager()
                policy_name = npm.isolate_pod(pod, namespace)
                results["actions_taken"].append({
                    "action": "isolate_pod",
                    "status": "success",
                    "policy_name": policy_name
                })
                logger.info(f"Pod {pod} isolated via NetworkPolicy")

            elif action == "log_only":
                results["actions_taken"].append({
                    "action": "log_only",
                    "status": "logged",
                })
                logger.info(f"Alert logged (no action): {alert.get('threat_type', 'unknown')}")

            else:
                results["actions_taken"].append({
                    "action": action,
                    "status": "skipped",
                    "reason": "response modules not available"
                })

        except Exception as e:
            logger.error(f"Response action '{action}' failed: {e}")
            results["actions_taken"].append({
                "action": action,
                "status": "failed",
                "error": str(e)
            })
            results["success"] = False

    return results


# =============================================================================
# API Endpoints
# =============================================================================

@app.route("/api/v1/alert", methods=["POST"])
def receive_alert():
    """
    POST /api/v1/alert — Receive and process a threat alert.

    This endpoint accepts pre-formed threat alerts (e.g., from external
    tools or manual testing). For processing raw Falco events through
    the ML pipeline, use POST /api/v1/event instead.

    Returns:
        201: Alert processed successfully with response actions taken
        400: Invalid alert payload
        200: Alert below confidence threshold (logged but no action)
    """
    data = request.get_json(force=True)

    # Validate payload
    is_valid, error = validate_alert(data)
    if not is_valid:
        return jsonify({"error": error}), 400

    # Enrich alert with timestamp
    data["received_at"] = datetime.now(timezone.utc).isoformat()

    # Check confidence threshold
    if data["confidence_score"] < CONFIDENCE_THRESHOLD:
        data["action"] = "below_threshold"
        alert_history.append(data)
        return jsonify({
            "status": "below_threshold",
            "message": f"Confidence {data['confidence_score']:.2f} < "
                       f"threshold {CONFIDENCE_THRESHOLD:.2f}",
            "alert_logged": True,
        }), 200

    # Execute automated response
    logger.info(f"HIGH-CONFIDENCE ALERT: {data['threat_type']} on "
                f"{data['pod']} (confidence: {data['confidence_score']:.2f})")

    response_result = execute_response(data)
    data["response"] = response_result
    alert_history.append(data)

    return jsonify({
        "status": "processed",
        "threat_type": data["threat_type"],
        "confidence_score": data["confidence_score"],
        "risk_level": data.get("risk_level", "MEDIUM"),
        "response": response_result,
    }), 201


@app.route("/api/v1/event", methods=["POST"])
def process_falco_event():
    """
    POST /api/v1/event — Process a raw Falco event through the ML pipeline.

    This is the primary endpoint for real-time threat detection. It accepts
    a raw Falco telemetry event, runs it through the autoencoder for anomaly
    detection, maps anomalies to MITRE ATT&CK techniques, and triggers
    automated response actions if warranted.

    Returns:
        200: Event processed with detection results
        400: Invalid event payload
        503: ML pipeline not available
    """
    pipeline = get_ml_pipeline()
    if pipeline is None:
        return jsonify({
            "error": "ML pipeline not available",
            "hint": "Ensure ml_engine package is installed"
        }), 503

    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "Empty event payload"}), 400

    # Process through ML pipeline
    result = pipeline.process_event(data)

    # If anomaly detected, create an alert entry and trigger response
    if result.get("is_anomaly"):
        alert_entry = {
            "pod": result["pod"],
            "namespace": result["namespace"],
            "threat_type": result["event_type"],
            "confidence_score": result["anomaly_score"],
            "anomaly_score": result["anomaly_score"],
            "risk_level": result["risk_level"],
            "mitre_technique": (result["mitre_techniques"][0]["id"]
                                if result["mitre_techniques"] else None),
            "received_at": datetime.now(timezone.utc).isoformat(),
            "source": "ml_pipeline",
        }

        # Execute response
        response_result = execute_response(alert_entry)
        alert_entry["response"] = response_result
        alert_history.append(alert_entry)
        result["response"] = response_result

    return jsonify(result), 200


@app.route("/api/v1/status", methods=["GET"])
def health_check():
    """GET /api/v1/status — System health check."""
    pipeline = get_ml_pipeline()
    pipeline_stats = pipeline.get_stats() if pipeline else {}

    return jsonify({
        "status": "healthy",
        "service": "AIOps Threat Intelligence — Detection Engine",
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "alerts_processed": len(alert_history),
        "response_modules_available": RESPONSE_MODULES_AVAILABLE,
        "ml_pipeline_available": ML_PIPELINE_AVAILABLE,
        "ml_pipeline_stats": pipeline_stats,
        "dry_run": DRY_RUN,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@app.route("/api/v1/history", methods=["GET"])
def get_history():
    """GET /api/v1/history — View recent alert history."""
    limit = request.args.get("limit", 20, type=int)
    alerts = list(alert_history)[-limit:]
    return jsonify({"count": len(alerts), "alerts": alerts}), 200


# =============================================================================
# CLI Entry Point
# =============================================================================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Kubernetes Threat Detection Webhook Server"
    )
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "5000")))
    parser.add_argument("--host", type=str, default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--confidence-threshold", type=float, default=None,
                        help="Minimum confidence score to trigger containment (default: env CONFIDENCE_THRESHOLD or 0.85)")
    parser.add_argument("--model-dir", type=str, default=None,
                        help="Directory containing trained autoencoder model (default: env MODEL_DIR)")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=None,
                        help="Run in dry-run mode (no real K8s actions)")
    parser.add_argument("--no-dry-run", dest="dry_run", action="store_false",
                        help="Disable dry-run mode (apply live K8s NetworkPolicies)")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.confidence_threshold is not None:
        CONFIDENCE_THRESHOLD = args.confidence_threshold
    if args.model_dir is not None:
        MODEL_DIR = args.model_dir
    if args.dry_run is not None:
        DRY_RUN = args.dry_run

    logger.info(f"Starting webhook server on {args.host}:{args.port}")
    logger.info(f"Confidence threshold: {CONFIDENCE_THRESHOLD}")
    logger.info(f"Dry-run mode: {DRY_RUN}")
    logger.info(f"Model directory: {MODEL_DIR or 'None (passthrough mode)'}")

    app.run(host=args.host, port=args.port, debug=args.debug)
