"""
=============================================================================
Webhook Server — Threat Alert Receiver for Automated Response
=============================================================================
Module: response_engine/webhook_server.py
Agent:  Agent 4 — "The Enforcer"

Purpose:
    Flask-based REST API that receives high-confidence threat alerts from
    Agent 3's ML engine and triggers automated remediation actions:
    - Pod isolation via dynamic NetworkPolicy (network_policy_manager.py)
    - Node cordon and pod migration (pod_migration.py)

API Endpoints:
    POST /api/v1/alert     — Receive threat alert and trigger response
    GET  /api/v1/status     — Health check and system status
    GET  /api/v1/history    — View recent alert history

Alert Payload Schema:
    {
        "pod": "api-backend-ghi56",
        "namespace": "aiops-security",
        "threat_type": "exfiltration",
        "confidence_score": 0.95,
        "mitre_technique": "T1041",
        "anomaly_score": 0.87,
        "risk_level": "CRITICAL",
        "predicted_next_stage": "impact"
    }

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
    from response_engine.pod_migration import PodMigrationManager
    RESPONSE_MODULES_AVAILABLE = True
except ImportError:
    RESPONSE_MODULES_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webhook_server")

# Flask application
app = Flask(__name__)
CORS(app)

# Configuration (can be overridden via environment variables)
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.85"))
MAX_HISTORY = 100

# In-memory alert history (bounded deque)
alert_history = deque(maxlen=MAX_HISTORY)


# =============================================================================
# Response Action Mapping
# =============================================================================
# Maps risk levels to automated response actions.
# CRITICAL: Full isolation + migration (highest severity)
# HIGH: Network isolation only (restrictive policy)
# MEDIUM: Monitoring enhancement (audit-only policy)
# LOW: Log only (no automated action)

RESPONSE_ACTIONS = {
    "CRITICAL": ["isolate_pod", "cordon_node", "migrate_pods"],
    "HIGH":     ["isolate_pod"],
    "MEDIUM":   ["apply_audit_policy"],
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
    3. Execute each action sequentially (order matters for safety)
    4. Log results for audit trail

    The response is deliberately graduated:
    - We don't isolate pods for LOW/MEDIUM threats (false positive cost)
    - We DO isolate and migrate for CRITICAL threats (attack in progress)
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

            elif action == "cordon_node" and RESPONSE_MODULES_AVAILABLE:
                pmm = PodMigrationManager()
                node_name = pmm.get_pod_node(pod, namespace)
                if node_name:
                    pmm.cordon_node(node_name)
                    results["actions_taken"].append({
                        "action": "cordon_node",
                        "status": "success",
                        "node": node_name
                    })

            elif action == "migrate_pods" and RESPONSE_MODULES_AVAILABLE:
                pmm = PodMigrationManager()
                migration_result = pmm.safe_drain_and_reschedule(pod, namespace)
                results["actions_taken"].append({
                    "action": "migrate_pods",
                    "status": "success",
                    "details": migration_result
                })

            elif action == "log_only":
                results["actions_taken"].append({
                    "action": "log_only",
                    "status": "logged",
                })
                logger.info(f"Alert logged (no action): {alert['threat_type']}")

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

    This is the primary integration point between Agent 3 (ML Engine)
    and Agent 4 (Response Engine). The ML engine sends alerts here
    when it detects a threat above the confidence threshold.

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


@app.route("/api/v1/status", methods=["GET"])
def health_check():
    """GET /api/v1/status — System health check."""
    return jsonify({
        "status": "healthy",
        "service": "AIOps Response Engine",
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "alerts_processed": len(alert_history),
        "response_modules_available": RESPONSE_MODULES_AVAILABLE,
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
    parser = argparse.ArgumentParser(description="AIOps Threat Alert Webhook Server")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--confidence-threshold", type=float, default=0.85)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    CONFIDENCE_THRESHOLD = args.confidence_threshold
    logger.info(f"Starting webhook server on {args.host}:{args.port}")
    logger.info(f"Confidence threshold: {CONFIDENCE_THRESHOLD}")
    app.run(host=args.host, port=args.port, debug=args.debug)
