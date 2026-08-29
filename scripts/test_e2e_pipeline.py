"""
=============================================================================
End-to-End Pipeline Integration Test
=============================================================================
Module: scripts/test_e2e_pipeline.py

Purpose:
    Tests the complete threat detection pipeline by:
    1. Starting the webhook server (or connecting to a running one)
    2. Generating synthetic Falco events (benign + attack)
    3. Sending them to the /api/v1/event endpoint
    4. Verifying that ML scoring, MITRE mapping, and response engine fire
    5. Checking that telemetry is persisted to dataset files
    6. Printing stage-by-stage evidence

Usage:
    # Start webhook server first in another terminal:
    #   python response_engine/webhook_server.py --port 5000 --model-dir models/autoencoder
    #
    # Then run this test:
    python scripts/test_e2e_pipeline.py
    python scripts/test_e2e_pipeline.py --url http://localhost:5000
=============================================================================
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime, timezone
from collections import Counter

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data_pipeline.mock_data_generator import (
    generate_benign_event,
    generate_container_escape_event,
    generate_exfiltration_event,
    generate_crypto_mining_event,
    generate_lateral_movement_event,
)

# ANSI colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def banner(text):
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")


def check(label, condition, detail=""):
    status = f"{GREEN}PASS{RESET}" if condition else f"{RED}FAIL{RESET}"
    print(f"  [{status}] {label}")
    if detail:
        print(f"         {detail}")
    return condition


def run_e2e_test(base_url: str = "http://localhost:5000"):
    """Run the complete end-to-end pipeline test."""
    banner("END-TO-END PIPELINE INTEGRATION TEST")
    print(f"  Target: {base_url}")
    print(f"  Time:   {datetime.now().isoformat()}")

    all_passed = True
    base_time = datetime.now(timezone.utc)

    # =========================================================================
    # STAGE 1: Verify webhook server is running
    # =========================================================================
    banner("STAGE 1: Webhook Server Health Check")
    try:
        resp = requests.get(f"{base_url}/api/v1/status", timeout=5)
        status_data = resp.json()
        all_passed &= check("Server is running", resp.status_code == 200)
        all_passed &= check("Status is healthy", status_data.get("status") == "healthy")
        all_passed &= check("ML pipeline available",
                            status_data.get("ml_pipeline_available", False),
                            f"ml_pipeline_stats={json.dumps(status_data.get('ml_pipeline_stats', {}))}")

        # Check inference mode
        ml_stats = status_data.get("ml_pipeline_stats", {})
        inference_mode = ml_stats.get("live_inference_mode", "unknown")
        all_passed &= check("Inference mode detected",
                            inference_mode in ("heuristic", "autoencoder"),
                            f"live_inference_mode={inference_mode}")
        print(f"\n  {YELLOW}Full status response:{RESET}")
        print(f"  {json.dumps(status_data, indent=2)}")
    except requests.ConnectionError:
        check("Server is running", False, "Cannot connect — is the webhook server running?")
        print(f"\n  {RED}FATAL: Cannot proceed without webhook server.{RESET}")
        print(f"  Start it with: python response_engine/webhook_server.py --port 5000 --model-dir models/autoencoder")
        return False

    # =========================================================================
    # STAGE 2: Send benign events
    # =========================================================================
    banner("STAGE 2: Sending Benign Events")
    benign_results = []
    for i in range(5):
        event = generate_benign_event(base_time)
        resp = requests.post(f"{base_url}/api/v1/event", json=event, timeout=5)
        result = resp.json()
        benign_results.append(result)
        risk = result.get("risk_level", "?")
        score = result.get("anomaly_score", 0)
        print(f"  Event {i+1}: risk={risk}, score={score:.4f}, is_anomaly={result.get('is_anomaly')}")

    benign_anomalies = sum(1 for r in benign_results if r.get("is_anomaly"))
    all_passed &= check("Benign events processed", len(benign_results) == 5)
    all_passed &= check("Most benign events classified LOW/MEDIUM",
                         benign_anomalies <= 1,
                         f"anomalies={benign_anomalies}/5")

    # =========================================================================
    # STAGE 3: Send attack events — verify ML scoring + MITRE mapping
    # =========================================================================
    banner("STAGE 3: Sending Attack Events (Expecting HIGH/CRITICAL)")
    attack_generators = [
        ("Container Escape (T1611)", generate_container_escape_event),
        ("Data Exfiltration (T1041)", generate_exfiltration_event),
        ("Crypto Mining (T1496)", generate_crypto_mining_event),
        ("Lateral Movement (T1046)", generate_lateral_movement_event),
    ]

    attack_results = []
    for label, gen_fn in attack_generators:
        event = gen_fn(base_time)
        resp = requests.post(f"{base_url}/api/v1/event", json=event, timeout=5)
        result = resp.json()
        attack_results.append(result)
        risk = result.get("risk_level", "?")
        score = result.get("anomaly_score", 0)
        mitre = [t["id"] for t in result.get("mitre_techniques", [])]
        is_anom = result.get("is_anomaly", False)
        response = result.get("response", {})
        actions = [a["action"] for a in response.get("actions_taken", [])] if response else []

        status_icon = f"{GREEN}[+]{RESET}" if is_anom else f"{RED}[-]{RESET}"
        print(f"  {status_icon} {label}:")
        print(f"      risk={risk}, score={score:.4f}, is_anomaly={is_anom}")
        print(f"      mitre={mitre}, actions={actions}")

    attack_anomalies = sum(1 for r in attack_results if r.get("is_anomaly"))
    attack_with_mitre = sum(1 for r in attack_results if r.get("mitre_techniques"))
    attack_with_response = sum(1 for r in attack_results if r.get("response"))

    all_passed &= check("Attack events processed", len(attack_results) == 4)
    all_passed &= check("Attacks detected as anomalies",
                         attack_anomalies >= 3,
                         f"{attack_anomalies}/4 detected")
    all_passed &= check("MITRE ATT&CK techniques mapped",
                         attack_with_mitre >= 3,
                         f"{attack_with_mitre}/4 mapped")
    all_passed &= check("Response engine triggered for anomalies",
                         attack_with_response >= 3,
                         f"{attack_with_response}/4 triggered")

    # =========================================================================
    # STAGE 4: Verify alert history
    # =========================================================================
    banner("STAGE 4: Verify Alert History")
    resp = requests.get(f"{base_url}/api/v1/history?limit=20", timeout=5)
    history = resp.json()
    alert_count = history.get("count", 0)
    all_passed &= check("Alert history has entries", alert_count > 0,
                         f"count={alert_count}")

    if alert_count > 0:
        latest = history["alerts"][-1]
        print(f"\n  {YELLOW}Latest alert:{RESET}")
        print(f"  pod={latest.get('pod')}, threat={latest.get('threat_type')}, "
              f"risk={latest.get('risk_level')}, mitre={latest.get('mitre_technique')}")

    # =========================================================================
    # STAGE 5: Verify telemetry persistence (dataset files)
    # =========================================================================
    banner("STAGE 5: Verify Telemetry Persistence")

    detections_path = os.path.join(
        PROJECT_ROOT, "datasets", "falco", "processed", "runtime_detections.jsonl")
    alerts_path = os.path.join(
        PROJECT_ROOT, "datasets", "falco", "processed", "runtime_alerts.jsonl")

    # Check detections file
    if os.path.exists(detections_path):
        with open(detections_path, "r") as f:
            detection_lines = [l.strip() for l in f if l.strip()]
        all_passed &= check("runtime_detections.jsonl exists and has data",
                             len(detection_lines) >= 9,
                             f"lines={len(detection_lines)}, path={detections_path}")

        # Verify schema of a detection record
        if detection_lines:
            sample = json.loads(detection_lines[-1])
            has_required = all(k in sample for k in
                               ["status", "anomaly_score", "risk_level", "is_anomaly"])
            all_passed &= check("Detection records have expected schema", has_required,
                                 f"keys={list(sample.keys())}")
    else:
        all_passed &= check("runtime_detections.jsonl exists", False,
                             f"Expected at: {detections_path}")

    # Check alerts file
    if os.path.exists(alerts_path):
        with open(alerts_path, "r") as f:
            alert_lines = [l.strip() for l in f if l.strip()]
        all_passed &= check("runtime_alerts.jsonl exists and has data",
                             len(alert_lines) >= 1,
                             f"lines={len(alert_lines)}, path={alerts_path}")
    else:
        all_passed &= check("runtime_alerts.jsonl exists", False,
                             f"Expected at: {alerts_path}")

    # =========================================================================
    # STAGE 6: Full pipeline evidence summary
    # =========================================================================
    banner("STAGE 6: Pipeline Flow Evidence Summary")

    all_results = benign_results + attack_results
    risk_dist = Counter(r.get("risk_level", "?") for r in all_results)
    total_anomalies = sum(1 for r in all_results if r.get("is_anomaly"))
    model_used = any(r.get("model_used") for r in all_results)

    evidence = {
        "total_events_sent": len(all_results),
        "total_anomalies_detected": total_anomalies,
        "risk_distribution": dict(risk_dist),
        "model_loaded_on_server": model_used,
        "inference_mode": inference_mode,
        "runtime_detections_persisted": os.path.exists(detections_path),
        "runtime_alerts_persisted": os.path.exists(alerts_path),
    }

    for key, val in evidence.items():
        print(f"  {key}: {val}")

    # =========================================================================
    # FINAL VERDICT
    # =========================================================================
    banner("FINAL VERDICT")
    if all_passed:
        print(f"  {GREEN}{BOLD}ALL CHECKS PASSED [OK]{RESET}")
        print(f"  The end-to-end pipeline is working correctly.")
    else:
        print(f"  {RED}{BOLD}SOME CHECKS FAILED [X]{RESET}")
        print(f"  Review the output above for details.")

    return all_passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="End-to-End Pipeline Integration Test")
    parser.add_argument("--url", type=str, default="http://localhost:5000",
                        help="Base URL of the webhook server")
    args = parser.parse_args()

    success = run_e2e_test(args.url)
    sys.exit(0 if success else 1)
