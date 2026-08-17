"""
=============================================================================
Falco Dataset Collector — Live Telemetry Collection by Scenario
=============================================================================
Module: data_pipeline/falco_dataset_collector.py

Purpose:
    Collects and organizes live Falco telemetry logs from a Kubernetes
    cluster or local stream into categorized scenario datasets for model
    training and evaluation.

Usage:
    # Collect 500 events under the 'normal' scenario
    python data_pipeline/falco_dataset_collector.py --scenario normal --count 500

    # Collect attack events streamed from stdin
    kubectl logs -l app=falco -n aiops-security --follow | \\
        python data_pipeline/falco_dataset_collector.py --scenario shell_execution --stdin
=============================================================================
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dataset_collector")

VALID_SCENARIOS = [
    "normal",
    "shell_execution",
    "credential_access",
    "network_scanning",
    "suspicious_network"
]

def collect_events(scenario: str, output_dir: str, count: int = 100, use_stdin: bool = False):
    if scenario not in VALID_SCENARIOS:
        logger.warning(f"Scenario '{scenario}' not in standard list {VALID_SCENARIOS}, proceeding anyway.")

    target_dir = os.path.join(output_dir, scenario)
    os.makedirs(target_dir, exist_ok=True)
    
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(target_dir, f"falco_{scenario}_{timestamp_str}.jsonl")
    
    logger.info(f"Collecting scenario '{scenario}' into: {out_file}")
    collected = 0

    with open(out_file, "w") as f:
        if use_stdin:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    f.write(json.dumps(event) + "\n")
                    collected += 1
                    if collected >= count:
                        break
                except json.JSONDecodeError:
                    continue
        else:
            logger.info("Stdin not active. Simulating mock event collection...")
            from data_pipeline.mock_data_generator import generate_benign_event, generate_container_escape_event
            base_time = datetime.now(timezone.utc)
            for i in range(count):
                if scenario == "normal":
                    evt = generate_benign_event(base_time)
                else:
                    evt = generate_container_escape_event(base_time)
                f.write(json.dumps(evt) + "\n")
                collected += 1

    logger.info(f"Successfully collected {collected} events into {out_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Falco telemetry dataset")
    parser.add_argument("--scenario", "-s", type=str, default="normal", choices=VALID_SCENARIOS)
    parser.add_argument("--output-dir", "-o", type=str, default="datasets/falco/raw")
    parser.add_argument("--count", "-c", type=int, default=100)
    parser.add_argument("--stdin", action="store_true", help="Read stream from stdin")
    args = parser.parse_args()

    collect_events(args.scenario, args.output_dir, args.count, args.stdin)
