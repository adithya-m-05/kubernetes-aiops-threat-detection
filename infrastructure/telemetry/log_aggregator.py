"""
=============================================================================
Falco Telemetry Log Ingestion & Normalizer
=============================================================================
Module: infrastructure/telemetry/log_aggregator.py

Purpose:
    Normalizes runtime security alert streams from Falco into a standard
    NDJSON format suitable for feature extraction and ML anomaly detection.

Unified Schema:
    {
        "timestamp":        ISO 8601 timestamp,
        "source":           "falco",
        "event_id":         UUID for deduplication,
        "pod":              Kubernetes pod name,
        "namespace":        Kubernetes namespace,
        "container_id":     Container identifier,
        "severity":         "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "event_type":       Category (shell_execution, sensitive_file_read, etc.),
        "syscall":          System call name (if applicable),
        "process":          Process name and command line,
        "network_metadata": {src_ip, dst_ip, src_port, dst_port, protocol},
        "mitre_technique":  MITRE ATT&CK technique ID (if tagged),
        "raw_event":        Original event payload for audit trail
    }

Usage:
    # Stream from Falco log file
    python log_aggregator.py --falco-log /var/log/falco/events.json \\
                             --output unified_telemetry.jsonl

    # Or pipe from stdin (for live kubectl log streaming)
    kubectl logs -l app=falco -n aiops-security --follow | \\
        python log_aggregator.py --stdin
=============================================================================
"""

import json
import uuid
import logging
import argparse
import sys
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Any, Generator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("log_aggregator")

# Severity Mapping for Falco alerts
FALCO_SEVERITY_MAP = {
    "EMERGENCY": "CRITICAL",
    "ALERT":     "CRITICAL",
    "CRITICAL":  "CRITICAL",
    "ERROR":     "HIGH",
    "WARNING":   "MEDIUM",
    "NOTICE":    "LOW",
    "INFO":      "LOW",
    "DEBUG":     "LOW",
}


def _classify_falco_event(rule_name: str) -> str:
    """Classify a Falco rule name into a standardized event type."""
    classification_map = {
        "shell":        "shell_execution",
        "sensitive":    "sensitive_file_read",
        "escape":       "container_escape",
        "outbound":     "unexpected_network_connection",
        "crypto":       "crypto_mining",
        "privilege":    "privilege_escalation",
        "network":      "network_anomaly",
        "read":         "file_access",
        "write":        "file_access",
        "process":      "process_execution",
    }
    for keyword, event_type in classification_map.items():
        if keyword in rule_name:
            return event_type
    return "unknown"


def parse_falco_event(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse a Falco JSON alert into the unified telemetry schema.
    """
    try:
        fields = raw_event.get("output_fields", {})
        tags = raw_event.get("tags", [])

        # Extract MITRE ATT&CK technique ID from Falco tags if present
        mitre_technique = None
        for tag in tags:
            if tag.startswith("T") and tag[1:].replace(".", "").isdigit():
                mitre_technique = tag
                break

        rule_name = raw_event.get("rule", "").lower()
        event_type = _classify_falco_event(rule_name)

        # Network metadata if present in Falco fd.* fields
        network_metadata = None
        if fields.get("fd.rip") or fields.get("fd.rport"):
            network_metadata = {
                "src_ip":   fields.get("fd.sip", ""),
                "dst_ip":   fields.get("fd.rip", ""),
                "src_port": fields.get("fd.sport", 0),
                "dst_port": fields.get("fd.rport", 0),
                "protocol": fields.get("fd.l4proto", "unknown"),
            }

        return {
            "timestamp":        raw_event.get("time", datetime.now(timezone.utc).isoformat()),
            "source":           "falco",
            "event_id":         str(uuid.uuid4()),
            "pod":              fields.get("k8s.pod.name", "unknown"),
            "namespace":        fields.get("k8s.ns.name", "unknown"),
            "container_id":     fields.get("container.id", "unknown"),
            "severity":         FALCO_SEVERITY_MAP.get(raw_event.get("priority", "INFO"), "LOW"),
            "event_type":       event_type,
            "syscall":          fields.get("evt.type", ""),
            "process":          fields.get("proc.cmdline", fields.get("proc.name", "")),
            "network_metadata": network_metadata,
            "mitre_technique":  mitre_technique,
            "raw_event":        raw_event,
        }
    except Exception as e:
        logger.error(f"Failed to parse Falco event: {e}")
        return None


def tail_json_log(filepath: str) -> Generator[Dict[str, Any], None, None]:
    """Continuously tail a JSON log file, yielding parsed events."""
    logger.info(f"Tailing Falco log file: {filepath}")
    while True:
        try:
            with open(filepath, "r") as f:
                f.seek(0, 2)  # Seek to end
                while True:
                    line = f.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                yield json.loads(line)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Malformed JSON in {filepath}: {e}")
                    else:
                        current_pos = f.tell()
                        f.seek(0, 2)
                        if f.tell() < current_pos:
                            logger.info(f"Log rotation detected for {filepath}")
                            break
                        f.seek(current_pos)
                        time.sleep(0.5)
        except FileNotFoundError:
            logger.warning(f"Log file not found (waiting): {filepath}")
            time.sleep(2)
        except KeyboardInterrupt:
            logger.info("Aggregator shutting down")
            return


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def forward_event(event: Dict[str, Any], forward_url: str) -> bool:
    """Forward normalized event to the Webhook API endpoint."""
    if not forward_url:
        return False
    try:
        if REQUESTS_AVAILABLE:
            resp = requests.post(forward_url, json=event, timeout=3.0)
            return resp.status_code in (200, 201)
        else:
            import urllib.request
            data = json.dumps(event, default=str).encode("utf-8")
            req = urllib.request.Request(
                forward_url,
                data=data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as response:
                return response.status in (200, 201)
    except Exception as e:
        logger.warning(f"Failed to forward event to {forward_url}: {e}")
        return False


def _classify_event_scenario(event: Dict[str, Any]) -> str:
    """Classify a normalized event into a raw dataset scenario folder."""
    event_type = event.get("event_type", "unknown")
    severity = event.get("severity", "LOW")
    scenario_map = {
        "shell_execution": "shell_execution",
        "sensitive_file_read": "credential_access",
        "file_access": "credential_access",
        "container_escape": "shell_execution",
        "privilege_escalation": "shell_execution",
        "unexpected_network_connection": "suspicious_network",
        "network_anomaly": "network_scanning",
        "crypto_mining": "suspicious_network",
        "process_execution": "normal",
    }
    scenario = scenario_map.get(event_type, "normal")
    # Promote to attack scenario if severity is high
    if scenario == "normal" and severity in ("HIGH", "CRITICAL"):
        scenario = "shell_execution"
    return scenario


def write_raw_event(raw_event: Dict[str, Any], normalized: Dict[str, Any], raw_output_dir: Optional[str]) -> None:
    """Persist raw Falco JSON into a scenario-categorized subfolder under datasets/falco/raw/."""
    if not raw_output_dir:
        return
    try:
        scenario = _classify_event_scenario(normalized)
        scenario_dir = os.path.join(raw_output_dir, scenario)
        os.makedirs(scenario_dir, exist_ok=True)
        # Append to a daily file to avoid thousands of tiny files
        from datetime import date
        date_str = date.today().strftime("%Y%m%d")
        raw_file = os.path.join(scenario_dir, f"falco_{scenario}_{date_str}.jsonl")
        with open(raw_file, "a") as f:
            f.write(json.dumps(raw_event, default=str) + "\n")
    except Exception as e:
        logger.warning(f"Failed to write raw event to {raw_output_dir}: {e}")


def write_unified_event(event: Dict[str, Any], output_path: Optional[str], stdout: bool = False) -> None:
    """Write normalized event to output destination."""
    event_json = json.dumps(event, default=str)
    if stdout:
        print(event_json)
    if output_path:
        out_dir = os.path.dirname(output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "a") as f:
            f.write(event_json + "\n")


def run_aggregator(
    falco_log: Optional[str] = None,
    output_path: Optional[str] = "unified_telemetry.jsonl",
    use_stdin: bool = False,
    forward_url: Optional[str] = None,
    raw_output_dir: Optional[str] = None
) -> None:
    """Main ingestion and normalization runner."""
    logger.info("=" * 60)
    logger.info("Falco Telemetry Normalizer Starting")
    logger.info(f"  Falco log:    {falco_log or 'N/A'}")
    logger.info(f"  Output:       {output_path or 'None'}")
    logger.info(f"  Forward URL:  {forward_url or 'None'}")
    logger.info(f"  Raw output:   {raw_output_dir or 'None'}")
    logger.info(f"  Stdin mode:   {use_stdin}")
    logger.info("=" * 60)

    event_count = 0
    if use_stdin:
        logger.info("Reading Falco events from stdin...")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                raw_event = json.loads(line)
                unified = parse_falco_event(raw_event)
                if unified:
                    write_unified_event(unified, output_path, stdout=True)
                    write_raw_event(raw_event, unified, raw_output_dir)
                    if forward_url:
                        forward_event(unified, forward_url)
                    event_count += 1
                    if event_count % 100 == 0:
                        logger.info(f"Processed {event_count} events")
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line")
    else:
        if falco_log:
            for raw_event in tail_json_log(falco_log):
                unified = parse_falco_event(raw_event)
                if unified:
                    write_unified_event(unified, output_path, stdout=True)
                    write_raw_event(raw_event, unified, raw_output_dir)
                    if forward_url:
                        forward_event(unified, forward_url)
                    event_count += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Falco Telemetry Ingestion & Normalizer"
    )
    parser.add_argument("--falco-log", type=str, default=None, help="Path to Falco NDJSON log")
    parser.add_argument("--output", type=str, default="unified_telemetry.jsonl", help="Output path for NDJSON")
    parser.add_argument("--stdin", action="store_true", help="Read events from stdin")
    parser.add_argument("--forward-url", type=str, default=None, help="Webhook URL to forward normalized events (e.g. http://localhost:5000/api/v1/event)")
    parser.add_argument("--raw-output-dir", type=str, default=None,
                        help="Directory to persist raw Falco events by scenario (e.g. datasets/falco/raw)")

    args = parser.parse_args()
    run_aggregator(
        falco_log=args.falco_log,
        output_path=args.output,
        use_stdin=args.stdin,
        forward_url=args.forward_url,
        raw_output_dir=args.raw_output_dir
    )
