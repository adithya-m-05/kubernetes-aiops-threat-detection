"""
=============================================================================
Telemetry Log Aggregator — Centralized JSON Telemetry Pipeline
=============================================================================
Module: infrastructure/telemetry/log_aggregator.py
Agent:  Agent 1 — "The Observer"

Purpose:
    Aggregates telemetry streams from multiple security data sources
    (Falco, KubeArmor, Kubernetes audit logs) into a single, centralized
    JSON format suitable for downstream ML processing.

Architecture:
    ┌──────────┐    ┌─────────────┐    ┌──────────────┐
    │  Falco   │───►│             │    │              │
    │  JSON    │    │    Log      │───►│  Unified     │
    ├──────────┤    │  Aggregator │    │  JSON Output │
    │KubeArmor │───►│             │    │  (NDJSON)    │
    │  JSON    │    └─────────────┘    └──────────────┘
    └──────────┘

Unified Schema:
    {
        "timestamp":        ISO 8601 timestamp,
        "source":           "falco" | "kubearmor" | "k8s_audit",
        "event_id":         UUID for deduplication,
        "pod":              Kubernetes pod name,
        "namespace":        Kubernetes namespace,
        "container_id":     Container identifier,
        "severity":         "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "event_type":       Category (shell_exec, file_read, net_conn, etc.),
        "syscall":          System call name (if applicable),
        "process":          Process name and command line,
        "network_metadata": {src_ip, dst_ip, src_port, dst_port, protocol},
        "mitre_technique":  MITRE ATT&CK technique ID (if tagged),
        "raw_event":        Original event payload for audit trail
    }

Academic Rationale:
    Telemetry normalization is essential for multi-source security analytics.
    By projecting heterogeneous event formats into a unified schema, we
    enable the ML pipeline (Agent 2) to process events from any source
    without source-specific parsing logic. This follows the ELK Stack
    pattern of "normalize at ingestion, analyze at query time."

Usage:
    # Start the aggregator (watches for new log files)
    python log_aggregator.py --falco-log /var/log/falco/events.json \\
                             --kubearmor-log /var/log/kubearmor/alerts.json \\
                             --output /var/log/aiops/unified_telemetry.jsonl

    # Or pipe from stdin (for Kubernetes log streaming)
    kubectl logs -l app=falco -n aiops-security --follow | \\
        python log_aggregator.py --stdin --source falco

Dependencies:
    - watchdog: Filesystem event monitoring for log rotation detection
    - Python 3.9+: For typing features and json module

References:
    - Falco Output Fields: https://falco.org/docs/reference/rules/supported-fields/
    - KubeArmor Telemetry: https://docs.kubearmor.io/documentation/getting-started/
=============================================================================
"""

import json
import uuid
import logging
import argparse
import sys
import os
from datetime import datetime, timezone
from typing import Dict, Optional, Any, Generator
from pathlib import Path

# Configure module-level logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("log_aggregator")


# =============================================================================
# Severity Mapping
# =============================================================================
# Maps source-specific severity levels to our unified severity enum.
# This normalization ensures consistent threat prioritization across
# heterogeneous telemetry sources.
# =============================================================================

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

KUBEARMOR_SEVERITY_MAP = {
    1: "LOW",    2: "LOW",    3: "LOW",
    4: "MEDIUM", 5: "MEDIUM", 6: "MEDIUM",
    7: "HIGH",   8: "HIGH",
    9: "CRITICAL", 10: "CRITICAL",
}


# =============================================================================
# Falco Event Parser
# =============================================================================
def parse_falco_event(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse a Falco JSON alert into the unified telemetry schema.

    Falco JSON output contains the following key fields:
    - rule: Name of the triggered rule
    - output: Human-readable alert message
    - priority: Severity level (EMERGENCY through DEBUG)
    - time: ISO 8601 timestamp
    - output_fields: Structured data including container, process, and
      file/network metadata (container.id, k8s.pod.name, proc.name, etc.)

    Why we extract output_fields individually:
        Falco provides rich contextual data in output_fields that our ML
        pipeline needs for feature extraction. Direct field mapping avoids
        the need for regex parsing of the output string.

    Args:
        raw_event: Parsed JSON object from Falco stdout

    Returns:
        Unified telemetry event dict, or None if parsing fails
    """
    try:
        fields = raw_event.get("output_fields", {})
        tags = raw_event.get("tags", [])

        # Extract MITRE ATT&CK technique ID from Falco tags
        # Our custom rules tag events with technique IDs (e.g., T1609, T1611)
        mitre_technique = None
        for tag in tags:
            if tag.startswith("T") and tag[1:].replace(".", "").isdigit():
                mitre_technique = tag
                break

        # Determine event type from rule name
        # This categorization feeds into the ML feature extraction pipeline
        rule_name = raw_event.get("rule", "").lower()
        event_type = _classify_falco_event(rule_name)

        # Build network metadata if available
        # Falco provides fd.* fields for network connections
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
            "severity":         FALCO_SEVERITY_MAP.get(
                                    raw_event.get("priority", "INFO"), "LOW"),
            "event_type":       event_type,
            "syscall":          fields.get("evt.type", ""),
            "process":          fields.get("proc.cmdline", ""),
            "network_metadata": network_metadata,
            "mitre_technique":  mitre_technique,
            "raw_event":        raw_event,
        }

    except Exception as e:
        logger.error(f"Failed to parse Falco event: {e}")
        return None


def _classify_falco_event(rule_name: str) -> str:
    """
    Classify a Falco rule name into a standardized event type.

    This classification is used downstream by the feature extraction
    module to determine which feature engineering functions to apply.

    The mapping is based on our custom Falco rules (see falco-config.yaml).
    """
    classification_map = {
        "shell":        "shell_execution",
        "sensitive":    "sensitive_file_read",
        "escape":       "container_escape",
        "outbound":     "unexpected_network_connection",
        "crypto":       "crypto_mining",
        "privilege":    "privilege_escalation",
        "network":      "network_anomaly",
    }
    for keyword, event_type in classification_map.items():
        if keyword in rule_name:
            return event_type
    return "unknown"


# =============================================================================
# KubeArmor Event Parser
# =============================================================================
def parse_kubearmor_event(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse a KubeArmor telemetry event into the unified schema.

    KubeArmor generates JSON events with the following structure:
    - ClusterName, NamespaceName, PodName, ContainerID
    - Operation: "Process", "File", or "Network"
    - Resource: The target resource (file path, process name, or IP:port)
    - Result: "Passed" or "Blocked"
    - Severity: Integer 1-10

    Why KubeArmor events are valuable:
        Unlike Falco (which primarily detects), KubeArmor both detects
        AND enforces. Events with Result="Blocked" indicate that the
        eBPF-LSM policy prevented a malicious action, while Result="Passed"
        events from Audit policies provide telemetry without enforcement.

    Args:
        raw_event: Parsed JSON object from KubeArmor relay

    Returns:
        Unified telemetry event dict, or None if parsing fails
    """
    try:
        operation = raw_event.get("Operation", "").lower()

        # Map KubeArmor operation types to our event type taxonomy
        event_type_map = {
            "process": "process_execution",
            "file":    "file_access",
            "network": "network_connection",
        }
        event_type = event_type_map.get(operation, "unknown")

        # Build network metadata for network events
        network_metadata = None
        if operation == "network":
            resource = raw_event.get("Resource", "")
            network_metadata = _parse_kubearmor_network_resource(resource)

        severity_int = raw_event.get("Severity", 1)

        return {
            "timestamp":        raw_event.get("UpdatedTime",
                                    datetime.now(timezone.utc).isoformat()),
            "source":           "kubearmor",
            "event_id":         str(uuid.uuid4()),
            "pod":              raw_event.get("PodName", "unknown"),
            "namespace":        raw_event.get("NamespaceName", "unknown"),
            "container_id":     raw_event.get("ContainerID", "unknown"),
            "severity":         KUBEARMOR_SEVERITY_MAP.get(severity_int, "LOW"),
            "event_type":       event_type,
            "syscall":          raw_event.get("Syscall", ""),
            "process":          raw_event.get("ProcessName", ""),
            "network_metadata": network_metadata,
            "mitre_technique":  None,  # KubeArmor doesn't tag MITRE IDs natively
            "raw_event":        raw_event,
        }

    except Exception as e:
        logger.error(f"Failed to parse KubeArmor event: {e}")
        return None


def _parse_kubearmor_network_resource(resource: str) -> Dict[str, Any]:
    """
    Parse KubeArmor network resource string into structured metadata.

    KubeArmor formats network resources as "protocol://ip:port" or
    simply "ip:port". This function extracts individual components
    for consistent representation in the unified schema.
    """
    try:
        protocol = "unknown"
        if "://" in resource:
            protocol, resource = resource.split("://", 1)

        parts = resource.rsplit(":", 1)
        ip = parts[0] if parts else ""
        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

        return {
            "src_ip":   "",
            "dst_ip":   ip,
            "src_port": 0,
            "dst_port": port,
            "protocol": protocol,
        }
    except Exception:
        return {"src_ip": "", "dst_ip": "", "src_port": 0,
                "dst_port": 0, "protocol": "unknown"}


# =============================================================================
# Log File Tail Generator
# =============================================================================
def tail_json_log(filepath: str) -> Generator[Dict[str, Any], None, None]:
    """
    Continuously tail a JSON log file, yielding parsed events.

    Implements a simple tail -f equivalent that handles:
    - Log rotation (detects file truncation and re-opens)
    - Partial line buffering (waits for complete JSON objects)
    - Graceful shutdown on keyboard interrupt

    Why not use watchdog here?
        For simple log tailing, a polling approach with seek() is more
        reliable across file systems and container storage drivers.
        Watchdog is better for detecting new files (log rotation), which
        we handle separately in the main aggregation loop.

    Args:
        filepath: Path to the NDJSON (newline-delimited JSON) log file

    Yields:
        Parsed JSON objects (dicts) from each line
    """
    logger.info(f"Starting to tail log file: {filepath}")

    while True:
        try:
            with open(filepath, "r") as f:
                # Seek to end of file to only process new events
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                yield json.loads(line)
                            except json.JSONDecodeError as e:
                                logger.warning(
                                    f"Malformed JSON in {filepath}: {e}")
                    else:
                        # No new data — check if file was truncated (rotation)
                        current_pos = f.tell()
                        f.seek(0, 2)
                        if f.tell() < current_pos:
                            logger.info(
                                f"Log rotation detected for {filepath}")
                            break
                        f.seek(current_pos)
                        # Brief sleep to avoid busy-waiting
                        import time
                        time.sleep(0.5)

        except FileNotFoundError:
            logger.warning(f"Log file not found (waiting): {filepath}")
            import time
            time.sleep(2)
        except KeyboardInterrupt:
            logger.info("Aggregator shutting down gracefully")
            return


# =============================================================================
# Unified Event Writer
# =============================================================================
def write_unified_event(
    event: Dict[str, Any],
    output_path: str,
    stdout: bool = False
) -> None:
    """
    Write a unified telemetry event to the output destination.

    Events are written in NDJSON (Newline-Delimited JSON) format, which is:
    - Appendable (no need to parse/rewrite the entire file)
    - Streamable (each line is a complete JSON object)
    - Compatible with tools like jq, pandas.read_json(lines=True), and Spark

    Args:
        event:       Unified telemetry event dictionary
        output_path: Path to the NDJSON output file
        stdout:      If True, also print to stdout for debugging
    """
    event_json = json.dumps(event, default=str)

    if stdout:
        print(event_json)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "a") as f:
            f.write(event_json + "\n")


# =============================================================================
# Main Aggregation Loop
# =============================================================================
def run_aggregator(
    falco_log: Optional[str] = None,
    kubearmor_log: Optional[str] = None,
    output_path: str = "unified_telemetry.jsonl",
    use_stdin: bool = False,
    stdin_source: str = "falco"
) -> None:
    """
    Main aggregation entry point.

    In production (Kubernetes), this would run as a sidecar container or
    a DaemonSet, tailing log files from Falco and KubeArmor simultaneously.
    For development, it can read from stdin (piped from kubectl logs).

    Args:
        falco_log:     Path to Falco NDJSON log file
        kubearmor_log: Path to KubeArmor NDJSON log file
        output_path:   Path for unified NDJSON output
        use_stdin:     Read from stdin instead of files
        stdin_source:  Source type for stdin events ("falco" or "kubearmor")
    """
    logger.info("=" * 60)
    logger.info("AIOps Telemetry Log Aggregator Starting")
    logger.info(f"  Falco log:     {falco_log or 'N/A'}")
    logger.info(f"  KubeArmor log: {kubearmor_log or 'N/A'}")
    logger.info(f"  Output:        {output_path}")
    logger.info(f"  Stdin mode:    {use_stdin} (source: {stdin_source})")
    logger.info("=" * 60)

    # Select the appropriate parser based on source
    parser_map = {
        "falco":     parse_falco_event,
        "kubearmor": parse_kubearmor_event,
    }

    event_count = 0

    if use_stdin:
        parser = parser_map.get(stdin_source, parse_falco_event)
        logger.info(f"Reading from stdin (source: {stdin_source})")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                raw_event = json.loads(line)
                unified = parser(raw_event)
                if unified:
                    write_unified_event(unified, output_path, stdout=True)
                    event_count += 1
                    if event_count % 100 == 0:
                        logger.info(f"Processed {event_count} events")
            except json.JSONDecodeError:
                logger.warning(f"Skipping malformed JSON line")
    else:
        # File-based tailing mode
        # In a full implementation, this would use threading or asyncio
        # to tail multiple files concurrently. For this academic demo,
        # we process Falco events as the primary stream.
        if falco_log:
            logger.info(f"Tailing Falco log: {falco_log}")
            for raw_event in tail_json_log(falco_log):
                unified = parse_falco_event(raw_event)
                if unified:
                    write_unified_event(unified, output_path, stdout=True)
                    event_count += 1


# =============================================================================
# CLI Entry Point
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AIOps Telemetry Log Aggregator — Centralized JSON Pipeline",
        epilog="Part of the AIOps Threat Intelligence project (NMIT ISE FYP)"
    )
    parser.add_argument(
        "--falco-log",
        type=str,
        default=None,
        help="Path to Falco NDJSON log file"
    )
    parser.add_argument(
        "--kubearmor-log",
        type=str,
        default=None,
        help="Path to KubeArmor NDJSON log file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="unified_telemetry.jsonl",
        help="Output path for unified NDJSON telemetry (default: unified_telemetry.jsonl)"
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read events from stdin instead of log files"
    )
    parser.add_argument(
        "--source",
        type=str,
        choices=["falco", "kubearmor"],
        default="falco",
        help="Source type when reading from stdin (default: falco)"
    )

    args = parser.parse_args()

    run_aggregator(
        falco_log=args.falco_log,
        kubearmor_log=args.kubearmor_log,
        output_path=args.output,
        use_stdin=args.stdin,
        stdin_source=args.source,
    )
