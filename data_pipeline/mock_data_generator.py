"""
=============================================================================
Mock Data Generator — Synthetic Benign and Malicious Telemetry
=============================================================================
Module: data_pipeline/mock_data_generator.py
Agent:  Agent 2 — "The Cleaner"

Purpose:
    Generates realistic synthetic telemetry data for testing the full
    pipeline without requiring a live Kubernetes cluster. Produces both
    benign and malicious events matching the unified telemetry schema.

Attack Types Simulated:
    - DDoS flood (high event rate, many connections, single target)
    - Data exfiltration (large outbound traffic, unusual ports)
    - Lateral movement (port scanning, multiple internal IPs)
    - Crypto mining (high CPU syscalls, stratum connections)
    - Container escape (procfs access, namespace manipulation)

Usage:
    python mock_data_generator.py --output mock_telemetry.jsonl --events 5000
=============================================================================
"""

import json
import uuid
import random
import argparse
import os
import logging
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock_data_generator")

# Realistic pod and namespace names
PODS = ["web-frontend-abc12", "web-frontend-def34", "api-backend-ghi56",
        "api-backend-jkl78", "redis-cache-mno90"]
NAMESPACES = ["aiops-security"]
SOURCES = ["falco", "kubearmor"]
INTERNAL_IPS = ["10.244.0.5", "10.244.0.6", "10.244.0.7", "10.244.1.2", "10.244.1.3"]
EXTERNAL_IPS = ["203.0.113.10", "198.51.100.25", "192.0.2.50", "45.33.32.156"]
BENIGN_SYSCALLS = ["read", "write", "close", "fstat", "mmap", "mprotect",
                   "brk", "access", "open", "epoll_wait", "accept"]
ATTACK_SYSCALLS = ["execve", "connect", "sendto", "recvfrom", "socket",
                   "setuid", "setns", "unshare", "mount", "ptrace"]


def generate_benign_event(base_time):
    """Generate a single benign telemetry event (normal operations)."""
    pod = random.choice(PODS)
    return {
        "timestamp": (base_time + timedelta(seconds=random.uniform(0, 60))).isoformat(),
        "source": random.choice(SOURCES),
        "event_id": str(uuid.uuid4()),
        "pod": pod,
        "namespace": "aiops-security",
        "container_id": f"containerd://{uuid.uuid4().hex[:12]}",
        "severity": random.choice(["LOW", "LOW", "LOW", "MEDIUM"]),
        "event_type": random.choice(["process_execution", "file_access",
                                      "network_connection"]),
        "syscall": random.choice(BENIGN_SYSCALLS),
        "process": random.choice(["python", "nginx", "redis-server", "node"]),
        "network_metadata": {
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": random.choice(INTERNAL_IPS),
            "src_port": random.randint(30000, 65535),
            "dst_port": random.choice([80, 443, 8080, 6379, 5432]),
            "protocol": "TCP"
        },
        "mitre_technique": None,
        "raw_event": {},
        "label": "benign"
    }


def generate_ddos_event(base_time):
    """Generate a DDoS flood event (high rate, many connections to one target)."""
    return {
        "timestamp": (base_time + timedelta(milliseconds=random.randint(0, 1000))).isoformat(),
        "source": "falco",
        "event_id": str(uuid.uuid4()),
        "pod": "web-frontend-abc12",
        "namespace": "aiops-security",
        "container_id": f"containerd://{uuid.uuid4().hex[:12]}",
        "severity": "HIGH",
        "event_type": "network_anomaly",
        "syscall": random.choice(["connect", "sendto", "socket"]),
        "process": "python",
        "network_metadata": {
            "src_ip": random.choice(EXTERNAL_IPS),
            "dst_ip": "10.244.0.5",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": "TCP"
        },
        "mitre_technique": "T1499",
        "raw_event": {},
        "label": "ddos"
    }


def generate_exfiltration_event(base_time):
    """Generate data exfiltration event (large outbound to external IP)."""
    return {
        "timestamp": (base_time + timedelta(seconds=random.uniform(0, 30))).isoformat(),
        "source": "falco",
        "event_id": str(uuid.uuid4()),
        "pod": "api-backend-ghi56",
        "namespace": "aiops-security",
        "container_id": f"containerd://{uuid.uuid4().hex[:12]}",
        "severity": "CRITICAL",
        "event_type": "unexpected_network_connection",
        "syscall": random.choice(["sendto", "write", "connect"]),
        "process": "curl",
        "network_metadata": {
            "src_ip": "10.244.0.7",
            "dst_ip": random.choice(EXTERNAL_IPS),
            "src_port": random.randint(30000, 65535),
            "dst_port": random.choice([443, 8443, 4443, 9999]),
            "protocol": "TCP"
        },
        "mitre_technique": "T1041",
        "raw_event": {},
        "label": "exfiltration"
    }


def generate_lateral_movement_event(base_time):
    """Generate lateral movement event (port scanning internal network)."""
    return {
        "timestamp": (base_time + timedelta(milliseconds=random.randint(0, 500))).isoformat(),
        "source": "kubearmor",
        "event_id": str(uuid.uuid4()),
        "pod": "api-backend-jkl78",
        "namespace": "aiops-security",
        "container_id": f"containerd://{uuid.uuid4().hex[:12]}",
        "severity": "HIGH",
        "event_type": "network_anomaly",
        "syscall": random.choice(["connect", "socket"]),
        "process": "nmap",
        "network_metadata": {
            "src_ip": "10.244.0.8",
            "dst_ip": random.choice(INTERNAL_IPS),
            "src_port": random.randint(40000, 65535),
            "dst_port": random.randint(1, 1024),
            "protocol": "TCP"
        },
        "mitre_technique": "T1046",
        "raw_event": {},
        "label": "lateral_movement"
    }


def generate_crypto_mining_event(base_time):
    """Generate crypto mining event (mining process, stratum connection)."""
    return {
        "timestamp": (base_time + timedelta(seconds=random.uniform(0, 60))).isoformat(),
        "source": "falco",
        "event_id": str(uuid.uuid4()),
        "pod": random.choice(PODS),
        "namespace": "aiops-security",
        "container_id": f"containerd://{uuid.uuid4().hex[:12]}",
        "severity": "CRITICAL",
        "event_type": "crypto_mining",
        "syscall": random.choice(ATTACK_SYSCALLS[:5]),
        "process": random.choice(["xmrig", "minerd", "cpuminer"]),
        "network_metadata": {
            "src_ip": "10.244.0.6",
            "dst_ip": random.choice(EXTERNAL_IPS),
            "src_port": random.randint(30000, 65535),
            "dst_port": random.choice([3333, 5555, 8332]),
            "protocol": "TCP"
        },
        "mitre_technique": "T1496",
        "raw_event": {},
        "label": "crypto_mining"
    }


def generate_dataset(num_events=5000, attack_ratio=0.2, seed=42):
    """
    Generate a complete labeled dataset with configurable attack ratio.

    The default 80/20 benign/malicious split is more balanced than real
    production data (~99/1) to provide sufficient attack samples for
    initial model training. SMOTE will further balance as needed.
    """
    random.seed(seed)
    events = []
    num_attack = int(num_events * attack_ratio)
    num_benign = num_events - num_attack
    base_time = datetime(2026, 3, 23, 10, 0, 0, tzinfo=timezone.utc)

    # Generate benign events
    logger.info(f"Generating {num_benign} benign events...")
    for i in range(num_benign):
        t = base_time + timedelta(minutes=i // 10)
        events.append(generate_benign_event(t))

    # Generate attack events (distributed across types)
    attack_generators = [generate_ddos_event, generate_exfiltration_event,
                         generate_lateral_movement_event, generate_crypto_mining_event]
    attacks_per_type = num_attack // len(attack_generators)

    for gen_func in attack_generators:
        label = gen_func.__doc__.split("(")[0].strip().split()[-1].lower()
        logger.info(f"Generating {attacks_per_type} {label} events...")
        for i in range(attacks_per_type):
            t = base_time + timedelta(minutes=random.randint(0, num_benign // 10))
            events.append(gen_func(t))

    random.shuffle(events)
    logger.info(f"Total events generated: {len(events)}")
    return events


def save_dataset(events, output_path="mock_telemetry.jsonl"):
    """Save events as NDJSON file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        for event in events:
            f.write(json.dumps(event, default=str) + "\n")
    logger.info(f"Dataset saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate mock security telemetry")
    parser.add_argument("--output", "-o", default="mock_telemetry.jsonl")
    parser.add_argument("--events", "-n", type=int, default=5000)
    parser.add_argument("--attack-ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    events = generate_dataset(args.events, args.attack_ratio, args.seed)
    save_dataset(events, args.output)

    # Print class distribution
    from collections import Counter
    labels = [e["label"] for e in events]
    print(f"\nClass Distribution: {dict(Counter(labels))}")
