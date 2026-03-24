"""
=============================================================================
MITRE ATT&CK Container Matrix Mapping
=============================================================================
Module: ml_engine/mitre_attack_mapping.py
Agent:  Agent 3 — "The Brain"

Purpose:
    Provides a structured mapping between detected anomaly types and the
    official MITRE ATT&CK Container Matrix technique IDs. This mapping
    enables the Bayesian predictor to map observed behaviors to known
    attack chains and predict the attacker's next likely action.

Data Source:
    Extracted via browser research from the official MITRE ATT&CK website:
    https://attack.mitre.org/matrices/enterprise/containers/

MITRE ATT&CK Container Matrix Tactics (9 total):
    1. Initial Access (TA0001)
    2. Execution (TA0002)
    3. Persistence (TA0003)
    4. Privilege Escalation (TA0004)
    5. Defense Evasion (TA0005)
    6. Credential Access (TA0006)
    7. Discovery (TA0007)
    8. Lateral Movement (TA0008)
    9. Impact (TA0040)
=============================================================================
"""

# =============================================================================
# MITRE ATT&CK Container Technique Database
# =============================================================================
# Full technique mapping from the official MITRE ATT&CK Containers matrix,
# researched from https://attack.mitre.org/matrices/enterprise/containers/

MITRE_CONTAINER_TECHNIQUES = {
    # --- Initial Access (TA0001) ---
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access",
              "description": "Exploit vulnerability in internet-facing containerized service"},
    "T1133": {"name": "External Remote Services", "tactic": "initial_access",
              "description": "Use external remote services to access containers"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial_access",
              "description": "Use compromised credentials to access containers"},

    # --- Execution (TA0002) ---
    "T1609": {"name": "Container Administration Command", "tactic": "execution",
              "description": "Execute commands via container admin tools (kubectl exec)"},
    "T1610": {"name": "Deploy Container", "tactic": "execution",
              "description": "Deploy a malicious container to execute code"},
    "T1053.007": {"name": "Container Orchestration Job", "tactic": "execution",
                  "description": "Abuse K8s Jobs/CronJobs for code execution"},
    "T1204.003": {"name": "Malicious Image", "tactic": "execution",
                  "description": "Trick user into running malicious container image"},

    # --- Persistence (TA0003) ---
    "T1098.006": {"name": "Additional Container Cluster Roles", "tactic": "persistence",
                  "description": "Create new RBAC roles for persistent access"},
    "T1525": {"name": "Implant Internal Image", "tactic": "persistence",
              "description": "Backdoor internal container registry images"},
    "T1543.005": {"name": "Container Service", "tactic": "persistence",
                  "description": "Create/modify container services for persistence"},

    # --- Privilege Escalation (TA0004) ---
    "T1611": {"name": "Escape to Host", "tactic": "privilege_escalation",
              "description": "Break out of container sandbox to host"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation",
              "description": "Exploit vulnerability to gain higher privileges"},

    # --- Defense Evasion (TA0005) ---
    "T1612": {"name": "Build Image on Host", "tactic": "defense_evasion",
              "description": "Build container images on host to evade detection"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "defense_evasion",
                  "description": "Disable security monitoring tools"},
    "T1070": {"name": "Indicator Removal", "tactic": "defense_evasion",
              "description": "Delete logs and artifacts to cover tracks"},
    "T1036.005": {"name": "Match Legitimate Name", "tactic": "defense_evasion",
                  "description": "Name malicious resources to match legitimate ones"},

    # --- Credential Access (TA0006) ---
    "T1110": {"name": "Brute Force", "tactic": "credential_access",
              "description": "Attempt to access accounts via brute force"},
    "T1528": {"name": "Steal Application Access Token", "tactic": "credential_access",
              "description": "Steal OAuth/API tokens from containers"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "credential_access",
                  "description": "Search container filesystem for credentials"},
    "T1552.007": {"name": "Container API", "tactic": "credential_access",
                  "description": "Access K8s API credentials from pod service account"},

    # --- Discovery (TA0007) ---
    "T1613": {"name": "Container and Resource Discovery", "tactic": "discovery",
              "description": "Enumerate containers, pods, and cluster resources"},
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery",
              "description": "Scan network for running services and open ports"},
    "T1069.003": {"name": "Cloud Groups", "tactic": "discovery",
                  "description": "Discover cloud IAM groups and permissions"},

    # --- Lateral Movement (TA0008) ---
    "T1550.001": {"name": "Application Access Token", "tactic": "lateral_movement",
                  "description": "Use stolen tokens to move laterally"},

    # --- Impact (TA0040) ---
    "T1485": {"name": "Data Destruction", "tactic": "impact",
              "description": "Destroy data in containers or persistent volumes"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "impact",
              "description": "DDoS against containerized services"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact",
              "description": "Prevent system recovery mechanisms"},
    "T1498": {"name": "Network Denial of Service", "tactic": "impact",
              "description": "Flood network to deny service"},
    "T1496": {"name": "Resource Hijacking", "tactic": "impact",
              "description": "Hijack compute resources for cryptomining"},
}


# =============================================================================
# Anomaly-to-MITRE Mapping
# =============================================================================
# Maps our detected anomaly event types (from Falco/KubeArmor) to the
# most likely MITRE ATT&CK techniques.

ANOMALY_TO_MITRE = {
    "shell_execution": ["T1609", "T1059"],
    "sensitive_file_read": ["T1552.001", "T1552.007"],
    "container_escape": ["T1611"],
    "unexpected_network_connection": ["T1046", "T1041"],
    "crypto_mining": ["T1496"],
    "privilege_escalation": ["T1068", "T1611"],
    "network_anomaly": ["T1046", "T1499", "T1498"],
    "process_execution": ["T1609", "T1204.003"],
    "file_access": ["T1552.001", "T1070"],
}

# Maps our ML classification labels to MITRE techniques
LABEL_TO_MITRE = {
    "ddos": ["T1499", "T1498"],
    "exfiltration": ["T1041", "T1048"],
    "lateral_movement": ["T1046", "T1550.001"],
    "crypto_mining": ["T1496"],
    "benign": [],
}


# =============================================================================
# Tactic Kill Chain Order
# =============================================================================
# The MITRE ATT&CK kill chain represents the stages of a cyber attack.
# Tactics are ordered from initial access through impact. This ordered
# representation enables the Bayesian predictor to model attack progression.

TACTIC_KILL_CHAIN = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "impact",
]


def get_technique_info(technique_id: str) -> dict:
    """Look up a MITRE technique by ID."""
    return MITRE_CONTAINER_TECHNIQUES.get(technique_id, {
        "name": "Unknown", "tactic": "unknown",
        "description": f"Technique {technique_id} not in database"
    })


def map_anomaly_to_techniques(event_type: str) -> list:
    """Map a detected anomaly type to possible MITRE techniques."""
    technique_ids = ANOMALY_TO_MITRE.get(event_type, [])
    return [{"id": tid, **get_technique_info(tid)} for tid in technique_ids]


def get_tactic_stage(technique_id: str) -> int:
    """Get the kill chain stage index (0-8) for a technique."""
    info = get_technique_info(technique_id)
    tactic = info.get("tactic", "unknown")
    if tactic in TACTIC_KILL_CHAIN:
        return TACTIC_KILL_CHAIN.index(tactic)
    return -1
