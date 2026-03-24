"""
=============================================================================
Network Policy Manager — Dynamic Pod Isolation via Kubernetes API
=============================================================================
Module: response_engine/network_policy_manager.py
Agent:  Agent 4 — "The Enforcer"

Purpose:
    Dynamically creates and applies Kubernetes NetworkPolicy objects to
    isolate compromised pods at runtime. This is the primary containment
    mechanism — it cuts network access to/from a compromised pod within
    seconds of threat detection.

How NetworkPolicy Works:
    Kubernetes NetworkPolicy is a firewall at the pod level. By default,
    all pods can communicate freely. When a NetworkPolicy selects a pod,
    only traffic explicitly allowed by the policy is permitted — all other
    traffic is denied (implicit deny).

    Our isolation policy:
    - Selects the compromised pod by label
    - Allows NO ingress (no traffic can reach the pod)
    - Allows NO egress (the pod cannot send traffic)
    - Effectively "quarantines" the pod while keeping it running for
      forensic analysis

Dependencies: kubernetes (Python client)

Usage:
    from response_engine.network_policy_manager import NetworkPolicyManager
    npm = NetworkPolicyManager()
    npm.isolate_pod("api-backend-ghi56", "aiops-security")
    npm.rollback_isolation("api-backend-ghi56", "aiops-security")
=============================================================================
"""

import logging
import json
from datetime import datetime, timezone
from typing import Optional, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("network_policy_manager")

try:
    from kubernetes import client, config
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    logger.warning("kubernetes package not available. Running in dry-run mode.")


class NetworkPolicyManager:
    """
    Manages Kubernetes NetworkPolicies for automated pod isolation.

    Supports:
    - Creating deny-all isolation policies
    - Rolling back isolation (removing policies)
    - Audit logging of all policy changes
    """

    def __init__(self, kubeconfig: Optional[str] = None):
        """
        Initialize the Kubernetes client.

        Attempts in-cluster config first (for when running as a pod),
        then falls back to kubeconfig file (for local development).
        """
        self.audit_log = []

        self.networking_api = None
        self.core_api = None
        if K8S_AVAILABLE:
            k8s_loaded = False
            try:
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes config")
                k8s_loaded = True
            except config.ConfigException:
                try:
                    config.load_kube_config(config_file=kubeconfig)
                    logger.info("Loaded kubeconfig file")
                    k8s_loaded = True
                except Exception as e:
                    logger.warning(f"Cannot load K8s config: {e}. Dry-run mode.")

            if k8s_loaded:
                self.networking_api = client.NetworkingV1Api()
                self.core_api = client.CoreV1Api()

    def _build_isolation_policy(
        self, pod_name: str, namespace: str
    ) -> Dict:
        """
        Build a deny-all NetworkPolicy spec for pod isolation.

        Policy Design:
        - matchLabels selects the specific pod by its 'statefulset.kubernetes.io/pod-name'
          or custom label matching the pod name
        - policyTypes: ["Ingress", "Egress"] — controls both directions
        - Empty ingress/egress rules = deny all traffic
        - This effectively "air-gaps" the pod from the cluster network

        Why not delete the pod?
            Deleting a compromised pod destroys forensic evidence.
            Network isolation preserves the pod's state (memory, filesystem)
            for incident response while preventing further damage.
        """
        policy_name = f"aiops-isolate-{pod_name}"

        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": policy_name,
                "namespace": namespace,
                "labels": {
                    "managed-by": "aiops-response-engine",
                    "isolation-target": pod_name,
                    "created-at": datetime.now(timezone.utc).isoformat(),
                },
                "annotations": {
                    "aiops.nmit.edu/purpose": "Automated threat isolation",
                    "aiops.nmit.edu/reversible": "true",
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "statefulset.kubernetes.io/pod-name": pod_name,
                    }
                },
                # Both Ingress and Egress — complete network isolation
                "policyTypes": ["Ingress", "Egress"],
                # Empty rules = deny ALL traffic in both directions
                # No ingress rules → no incoming connections allowed
                # No egress rules → no outgoing connections allowed
            },
        }

    def isolate_pod(self, pod_name: str, namespace: str) -> str:
        """
        Apply a deny-all NetworkPolicy to isolate a compromised pod.

        Step-by-step:
        1. Build the isolation policy spec
        2. Check if a policy already exists (idempotency)
        3. Apply the policy via Kubernetes API
        4. Log the action for audit trail

        Returns:
            Name of the created/existing NetworkPolicy
        """
        policy_spec = self._build_isolation_policy(pod_name, namespace)
        policy_name = policy_spec["metadata"]["name"]

        logger.info(f"Isolating pod '{pod_name}' in namespace '{namespace}'")

        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "isolate_pod",
            "pod": pod_name,
            "namespace": namespace,
            "policy_name": policy_name,
            "status": "pending",
        }

        if self.networking_api:
            try:
                # Check if policy already exists
                try:
                    self.networking_api.read_namespaced_network_policy(
                        policy_name, namespace)
                    logger.info(f"Policy '{policy_name}' already exists")
                    audit_entry["status"] = "already_exists"
                    self.audit_log.append(audit_entry)
                    return policy_name
                except client.ApiException as e:
                    if e.status != 404:
                        raise

                # Create the NetworkPolicy
                body = client.V1NetworkPolicy(
                    metadata=client.V1ObjectMeta(
                        name=policy_name,
                        namespace=namespace,
                        labels=policy_spec["metadata"]["labels"],
                        annotations=policy_spec["metadata"]["annotations"],
                    ),
                    spec=client.V1NetworkPolicySpec(
                        pod_selector=client.V1LabelSelector(
                            match_labels=policy_spec["spec"]["podSelector"]["matchLabels"]
                        ),
                        policy_types=["Ingress", "Egress"],
                    ),
                )

                self.networking_api.create_namespaced_network_policy(
                    namespace, body)
                audit_entry["status"] = "created"
                logger.info(f"NetworkPolicy '{policy_name}' created successfully")

            except Exception as e:
                audit_entry["status"] = "failed"
                audit_entry["error"] = str(e)
                logger.error(f"Failed to create NetworkPolicy: {e}")
        else:
            # Dry-run mode — log the policy YAML that would be applied
            logger.info(f"[DRY-RUN] Would create NetworkPolicy:")
            logger.info(json.dumps(policy_spec, indent=2))
            audit_entry["status"] = "dry_run"

        self.audit_log.append(audit_entry)
        return policy_name

    def rollback_isolation(self, pod_name: str, namespace: str) -> bool:
        """
        Remove the isolation NetworkPolicy to restore pod connectivity.

        Used after threat remediation is confirmed. The pod's network
        access is restored to its pre-isolation state.
        """
        policy_name = f"aiops-isolate-{pod_name}"
        logger.info(f"Rolling back isolation for pod '{pod_name}'")

        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "rollback_isolation",
            "pod": pod_name,
            "policy_name": policy_name,
            "status": "pending",
        }

        if self.networking_api:
            try:
                self.networking_api.delete_namespaced_network_policy(
                    policy_name, namespace)
                audit_entry["status"] = "deleted"
                logger.info(f"NetworkPolicy '{policy_name}' deleted")
                self.audit_log.append(audit_entry)
                return True
            except client.ApiException as e:
                if e.status == 404:
                    audit_entry["status"] = "not_found"
                    logger.info(f"Policy '{policy_name}' not found")
                else:
                    audit_entry["status"] = "failed"
                    audit_entry["error"] = str(e)
                    logger.error(f"Rollback failed: {e}")
        else:
            logger.info(f"[DRY-RUN] Would delete NetworkPolicy '{policy_name}'")
            audit_entry["status"] = "dry_run"

        self.audit_log.append(audit_entry)
        return False

    def get_audit_log(self) -> list:
        """Return the audit trail of all policy changes."""
        return list(self.audit_log)
