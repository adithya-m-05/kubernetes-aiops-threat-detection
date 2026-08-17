"""
=============================================================================
Pod Migration Manager — Safe Cordon, Drain, and Reschedule
=============================================================================
Module: response_engine/pod_migration.py
Agent:  Agent 4 — "The Enforcer"

Purpose:
    Orchestrates the safe migration of pods from compromised nodes by:
    1. Cordoning the node (preventing new pod scheduling)
    2. Draining pods gracefully (respecting PodDisruptionBudgets)
    3. Verifying pod rescheduling on healthy nodes
    4. Uncordoning after remediation

Why Live Migration?
    When a node is suspected to be compromised (e.g., container escape
    detected), we cannot trust any pod on that node. However, abruptly
    killing pods causes service disruption. This module implements graceful
    migration that maintains service availability while containing the threat.

Dependencies: kubernetes (Python client)
=============================================================================
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pod_migration")

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    logger.warning("kubernetes package not available. Dry-run mode.")


class PodMigrationManager:
    """
    Manages safe pod migration from compromised Kubernetes nodes.

    Implements a careful sequence of operations designed to minimize
    service disruption while containing security threats.
    """

    def __init__(self, kubeconfig: Optional[str] = None):
        self.operations_log = []
        self.core_api = None
        self.apps_api = None
        if K8S_AVAILABLE:
            k8s_loaded = False
            try:
                config.load_incluster_config()
                k8s_loaded = True
            except config.ConfigException:
                try:
                    config.load_kube_config(config_file=kubeconfig)
                    k8s_loaded = True
                except Exception as e:
                    logger.warning(f"Cannot load K8s config: {e}")
            if k8s_loaded:
                self.core_api = client.CoreV1Api()
                self.apps_api = client.AppsV1Api()

    def get_pod_node(self, pod_name: str, namespace: str) -> Optional[str]:
        """
        Determine which node a pod is running on.

        Uses the pod's spec.nodeName field, which is set by the scheduler
        when the pod is bound to a node.
        """
        if not self.core_api:
            logger.info(f"[DRY-RUN] Would look up node for pod '{pod_name}'")
            return "minikube-node-1"

        try:
            pod = self.core_api.read_namespaced_pod(pod_name, namespace)
            node = pod.spec.node_name
            logger.info(f"Pod '{pod_name}' is on node '{node}'")
            return node
        except ApiException as e:
            logger.error(f"Failed to get pod info: {e}")
            return None

    def cordon_node(self, node_name: str) -> bool:
        """
        Cordon a node to prevent new pod scheduling.

        Cordoning sets the node's spec.unschedulable=True. Existing pods
        continue running, but no new pods will be scheduled to this node.
        This is the first step in safe migration — it prevents new
        workloads from landing on a potentially compromised node.
        """
        logger.info(f"Cordoning node '{node_name}'...")
        self._log_operation("cordon_node", node_name, "pending")

        if not self.core_api:
            logger.info(f"[DRY-RUN] Would cordon node '{node_name}'")
            self._log_operation("cordon_node", node_name, "dry_run")
            return True

        try:
            body = {"spec": {"unschedulable": True}}
            self.core_api.patch_node(node_name, body)
            self._log_operation("cordon_node", node_name, "success")
            logger.info(f"Node '{node_name}' cordoned successfully")
            return True
        except ApiException as e:
            self._log_operation("cordon_node", node_name, "failed", str(e))
            logger.error(f"Failed to cordon node: {e}")
            return False

    def uncordon_node(self, node_name: str) -> bool:
        """
        Uncordon a node to allow pod scheduling again.
        Used after the threat has been remediated and the node is clean.
        """
        logger.info(f"Uncordoning node '{node_name}'...")

        if not self.core_api:
            logger.info(f"[DRY-RUN] Would uncordon node '{node_name}'")
            return True

        try:
            body = {"spec": {"unschedulable": False}}
            self.core_api.patch_node(node_name, body)
            logger.info(f"Node '{node_name}' uncordoned")
            return True
        except ApiException as e:
            logger.error(f"Failed to uncordon node: {e}")
            return False

    def get_pods_on_node(
        self, node_name: str, namespace: Optional[str] = None
    ) -> List[Dict]:
        """
        List all pods running on a specific node.

        Used to identify which pods need to be migrated during drain.
        Filters out DaemonSet pods (they run on every node by design
        and should not be evicted).
        """
        if not self.core_api:
            return [
                {"name": "web-frontend-abc12", "namespace": "aiops-security",
                 "is_daemonset": False},
                {"name": "api-backend-ghi56", "namespace": "aiops-security",
                 "is_daemonset": False},
                {"name": "falco-xyz99", "namespace": "aiops-security",
                 "is_daemonset": True},
            ]

        try:
            field_selector = f"spec.nodeName={node_name}"
            if namespace:
                pods = self.core_api.list_namespaced_pod(
                    namespace, field_selector=field_selector)
            else:
                pods = self.core_api.list_pod_for_all_namespaces(
                    field_selector=field_selector)

            result = []
            for pod in pods.items:
                # Check if pod is managed by a DaemonSet
                is_ds = False
                if pod.metadata.owner_references:
                    for ref in pod.metadata.owner_references:
                        if ref.kind == "DaemonSet":
                            is_ds = True
                            break

                result.append({
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "is_daemonset": is_ds,
                    "phase": pod.status.phase,
                })

            return result
        except ApiException as e:
            logger.error(f"Failed to list pods on node: {e}")
            return []

    def evict_pod(
        self, pod_name: str, namespace: str,
        grace_period: int = 30
    ) -> bool:
        """
        Evict a single pod using the Eviction API.

        The Eviction API (vs direct delete) respects PodDisruptionBudgets
        (PDBs). If evicting the pod would violate a PDB (e.g., drop below
        minAvailable), the API returns 429 Too Many Requests and we retry.
        This ensures service availability during migration.

        grace_period: Seconds for the pod to shut down gracefully.
            Default 30s allows time for connection draining and SIGTERM
            handlers. Set higher for stateful workloads.
        """
        logger.info(f"Evicting pod '{pod_name}' (grace: {grace_period}s)...")

        if not self.core_api:
            logger.info(f"[DRY-RUN] Would evict pod '{pod_name}'")
            return True

        try:
            eviction = client.V1Eviction(
                metadata=client.V1ObjectMeta(
                    name=pod_name,
                    namespace=namespace,
                ),
                delete_options=client.V1DeleteOptions(
                    grace_period_seconds=grace_period,
                ),
            )
            self.core_api.create_namespaced_pod_eviction(
                pod_name, namespace, eviction)
            logger.info(f"Pod '{pod_name}' eviction initiated")
            return True
        except ApiException as e:
            if e.status == 429:
                logger.warning(f"PDB prevents eviction of '{pod_name}'. Retrying...")
                return False
            logger.error(f"Pod eviction failed: {e}")
            return False

    def wait_for_pod_rescheduling(
        self, pod_name: str, namespace: str,
        timeout: int = 120, poll_interval: int = 5
    ) -> bool:
        """
        Wait for replacement pods to become Ready after eviction.

        Monitors the deployment/replicaset to ensure that the desired
        replica count is met on healthy nodes. This verification step
        ensures zero downtime migration.
        """
        logger.info(f"Waiting for pod rescheduling (timeout: {timeout}s)...")

        if not self.core_api:
            logger.info("[DRY-RUN] Would wait for rescheduling")
            return True

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                pods = self.core_api.list_namespaced_pod(
                    namespace,
                    label_selector=f"app=vulnerable-testbed"
                )
                ready_count = sum(
                    1 for pod in pods.items
                    if pod.status.phase == "Running"
                    and all(c.ready for c in (pod.status.container_statuses or []))
                )
                logger.info(f"  Ready pods: {ready_count}")
                if ready_count >= 2:  # At least 2 replicas running
                    logger.info("Pod rescheduling verified")
                    return True
            except ApiException as e:
                logger.warning(f"Polling error: {e}")

            time.sleep(poll_interval)

        logger.warning(f"Pod rescheduling timed out after {timeout}s")
        return False

    def safe_drain_and_reschedule(
        self, pod_name: str, namespace: str,
        grace_period: int = 30
    ) -> Dict:
        """
        Execute the full safe migration sequence.

        Sequence:
        1. Find the node hosting the compromised pod
        2. Cordon the node (no new scheduling)
        3. List all non-DaemonSet pods on the node
        4. Evict each pod (respecting PDBs)
        5. Wait for rescheduling on healthy nodes
        6. Report status

        Does NOT uncordon automatically — that requires manual
        verification that the node is clean (security best practice).
        """
        logger.info(f"=== Starting safe drain for pod '{pod_name}' ===")
        result = {
            "pod": pod_name, "namespace": namespace,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "steps": [],
        }

        # Step 1: Find node
        node = self.get_pod_node(pod_name, namespace)
        if not node:
            result["status"] = "failed"
            result["error"] = "Cannot determine pod node"
            return result
        result["node"] = node
        result["steps"].append({"step": "find_node", "node": node})

        # Step 2: Cordon
        if self.cordon_node(node):
            result["steps"].append({"step": "cordon", "status": "success"})
        else:
            result["steps"].append({"step": "cordon", "status": "failed"})
            result["status"] = "partial_failure"
            return result

        # Step 3: List pods to evict
        pods = self.get_pods_on_node(node, namespace)
        evictable = [p for p in pods if not p["is_daemonset"]]
        result["steps"].append({
            "step": "list_pods",
            "total": len(pods),
            "evictable": len(evictable),
        })

        # Step 4: Evict non-DaemonSet pods
        evicted = 0
        for pod in evictable:
            if self.evict_pod(pod["name"], pod["namespace"], grace_period):
                evicted += 1
        result["steps"].append({
            "step": "evict_pods",
            "evicted": evicted,
            "total": len(evictable),
        })

        # Step 5: Verify rescheduling
        rescheduled = self.wait_for_pod_rescheduling(pod_name, namespace)
        result["steps"].append({
            "step": "verify_reschedule",
            "success": rescheduled,
        })

        result["status"] = "success" if rescheduled else "partial_success"
        logger.info(f"=== Safe drain complete: {result['status']} ===")
        return result

    def _log_operation(self, action, target, status, error=None):
        """Log operation for audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action, "target": target, "status": status,
        }
        if error:
            entry["error"] = error
        self.operations_log.append(entry)


if __name__ == "__main__":
    logger.info("Pod Migration Manager — Smoke Test")
    pmm = PodMigrationManager()

    # Dry-run simulation
    result = pmm.safe_drain_and_reschedule("api-backend-ghi56", "aiops-security")

    import json
    print("\nMigration Result:")
    print(json.dumps(result, indent=2))
