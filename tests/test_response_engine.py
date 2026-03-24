"""
Unit tests for the response engine modules.
Tests: Webhook API, NetworkPolicy generation, Pod migration.
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestWebhookServer:
    @pytest.fixture
    def client(self):
        from response_engine.webhook_server import app
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_health_check(self, client):
        response = client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"

    def test_valid_alert(self, client):
        alert = {
            "pod": "api-backend-ghi56",
            "namespace": "aiops-security",
            "threat_type": "exfiltration",
            "confidence_score": 0.95,
            "risk_level": "HIGH",
        }
        response = client.post("/api/v1/alert",
                               data=json.dumps(alert),
                               content_type="application/json")
        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "processed"

    def test_low_confidence_alert(self, client):
        alert = {
            "pod": "test-pod",
            "namespace": "aiops-security",
            "threat_type": "unknown",
            "confidence_score": 0.3,
        }
        response = client.post("/api/v1/alert",
                               data=json.dumps(alert),
                               content_type="application/json")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "below_threshold"

    def test_invalid_alert_missing_field(self, client):
        alert = {"pod": "test-pod"}  # Missing required fields
        response = client.post("/api/v1/alert",
                               data=json.dumps(alert),
                               content_type="application/json")
        assert response.status_code == 400

    def test_alert_history(self, client):
        # Send an alert first
        alert = {
            "pod": "test-pod",
            "namespace": "test",
            "threat_type": "test",
            "confidence_score": 0.5,
        }
        client.post("/api/v1/alert", data=json.dumps(alert),
                    content_type="application/json")
        response = client.get("/api/v1/history")
        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] >= 1


class TestNetworkPolicyManager:
    def test_build_isolation_policy(self):
        from response_engine.network_policy_manager import NetworkPolicyManager
        npm = NetworkPolicyManager()
        policy = npm._build_isolation_policy("test-pod", "test-ns")
        assert policy["metadata"]["name"] == "aiops-isolate-test-pod"
        assert "Ingress" in policy["spec"]["policyTypes"]
        assert "Egress" in policy["spec"]["policyTypes"]

    def test_isolate_pod_dry_run(self):
        from response_engine.network_policy_manager import NetworkPolicyManager
        npm = NetworkPolicyManager()
        name = npm.isolate_pod("test-pod", "test-ns")
        assert name == "aiops-isolate-test-pod"
        assert len(npm.audit_log) > 0

    def test_rollback_dry_run(self):
        from response_engine.network_policy_manager import NetworkPolicyManager
        npm = NetworkPolicyManager()
        npm.rollback_isolation("test-pod", "test-ns")
        assert len(npm.audit_log) > 0

    def test_audit_log(self):
        from response_engine.network_policy_manager import NetworkPolicyManager
        npm = NetworkPolicyManager()
        npm.isolate_pod("pod1", "ns1")
        npm.isolate_pod("pod2", "ns2")
        log = npm.get_audit_log()
        assert len(log) == 2


class TestPodMigration:
    def test_safe_drain_dry_run(self):
        from response_engine.pod_migration import PodMigrationManager
        pmm = PodMigrationManager()
        result = pmm.safe_drain_and_reschedule("test-pod", "test-ns")
        assert "steps" in result
        assert result["node"] is not None

    def test_get_pod_node_dry_run(self):
        from response_engine.pod_migration import PodMigrationManager
        pmm = PodMigrationManager()
        node = pmm.get_pod_node("test-pod", "test-ns")
        assert node is not None  # Returns mock value in dry-run

    def test_cordon_dry_run(self):
        from response_engine.pod_migration import PodMigrationManager
        pmm = PodMigrationManager()
        result = pmm.cordon_node("test-node")
        assert result is True

    def test_uncordon_dry_run(self):
        from response_engine.pod_migration import PodMigrationManager
        pmm = PodMigrationManager()
        result = pmm.uncordon_node("test-node")
        assert result is True
