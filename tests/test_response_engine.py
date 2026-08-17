"""
Unit tests for the response engine modules.
Tests: Webhook API, Event Processing API, NetworkPolicy generation.
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

    def test_raw_event_inference_endpoint(self, client):
        event = {
            "pod": "web-frontend-abc12",
            "namespace": "aiops-security",
            "severity": "CRITICAL",
            "event_type": "shell_execution",
            "syscall": "execve",
            "process": "bash",
            "network_metadata": {"dst_port": 80, "dst_ip": "10.244.0.5"}
        }
        response = client.post("/api/v1/event",
                               data=json.dumps(event),
                               content_type="application/json")
        assert response.status_code in (200, 503)
        if response.status_code == 200:
            data = response.get_json()
            assert data["status"] == "processed"
            assert "anomaly_score" in data

    def test_alert_history(self, client):
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
