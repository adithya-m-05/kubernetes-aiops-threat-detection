# AI-Based Runtime Threat Detection and Automated Response for Kubernetes Containers

> **NMIT — Department of Information Science and Engineering**  
> **Final Year Project (2025–2026)**

---

## Abstract

Modern cloud-native systems rely on Kubernetes to orchestrate containerized microservices across distributed environments. However, traditional perimeter defenses fail to detect runtime security incidents such as container escapes, unauthorized interactive shells, credential harvesting, or lateral network discovery.

This project delivers an end-to-end, closed-loop runtime threat detection and containment system:
1. **Runtime Telemetry**: Captures container system calls and security events using **Falco**.
2. **Feature Engineering**: Normalizes multi-dimensional event features across temporal, traffic, syscall, and behavioral categories.
3. **ML Anomaly Detection**: Employs an unsupervised **PyTorch Autoencoder** trained on benign workload profiles to detect anomalous behavior and zero-day execution patterns via reconstruction error.
4. **MITRE ATT&CK Mapping**: Maps anomalies deterministically to the **MITRE ATT&CK Container Matrix** for explainable threat characterization.
5. **Automated Containment**: Dynamically applies Kubernetes **NetworkPolicy** isolation rules to quarantine compromised pods without terminating them, preserving memory and filesystem state for forensic analysis.
6. **SOC Dashboard**: Visualizes live alerts, pod status, and automated responses in real time.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Kubernetes Cluster                            │
│                                                                        │
│  ┌───────────────────────────┐         ┌────────────────────────────┐  │
│  │ Vulnerable Container App  │         │     Falco (DaemonSet)      │  │
│  │ (Microservice Workloads)  │──syscalls──►│ Runtime Syscall Monitor │  │
│  └─────────────▲─────────────┘         └─────────────┬──────────────┘  │
│                │                                     │                 │
│         NetworkPolicy                                │ JSON Alerts     │
│         (Deny Ingress/Egress)                        ▼                 │
│                │                       ┌────────────────────────────┐  │
│                └───────────────────────┤ Log Aggregator / Ingestion │  │
│                                        └─────────────┬──────────────┘  │
└──────────────────────────────────────────────────────┼─────────────────┘
                                                       │ Unified NDJSON
                                                       ▼
                                         ┌────────────────────────────┐
                                         │  Preprocessing & Feature   │
                                         │         Extraction         │
                                         └─────────────┬──────────────┘
                                                       │ Scaled Features
                                                       ▼
                                         ┌────────────────────────────┐
                                         │ PyTorch Autoencoder Model  │
                                         │  (Reconstruction Error)    │
                                         └─────────────┬──────────────┘
                                                       │ Anomaly Score > Threshold
                                                       ▼
                                         ┌────────────────────────────┐
                                         │  MITRE ATT&CK Mapping &    │
                                         │      Risk Assessment       │
                                         └─────────────┬──────────────┘
                                                       │ High/Critical
                                                       ▼
                                         ┌────────────────────────────┐
                                         │  Response Engine & Webhook │
                                         │  (Dynamic NetworkPolicy)   │
                                         └─────────────┬──────────────┘
                                                       │
                                                       ▼
                                         ┌────────────────────────────┐
                                         │   SOC Dashboard (UI)       │
                                         │   Live Alerts & Responses  │
                                         └────────────────────────────┘
```

---

## Project Structure

```
FYP/
├── config.py                # Central project configuration
├── infrastructure/          # Telemetry & K8s Infrastructure
│   ├── k8s/                 # Kubernetes manifests
│   │   ├── namespace.yaml
│   │   ├── vulnerable-app/  # Intentionally vulnerable testbed
│   │   └── falco/           # Falco DaemonSet & custom security rules
│   └── telemetry/
│       └── log_aggregator.py# Falco event stream normalizer
├── data_pipeline/           # Data Ingestion & Engineering
│   ├── preprocessing.py     # JSON ingestion and schema validation
│   ├── feature_extraction.py# Temporal, traffic, syscall, behavioral features
│   ├── data_balancing.py    # Normalization, PCA, and SMOTE balancing
│   ├── mock_data_generator.py# Synthetic Falco event generator
│   └── falco_dataset_collector.py # Live Falco scenario collector
├── ml_engine/               # Machine Learning & Threat Intelligence
│   ├── pipeline.py          # Central runtime inference pipeline
│   ├── autoencoder.py       # PyTorch Anomaly Detection Autoencoder
│   ├── mitre_attack_mapping.py # MITRE ATT&CK Container Matrix mapping
│   └── random_forest_classifier.py # (Optional) Secondary classifier
├── response_engine/         # Automated Containment & API
│   ├── webhook_server.py    # Flask REST API for alerts and inference
│   └── network_policy_manager.py # Kubernetes NetworkPolicy orchestrator
├── dashboard/               # SOC Dashboard Frontend
│   ├── index.html           # Main dashboard UI
│   ├── js/                  # api.js, app.js, charts.js, components.js
│   └── css/                 # Modern dark-mode responsive styling
├── datasets/                # Runtime & Scenario Datasets
│   ├── falco/               # Raw & processed Falco telemetry
│   └── README.md            # Dataset documentation
├── models/                  # Saved Model Weights & Metadata
│   └── autoencoder/         # model.pt, model_meta.json
├── scripts/                 # Automation Scripts
│   └── train_model.py       # End-to-end model training script
├── tests/                   # Unit & Integration Test Suite
├── docs/                    # Architecture diagrams and specifications
├── archive/                 # Archived out-of-scope legacy modules
├── requirements.txt         # Project dependencies
├── how_to_run.md            # Step-by-step execution guide
└── novelty_analysis.md      # Literature comparison & thesis novelty
```

---

## Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| **Runtime Security** | Falco (eBPF / Kernel module) | Container syscall monitoring and threat detection |
| **Orchestration** | Kubernetes (Minikube / Kind) | Microservice deployment and security isolation |
| **Data Pipeline** | Python, Pandas, Scikit-learn | Telemetry normalization and feature extraction |
| **Machine Learning** | PyTorch (Autoencoder) | Unsupervised anomaly & zero-day detection |
| **Threat Intelligence** | MITRE ATT&CK Container Matrix | Explainable attack classification |
| **Automated Response** | Python Kubernetes Client, Flask | Dynamic NetworkPolicy pod quarantine |
| **Dashboard UI** | HTML5, Vanilla CSS, Vanilla JS, Chart.js | Real-time security operations center interface |

---

## Quick Start

### 1. Prerequisites
- Python 3.9+
- (Optional for full K8s mode) Docker Desktop, Minikube, kubectl

### 2. Setup Environment
```bash
git clone <repo-url> && cd FYP
python -m venv .venv

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Install dependencies:
pip install -r requirements.txt
```

### 3. Local Demo Execution (No Kubernetes Required)
```bash
# 1. Train the Autoencoder model
python scripts/train_model.py --events 2000 --epochs 30

# 2. Start the Threat Detection Webhook API (Terminal 1)
python response_engine/webhook_server.py --port 5000

# 3. Serve the SOC Dashboard (Terminal 2)
npx -y serve dashboard -l 3333
```
Open **http://localhost:3333** in your browser to view the SOC dashboard.

### 4. Send a Test Threat Alert
```powershell
Invoke-RestMethod -Method POST -Uri "http://localhost:5000/api/v1/alert" -ContentType "application/json" -Body '{
  "pod": "api-backend-ghi56",
  "namespace": "aiops-security",
  "threat_type": "container_escape",
  "confidence_score": 0.94,
  "mitre_technique": "T1611",
  "anomaly_score": 0.89,
  "risk_level": "CRITICAL"
}'
```

### 5. Run Test Suite
```bash
pytest tests/ -v
```

---

## Academic References

1. **MITRE ATT&CK® Container Matrix** — https://attack.mitre.org/matrices/enterprise/containers/
2. **Falco Runtime Security** — https://falco.org/docs/
3. **An & Cho (2015)** — *Variational Autoencoder based Anomaly Detection using Reconstruction Probability*, SNU Data Mining Center.
4. **Hindy et al. (2020)** — *Utilising Deep Learning Techniques for Effective Zero-Day Attack Detection*, Electronics (MDPI).
5. **Kubernetes Network Policies** — https://kubernetes.io/docs/concepts/services-networking/network-policies/

---

## License

Developed for academic purposes at NMIT. All rights reserved.
