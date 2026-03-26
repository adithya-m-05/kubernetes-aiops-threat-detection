# AIOps-Enabled Threat Intelligence for Real-Time Security of Containerized Applications

> **NMIT — Department of Information Science and Engineering**
> **Final Year Project (2025–2026)**

---

## Abstract

This project implements an end-to-end **AIOps (Artificial Intelligence for IT Operations)** pipeline
that monitors containerized applications running on Kubernetes, detects both known and zero-day
security threats in real time, maps detected anomalies to the **MITRE ATT&CK Container Matrix**,
and executes automated remediation actions — all without human intervention.

The system demonstrates the intersection of **DevSecOps**, **data engineering**, and
**machine learning** in a modular, academically documented architecture.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                              │
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────┐ │
│  │  Vulnerable   │   │    Falco     │   │   KubeArmor (eBPF)      │ │
│  │  Microservice │   │  (DaemonSet) │   │   Network + Syscall     │ │
│  │   Testbed     │   │              │   │   Telemetry             │ │
│  └──────┬───────┘   └──────┬───────┘   └──────────┬──────────────┘ │
│         │                  │                       │                 │
│         └──────────────────┼───────────────────────┘                 │
│                            ▼                                         │
│                  ┌─────────────────┐                                 │
│                  │  Log Aggregator │  ◄── Centralized JSON Telemetry │
│                  └────────┬────────┘                                 │
└───────────────────────────┼──────────────────────────────────────────┘
                            ▼
              ┌─────────────────────────┐
              │   Data Pipeline         │
              │  • Feature Extraction   │
              │  • PCA Reduction        │
              │  • SMOTE Balancing      │
              └────────────┬────────────┘
                           ▼
              ┌─────────────────────────┐
              │   ML Engine             │
              │  • Autoencoder (0-day)  │
              │  • Random Forest (known)│
              │  • Bayesian → MITRE     │
              └────────────┬────────────┘
                           ▼
              ┌─────────────────────────┐   ┌─────────────────────────┐
              │   Response Engine       │   │   SOC Dashboard (UI)    │
              │  • Webhook API          │◄──┤  • Live Alerts Table    │
              │  • NetworkPolicy Gen    │   │  • Response Timeline    │
              │  • Pod Migration        │   │  • Entity Status Grid   │
              └─────────────────────────┘   └─────────────────────────┘
```

---

## Project Structure

```
FYP/
├── infrastructure/          # Agent 1 — Telemetry & Infrastructure
│   ├── k8s/                 # Kubernetes manifests
│   │   ├── namespace.yaml
│   │   ├── vulnerable-app/  # Intentionally vulnerable testbed
│   │   ├── falco/           # Runtime syscall monitoring
│   │   └── kubearmor/       # eBPF-based security policies
│   └── telemetry/
│       └── log_aggregator.py
├── data_pipeline/           # Agent 2 — Data Engineering
│   ├── preprocessing.py
│   ├── feature_extraction.py
│   ├── data_balancing.py
│   └── mock_data_generator.py
├── ml_engine/               # Agent 3 — ML & Threat Intelligence
│   ├── autoencoder.py
│   ├── random_forest_classifier.py
│   ├── bayesian_attack_predictor.py
│   └── mitre_attack_mapping.py
├── response_engine/         # Agent 4 — Automated Response
│   ├── webhook_server.py
│   ├── network_policy_manager.py
│   └── pod_migration.py
├── dashboard/               # Agent 5 — UI / SOC Dashboard
│   ├── index.html           # Main Application Shell
│   ├── js/                  # api.js, app.js, charts.js, components.js
│   └── css/                 # base.css, layout.css, components.css
├── tests/                   # Unit and integration tests
├── docs/                    # Architecture documentation
└── requirements.txt
```

---

## Tech Stack

| Layer              | Technology                                      |
|--------------------|--------------------------------------------------|
| **Infrastructure** | Kubernetes (Minikube/Kind), Docker               |
| **Telemetry**      | Falco (syscalls), KubeArmor (eBPF probes)        |
| **Data Pipeline**  | Python, Pandas, Scikit-learn, imbalanced-learn    |
| **ML Engine**      | PyTorch (Autoencoder), Scikit-learn (Random Forest), pgmpy (Bayesian Network) |
| **Orchestration**  | Python Kubernetes Client, Flask                   |
| **Frontend UI**    | HTML5, Vanilla CSS, Vanilla JavaScript, Chart.js  |

---

## Datasets

The machine learning models in this project are designed to be trained on the **BOA Network Dataset** (`boa_dataset/`) and the **DVWA Exploit Dataset** (`dvwa_dataset/`). 

> **Note:** Due to their large size, the raw and processed CSV datasets, PCAP files, and other generated artifacts are excluded from this repository. 

If you are cloning this project, you will need to download these datasets (e.g., from Kaggle) and place them in the root directory under the `boa_dataset/` and `dvwa_dataset/` folders. Alternatively, you can use the built-in `mock_data_generator.py` to test the pipeline without downloading the full datasets.

---

## Quick Start

### Prerequisites
- Python 3.9+
- Docker Desktop
- Minikube or Kind
- kubectl

### Installation

```bash
# Clone the repository
git clone <repo-url> && cd FYP

# Install Python dependencies
pip install -r requirements.txt

# Stand up the Kubernetes cluster (Minikube example)
minikube start --driver=docker

# Deploy the full infrastructure stack
kubectl apply -f infrastructure/k8s/namespace.yaml
kubectl apply -f infrastructure/k8s/vulnerable-app/
kubectl apply -f infrastructure/k8s/falco/
kubectl apply -f infrastructure/k8s/kubearmor/
```

### Running the Pipeline

```bash
# 1. Generate mock telemetry data
python data_pipeline/mock_data_generator.py

# 2. Run the preprocessing pipeline
python data_pipeline/preprocessing.py

# 3. Train ML models (using default mock data)
python ml_engine/autoencoder.py --train
python ml_engine/random_forest_classifier.py --train

# Alternatively, train using a specific downloaded dataset (e.g., DVWA):
# python ml_engine/autoencoder.py --train --data "dvwa_dataset\processed\dvwa_dataset_ml_ready.csv"
# python ml_engine/random_forest_classifier.py --train --data "dvwa_dataset\processed\dvwa_dataset_ml_ready.csv"

# 4. Start the response engine webhook (API for the dashboard)
python response_engine/webhook_server.py --port 5000

# 5. Start the SOC Dashboard frontend (Run in a new terminal)
npx -y serve dashboard -l 3333
# Open http://localhost:3333 in your browser

# 6. Run tests
pytest tests/ -v
```

---

## Academic References

1. MITRE ATT&CK® Container Matrix — https://attack.mitre.org/matrices/enterprise/containers/
2. Falco Runtime Security — https://falco.org/docs/
3. KubeArmor eBPF Security — https://kubearmor.io/
4. Chawla et al. (2002) — SMOTE: Synthetic Minority Over-sampling Technique
5. An & Cho (2015) — Variational Autoencoder based Anomaly Detection

---

## License

This project is developed for academic purposes at NMIT. All rights reserved.
