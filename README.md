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
              ┌─────────────────────────┐
              │   Response Engine       │
              │  • Webhook API          │
              │  • NetworkPolicy Gen    │
              │  • Pod Migration        │
              └─────────────────────────┘
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

# 3. Train ML models
python ml_engine/autoencoder.py --train
python ml_engine/random_forest_classifier.py --train

# 4. Start the response engine webhook
python response_engine/webhook_server.py

# 5. Run tests
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
