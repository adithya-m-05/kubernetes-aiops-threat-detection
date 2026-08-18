# AIOps-Enabled Threat Intelligence for Real-Time Security of Containerized Applications

> **NMIT — Department of Information Science and Engineering**  
> **Final Year Project (2025–2026)**

---

## 1. Overview

Modern cloud-native systems rely on Kubernetes to orchestrate containerized microservices across distributed environments. Traditional perimeter defenses fail to detect runtime security incidents such as container escapes, unauthorized interactive shells, credential harvesting, or lateral network discovery.

This project implements an end-to-end, closed-loop runtime threat detection and containment system that follows the **DETECT → EXPLAIN → RESPOND** paradigm:

1. **Runtime Telemetry**: Captures container system calls and security events using **Falco**.
2. **Feature Engineering**: Normalizes multi-dimensional event features across temporal, traffic, syscall, and behavioral categories.
3. **ML Anomaly Detection**: Employs an unsupervised **PyTorch Autoencoder** trained on benign workload profiles to detect anomalous runtime behavior via reconstruction error.
4. **MITRE ATT&CK Mapping**: Maps detected anomalies deterministically to the **MITRE ATT&CK Container Matrix** for explainable threat characterization.
5. **Automated Containment**: Dynamically applies Kubernetes **NetworkPolicy** isolation rules to quarantine compromised pods without terminating them, preserving the opportunity for later investigation.
6. **SOC Dashboard**: Visualizes live alerts, pod status, and automated response actions in real time.

---

## 2. Problem Statement

Kubernetes environments are vulnerable to runtime attacks that bypass traditional static defenses. Existing approaches either rely on rule-based signature matching (which cannot detect novel behavior), require labeled datasets of every attack type (impractical for emerging threats), or provide detection without automated remediation (requiring manual intervention).

---

## 3. Objectives

1. Develop an unsupervised anomaly detection model using an Autoencoder trained on benign Falco runtime telemetry.
2. Map detected anomalies to the MITRE ATT&CK Container Matrix for explainability.
3. Automate containment of high-risk pods using Kubernetes NetworkPolicy quarantine.
4. Provide a real-time SOC dashboard for monitoring threats, affected pods, and response actions.

---

## 4. Proposed Solution

An AIOps-enabled runtime security prototype that combines automated telemetry analysis, unsupervised anomaly detection, threat-intelligence mapping, and automated Kubernetes containment into a single closed-loop system.

---

## 5. Core Architecture

```
┌──────────────────────┐
│ Kubernetes Container │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│        Falco         │
│ Runtime Monitoring   │
└──────────┬───────────┘
           │
     JSON Events
           │
           ▼
┌──────────────────────┐
│   Preprocessing      │
│ & Feature Extraction │
└──────────┬───────────┘
           │
     Feature Vector
           │
           ▼
┌──────────────────────┐
│ PyTorch Autoencoder  │
│ Anomaly Detection    │
└──────────┬───────────┘
           │
  Reconstruction Error
           │
           ▼
┌──────────────────────┐
│ Anomaly Thresholding │
└──────────┬───────────┘
           │
     Anomaly Detected
           │
           ▼
┌──────────────────────┐
│ MITRE ATT&CK Mapping │
└──────────┬───────────┘
           │
     Risk Assessment
           │
           ▼
┌──────────────────────┐
│ Response Engine      │
│ NetworkPolicy        │
│ Quarantine           │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ SOC Dashboard        │
│ Alerts / Pod Status  │
│ Response Logs        │
└──────────────────────┘
```

---

## 6. How the System Works

### Detection Flow

1. **Falco** monitors container runtime behavior via syscall interception.
2. Events are **preprocessed** (schema validation, timestamp normalization, deduplication).
3. **Features** are extracted across temporal, traffic, syscall, and behavioral categories.
4. The trained **Autoencoder** computes reconstruction error for each event/session.
5. Events with reconstruction error exceeding the **threshold** are flagged as anomalies.
6. Anomalies are mapped to **MITRE ATT&CK** Container Matrix techniques.
7. **Risk assessment** determines the response action (log, monitor, or isolate).
8. High-risk anomalies trigger **NetworkPolicy quarantine** of the affected pod.
9. All events, alerts, and responses are displayed on the **SOC dashboard**.

---

## 7. Machine Learning Approach

### Autoencoder Architecture

The project uses an undercomplete Autoencoder (the project's primary and only ML model):

```
Encoder: input_dim → 128 → 64 → 32 (latent space)
Decoder: 32 → 64 → 128 → input_dim
```

- **Training**: Trained exclusively on benign (normal) runtime behavior.
- **Inference**: Computes per-sample Mean Squared Error (MSE) between input and reconstruction.
- **Detection**: MSE > threshold → anomaly. MSE ≤ threshold → normal.

### Thresholding Strategy

The anomaly threshold is set at the **95th percentile** of reconstruction errors on benign validation data. This provides a principled, data-driven decision boundary:

```
Train on normal behavior → Calculate validation MSE → P95 = threshold
```

### Why Unsupervised?

Supervised classifiers require labeled examples of every attack type. The unsupervised Autoencoder learns only what "normal" looks like, enabling detection of anomalous runtime behaviors that may correspond to unknown or novel attack techniques without requiring attack-labeled training data.

---

## 8. MITRE ATT&CK Integration

Detected anomalies are mapped deterministically to the **MITRE ATT&CK Container Matrix** for explainability:

| Event Type | MITRE Technique |
|---|---|
| Shell execution | T1609 — Container Administration Command |
| Container escape | T1611 — Escape to Host |
| Sensitive file read | T1552.001 — Credentials In Files |
| Network scanning | T1046 — Network Service Discovery |
| Crypto mining | T1496 — Resource Hijacking |

This mapping provides security operators with standardized threat context without requiring an AI-powered threat intelligence engine.

---

## 9. Automated NetworkPolicy Response

When a HIGH or CRITICAL risk anomaly is detected, the system automatically generates and applies a Kubernetes **NetworkPolicy** that denies all ingress and egress traffic to the affected pod:

```
Anomaly detected → Risk assessed → NetworkPolicy created → Pod network isolated
```

- The pod remains running (preserving runtime state for later investigation).
- Supports `DRY_RUN=true` mode for testing without Kubernetes.
- Supports rollback (removing the isolation policy) after investigation.

---

## 10. Dashboard

The SOC dashboard displays:
- **System status**: Detection engine health, model loaded status
- **Threat alerts**: Timestamp, pod, namespace, threat type, anomaly score, risk level, MITRE technique, response status
- **Pod status**: NORMAL / SUSPICIOUS / ISOLATED
- **Response log**: Automated containment actions with audit trail

---

## 11. Dataset

The primary dataset is **Falco runtime telemetry** — JSON events generated by Falco's syscall monitoring. For local development, a mock data generator produces synthetic Falco events matching the same schema.

See [`datasets/README.md`](datasets/README.md) for detailed dataset documentation.

---

## 12. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Runtime Security** | Falco (eBPF / Kernel module) | Container syscall monitoring |
| **Orchestration** | Kubernetes (Minikube) | Microservice deployment and network isolation |
| **Data Pipeline** | Python, Pandas | Telemetry preprocessing and feature extraction |
| **Machine Learning** | PyTorch (Autoencoder) | Unsupervised anomaly detection |
| **Threat Intelligence** | MITRE ATT&CK Container Matrix | Explainable attack classification |
| **Automated Response** | Python Kubernetes Client, Flask | Dynamic NetworkPolicy pod quarantine |
| **Dashboard UI** | HTML5, Vanilla CSS, Vanilla JS, Chart.js | Real-time security operations interface |

---

## 13. Project Structure

```
FYP/
├── config.py                    # Central project configuration
├── infrastructure/              # Telemetry & K8s Infrastructure
│   ├── k8s/                     # Kubernetes manifests
│   │   ├── namespace.yaml
│   │   ├── vulnerable-app/      # Intentionally vulnerable testbed
│   │   └── falco/               # Falco DaemonSet & custom rules
│   └── telemetry/
│       └── log_aggregator.py    # Falco event stream normalizer
├── data_pipeline/               # Data Ingestion & Engineering
│   ├── preprocessing.py         # JSON ingestion and schema validation
│   ├── feature_extraction.py    # Temporal, traffic, syscall, behavioral features
│   ├── mock_data_generator.py   # Synthetic Falco event generator
│   └── falco_dataset_collector.py # Live Falco scenario collector
├── ml_engine/                   # Machine Learning & Threat Intelligence
│   ├── pipeline.py              # Central runtime inference pipeline
│   ├── autoencoder.py           # PyTorch Anomaly Detection Autoencoder
│   └── mitre_attack_mapping.py  # MITRE ATT&CK Container Matrix mapping
├── response_engine/             # Automated Containment & API
│   ├── webhook_server.py        # Flask REST API for alerts and inference
│   └── network_policy_manager.py # Kubernetes NetworkPolicy orchestrator
├── dashboard/                   # SOC Dashboard Frontend
│   ├── index.html               # Main dashboard UI
│   ├── js/                      # api.js, app.js, charts.js, components.js
│   └── css/                     # Modern dark-mode responsive styling
├── datasets/                    # Falco Telemetry Datasets
│   └── falco/
│       ├── raw/                 # Raw NDJSON event files by scenario
│       └── processed/           # Feature-engineered training data
├── models/                      # Saved Model Weights & Metadata
│   └── autoencoder/
│       ├── model.pt             # Trained model weights
│       └── model_meta.json      # Threshold, feature names, training history
├── scripts/
│   └── train_model.py           # End-to-end model training script
├── tests/                       # Unit & Integration Test Suite
├── docs/
│   └── architecture.md          # System architecture documentation
├── requirements.txt             # Project dependencies
├── how_to_run.md                # Step-by-step execution guide
└── novelty_analysis.md          # Literature comparison & novelty analysis
```

---

## 14. Local Simulation

See [`how_to_run.md`](how_to_run.md) **Scenario A** for complete instructions.

```bash
# 1. Train the Autoencoder
python scripts/train_model.py --events 2000 --epochs 30

# 2. Start the API server (Terminal 1)
python response_engine/webhook_server.py --port 5000 --model-dir models/autoencoder

# 3. Serve the dashboard (Terminal 2)
npx -y serve dashboard -l 3333
```

---

## 15. Kubernetes Demonstration

See [`how_to_run.md`](how_to_run.md) **Scenario B** for complete instructions.

Requires Docker Desktop, Minikube, kubectl, and Helm. Deploys Falco as a DaemonSet and a vulnerable test application for real-time monitoring.

---

## 16. Testing

```bash
pytest tests/ -v
```

Tests cover: preprocessing, feature extraction, autoencoder forward pass, anomaly detection, MITRE mapping, webhook API, and NetworkPolicy generation.

---

## 17. Limitations

1. **Synthetic data dependency**: Training and evaluation currently rely on synthetic Falco events; results may differ with production telemetry.
2. **Single-node Kubernetes**: Demonstrated on Minikube (single-node); multi-node cluster behavior not validated.
3. **Threshold sensitivity**: The P95 threshold is derived from training data distribution; operational tuning may be required.
4. **Feature extraction paths**: Batch training uses windowed aggregate features; real-time inference uses per-event features. These are complementary but architecturally distinct.
5. **No authentication**: The dashboard and API do not implement authentication (out of scope for prototype).

---

## 18. Future Scope

1. Integrate with production Kubernetes clusters for real-world validation.
2. Implement online/incremental learning for threshold adaptation.
3. Add support for additional telemetry sources (e.g., network flow data).
4. Extend the MITRE mapping with confidence-weighted technique ranking.
5. Implement SOC operator feedback loop for false-positive reduction.

---

## 19. Academic References

1. **MITRE ATT&CK® Container Matrix** — https://attack.mitre.org/matrices/enterprise/containers/
2. **Falco Runtime Security** — https://falco.org/docs/
3. **An & Cho (2015)** — *Variational Autoencoder based Anomaly Detection using Reconstruction Probability*, SNU Data Mining Center.
4. **Hindy et al. (2020)** — *Utilising Deep Learning Techniques for Effective Zero-Day Attack Detection*, Electronics (MDPI).
5. **Kubernetes Network Policies** — https://kubernetes.io/docs/concepts/services-networking/network-policies/

---

## License

Developed for academic purposes at NMIT. All rights reserved.
