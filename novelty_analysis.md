# Novelty Analysis & Literature Comparison

> **Project Title:** AI-Based Runtime Threat Detection and Automated Response for Kubernetes Containers  
> **Institution:** NMIT — Department of Information Science and Engineering

---

## 1. Executive Summary & Core Novelties

Existing research predominantly treats container security either as **static image vulnerability scanning** (pre-deployment), **rule-based signature matching** (runtime without anomaly detection), or **theoretical intrusion detection** without automated Kubernetes-native remediation.

This project introduces a **closed-loop runtime threat detection and containment framework** that directly addresses the limitations of existing approaches:

| # | Core Contribution | Existing Literature Limitation | How This Project Solves It |
|---|---|---|---|
| **1** | **Unsupervised Runtime Anomaly Detection (Autoencoder)** | Supervised IDS models fail against zero-day exploits and require labeled attack data. | Trains an undercomplete Autoencoder on normal container syscall behaviors; detects anomalies and novel attacks via MSE reconstruction error. |
| **2** | **Multi-Category Telemetry Feature Engineering** | Most models use single-dimensional metrics (e.g., netflow only or packet size only). | Aggregates Falco syscall telemetry into windowed temporal, traffic, syscall distribution, and behavioral metrics. |
| **3** | **Deterministic MITRE ATT&CK Container Mapping** | ML anomaly scores lack explainability for security operators. | Maps detected anomalies deterministically to the MITRE ATT&CK Container Matrix techniques (e.g., T1611 Escape to Host, T1609 Container Admin Execution). |
| **4** | **Non-Destructive Kubernetes Containment (NetworkPolicy Quarantine)** | Traditional automated responses kill/delete compromised pods, destroying memory and volatile forensic evidence. | Dynamically applies Kubernetes `NetworkPolicy` objects (deny-all ingress/egress) to isolate compromised pods while preserving their runtime state for digital forensics. |
| **5** | **Closed-Loop End-to-End Architecture** | Literature presents disconnected research prototypes (e.g., detection-only papers with no response mechanism). | Implements a continuous closed loop: Falco Ingestion → Feature Extraction → Autoencoder Inference → MITRE Mapping → NetworkPolicy Isolation → SOC Dashboard. |

---

## 2. Comparative Analysis Against Existing Literature

### A. Zero-Day & Deep Learning Anomaly Detection
* **Hindy et al. (2020) — *Utilising Deep Learning Techniques for Effective Zero-Day Attack Detection***
  * *Their Approach:* Autoencoders on generic network datasets (CICIDS2017, NSL-KDD).
  * *Our Differentiation:* We apply Autoencoder anomaly detection specifically to **containerized Kubernetes runtime telemetry** (Falco system calls and process executions) rather than generic network flows. Furthermore, our system integrates automated mitigation and MITRE mapping.

### B. Machine Learning in Container Environments
* **Recent Surveys on Container IDS (e.g., Assessing ML for Containerized Services)**
  * *Their Approach:* Benchmark supervised classifiers (Random Forest, SVM, Decision Trees) on static datasets.
  * *Our Differentiation:* Supervised models require labeled training datasets and fail on unseen zero-day attacks. Our core detection is **unsupervised** (reconstruction loss on benign baseline behavior), allowing detection of novel privilege escalations and container escapes.

### C. Intrusion Detection & Response Systems (IDRS)
* **Rose et al. (2022) — *IDERES: Intrusion Detection and Response System***
  * *Their Approach:* Evaluates theoretical responses on IoT networks using static attack graphs.
  * *Our Differentiation:* We target **cloud-native Kubernetes environments** with a live, executable response engine that programmatically creates native `networking.k8s.io/v1` NetworkPolicy objects via the official Kubernetes Python API.

### D. Moving Target Defense & Pre-deployment Policy Generation
* **BEACON / ADA (2024–2025) — *Automated Container Policies and Ephemeral Rotation***
  * *Their Approach:* Focus on static analysis or continuous pod rotation regardless of whether an attack has occurred.
  * *Our Differentiation:* We focus on **dynamic, event-driven runtime detection and targeted containment**. Rather than incurring continuous rotation overhead, our system acts proportionally when anomalous behavior is detected.

---

## 3. Feature Comparison Matrix

| Capability | Static Image Scanners (Trivy/Clair) | Standard Falco (Rule-based) | Academic ML IDS Papers | **This Project** |
|---|:---:|:---:|:---:|:---:|
| Zero-day / Novel Anomaly Detection | ❌ | ❌ | ✅ | **✅** |
| Runtime Container Syscall Telemetry | ❌ | ✅ | Partial | **✅** |
| Multi-Category Feature Engineering | ❌ | ❌ | Partial | **✅** |
| MITRE ATT&CK Explainability | ❌ | Partial (Tags) | ❌ | **✅** |
| Automated Pod Containment (NetworkPolicy) | ❌ | ❌ | ❌ (Theoretical) | **✅ (Kubernetes API)** |
| Non-Destructive Forensic State Preservation | ❌ | ❌ | ❌ | **✅** |
| Real-Time SOC Operator Dashboard | ❌ | ❌ | ❌ | **✅** |
| End-to-End Closed-Loop Pipeline | ❌ | ❌ | ❌ | **✅** |

---

## 4. Key Defense Arguments for Thesis & Viva

1. **Why Autoencoder over Supervised Classifiers as Primary Model?**
   > *"Supervised learning requires large, representative datasets of every conceivable attack type. In runtime container security, novel container escapes and zero-day vulnerabilities cannot be anticipated in training labels. An Autoencoder trained strictly on benign baseline workloads detects any anomalous behavior exceeding the reconstruction threshold ($MSE > \text{threshold}$), making it resilient to zero-day techniques."*

2. **Why NetworkPolicy Isolation instead of Pod Termination (`kubectl delete pod`)?**
   > *"Deleting a compromised container immediately destroys volatile memory (RAM), open socket handles, temporary file artifacts, and process trees required for Incident Response (IR) and forensic investigation. By injecting a deny-all NetworkPolicy at runtime, we sever all external and lateral network connectivity (halting exfiltration or command-and-control) while keeping the container intact for forensic dump and post-mortem analysis."*

3. **How is Explainability Maintained?**
   > *"Raw anomaly scores (e.g., $0.084$ MSE) are non-intuitive for security operators. Our pipeline links anomaly triggers with Falco event categories and deterministically maps them to MITRE ATT&CK Container Matrix techniques (such as T1611 for container escape or T1609 for shell executions), providing clear context on the SOC dashboard."*
