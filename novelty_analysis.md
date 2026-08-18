# Novelty Analysis & Literature Comparison

> **Project Title:** AIOps-Enabled Threat Intelligence for Real-Time Security of Containerized Applications  
> **Institution:** NMIT — Department of Information Science and Engineering

---

## 1. Core Contributions

Existing research predominantly treats container security either as **static image vulnerability scanning** (pre-deployment), **rule-based signature matching** (runtime without ML-based anomaly detection), or **theoretical intrusion detection** without automated Kubernetes-native remediation.

This project introduces a **closed-loop runtime threat detection and containment framework** centered around three contributions:

| # | Contribution | Role in Project |
|---|---|---|
| **1 (Primary)** | **Unsupervised Runtime Anomaly Detection** | An undercomplete Autoencoder trained on benign Falco runtime telemetry detects anomalous container behavior via reconstruction error — enabling detection of previously unseen anomalous patterns without requiring labeled attack data. |
| **2 (Secondary)** | **Automated Kubernetes NetworkPolicy Containment** | Dynamically applies deny-all NetworkPolicy objects to isolate compromised pods at runtime while keeping them running, preserving the opportunity for later investigation. |
| **3 (Supporting)** | **Deterministic MITRE ATT&CK Mapping** | Maps detected anomalies to the MITRE ATT&CK Container Matrix techniques for explainable threat characterization, bridging the gap between raw anomaly scores and actionable security context. |

---

## 2. Comparative Analysis Against Existing Literature

### A. Deep Learning Anomaly Detection for Security
* **Hindy et al. (2020) — *Utilising Deep Learning Techniques for Effective Zero-Day Attack Detection***
  * *Their Approach:* Autoencoders on generic network datasets (CICIDS2017, NSL-KDD).
  * *Our Differentiation:* We apply Autoencoder anomaly detection specifically to **containerized Kubernetes runtime telemetry** (Falco system calls and process executions) rather than generic network flows. Furthermore, our system integrates automated containment and MITRE mapping into a closed-loop pipeline.

### B. Machine Learning in Container Environments
* **Recent Surveys on Container IDS (e.g., Assessing ML for Containerized Services)**
  * *Their Approach:* Benchmark supervised classifiers (Random Forest, SVM, Decision Trees) on static datasets.
  * *Our Differentiation:* Supervised models require labeled training datasets and cannot generalize to previously unseen attack patterns. Our core detection is **unsupervised** (reconstruction loss on benign baseline behavior), enabling detection of anomalous runtime behaviors without requiring comprehensive attack-labeled training data.

### C. Intrusion Detection & Response Systems (IDRS)
* **Rose et al. (2022) — *IDERES: Intrusion Detection and Response System***
  * *Their Approach:* Evaluates theoretical responses on IoT networks using static attack graphs.
  * *Our Differentiation:* We target **cloud-native Kubernetes environments** with a live, executable response engine that programmatically creates native `networking.k8s.io/v1` NetworkPolicy objects via the official Kubernetes Python API.

### D. Pre-deployment Policy Generation
* **BEACON / ADA (2024–2025) — *Automated Container Policies and Ephemeral Rotation***
  * *Their Approach:* Focus on static analysis or continuous pod rotation regardless of whether an attack has occurred.
  * *Our Differentiation:* We focus on **dynamic, event-driven runtime detection and targeted containment**. Rather than incurring continuous rotation overhead, our system acts proportionally when anomalous behavior is actually detected.

---

## 3. Feature Comparison Matrix

| Capability | Static Image Scanners (Trivy/Clair) | Standard Falco (Rule-based) | Academic ML IDS Papers | **This Project** |
|---|:---:|:---:|:---:|:---:|
| Unsupervised Anomaly Detection | ❌ | ❌ | ✅ | **✅** |
| Runtime Container Syscall Telemetry | ❌ | ✅ | Partial | **✅** |
| Multi-Category Feature Engineering | ❌ | ❌ | Partial | **✅** |
| MITRE ATT&CK Explainability | ❌ | Partial (Tags) | ❌ | **✅** |
| Automated Pod Containment (NetworkPolicy) | ❌ | ❌ | ❌ (Theoretical) | **✅ (Kubernetes API)** |
| Non-Destructive Pod Isolation | ❌ | ❌ | ❌ | **✅** |
| Real-Time SOC Operator Dashboard | ❌ | ❌ | ❌ | **✅** |
| End-to-End Closed-Loop Pipeline | ❌ | ❌ | ❌ | **✅** |

---

## 4. Key Defense Arguments for Thesis & Viva

1. **Why Autoencoder over Supervised Classifiers as Primary Model?**
   > *"Supervised learning requires large, representative datasets of every conceivable attack type. In runtime container security, novel privilege escalations and container vulnerabilities cannot be fully anticipated in training labels. An Autoencoder trained strictly on benign baseline workloads detects any behavior that deviates significantly from the learned normal manifold (MSE > threshold), enabling detection of previously unseen anomalous patterns."*

2. **Why NetworkPolicy Isolation instead of Pod Termination (`kubectl delete pod`)?**
   > *"Terminating a compromised container immediately destroys volatile runtime state (memory, open sockets, temporary files, process trees). By applying a deny-all NetworkPolicy at runtime, we sever all external and lateral network connectivity (halting exfiltration or command-and-control) while keeping the container running. This preserves the opportunity for later investigation and analysis."*

3. **How is Explainability Maintained?**
   > *"Raw anomaly scores (e.g., 0.084 MSE) are non-intuitive for security operators. Our pipeline links anomaly triggers with Falco event categories and deterministically maps them to MITRE ATT&CK Container Matrix techniques (such as T1611 for container escape or T1609 for shell executions), providing clear, standardized context on the SOC dashboard."*

4. **What is the system's detection scope?**
   > *"The unsupervised Autoencoder is designed to detect previously unseen anomalous runtime behaviors that may correspond to unknown or novel attack techniques. It achieves this by learning a model of normal behavior and flagging significant deviations. The effectiveness depends on the quality and representativeness of the benign training data and the chosen anomaly threshold."*
