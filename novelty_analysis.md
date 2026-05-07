# Novelty Analysis: How Our Project Differs from Existing Literature

> **Project:** AIOps-Enabled Threat Intelligence for Real-Time Security of Containerized Applications  
> **Compared Against:** 30+ papers from `old papers/` and `papers new/` directories

---

## TL;DR — Our 6 Unique Contributions

| # | Novelty Claim | Why No Paper Does This |
|---|---------------|----------------------|
| **1** | **Hybrid ML Detection** (Autoencoder + Random Forest) for simultaneous zero-day AND known threat detection in containers | Papers use either supervised OR unsupervised — never both together in a single pipeline |
| **2** | **Bayesian Attack Prediction** using MITRE ATT&CK kill chain to predict the attacker's *next move* | No paper combines probabilistic prediction with container security |
| **3** | **Automated Kubernetes-native response** (dynamic NetworkPolicy + live pod migration) | Papers either detect only, or propose theoretical responses — none implement real K8s API calls |
| **4** | **End-to-end closed-loop system** from telemetry → ML → prediction → response → dashboard | Every paper covers only 1-2 stages; none implement the full loop |
| **5** | **Dual-source eBPF telemetry** fusion (Falco syscalls + KubeArmor eBPF) in a unified schema | Papers use single data sources; none aggregate from multiple runtime security tools |
| **6** | **Real-time SOC dashboard** with live threat visualization + MITRE ATT&CK mapping | Most papers are offline/batch; none provide an operational security dashboard |

---

## Paper-by-Paper Comparison

### OLD PAPERS

---

#### 1. Utilising Deep Learning Techniques for Effective Zero-Day Attack Detection
**Authors:** Hindy et al. (2020) — *Electronics, MDPI*

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **ML Technique** | Autoencoder for outlier detection | Autoencoder (zero-day) **+ Random Forest** (known threats) |
| **Dataset** | CICIDS2017, NSL-KDD (generic network) | DVWA + BOA (container-specific attack telemetry) |
| **Target Environment** | Generic network IDS | **Kubernetes containers** (Falco/KubeArmor syscalls) |
| **Attack Prediction** | ❌ None | ✅ Bayesian Network predicts next kill chain stage |
| **MITRE ATT&CK** | ❌ Not mapped | ✅ Full Container Matrix mapping (28 techniques) |
| **Automated Response** | ❌ Detection only | ✅ NetworkPolicy isolation + pod migration |
| **Dashboard** | ❌ None | ✅ Real-time SOC dashboard |

> **Key Gap:** This paper proves autoencoders work for zero-day detection (89–99% accuracy) but stops at detection. Our project extends this by adding classification, prediction, and automated response.

---

#### 2. ML-Based Threat Detection for Container Orchestration / Kubernetes
**Focus:** Survey/approach for ML-based container security

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Scope** | Conceptual framework / survey | **Working implementation** with full source code |
| **ML Models** | Discusses various approaches (clustering, isolation forest) | **Implements** Autoencoder + Random Forest + Bayesian Network |
| **Response** | Mentions automated response as a concept | **Implements** real K8s API calls (NetworkPolicy, pod eviction) |
| **Kill Chain** | Not addressed | ✅ Full MITRE ATT&CK kill chain modeling |

> **Key Gap:** Survey-level work that identifies the need but doesn't implement a complete system.

---

#### 3. DDoS Attack Detection using Machine Learning
**Focus:** ML classifiers for DDoS detection

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Attack Types** | DDoS only | DDoS, exfiltration, lateral movement, crypto mining, **+ zero-day** |
| **Environment** | Generic network | **Kubernetes containers** |
| **ML Approach** | Supervised classification (RF, SVM, etc.) | Supervised **+ unsupervised** (dual model) |
| **Response** | ❌ Detection only | ✅ Graduated response (log → audit → isolate → migrate) |
| **Prediction** | ❌ None | ✅ Bayesian prediction of next attack stage |

> **Key Gap:** Single attack type, single ML model, no container context, no response.

---

#### 4. AIOps in Cloud-native DevOps IT Operations Management
**Focus:** AIOps concepts and taxonomy

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Type** | Conceptual/survey paper | **Working system** |
| **Focus** | IT operations (performance, availability) | **Security-focused** AIOps (threat detection) |
| **Anomaly Detection** | Discussed conceptually | **Implemented** (autoencoder reconstruction error) |
| **Self-Healing** | Mentioned as a goal | **Implemented** (automated pod isolation + migration) |
| **Security Specific** | ❌ General IT ops | ✅ MITRE ATT&CK, threat classification, kill chain |

> **Key Gap:** This paper provides the AIOps vision; our project **implements it specifically for security** with ML models and Kubernetes-native remediation.

---

#### 5. ContainerLeaks: Emerging Security Threats of Information Leakages in Container Clouds
**Authors:** Gao et al. (2017) — *IEEE DSN*

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Focus** | Side-channel attacks via shared kernel (info leakage) | **Runtime behavioral** threat detection |
| **Defense** | Kernel-level namespace isolation (power namespace) | **Application-level** ML detection + K8s response |
| **ML Usage** | ❌ None — kernel modification approach | ✅ Autoencoder + Random Forest + Bayesian |
| **Real-time** | ❌ Research prototype | ✅ Continuous monitoring with live dashboard |

> **Key Gap:** Addresses container isolation weaknesses at the kernel level; our project detects and responds to runtime attacks at the orchestration level — complementary approaches.

---

#### 6. Comprehensive Survey on Security in Cloud Computing
**Focus:** Broad survey of cloud security challenges

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Scope** | Survey covering all cloud security (access, network, data) | **Focused implementation** on container runtime security |
| **Implementation** | ❌ Review only | ✅ Full working system |
| **Container Specific** | Brief mention | ✅ Deeply integrated with K8s APIs |

> **Key Gap:** Survey paper without implementation.

---

### NEW PAPERS

---

#### 7. Enhancing Intrusion Detection in Containerized Services: Assessing Machine Learning
**Focus:** Evaluating ML algorithms for container IDS

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **ML Models** | Compares multiple classifiers (supervised) | Uses supervised **+ unsupervised** together |
| **Zero-Day** | ❌ Supervised only (can't detect unknown attacks) | ✅ Autoencoder for zero-day + RF for known |
| **Response** | ❌ Detection only | ✅ Automated K8s response engine |
| **Attack Prediction** | ❌ None | ✅ Bayesian kill chain prediction |
| **MITRE ATT&CK** | ❌ Not used | ✅ Full Container Matrix integration |

> **Key Gap:** Evaluates which ML model is best for container IDS but doesn't build a complete system. No zero-day capability, no response, no prediction.

---

#### 8. IDERES: Intrusion Detection and Response System using ML and Attack Graphs
**Authors:** Rose et al. (2022) — *Journal of Systems Architecture*

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Target** | IoT networks | **Kubernetes containers** |
| **Attack Modeling** | Attack graphs (static) | **Bayesian Network** (probabilistic, dynamic) |
| **Response** | Computes mitigation actions (theoretical) | **Executes** real K8s API calls (NetworkPolicy, eviction) |
| **ML Approach** | Anomaly-based (single model) | **Dual model** (autoencoder + random forest) |
| **Framework** | ❌ Not MITRE ATT&CK | ✅ Full MITRE ATT&CK Container Matrix |
| **Container Support** | ❌ No | ✅ Yes — Falco/KubeArmor integration |

> **Key Gap:** Closest paper to our approach (detection + response + attack modeling), but targets IoT, uses static attack graphs instead of probabilistic Bayesian networks, and doesn't have container-native response mechanisms.

---

#### 9. BEACON: Automatic Container Policy Generation using Environment-aware Dynamic Analysis
**Focus:** Auto-generating security policies for containers

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Approach** | Static analysis → generate policies | **Runtime** ML-based threat detection → dynamic response |
| **When** | Pre-deployment (preventive) | **Runtime** (reactive + predictive) |
| **ML Usage** | ❌ Rule-based analysis | ✅ ML models for detection + Bayesian for prediction |
| **Response** | Generates policies pre-deployment | **Creates policies dynamically** at runtime in response to attacks |

> **Key Gap:** BEACON is preventive (pre-deployment policy generation); our project is reactive + predictive (runtime detection and response). They're complementary — BEACON prevents known issues, we detect novel attacks at runtime.

---

#### 10. ADA: Automated Moving Target Defense for AI Workloads via Ephemeral Infrastructure-Native Rotation in Kubernetes
**Authors:** Sheriff et al. (2025) — *arXiv*

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Approach** | Moving Target Defense (continuous rotation of pods) | **Detect-then-respond** (isolate/migrate compromised pods) |
| **Strategy** | Proactive (rotate before attack) | **Reactive + Predictive** (detect attack, predict next move, respond) |
| **ML Usage** | ❌ No ML — infrastructure rotation | ✅ Autoencoder + RF + Bayesian Network |
| **MITRE ATT&CK** | References kill chain disruption conceptually | ✅ **Implements** full kill chain prediction with Bayesian CPDs |
| **Threat Detection** | ❌ No detection — assumes attacks will come | ✅ Detects both known and zero-day attacks |

> **Key Gap:** ADA prevents attacks by constantly rotating infrastructure (making targets ephemeral), but has no detection or classification capability. Our project detects, classifies, predicts, and responds to specific threats.

---

#### 11. A Secure and Lightweight Container Migration Technique in Cloud Computing
**Focus:** Secure container live migration with encryption

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Migration Purpose** | Load balancing, fault tolerance | **Security response** — migrate away from compromised nodes |
| **Trigger** | Manual or performance-based | **Automated** — triggered by ML threat detection |
| **ML Integration** | ❌ None | ✅ Migration triggered by Bayesian threat assessment |
| **Security Context** | Migration itself is secured (encryption) | Migration is a **security response action** |

> **Key Gap:** Focuses on making migration secure; our project uses migration as a security response mechanism, automatically triggered by ML-detected threats.

---

#### 12. Quick Service During DDoS Attacks in Container-Based Cloud Environment
**Authors:** Kumar & Agarwal (2024) — *JNCA*

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Focus** | Maintaining service availability during DDoS | **Detecting and responding** to multiple attack types |
| **Approach** | Traffic categorization + resource allocation (queueing theory) | **ML-based** detection + automated K8s response |
| **Attack Types** | DDoS only | DDoS + exfiltration + lateral movement + crypto mining + zero-day |
| **ML Usage** | ❌ Mathematical/queueing model | ✅ Autoencoder + RF + Bayesian |
| **Prediction** | ❌ No | ✅ Predicts next attack stage |

> **Key Gap:** Addresses service resilience during DDoS, but only for DDoS and without ML. Our project handles multiple attack types and uses ML for detection.

---

#### 13. Securing Kubernetes: AI-Powered Container Security
**Focus:** AI/ML for Kubernetes security (survey-type)

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Type** | Conceptual/survey | **Working implementation** |
| **Implementation** | ❌ Conceptual | ✅ Full pipeline with code |
| **Novelty** | Discusses the idea of AI for K8s security | **Demonstrates** it end-to-end |

> **Key Gap:** Conceptual paper; our project is the implementation.

---

#### 14. Facing DDoS Bandwidth Flooding Attacks
**Focus:** DDoS mitigation strategies

| Aspect | This Paper | Our Project |
|--------|-----------|-------------|
| **Scope** | DDoS-specific network defense | Multi-threat container security |
| **Environment** | General network | **Kubernetes containers** |
| **Response** | Network-level filtering | **Orchestration-level** (pod isolation, migration) |

---

#### 15. Other Supporting Papers (Container Migration, Load Balancing, QoS, Multi-Cloud)

These papers address adjacent concerns:
- **Fast state transfer for live migration** — Performance optimization for migration (not security-triggered)
- **Task scheduling and load balancing in SDN** — Performance, not security
- **Detection of QoS degradation in containers** — Performance monitoring, not threat detection
- **Containerization in multi-cloud** — Deployment patterns, not security
- **Containers for energy-efficient cloud computing** — Efficiency, not security
- **High performance cloud computing & load balancing** — Performance, not security
- **Parallel path selection for DDoS** — DDoS-specific, no ML, no containers
- **Managing security issues in software containers** — Survey of container security issues
- **On cloud security attacks intrusion detection** — General cloud IDS survey
- **Allocating distributed AI/ML applications** — ML deployment, not security

> **Key Gap across ALL supporting papers:** None addresses the specific intersection of ML-based threat detection + automated Kubernetes-native response + attack chain prediction in a unified system.

---

## Feature Comparison Matrix

The following matrix shows which capabilities each category of paper provides vs. our project:

| Capability | Zero-Day Papers | DDoS Papers | Container Security Papers | AIOps Papers | IDS+Response Papers | **Our Project** |
|:-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| Zero-day detection (unsupervised) | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Known threat classification | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| **Both combined** | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Attack chain prediction | ❌ | ❌ | ❌ | ❌ | Partial (static graphs) | **✅ Bayesian** |
| MITRE ATT&CK mapping | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Container/K8s specific | ❌ | ❌ | ✅ | Partial | ❌ (IoT) | **✅** |
| Automated response | ❌ | ❌ | ❌ | Mentioned | Partial | **✅ K8s API** |
| Pod isolation (NetworkPolicy) | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Live pod migration | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Multi-source telemetry fusion | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Real-time dashboard | ❌ | ❌ | ❌ | Mentioned | ❌ | **✅** |
| Graduated response (LOW→CRITICAL) | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| Working implementation | ✅ | ✅ | Varies | ❌ | ✅ | **✅** |

---

## Detailed Novelty Arguments (For Viva/Thesis)

### Novelty 1: Hybrid ML Detection Architecture
> *"Existing works use either supervised classifiers for known attack detection (Random Forest, SVM) [Papers 3, 7, 8] or unsupervised methods for zero-day detection (Autoencoders) [Paper 1]. Our system is the first to combine both in a dual-model architecture within a container security context — the Autoencoder catches novel attacks while the Random Forest classifies known threat types, providing comprehensive coverage."*

### Novelty 2: Bayesian Attack Prediction with MITRE ATT&CK
> *"While IDERES [Paper 8] uses attack graphs for threat modeling, these are static, pre-computed graphs that cannot adapt to live attack progression. Our Bayesian Network models the MITRE ATT&CK Container Matrix as a probabilistic DAG, enabling real-time inference of the attacker's most likely next move given observed evidence. This predictive capability enables proactive defense — we can prepare countermeasures for predicted attack stages before they occur."*

### Novelty 3: Kubernetes-Native Automated Response
> *"Papers like ADA [Paper 10] and BEACON [Paper 9] interact with Kubernetes at the infrastructure level, but neither detects attacks nor generates responses to detected threats at runtime. Our response engine uses the Kubernetes Python API to dynamically create NetworkPolicies for pod isolation and execute graceful pod migration via the Eviction API, respecting PodDisruptionBudgets — a production-grade response mechanism that no reviewed paper implements."*

### Novelty 4: End-to-End Closed-Loop Architecture
> *"The literature treats detection, prediction, and response as isolated research problems. Our system implements a complete closed loop: Falco/KubeArmor telemetry → log aggregation → preprocessing → ML detection → MITRE mapping → Bayesian prediction → automated response → SOC dashboard. This mirrors real-world SOC workflows and demonstrates the practical viability of a fully automated threat intelligence pipeline."*

### Novelty 5: Dual-Source eBPF Telemetry Fusion
> *"No reviewed paper aggregates telemetry from multiple runtime security tools. Our log aggregator normalizes events from both Falco (syscall monitoring) and KubeArmor (eBPF-based policy enforcement) into a unified JSON schema, enabling the ML pipeline to leverage complementary data sources for improved detection accuracy."*

### Novelty 6: Graduated Response Protocol
> *"Our response engine implements a risk-graduated response protocol: LOW → log only, MEDIUM → audit monitoring, HIGH → NetworkPolicy isolation, CRITICAL → full isolation + node cordon + pod migration. This graduated approach addresses the false positive problem that plagues automated security systems — we don't disrupt service for low-confidence alerts."*

---

## How to Present This in Your Thesis/Viva

### One-Liner Summary
> *"While existing literature addresses container security detection, attack prediction, and automated response as separate research problems, our project is the first to integrate all three into a single, working, Kubernetes-native pipeline using a hybrid ML architecture (Autoencoder + Random Forest + Bayesian Network) with MITRE ATT&CK mapping and a real-time SOC dashboard."*

### When Asked "What's New?"

1. **"No paper combines detection + prediction + response"** → Show the feature matrix above
2. **"The Bayesian + MITRE ATT&CK integration is novel"** → No container security paper uses Bayesian Networks for kill chain prediction
3. **"We implemented real Kubernetes API responses"** → Other papers propose responses theoretically; we call `create_namespaced_network_policy()` and `create_namespaced_pod_eviction()` via the actual K8s Python client
4. **"Dual-model ML is unique in this domain"** → Autoencoder for zero-day + Random Forest for known threats, working together

### When Asked "How is this different from [specific paper]?"

Use the per-paper comparison tables above to point out the specific gaps.
