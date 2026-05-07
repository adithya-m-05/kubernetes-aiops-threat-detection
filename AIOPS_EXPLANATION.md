# AIOps Integration in the Threat Intelligence Pipeline

**Artificial Intelligence for IT Operations (AIOps)** is not just a feature of this project—it is the foundational architecture of the entire system. This project is a textbook implementation of a specialized branch of AIOps known as **Security AIOps (SecOps AIOps)**.

Gartner defines AIOps as the combination of big data and machine learning to automate IT operations processes, including event correlation, anomaly detection, and causality determination. 

An AIOps platform consistently consists of three core phases: **Observe (Telemetry) → Analyze (Machine Learning) → Act (Automation)**. 

This project maps perfectly to this exact closed-loop AIOps architecture:

---

## 1. The "Observe" Phase (Data Aggregation)
AIOps requires massive amounts of telemetry from different sources to understand the system state.

* **How our project does it:** The `log_aggregator.py` (Agent 1) constantly ingests real-time telemetry from multiple discrete security tools (**Falco** for syscalls and **KubeArmor** for eBPF events). It normalizes this messy, heterogeneous data into a single, structured JSON stream.
* **The AIOps Concept:** This represents the "Big Data" ingestion layer of AIOps. We aren't just looking at a single log file; we are fusing multiple data streams to get a holistic view of the Kubernetes cluster's health and security posture.

## 2. The "Analyze" Phase (Machine Learning & AI)
Traditional IT Operations rely on humans writing static rules (e.g., "Alert me if CPU > 90%"). AIOps replaces these static rules with AI models that can find complex patterns and anomalies dynamically.

* **How our project does it:** The `ml_engine` (Agent 3) utilizes three distinct AI techniques:
    1. **Autoencoder:** An unsupervised deep learning model that learns what "normal" container traffic looks like and flags deviations as anomalies (providing Zero-day detection).
    2. **Random Forest Classifier:** A supervised machine learning model that categorizes the anomaly into known threat types (e.g., DDoS, Crypto-mining, Data Exfiltration).
    3. **Bayesian Network Predictor:** A probabilistic AI model that analyzes the current attack stage (mapped via the MITRE ATT&CK matrix) and predicts what the attacker's most likely next move will be.
* **The AIOps Concept:** This represents the "Intelligence" component of AIOps. The system performs the analytical work of a human Security Operations Center (SOC) analyst—correlating events, identifying the threat, and predicting future risk.

## 3. The "Act" Phase (Automated Remediation / Self-Healing)
The ultimate goal of true AIOps is "closed-loop automation," where the system not only detects a problem but remediates it without human intervention.

* **How our project does it:** The `response_engine` (Agent 4) receives the threat assessment from the ML engine and takes immediate action based on the calculated risk level. It dynamically generates Kubernetes `NetworkPolicy` objects to isolate the compromised pod, and utilizes the `PodMigrationManager` to safely drain and reschedule workloads away from the infected node.
* **The AIOps Concept:** This represents "Self-Healing Infrastructure." Instead of alerting a human operator at 3 AM to manually quarantine a server, the AIOps system detects the anomaly, classifies the threat, and automatically quarantines the container in milliseconds, preventing the attack from spreading.

---

## Summary for Presentation/Viva

> *"Our project is a pure AIOps implementation focused specifically on cybersecurity. Traditional security relies on human analysts reading logs and writing static firewall rules. We built a closed-loop AIOps system that **Observes** the Kubernetes cluster using eBPF telemetry, **Analyzes** that data using a hybrid ML architecture to detect zero-day and known threats, and then automatically **Acts** by modifying the infrastructure state to quarantine compromised pods—all in real-time, without human intervention."*
