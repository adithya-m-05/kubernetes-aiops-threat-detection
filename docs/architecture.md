# System Architecture — AIOps Threat Intelligence

## Data Flow Architecture

```mermaid
graph TD
    subgraph Kubernetes Cluster
        VA[Vulnerable App Testbed] -->|syscalls| F[Falco DaemonSet]
        VA -->|eBPF probes| KA[KubeArmor]
    end

    F -->|JSON alerts| LA[Log Aggregator]
    KA -->|JSON events| LA
    LA -->|Unified NDJSON| PP[Preprocessing Pipeline]

    PP -->|Clean DataFrame| FE[Feature Extraction]
    FE -->|Feature Matrix| DB[Data Balancing]
    DB -->|Normalized + PCA + SMOTE| ML{ML Engine}

    ML -->|Reconstruction Error| AE[Autoencoder - Zero-Day]
    ML -->|Classification| RF[Random Forest - Known Attacks]
    AE -->|Anomaly Score| BA[Bayesian Predictor]
    RF -->|Threat Label| BA
    BA -->|MITRE ATT&CK Mapping| WH[Webhook API]

    WH -->|High Confidence Alert| RE{Response Engine}
    RE -->|Isolate| NP[NetworkPolicy Manager]
    RE -->|Migrate| PM[Pod Migration Manager]
    NP -->|Apply Policy| KC[Kubernetes API]
    PM -->|Cordon + Drain| KC
    KC -->|Remediate| VA
```

## Component Interaction Matrix

| Producer → Consumer | Data Format | Protocol |
|---|---|---|
| Falco → Log Aggregator | NDJSON | stdout/file |
| KubeArmor → Log Aggregator | JSON | relay API |
| Log Aggregator → Preprocessing | NDJSON file | filesystem |
| Preprocessing → Feature Extraction | pandas DataFrame | in-memory |
| Feature Extraction → Data Balancing | pandas DataFrame | in-memory |
| Data Balancing → Autoencoder | numpy array | in-memory |
| Data Balancing → Random Forest | numpy array | in-memory |
| ML Engine → Webhook | JSON alert | HTTP POST |
| Webhook → NetworkPolicy Manager | function call | in-process |
| Webhook → Pod Migration Manager | function call | in-process |
| Response Engine → Kubernetes | API objects | K8s REST API |

## ML Pipeline Architecture

```mermaid
graph LR
    subgraph Feature Engineering
        T[Temporal] --> FM[Feature Matrix]
        TR[Traffic] --> FM
        SC[Syscall N-grams] --> FM
        BH[Behavioral] --> FM
    end

    subgraph Preprocessing
        FM --> N[Normalization]
        N --> PCA[PCA Reduction]
        PCA --> SM[SMOTE Balance]
    end

    subgraph Dual Detection
        SM --> AE[Autoencoder]
        SM --> RF[Random Forest]
        AE -->|Anomaly Score| D{Decision}
        RF -->|Attack Label| D
    end

    subgraph Threat Intel
        D --> MITRE[MITRE ATT&CK Map]
        MITRE --> BN[Bayesian Network]
        BN -->|Next Attack Prediction| ALERT[Alert]
    end
```

## MITRE ATT&CK Kill Chain Mapping

```mermaid
graph LR
    IA[Initial Access] --> EX[Execution]
    EX --> PE[Persistence]
    EX --> PR[Privilege Escalation]
    EX --> DI[Discovery]
    PR --> DE[Defense Evasion]
    DI --> CA[Credential Access]
    DI --> LM[Lateral Movement]
    CA --> LM
    LM --> IM[Impact]

    style IA fill:#e74c3c,color:#fff
    style EX fill:#e67e22,color:#fff
    style PE fill:#f39c12,color:#fff
    style PR fill:#f1c40f,color:#000
    style DE fill:#2ecc71,color:#fff
    style CA fill:#1abc9c,color:#fff
    style DI fill:#3498db,color:#fff
    style LM fill:#9b59b6,color:#fff
    style IM fill:#c0392b,color:#fff
```

## Response Engine Decision Matrix

| Risk Level | Confidence | Actions |
|---|---|---|
| CRITICAL | ≥0.95 | Isolate pod + Cordon node + Migrate pods |
| HIGH | ≥0.85 | Isolate pod (NetworkPolicy deny-all) |
| MEDIUM | ≥0.70 | Apply audit policy + enhance monitoring |
| LOW | <0.70 | Log alert only |
