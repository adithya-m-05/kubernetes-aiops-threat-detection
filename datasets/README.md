# Datasets Documentation

> **AIOps-Enabled Threat Intelligence for Real-Time Security of Containerized Applications**

## Primary Dataset: Falco Runtime Telemetry

The project uses **Falco runtime telemetry** as its sole primary data source. All ML training
and inference operates on events matching the unified Falco JSON schema.

### Directory Structure

```
datasets/
└── falco/
    ├── raw/                   # Raw NDJSON event files by scenario
    │   ├── normal/            # Baseline benign container operations
    │   ├── shell_execution/   # Interactive shell spawning (kubectl exec, bash)
    │   ├── credential_access/ # Sensitive file reads (/etc/shadow, tokens)
    │   └── network_scanning/  # Port scanning and network discovery (nmap)
    └── processed/             # Feature-engineered CSV files for training
```

### What Constitutes Normal Data

Normal (benign) telemetry consists of routine container operations:
- Standard process execution (`nginx`, `python`, `node`, `redis-server`)
- File I/O operations using benign syscalls (`read`, `write`, `close`, `fstat`)
- Internal network connections to expected ports (80, 443, 8080, 6379)
- Low severity events within the `aiops-security` namespace

### What Constitutes Anomalous/Attack Data

Anomalous telemetry represents simulated attack behaviors:
- **Shell execution**: Interactive shell access (`/bin/bash`, `sh`) via `kubectl exec`
- **Credential access**: Reading sensitive files (`/etc/shadow`, service account tokens)
- **Network scanning**: Port scanning and network discovery (`nmap`, `nc`)
- **Container escape**: Namespace manipulation (`setns`, `unshare`, `mount`)
- **Crypto mining**: Mining processes (`xmrig`, `minerd`) connecting to mining pools

### Data Flow

```
Falco JSON Stream (Live or Mock)
       │
       ▼
data_pipeline/preprocessing.py     → Clean & validate schema
       │
       ▼
data_pipeline/feature_extraction.py → Temporal, traffic, syscall, behavioral features
       │
       ▼
ml_engine/autoencoder.py           → Trained on benign features, detects anomalies
```

### Training vs. Testing

- **Training**: Autoencoder is trained on **benign-only** feature vectors (normal runtime behavior).
- **Threshold calibration**: The 95th percentile of reconstruction errors on benign validation data sets the anomaly threshold.
- **Testing/evaluation**: Both benign and attack events are processed; anomalies are flagged when reconstruction error exceeds the threshold.

### Generating Synthetic Data

For local development and testing without a Kubernetes cluster:

```bash
# Generate 3000 synthetic Falco events (80% benign, 20% attack)
python data_pipeline/mock_data_generator.py --output datasets/falco/raw/mock_telemetry.jsonl --events 3000
```

### Collecting Live Falco Data

When running with a Kubernetes cluster and Falco:

```bash
# Collect 500 normal baseline events
python data_pipeline/falco_dataset_collector.py --scenario normal --count 500

# Collect attack scenario events from live Falco stream
kubectl logs -l app.kubernetes.io/name=falco -n aiops-security --follow | \
    python data_pipeline/falco_dataset_collector.py --scenario shell_execution --stdin
```
