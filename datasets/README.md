# Datasets Documentation

This directory defines the dataset architecture for the Kubernetes Runtime Threat Detection project.

## Dataset Strategy

The project utilizes a two-tier dataset strategy:

1. **Primary Runtime Telemetry Dataset (`datasets/falco/`)**:
   - Falco runtime security events captured from Kubernetes container workloads.
   - Scenarios include:
     - `raw/normal/`: Baseline benign container operational syscalls.
     - `raw/shell_execution/`: Terminal spawning / interactive shell execution inside containers (`kubectl exec`, `sh`, `bash`).
     - `raw/credential_access/`: Sensitive file and token reads (`/etc/shadow`, serviceaccount tokens).
     - `raw/network_scanning/`: Network scanning and port discovery (`nmap`, `nc`).
     - `raw/suspicious_network/`: Unexpected outbound connections, exfiltration, or cryptomining stratum protocols.
   - `processed/`: Formatted, cleaned, and feature-engineered CSV files ready for Autoencoder training and validation.

2. **Offline Reference / Benchmark Datasets**:
   - `dvwa_dataset/`: Web application exploit telemetry (DVWA) for baseline comparison.
   - `boa_dataset/`: Network flow traffic benchmarks (BoA).
   - *Note*: Large raw PCAP / external archives remain gitignored and are used for offline benchmarking.

## Data Pipeline Flow

```
Falco JSON Stream (Live or Mock)
       │
       ▼
data_pipeline/preprocessing.py (Clean & Schema Validation)
       │
       ▼
data_pipeline/feature_extraction.py (Temporal, Traffic, Syscall, Behavioral features)
       │
       ▼
models/autoencoder/ (Trained PyTorch Anomaly Detector)
```
