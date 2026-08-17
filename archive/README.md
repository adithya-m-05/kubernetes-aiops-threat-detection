# Archived Components

This directory contains components that were part of the original project scope but have been moved out of the core pipeline to maintain focus.

These modules were **working implementations** but are not part of the final system's core scope.

## Contents

| File/Directory | Original Location | Reason for Archiving |
|---|---|---|
| `bayesian_attack_predictor.py` | `ml_engine/` | Attack chain prediction via Bayesian Networks (pgmpy). Removed to focus on detection rather than prediction. |
| `pod_migration.py` | `response_engine/` | Kubernetes node cordon/drain/pod migration. Too complex for FYP scope — NetworkPolicy isolation is sufficient. |
| `k8s_kubearmor/` | `infrastructure/k8s/kubearmor/` | eBPF-based KubeArmor security policies. Removed to focus on single telemetry source (Falco). |
| `trained_models/` | `ml_engine/` | Pre-trained DVWA autoencoder and RF models. Feature space (231-dim) doesn't match new Falco pipeline. |

## Can These Be Restored?

Yes. These components were designed to be modular:
- **Bayesian predictor**: Can be re-added by importing it in `pipeline.py` and calling `predict_next_stage()` after MITRE mapping.
- **Pod migration**: Can be re-added by importing it in `webhook_server.py` and adding `migrate_pods` to the `CRITICAL` response actions.
- **KubeArmor**: The log aggregator still has a `parse_kubearmor_event()` function that can be uncommented.
