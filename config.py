"""
=============================================================================
Configuration — AIOps-Enabled Threat Intelligence System
=============================================================================
Module: config.py

Purpose:
    Provides centralized configuration management with environment variable
    overrides for all components: data pipeline, ML engine, response engine,
    and dashboard integration.
=============================================================================
"""

import os
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent
DATASETS_DIR = PROJECT_ROOT / "datasets"
MODELS_DIR = PROJECT_ROOT / "models"
AUTOENCODER_MODEL_DIR = MODELS_DIR / "autoencoder"

# Kubernetes / Infrastructure Configuration
KUBERNETES_NAMESPACE = os.environ.get("KUBERNETES_NAMESPACE", "aiops-security")
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() in ("true", "1", "yes")

# ML Engine & Anomaly Detection Parameters
MODEL_PATH = os.environ.get("MODEL_PATH", str(AUTOENCODER_MODEL_DIR))
ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "0.0"))  # 0.0 = use saved threshold
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.85"))

# API & Webhook Server Configuration
API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", "5000"))
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "3333"))

# Logging Configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
