"""
=============================================================================
Preprocessing Module — JSON Telemetry Ingestion and Cleaning
=============================================================================
Module: data_pipeline/preprocessing.py
Agent:  Agent 2 — "The Cleaner"

Purpose:
    Ingests the unified JSON telemetry logs produced by Agent 1's
    log_aggregator.py and transforms them into clean, ML-ready DataFrames.

Pipeline Stages:
    1. JSON Ingestion   → Read NDJSON files into raw DataFrames
    2. Schema Validation → Ensure all required fields are present
    3. Type Coercion    → Convert timestamps, numeric fields, categoricals
    4. Missing Data     → Handle nulls with domain-appropriate strategies
    5. Deduplication    → Remove duplicate events by event_id
    6. Output           → Clean DataFrame ready for feature_extraction.py

Academic Rationale:
    Data preprocessing is the most critical and time-consuming step in any
    ML pipeline (estimated 60-80% of effort in real-world projects). In
    security analytics, data quality directly impacts detection accuracy —
    a single malformed timestamp can cause a benign session to be flagged
    as anomalous due to incorrect duration calculation.

Dependencies:
    - pandas: DataFrame operations and I/O
    - numpy: Numeric operations and NaN handling

Usage:
    from data_pipeline.preprocessing import preprocess_telemetry
    df = preprocess_telemetry("path/to/unified_telemetry.jsonl")

    # Or as a standalone script:
    python preprocessing.py --input unified_telemetry.jsonl --output clean_data.csv
=============================================================================
"""

import json
import logging
import argparse
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

import numpy as np
import pandas as pd

# Configure logging for academic traceability
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("preprocessing")


# =============================================================================
# Schema Definition
# =============================================================================
# The unified schema expected from log_aggregator.py.
# Each field has a defined type and handling strategy for missing values.
# This explicit schema definition makes the pipeline self-documenting
# and aids in academic review.
# =============================================================================

EXPECTED_SCHEMA = {
    "timestamp":        {"type": "datetime", "required": True,  "default": None},
    "source":           {"type": "category", "required": True,  "default": "unknown"},
    "event_id":         {"type": "string",   "required": True,  "default": None},
    "pod":              {"type": "string",   "required": False, "default": "unknown"},
    "namespace":        {"type": "string",   "required": False, "default": "unknown"},
    "container_id":     {"type": "string",   "required": False, "default": "unknown"},
    "severity":         {"type": "category", "required": True,  "default": "LOW"},
    "event_type":       {"type": "category", "required": True,  "default": "unknown"},
    "syscall":          {"type": "string",   "required": False, "default": ""},
    "process":          {"type": "string",   "required": False, "default": ""},
    "mitre_technique":  {"type": "string",   "required": False, "default": None},
}

# Severity levels ordered for numeric encoding
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# =============================================================================
# JSON Ingestion
# =============================================================================
def ingest_telemetry(filepath: str) -> pd.DataFrame:
    """
    Read NDJSON (Newline-Delimited JSON) telemetry into a DataFrame.

    NDJSON format is chosen because:
    1. It supports streaming — files can be appended without rewriting
    2. Each line is independently parseable — resilient to partial corruption
    3. Compatible with pandas.read_json(lines=True) for efficient I/O

    The function handles:
    - Flattening of nested 'network_metadata' into top-level columns
    - Extraction of raw_event fields if needed (not stored to save memory)
    - Graceful handling of malformed lines (logged and skipped)

    Args:
        filepath: Path to the NDJSON telemetry file

    Returns:
        Raw DataFrame with all telemetry fields

    Raises:
        FileNotFoundError: If the input file does not exist
        ValueError: If the file contains no valid events
    """
    logger.info(f"Ingesting telemetry from: {filepath}")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Telemetry file not found: {filepath}")

    # Read NDJSON with error handling for malformed lines
    records = []
    malformed_count = 0

    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)

                # Flatten nested network_metadata into top-level columns
                # This denormalization makes downstream feature extraction
                # simpler and avoids nested column access in pandas
                network = record.pop("network_metadata", None)
                if network and isinstance(network, dict):
                    record["net_src_ip"]   = network.get("src_ip", "")
                    record["net_dst_ip"]   = network.get("dst_ip", "")
                    record["net_src_port"] = network.get("src_port", 0)
                    record["net_dst_port"] = network.get("dst_port", 0)
                    record["net_protocol"] = network.get("protocol", "unknown")
                else:
                    record["net_src_ip"]   = ""
                    record["net_dst_ip"]   = ""
                    record["net_src_port"] = 0
                    record["net_dst_port"] = 0
                    record["net_protocol"] = "unknown"

                # Remove raw_event to save memory (it's a full copy of input)
                record.pop("raw_event", None)

                records.append(record)

            except json.JSONDecodeError as e:
                malformed_count += 1
                if malformed_count <= 5:
                    logger.warning(
                        f"Malformed JSON at line {line_num}: {e}")

    if malformed_count > 5:
        logger.warning(
            f"Total malformed lines skipped: {malformed_count}")

    if not records:
        raise ValueError("No valid telemetry events found in file")

    df = pd.DataFrame(records)
    logger.info(
        f"Ingested {len(df)} events "
        f"({malformed_count} malformed lines skipped)")

    return df


# =============================================================================
# Schema Validation
# =============================================================================
def validate_schema(df: pd.DataFrame) -> pd.DataFrame:
    """
    Validate and enforce the expected telemetry schema.

    This function ensures that:
    1. All required columns exist (adding defaults for missing ones)
    2. Data types are correct (timestamps, categoricals, numerics)
    3. Column names are consistent

    Why explicit validation?
        In a multi-source telemetry pipeline, schema drift is inevitable.
        Sources may add/remove fields, change formats, or introduce nulls.
        Explicit validation catches these issues early, before they corrupt
        ML model training data.

    Args:
        df: Raw ingested DataFrame

    Returns:
        Schema-validated DataFrame with consistent types
    """
    logger.info("Validating telemetry schema...")

    # Add missing columns with default values
    for col, spec in EXPECTED_SCHEMA.items():
        if col not in df.columns:
            if spec["required"]:
                logger.warning(
                    f"Required column '{col}' missing — "
                    f"filling with default: {spec['default']}")
            df[col] = spec["default"]

    # Convert timestamp to datetime
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce",    # Invalid timestamps become NaT
            utc=True            # Standardize to UTC
        )
        # Drop rows with unparseable timestamps (critical field)
        nat_count = df["timestamp"].isna().sum()
        if nat_count > 0:
            logger.warning(
                f"Dropping {nat_count} rows with invalid timestamps")
            df = df.dropna(subset=["timestamp"])

    # Convert categorical columns
    for col in ["source", "severity", "event_type"]:
        if col in df.columns:
            df[col] = df[col].astype("category")

    # Encode severity as ordered numeric for ML features
    # LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3
    df["severity_numeric"] = df["severity"].map(
        {s: i for i, s in enumerate(SEVERITY_ORDER)}
    ).fillna(0).astype(int)

    logger.info(f"Schema validation complete. Shape: {df.shape}")
    return df


# =============================================================================
# Missing Data Handling
# =============================================================================
def handle_missing_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Handle missing values with domain-appropriate strategies.

    Strategy by field type:
    - Categorical (source, event_type): Fill with "unknown"
    - String (pod, process, syscall): Fill with empty string
    - Numeric (ports): Fill with 0
    - Timestamps: Already handled in validate_schema (rows dropped)

    Why not just dropna()?
        In security data, missing fields often carry information.
        A missing 'process' field in a network event is normal (no process
        context for raw packets), while a missing 'pod' might indicate
        a host-level event. Blanket row dropping would lose valid data.

    Args:
        df: Schema-validated DataFrame

    Returns:
        DataFrame with no missing values
    """
    logger.info("Handling missing data...")

    # String columns — fill with empty string
    string_cols = ["pod", "namespace", "container_id", "syscall",
                   "process", "mitre_technique",
                   "net_src_ip", "net_dst_ip", "net_protocol"]
    for col in string_cols:
        if col in df.columns:
            df[col] = df[col].fillna("")

    # Numeric columns — fill with 0
    numeric_cols = ["net_src_port", "net_dst_port", "severity_numeric"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    missing_total = df.isna().sum().sum()
    logger.info(f"Remaining missing values after handling: {missing_total}")

    return df


# =============================================================================
# Deduplication
# =============================================================================
def deduplicate_events(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove duplicate telemetry events.

    Deduplication is performed on 'event_id' (UUID assigned by the
    log_aggregator). This handles cases where:
    - The same event is emitted by both Falco and KubeArmor
    - Log shipping retries produce duplicate entries
    - Multiple aggregator instances process the same log file

    Args:
        df: Cleaned DataFrame

    Returns:
        Deduplicated DataFrame
    """
    initial_count = len(df)
    df = df.drop_duplicates(subset=["event_id"], keep="first")
    dropped = initial_count - len(df)

    if dropped > 0:
        logger.info(f"Removed {dropped} duplicate events")

    return df


# =============================================================================
# Main Preprocessing Pipeline
# =============================================================================
def preprocess_telemetry(
    input_path: str,
    output_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Execute the complete preprocessing pipeline.

    Pipeline: Ingest → Validate → Handle Missing → Deduplicate → Output

    This function is the primary entry point for downstream modules
    (feature_extraction.py, data_balancing.py) and can be called
    programmatically or via the CLI.

    Args:
        input_path:  Path to unified NDJSON telemetry file
        output_path: Optional path to save cleaned CSV output

    Returns:
        Clean, ML-ready DataFrame
    """
    logger.info("=" * 60)
    logger.info("Starting Preprocessing Pipeline")
    logger.info("=" * 60)

    # Step 1: Ingest raw telemetry
    df = ingest_telemetry(input_path)
    logger.info(f"  [1/4] Ingestion complete: {len(df)} events")

    # Step 2: Validate and enforce schema
    df = validate_schema(df)
    logger.info(f"  [2/4] Schema validation complete: {df.shape}")

    # Step 3: Handle missing data
    df = handle_missing_data(df)
    logger.info(f"  [3/4] Missing data handled: {df.isna().sum().sum()} remaining")

    # Step 4: Deduplicate
    df = deduplicate_events(df)
    logger.info(f"  [4/4] Deduplication complete: {len(df)} unique events")

    # Optional: Save cleaned output
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        df.to_csv(output_path, index=False)
        logger.info(f"Cleaned data saved to: {output_path}")

    logger.info("=" * 60)
    logger.info(f"Preprocessing complete. Final shape: {df.shape}")
    logger.info("=" * 60)

    return df


# =============================================================================
# CLI Entry Point
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AIOps Telemetry Preprocessing Pipeline",
        epilog="Part of the AIOps Threat Intelligence project (NMIT ISE FYP)"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        required=True,
        help="Path to unified NDJSON telemetry file"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Path to save cleaned CSV output (optional)"
    )

    args = parser.parse_args()
    df = preprocess_telemetry(args.input, args.output)

    # Print summary statistics for academic analysis
    print("\n--- Dataset Summary ---")
    print(f"Total events:     {len(df)}")
    print(f"Columns:          {list(df.columns)}")
    print(f"Sources:          {df['source'].value_counts().to_dict()}")
    print(f"Event types:      {df['event_type'].value_counts().to_dict()}")
    print(f"Severity dist:    {df['severity'].value_counts().to_dict()}")
