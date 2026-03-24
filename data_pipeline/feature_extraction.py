"""
=============================================================================
Feature Extraction — Engineering ML Features from Security Telemetry
=============================================================================
Module: data_pipeline/feature_extraction.py
Agent:  Agent 2 — "The Cleaner"

Purpose:
    Extracts discriminative features from cleaned telemetry data for use
    in the ML classification and anomaly detection models (Agent 3).

Feature Categories:
    1. Temporal Features   — Session duration, event frequency, time-of-day
    2. Traffic Features    — Volume, packet sizes, port distributions
    3. Syscall Features    — System call sequence n-grams and frequencies
    4. Behavioral Features — Process diversity, network diversity, severity

Academic Rationale:
    Feature engineering is the process of using domain knowledge to create
    input variables that make ML algorithms work. In network security:
    - Session duration distinguishes quick port scans from sustained sessions
    - Packet size variance identifies data exfiltration (large outbound)
    - Syscall n-grams capture attack tool fingerprints (e.g., nmap patterns)
    - Event frequency spikes indicate DDoS or brute-force attacks

    Each feature function below documents WHY the feature is discriminative
    for the specific attack type it helps detect, per academic standards.

Dependencies:
    pandas, numpy, scikit-learn (CountVectorizer for n-grams)

Usage:
    from data_pipeline.feature_extraction import extract_all_features
    feature_df = extract_all_features(clean_df, window_seconds=60)
=============================================================================
"""

import logging
from typing import Optional
from collections import Counter

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("feature_extraction")


# =============================================================================
# Configuration
# =============================================================================
# Default time window for aggregating events into sessions.
# A 60-second window balances granularity with statistical significance.
DEFAULT_WINDOW_SECONDS = 60

# N-gram size for syscall sequence encoding.
# Bigrams (n=2) capture immediate syscall transitions (e.g., open→read),
# which are distinctive patterns for attack tool fingerprinting.
SYSCALL_NGRAM_SIZE = 2

# Top-K most common syscalls to use as feature dimensions.
# This limits the feature space while covering 95%+ of observed syscalls.
TOP_K_SYSCALLS = 20


# =============================================================================
# Temporal Feature Extraction
# =============================================================================
def extract_temporal_features(df: pd.DataFrame,
                               window_seconds: int = DEFAULT_WINDOW_SECONDS
                               ) -> pd.DataFrame:
    """
    Extract time-based features from telemetry events.

    Features computed per (pod, time_window):
    - session_duration:  Time span (seconds) between first and last event
    - event_count:       Total number of events in the window
    - event_rate:        Events per second
    - hour_of_day:       Hour (0-23) — attacks often occur outside business hours
    - is_off_hours:      Binary flag for events between 22:00-06:00

    Why these features matter:
    - session_duration: Very short sessions (<1s) indicate port scans;
      very long sessions (>1h) may indicate persistent backdoors.
    - event_rate: A sudden spike in event rate is the primary indicator
      of DDoS attacks and brute-force credential stuffing (T1110).
    - is_off_hours: Insider threats and external attacks disproportionately
      occur during off-hours when SOC staffing is minimal.

    Args:
        df: Cleaned DataFrame with 'timestamp' and 'pod' columns
        window_seconds: Time window for session aggregation (default: 60s)

    Returns:
        DataFrame with temporal features, indexed by (pod, window_start)
    """
    logger.info(f"Extracting temporal features (window={window_seconds}s)...")

    # Ensure timestamp is datetime and sorted
    df = df.sort_values("timestamp").copy()

    # Create time windows by flooring timestamps
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    # Group by pod and time window for session-level features
    grouped = df.groupby(["pod", "window_start"])

    temporal = grouped.agg(
        session_duration=("timestamp", lambda x: (x.max() - x.min()).total_seconds()),
        event_count=("event_id", "count"),
        first_event=("timestamp", "min"),
    ).reset_index()

    # Derive additional temporal features
    temporal["event_rate"] = (
        temporal["event_count"] / temporal["session_duration"].clip(lower=1)
    )
    temporal["hour_of_day"] = temporal["first_event"].dt.hour
    temporal["is_off_hours"] = temporal["hour_of_day"].apply(
        lambda h: 1 if h >= 22 or h < 6 else 0
    )

    # Drop intermediate columns
    temporal = temporal.drop(columns=["first_event"])

    logger.info(f"  Temporal features: {temporal.shape}")
    return temporal


# =============================================================================
# Traffic Volume Feature Extraction
# =============================================================================
def extract_traffic_features(df: pd.DataFrame,
                              window_seconds: int = DEFAULT_WINDOW_SECONDS
                              ) -> pd.DataFrame:
    """
    Extract network traffic volume and packet size features.

    Features computed per (pod, time_window):
    - unique_dst_ips:      Number of distinct destination IPs
    - unique_dst_ports:    Number of distinct destination ports
    - port_entropy:        Shannon entropy of destination port distribution
    - avg_dst_port:        Mean destination port number
    - std_dst_port:        Std deviation of destination ports
    - has_high_ports:      Whether any port > 1024 was contacted
    - network_event_ratio: Fraction of events that are network-related

    Why these features matter:
    - unique_dst_ips: A high count indicates network scanning (T1046).
      Normal pods contact 2-5 IPs; scanners contact hundreds.
    - port_entropy: Uniform port distribution (high entropy) is a
      hallmark of port scanning. Normal traffic has low entropy
      (concentrated on ports 80, 443, 8080).
    - has_high_ports: Communication on ephemeral ports (>1024) may
      indicate reverse shells or C2 channels.

    Args:
        df: Cleaned DataFrame with network metadata columns
        window_seconds: Time window for aggregation

    Returns:
        DataFrame with traffic features
    """
    logger.info("Extracting traffic volume features...")

    df = df.copy()
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    # Filter to network-relevant events
    net_df = df[df["net_dst_port"] > 0].copy()

    if len(net_df) == 0:
        logger.warning("No network events found — returning empty features")
        return pd.DataFrame(columns=[
            "pod", "window_start", "unique_dst_ips", "unique_dst_ports",
            "port_entropy", "avg_dst_port", "std_dst_port",
            "has_high_ports", "network_event_ratio"
        ])

    # Aggregate network metrics per pod per window
    grouped = net_df.groupby(["pod", "window_start"])

    traffic = grouped.agg(
        unique_dst_ips=("net_dst_ip", "nunique"),
        unique_dst_ports=("net_dst_port", "nunique"),
        avg_dst_port=("net_dst_port", "mean"),
        std_dst_port=("net_dst_port", "std"),
        max_dst_port=("net_dst_port", "max"),
    ).reset_index()

    # Fill NaN standard deviation (single-value groups) with 0
    traffic["std_dst_port"] = traffic["std_dst_port"].fillna(0)

    # Shannon entropy of port distribution
    # High entropy = uniform distribution = scanning behavior
    traffic["port_entropy"] = grouped["net_dst_port"].apply(
        _compute_shannon_entropy
    ).reset_index(drop=True)

    # Binary flag for ephemeral/high port usage
    traffic["has_high_ports"] = (traffic["max_dst_port"] > 1024).astype(int)
    traffic = traffic.drop(columns=["max_dst_port"])

    # Compute network event ratio (network events / total events)
    total_events = df.groupby(["pod", "window_start"]).size().reset_index(name="total")
    net_events = net_df.groupby(["pod", "window_start"]).size().reset_index(name="net_count")
    ratio_df = total_events.merge(net_events, on=["pod", "window_start"], how="left")
    ratio_df["network_event_ratio"] = (
        ratio_df["net_count"].fillna(0) / ratio_df["total"].clip(lower=1)
    )

    traffic = traffic.merge(
        ratio_df[["pod", "window_start", "network_event_ratio"]],
        on=["pod", "window_start"],
        how="left"
    )

    logger.info(f"  Traffic features: {traffic.shape}")
    return traffic


def _compute_shannon_entropy(series: pd.Series) -> float:
    """
    Compute Shannon entropy H(X) = -Σ p(x) log2(p(x)) for a series.

    Shannon entropy quantifies the "randomness" of a distribution.
    For port numbers:
    - Low entropy (→0): Traffic concentrated on few ports (normal)
    - High entropy (→log2(n)): Uniform distribution across many ports (scanning)
    """
    counts = series.value_counts(normalize=True)
    return -(counts * np.log2(counts + 1e-10)).sum()


# =============================================================================
# System Call Sequence Feature Extraction
# =============================================================================
def extract_syscall_features(df: pd.DataFrame,
                              window_seconds: int = DEFAULT_WINDOW_SECONDS
                              ) -> pd.DataFrame:
    """
    Extract system call sequence features using n-gram frequency vectors.

    Features:
    - syscall_diversity:   Number of unique syscalls in the window
    - syscall_count:       Total syscall events
    - top_syscall_*:       Frequency of top-K most common syscalls
    - ngram_*:             Frequency of top bigram patterns

    Why syscall n-grams?
        System calls are the language of user-kernel interaction. Every
        action—reading a file, opening a network socket, executing a
        binary—translates to a specific syscall sequence.

        Attack tools have distinctive syscall fingerprints:
        - nmap scan:      socket → connect → close (rapid repetition)
        - Data exfiltration: open → read → write → sendto
        - Privilege escalation: setuid → execve
        - Container escape: unshare → mount → chroot

        N-gram encoding captures these sequential patterns as countable
        features that Random Forest can split on effectively.

    Args:
        df: Cleaned DataFrame with 'syscall' column
        window_seconds: Time window for aggregation

    Returns:
        DataFrame with syscall features
    """
    logger.info("Extracting syscall sequence features...")

    df = df.copy()
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    # Filter to events with syscall data
    syscall_df = df[df["syscall"].str.len() > 0].copy()

    if len(syscall_df) == 0:
        logger.warning("No syscall events found — returning empty features")
        return pd.DataFrame(columns=["pod", "window_start",
                                      "syscall_diversity", "syscall_count"])

    grouped = syscall_df.groupby(["pod", "window_start"])

    # Basic syscall statistics
    syscall_features = grouped.agg(
        syscall_diversity=("syscall", "nunique"),
        syscall_count=("syscall", "count"),
    ).reset_index()

    # Top-K syscall frequency features
    # These create a bag-of-syscalls representation
    top_syscalls = syscall_df["syscall"].value_counts().head(TOP_K_SYSCALLS).index.tolist()

    for syscall_name in top_syscalls:
        col_name = f"syscall_freq_{syscall_name}"
        syscall_features[col_name] = grouped["syscall"].apply(
            lambda x: (x == syscall_name).sum()
        ).reset_index(drop=True)

    # Bigram (n-gram) features for sequence patterns
    bigram_features = grouped["syscall"].apply(
        _extract_bigrams
    ).reset_index(drop=True)

    if isinstance(bigram_features, pd.Series) and len(bigram_features) > 0:
        bigram_df = pd.DataFrame(bigram_features.tolist())
        bigram_df.columns = [f"bigram_{col}" for col in bigram_df.columns]
        syscall_features = pd.concat(
            [syscall_features.reset_index(drop=True), bigram_df], axis=1
        )

    logger.info(f"  Syscall features: {syscall_features.shape}")
    return syscall_features


def _extract_bigrams(syscall_series: pd.Series) -> dict:
    """
    Extract bigram frequencies from a syscall sequence.

    A bigram is a pair of consecutive syscalls (e.g., "open→read").
    The frequency of each bigram pattern characterizes the behavior:
    - "connect→close" repeated many times = port scanning
    - "read→sendto" = data exfiltration
    """
    syscalls = syscall_series.tolist()
    bigrams = [f"{syscalls[i]}_{syscalls[i+1]}"
               for i in range(len(syscalls) - 1)]
    counter = Counter(bigrams)

    # Return top-10 bigrams as a dict
    return dict(counter.most_common(10))


# =============================================================================
# Behavioral Feature Extraction
# =============================================================================
def extract_behavioral_features(df: pd.DataFrame,
                                 window_seconds: int = DEFAULT_WINDOW_SECONDS
                                 ) -> pd.DataFrame:
    """
    Extract high-level behavioral features that capture attack patterns.

    Features:
    - severity_mean:         Average severity numeric (0-3)
    - severity_max:          Maximum severity in window
    - critical_event_ratio:  Fraction of CRITICAL events
    - event_type_diversity:  Number of distinct event types
    - process_diversity:     Number of distinct processes
    - has_shell_exec:        Whether shell execution was observed
    - has_privilege_esc:     Whether privilege escalation was attempted
    - has_file_access:       Whether sensitive file access occurred
    - mitre_technique_count: Number of distinct MITRE techniques observed

    Why behavioral features?
        Individual events may be benign in isolation, but malicious in
        combination. Behavioral features capture these higher-order
        patterns:
        - High process_diversity + shell_exec = likely compromised pod
        - Multiple MITRE techniques in one window = active attack chain
        - Escalating severity over time = progressing multi-stage attack

    Args:
        df: Cleaned DataFrame
        window_seconds: Time window for aggregation

    Returns:
        DataFrame with behavioral features
    """
    logger.info("Extracting behavioral features...")

    df = df.copy()
    df["window_start"] = df["timestamp"].dt.floor(f"{window_seconds}s")

    grouped = df.groupby(["pod", "window_start"])

    behavioral = grouped.agg(
        severity_mean=("severity_numeric", "mean"),
        severity_max=("severity_numeric", "max"),
        event_type_diversity=("event_type", "nunique"),
        process_diversity=("process", "nunique"),
    ).reset_index()

    # Critical event ratio
    critical_counts = df[df["severity"] == "CRITICAL"].groupby(
        ["pod", "window_start"]
    ).size().reset_index(name="critical_count")
    total_counts = grouped.size().reset_index(name="total_count")

    behavioral = behavioral.merge(
        critical_counts, on=["pod", "window_start"], how="left"
    )
    behavioral = behavioral.merge(
        total_counts, on=["pod", "window_start"], how="left"
    )
    behavioral["critical_event_ratio"] = (
        behavioral["critical_count"].fillna(0) /
        behavioral["total_count"].clip(lower=1)
    )

    # Binary indicator features for specific event types
    for event_type, col_name in [
        ("shell_execution",      "has_shell_exec"),
        ("privilege_escalation", "has_privilege_esc"),
        ("sensitive_file_read",  "has_file_access"),
        ("container_escape",     "has_escape_attempt"),
    ]:
        type_flags = df[df["event_type"] == event_type].groupby(
            ["pod", "window_start"]
        ).size().reset_index(name=col_name)
        type_flags[col_name] = (type_flags[col_name] > 0).astype(int)
        behavioral = behavioral.merge(
            type_flags, on=["pod", "window_start"], how="left"
        )
        behavioral[col_name] = behavioral[col_name].fillna(0).astype(int)

    # MITRE technique count
    mitre_counts = df[df["mitre_technique"].str.len() > 0].groupby(
        ["pod", "window_start"]
    )["mitre_technique"].nunique().reset_index(name="mitre_technique_count")
    behavioral = behavioral.merge(
        mitre_counts, on=["pod", "window_start"], how="left"
    )
    behavioral["mitre_technique_count"] = (
        behavioral["mitre_technique_count"].fillna(0).astype(int)
    )

    # Clean up intermediate columns
    behavioral = behavioral.drop(
        columns=["critical_count", "total_count"], errors="ignore"
    )

    logger.info(f"  Behavioral features: {behavioral.shape}")
    return behavioral


# =============================================================================
# Unified Feature Extraction Pipeline
# =============================================================================
def extract_all_features(
    df: pd.DataFrame,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    output_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Extract all feature categories and merge into a single feature matrix.

    This is the main entry point for the feature extraction pipeline.
    It produces a wide DataFrame where each row represents a (pod, time_window)
    session, and columns are the engineered features from all categories.

    Pipeline:
        temporal + traffic + syscall + behavioral → merged feature matrix

    The merge strategy is a left join on (pod, window_start), ensuring
    that every temporal window has a row even if no network/syscall events
    occurred (missing features filled with 0).

    Args:
        df: Clean DataFrame from preprocessing.py
        window_seconds: Time window for session aggregation
        output_path: Optional path to save feature CSV

    Returns:
        Wide feature matrix DataFrame
    """
    logger.info("=" * 60)
    logger.info("Starting Feature Extraction Pipeline")
    logger.info(f"  Input shape:   {df.shape}")
    logger.info(f"  Time window:   {window_seconds}s")
    logger.info("=" * 60)

    # Extract all feature categories
    temporal  = extract_temporal_features(df, window_seconds)
    traffic   = extract_traffic_features(df, window_seconds)
    syscall   = extract_syscall_features(df, window_seconds)
    behavioral = extract_behavioral_features(df, window_seconds)

    # Merge all features on (pod, window_start)
    features = temporal
    for feature_df in [traffic, syscall, behavioral]:
        if len(feature_df) > 0:
            features = features.merge(
                feature_df,
                on=["pod", "window_start"],
                how="left",
                suffixes=("", "_dup")
            )

    # Fill NaN features (from left joins where a category had no events)
    numeric_cols = features.select_dtypes(include=[np.number]).columns
    features[numeric_cols] = features[numeric_cols].fillna(0)

    # Remove duplicate columns from merges
    features = features.loc[:, ~features.columns.str.endswith("_dup")]

    # Optional: save to CSV
    if output_path:
        features.to_csv(output_path, index=False)
        logger.info(f"Feature matrix saved to: {output_path}")

    logger.info("=" * 60)
    logger.info(f"Feature extraction complete. Shape: {features.shape}")
    logger.info(f"Features: {list(features.columns)}")
    logger.info("=" * 60)

    return features
