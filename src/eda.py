"""
Exploratory Data Analysis (EDA) Module for Network Traffic Anomaly Detection.
Computes dataset distributions, protocol breakdowns, and statistical properties.
"""

import pandas as pd
import numpy as np
from typing import Dict, Any

from src.config import FEATURE_CATEGORIES, CATEGORICAL_FEATURES, NUMERICAL_FEATURES


def generate_dataset_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Computes comprehensive exploratory data statistics.
    
    Args:
        df: Input DataFrame with labels
        
    Returns:
        Dict[str, Any]: Formatted summary metrics
    """
    total_records = len(df)
    binary_counts = df["binary_label"].value_counts().to_dict()
    attack_counts = df["attack_class"].value_counts().to_dict() if "attack_class" in df.columns else {}
    protocol_counts = df["protocol_type"].value_counts().to_dict()
    
    summary = {
        "total_records": total_records,
        "features_count": len(df.columns),
        "normal_records": binary_counts.get(0, 0),
        "anomaly_records": binary_counts.get(1, 0),
        "anomaly_rate": round(binary_counts.get(1, 0) / total_records * 100, 2),
        "attack_distribution": attack_counts,
        "protocol_distribution": protocol_counts,
        "missing_values": int(df.isnull().sum().sum())
    }
    return summary


def print_eda_report(train_summary: Dict[str, Any], test_summary: Dict[str, Any]):
    """
    Prints human-readable EDA summary table to terminal.
    """
    print("=" * 60)
    print("      NSL-KDD NETWORK TRAFFIC DATASET EDA PROFILE")
    print("=" * 60)
    print(f"Training Partition Records: {train_summary['total_records']:,}")
    print(f"  - Normal Traffic:         {train_summary['normal_records']:,} ({100-train_summary['anomaly_rate']:.1f}%)")
    print(f"  - Anomalous Traffic:      {train_summary['anomaly_records']:,} ({train_summary['anomaly_rate']:.1f}%)")
    print(f"  - Missing Values:         {train_summary['missing_values']}")
    print(f"  - Attack Breakdown:")
    for k, v in train_summary["attack_distribution"].items():
        pct = (v / train_summary['total_records']) * 100
        print(f"      * {k:<10}: {v:,} ({pct:.2f}%)")
        
    print(f"  - Protocol Distribution:")
    for k, v in train_summary["protocol_distribution"].items():
        pct = (v / train_summary['total_records']) * 100
        print(f"      * {k.upper():<6}: {v:,} ({pct:.2f}%)")
        
    print("-" * 60)
    print(f"Testing Partition Records:  {test_summary['total_records']:,}")
    print(f"  - Normal Traffic:         {test_summary['normal_records']:,} ({100-test_summary['anomaly_rate']:.1f}%)")
    print(f"  - Anomalous Traffic:      {test_summary['anomaly_records']:,} ({test_summary['anomaly_rate']:.1f}%)")
    print(f"  - Missing Values:         {test_summary['missing_values']}")
    print("=" * 60)
