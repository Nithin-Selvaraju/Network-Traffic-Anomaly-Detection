"""
Data Ingestion and Schema Mapping Module for Network Traffic Anomaly Detection.
Responsible for loading NSL-KDD datasets, parsing features, removing the difficulty column,
and creating binary and multi-class target labels.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Any

from src.config import (
    ALL_COLUMNS,
    FEATURE_COLS_41,
    CATEGORICAL_FEATURES,
    NUMERICAL_FEATURES,
    ATTACK_MAPPING,
    TRAIN_DATA_PATH,
    TEST_DATA_PATH
)


def load_raw_dataset(file_path: Path) -> pd.DataFrame:
    """
    Loads raw NSL-KDD CSV/TXT dataset with standard 43 columns.
    
    Args:
        file_path: Path to the dataset file (KDDTrain+.txt or KDDTest+.txt)
        
    Returns:
        pd.DataFrame: Loaded dataframe with assigned column headers
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")
    
    print(f"[*] Ingesting raw network records from: {file_path.name}")
    df = pd.read_csv(file_path, header=None, names=ALL_COLUMNS)
    print(f"[+] Loaded {len(df):,} records across {df.shape[1]} raw attributes.")
    return df


def prepare_labels_and_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocesses target labels according to patent claims:
    1. Removes 'difficulty' column (non-discriminative).
    2. Maps normal traffic to 0, and all attack types (DoS, Probe, R2L, U2R) to 1 (binary_label).
    3. Maps granular attack names to 5 high-level classes: Normal, DoS, Probe, R2L, U2R (attack_class).
    
    Args:
        df: Raw DataFrame with 43 columns
        
    Returns:
        pd.DataFrame: Cleaned DataFrame with formatted features and labels
    """
    df = df.copy()
    
    # Step 1: Remove 'difficulty' column if present
    if "difficulty" in df.columns:
        df = df.drop(columns=["difficulty"])
        print("[+] Dropped 'difficulty' metadata attribute.")
        
    # Step 2: Ensure label is clean string
    df["label"] = df["label"].astype(str).str.strip().str.rstrip('.')
    
    # Step 3: Binary label creation (0 = Normal, 1 = Attack)
    df["binary_label"] = df["label"].apply(lambda x: 0 if x.lower() == "normal" else 1)
    
    # Step 4: 5-Class Attack category mapping
    df["attack_class"] = df["label"].apply(
        lambda x: ATTACK_MAPPING.get(x.lower(), "Unknown_Attack" if x.lower() != "normal" else "Normal")
    )
    
    # Check for missing values across all features
    null_count = df.isnull().sum().sum()
    print(f"[+] Missing/Null values count: {null_count}")
    
    return df


def load_nsl_kdd_datasets(
    train_path: Path = TRAIN_DATA_PATH,
    test_path: Path = TEST_DATA_PATH
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Loads and prepares both training and testing datasets.
    
    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: (train_df, test_df)
    """
    train_raw = load_raw_dataset(train_path)
    train_df = prepare_labels_and_features(train_raw)
    
    test_raw = load_raw_dataset(test_path)
    test_df = prepare_labels_and_features(test_raw)
    
    print("\n--- Ingestion Summary ---")
    print(f"Training set: {len(train_df):,} records ({train_df['binary_label'].value_counts().to_dict()})")
    print(f"Testing set:  {len(test_df):,} records ({test_df['binary_label'].value_counts().to_dict()})")
    
    return train_df, test_df
