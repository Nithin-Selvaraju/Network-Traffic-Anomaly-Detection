"""
Data Preprocessing Module for Network Traffic Anomaly Detection.
Implements:
1. Categorical Encoding (LabelEncoder for 'protocol_type', 'service', 'flag')
2. Numerical Feature Normalization (MinMaxScaler to [0, 1])
3. Stratified Train-Test Splitting
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from typing import Tuple, Dict, Any, Optional

from src.config import (
    FEATURE_COLS_41,
    CATEGORICAL_FEATURES,
    NUMERICAL_FEATURES
)


class DataPreprocessor:
    """
    Fits and manages encoders and scalers for NSL-KDD network traffic data.
    Ensures zero data leakage by fitting exclusively on the training partition.
    """
    
    def __init__(self):
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.scaler = MinMaxScaler(feature_range=(0, 1))
        self.feature_columns = FEATURE_COLS_41.copy()
        self.categorical_features = CATEGORICAL_FEATURES.copy()
        self.numerical_features = NUMERICAL_FEATURES.copy()
        self.is_fitted = False
        self.class_encoder = LabelEncoder()

    def fit(self, df: pd.DataFrame) -> "DataPreprocessor":
        """
        Fits LabelEncoders on categorical columns and MinMaxScaler on numerical columns.
        
        Args:
            df: Training DataFrame containing raw features
        """
        print("[*] Fitting DataPreprocessor on training set...")
        
        # 1. Fit LabelEncoders on categorical string features
        for col in self.categorical_features:
            le = LabelEncoder()
            # Fit on unique classes, ensure unknown handling
            le.fit(df[col].astype(str).unique())
            self.label_encoders[col] = le
            print(f"  - Fitted LabelEncoder for '{col}' ({len(le.classes_)} unique categories)")

        # 2. Fit Multi-class Target Encoder
        if "attack_class" in df.columns:
            self.class_encoder.fit(df["attack_class"])
            print(f"  - Fitted Attack Class Encoder ({len(self.class_encoder.classes_)} classes: {list(self.class_encoder.classes_)})")

        # 3. Fit MinMaxScaler on numerical features
        self.scaler.fit(df[self.numerical_features])
        print(f"  - Fitted MinMaxScaler on {len(self.numerical_features)} numerical features to [0, 1] range.")
        
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transforms categorical and numerical features using fitted encoders/scalers.
        
        Args:
            df: Input DataFrame
            
        Returns:
            pd.DataFrame: Fully encoded and scaled feature DataFrame
        """
        if not self.is_fitted:
            raise RuntimeError("DataPreprocessor must be fitted before transforming data.")
        
        transformed_df = df[self.feature_columns].copy()
        
        # Transform categorical features
        for col in self.categorical_features:
            le = self.label_encoders[col]
            # Handle unseen categories in test set by mapping unknown categories to first or most frequent class
            known_classes = set(le.classes_)
            transformed_col = df[col].astype(str).map(
                lambda s: s if s in known_classes else le.classes_[0]
            )
            transformed_df[col] = le.transform(transformed_col)
            
        # Scale numerical features
        transformed_df[self.numerical_features] = self.scaler.transform(df[self.numerical_features])
        
        return transformed_df

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform in one step."""
        return self.fit(df).transform(df)


def perform_stratified_split(
    df: pd.DataFrame,
    test_size: float = 0.20,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Performs 80:20 stratified train-test split maintaining binary class distribution.
    
    Args:
        df: Input DataFrame containing 'binary_label'
        test_size: Test proportion (default 0.20)
        random_state: Random seed for reproducibility
        
    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: (train_split, test_split)
    """
    print(f"[*] Performing {int((1-test_size)*100)}:{int(test_size*100)} stratified train-test split...")
    train_df, test_df = train_test_split(
        df,
        test_size=test_size,
        stratify=df["binary_label"],
        random_state=random_state
    )
    print(f"[+] Training partition size: {len(train_df):,} records")
    print(f"[+] Testing partition size:  {len(test_df):,} records")
    return train_df.reset_index(drop=True), test_df.reset_index(drop=True)
