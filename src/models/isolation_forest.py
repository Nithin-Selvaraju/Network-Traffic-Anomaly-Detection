"""
Isolation Forest Anomaly Detection Module.
Implements unsupervised recursive random partitioning for zero-day threat detection.
"""

import time
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple

from src.config import ISOLATION_FOREST_PARAMS


class IsolationForestDetector:
    """
    Unsupervised Isolation Forest detector.
    Identifies anomalous network connections through recursive random partitioning.
    """
    
    def __init__(self, params: Dict[str, Any] = None):
        self.params = params or ISOLATION_FOREST_PARAMS.copy()
        self.model = IsolationForest(**self.params)
        self.training_time: float = 0.0
        self.is_fitted: bool = False

    def train(self, X_train: pd.DataFrame | np.ndarray) -> "IsolationForestDetector":
        """
        Trains the Isolation Forest model on unlabelled scaled feature data.
        
        Args:
            X_train: Scaled feature matrix
        """
        print(f"[*] Training Isolation Forest (n_estimators={self.params.get('n_estimators')}, contamination={self.params.get('contamination')})...")
        start_time = time.time()
        self.model.fit(X_train)
        self.training_time = time.time() - start_time
        self.is_fitted = True
        print(f"[+] Isolation Forest trained successfully in {self.training_time:.2f} seconds.")
        return self

    def predict(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """
        Predicts binary anomaly labels (0 = Normal, 1 = Anomaly).
        Translates sklearn's (-1: anomaly, 1: normal) format into standard binary indicator (1: anomaly, 0: normal).
        
        Args:
            X: Scaled feature matrix
            
        Returns:
            np.ndarray: Binary anomaly predictions (0 or 1)
        """
        if not self.is_fitted:
            raise RuntimeError("IsolationForestDetector must be trained before predicting.")
        
        raw_preds = self.model.predict(X)
        # Convert -1 -> 1 (Anomaly), 1 -> 0 (Normal)
        binary_preds = np.where(raw_preds == -1, 1, 0)
        return binary_preds

    def get_anomaly_scores(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """
        Returns continuous anomaly score (lower means more anomalous).
        """
        return self.model.decision_function(X)
