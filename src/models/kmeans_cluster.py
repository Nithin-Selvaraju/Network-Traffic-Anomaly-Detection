"""
K-Means Clustering Anomaly Detection Module.
Partitions the feature space into behavioral groups and applies modal mapping
to identify anomalous traffic clusters.
"""

import time
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from scipy import stats
from typing import Dict, Any, Tuple, Optional

from src.config import KMEANS_PARAMS


class KMeansDetector:
    """
    K-Means clustering based anomaly detector.
    Groups connections into k=2 clusters and utilizes modal ground-truth mapping
    to assign cluster identities (Normal vs. Anomaly).
    """
    
    def __init__(self, params: Dict[str, Any] = None):
        self.params = params or KMEANS_PARAMS.copy()
        self.model = KMeans(**self.params)
        self.cluster_to_label_map: Dict[int, int] = {}
        self.training_time: float = 0.0
        self.is_fitted: bool = False

    def train(
        self,
        X_train: pd.DataFrame | np.ndarray,
        y_train: Optional[pd.Series | np.ndarray] = None
    ) -> "KMeansDetector":
        """
        Trains K-Means model on unlabelled scaled feature data, and performs modal mapping
        if ground truth labels are provided for calibration.
        
        Args:
            X_train: Scaled feature matrix
            y_train: Optional ground truth binary labels for modal mapping calibration
        """
        print(f"[*] Training K-Means Clustering (n_clusters={self.params.get('n_clusters')}, n_init={self.params.get('n_init')})...")
        start_time = time.time()
        cluster_labels = self.model.fit_predict(X_train)
        self.training_time = time.time() - start_time
        
        # Modal mapping calibration
        if y_train is not None:
            y_arr = np.array(y_train)
            for c in range(self.params.get("n_clusters", 2)):
                mask = (cluster_labels == c)
                if np.sum(mask) > 0:
                    # Find modal class in cluster c
                    mode_val = int(stats.mode(y_arr[mask], keepdims=True)[0][0])
                    self.cluster_to_label_map[c] = mode_val
                else:
                    self.cluster_to_label_map[c] = c
            print(f"[+] K-Means cluster-to-anomaly modal mapping established: {self.cluster_to_label_map}")
        else:
            # Heuristic fallback: smaller cluster is deemed anomalous
            counts = np.bincount(cluster_labels)
            anomaly_cluster = np.argmin(counts)
            self.cluster_to_label_map = {anomaly_cluster: 1, (1 - anomaly_cluster): 0}
            print(f"[+] Fallback cluster mapping (minimal cluster anomaly): {self.cluster_to_label_map}")
            
        self.is_fitted = True
        print(f"[+] K-Means trained successfully in {self.training_time:.2f} seconds.")
        return self

    def predict(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """
        Predicts binary anomaly labels (0 = Normal, 1 = Anomaly).
        
        Args:
            X: Scaled feature matrix
            
        Returns:
            np.ndarray: Binary anomaly predictions
        """
        if not self.is_fitted:
            raise RuntimeError("KMeansDetector must be trained before predicting.")
        
        raw_clusters = self.model.predict(X)
        binary_preds = np.array([self.cluster_to_label_map.get(c, 0) for c in raw_clusters])
        return binary_preds

    def transform(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Computes distances to cluster centroids."""
        return self.model.transform(X)
