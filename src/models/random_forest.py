"""
Random Forest Classification Module.
Implements supervised ensemble classification with decision trees,
calculating Gini impurity for splits, feature importance ranking, and multi-class support.
"""

import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Any, List, Tuple, Optional

from src.config import RANDOM_FOREST_PARAMS, FEATURE_COLS_41


class RandomForestDetector:
    """
    Supervised Random Forest Classifier.
    Trains an ensemble of 100 decision trees to classify network records with high accuracy
    and provides interpretable feature importance rankings.
    """
    
    def __init__(self, params: Dict[str, Any] = None):
        self.params = params or RANDOM_FOREST_PARAMS.copy()
        self.model = RandomForestClassifier(**self.params)
        self.feature_names: List[str] = list(FEATURE_COLS_41)
        self.training_time: float = 0.0
        self.is_fitted: bool = False

    def train(
        self,
        X_train: pd.DataFrame | np.ndarray,
        y_train: pd.Series | np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> "RandomForestDetector":
        """
        Trains the Random Forest model on preprocessed features and labels.
        
        Args:
            X_train: Scaled feature matrix
            y_train: Target labels (binary or multi-class)
            feature_names: Optional list of feature names
        """
        if feature_names is not None:
            self.feature_names = feature_names
        elif isinstance(X_train, pd.DataFrame):
            self.feature_names = list(X_train.columns)
            
        print(f"[*] Training Random Forest (n_estimators={self.params.get('n_estimators')}, criterion='{self.params.get('criterion')}')...")
        start_time = time.time()
        self.model.fit(X_train, y_train)
        self.training_time = time.time() - start_time
        self.is_fitted = True
        print(f"[+] Random Forest trained successfully in {self.training_time:.2f} seconds.")
        return self

    def predict(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """
        Predicts classification labels.
        """
        if not self.is_fitted:
            raise RuntimeError("RandomForestDetector must be trained before predicting.")
        return self.model.predict(X)

    def predict_proba(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """
        Predicts class probabilities.
        """
        if not self.is_fitted:
            raise RuntimeError("RandomForestDetector must be trained before predicting.")
        return self.model.predict_proba(X)

    def get_feature_importances(self) -> pd.DataFrame:
        """
        Extracts Gini-based feature importance ranking.
        
        Returns:
            pd.DataFrame: Ranked dataframe of features and their importance scores
        """
        if not self.is_fitted:
            raise RuntimeError("RandomForestDetector must be trained before extracting feature importances.")
        
        importances = self.model.feature_importances_
        df_importance = pd.DataFrame({
            "Feature": self.feature_names,
            "Importance": importances
        }).sort_values(by="Importance", ascending=False).reset_index(drop=True)
        
        return df_importance
