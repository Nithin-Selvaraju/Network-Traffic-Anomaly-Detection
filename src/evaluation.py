"""
Model Evaluation Framework Module.
Calculates Accuracy, Precision, Recall, F1-Score, Confusion Matrices,
and generates comparative performance benchmark tables.
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from typing import Dict, Any, List


def evaluate_binary_model(
    model_name: str,
    y_true: np.ndarray | pd.Series,
    y_pred: np.ndarray,
    training_time: float = 0.0
) -> Dict[str, Any]:
    """
    Evaluates binary classification performance metrics.
    
    Args:
        model_name: Name of the detection model
        y_true: Ground truth binary labels (0 = Normal, 1 = Anomaly)
        y_pred: Predicted binary labels (0 = Normal, 1 = Anomaly)
        training_time: Training execution duration in seconds
        
    Returns:
        Dict[str, Any]: Dictionary containing all key metrics
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    
    # Extract TN, FP, FN, TP
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    
    metrics = {
        "Model": model_name,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1-Score": f1,
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "Training Time (s)": round(training_time, 2),
        "Confusion Matrix": cm
    }
    return metrics


def create_comparative_table(results_list: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Constructs the comparative benchmark summary table (matching patent Section 7.7 & Table 1).
    
    Args:
        results_list: List of model metric dictionaries
        
    Returns:
        pd.DataFrame: Formatted ranking DataFrame
    """
    rows = []
    for res in results_list:
        rows.append({
            "Model": res["Model"],
            "Accuracy (%)": round(res["Accuracy"] * 100, 2),
            "Precision": round(res["Precision"], 3),
            "Recall": round(res["Recall"], 3),
            "F1-Score": round(res["F1-Score"], 3),
            "Training Time (s)": res.get("Training Time (s)", 0.0)
        })
        
    df_table = pd.DataFrame(rows).sort_values(by="F1-Score", ascending=False).reset_index(drop=True)
    return df_table


def print_evaluation_summary(results_list: List[Dict[str, Any]]):
    """
    Prints comparative summary table and detailed confusion matrix breakdown.
    """
    df_summary = create_comparative_table(results_list)
    print("\n" + "=" * 70)
    print("        NETWORK TRAFFIC ANOMALY DETECTION BENCHMARK RESULTS")
    print("=" * 70)
    print(df_summary.to_string(index=False))
    print("=" * 70)
    
    print("\nDetailed Confusion Matrix Breakdown:")
    for res in results_list:
        print(f"\n--- {res['Model']} ---")
        print(f"  True Positives (Attacks detected):     {res['TP']:,}")
        print(f"  True Negatives (Normal detected):      {res['TN']:,}")
        print(f"  False Positives (False Alarms):        {res['FP']:,}")
        print(f"  False Negatives (Missed Attacks):      {res['FN']:,}")
