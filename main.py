"""
Main Orchestration Pipeline for Network Traffic Anomaly Detection.
Executes end-to-end workflow:
1. Data Ingestion & Schema Parsing (NSL-KDD KDDTrain+ & KDDTest+)
2. Exploratory Data Analysis & Integrity Checks
3. Preprocessing (Label Encoding, MinMax Scaling, Stratified Split)
4. Model Training:
   - Module 1: Isolation Forest (Unsupervised Anomaly Detection)
   - Module 2: K-Means Clustering (Unsupervised Clustering + Modal Mapping)
   - Module 3: Random Forest Classifier (Supervised Ensemble Learning)
5. Model Evaluation & Benchmark Ranking
6. Visual Analytics Dashboard Generation (Static PNGs + Interactive Plotly HTML)
"""

import sys
import time
import argparse
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

from src.config import (
    TRAIN_DATA_PATH,
    TEST_DATA_PATH,
    OUTPUTS_DIR,
    MODELS_DIR,
    FIGURES_DIR
)
from src.data_loader import load_nsl_kdd_datasets
from src.eda import generate_dataset_summary, print_eda_report
from src.preprocessing import DataPreprocessor, perform_stratified_split
from src.models.isolation_forest import IsolationForestDetector
from src.models.kmeans_cluster import KMeansDetector
from src.models.random_forest import RandomForestDetector
from src.evaluation import (
    evaluate_binary_model,
    create_comparative_table,
    print_evaluation_summary
)
from src.visualization import generate_all_visualizations


def run_pipeline(use_stratified_split: bool = False):
    """
    Executes complete anomaly detection pipeline.
    
    Args:
        use_stratified_split: If True, uses an 80:20 stratified split on KDDTrain+
                              (as described in working example). If False, evaluates
                              on standard held-out KDDTest+ dataset.
    """
    overall_start_time = time.time()
    print("=" * 80)
    print("      NETWORK TRAFFIC ANOMALY DETECTION MACHINE LEARNING PIPELINE")
    print("=" * 80)
    
    # Ensure output folders exist
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # STAGE 1: Data Collection & Ingestion
    # -------------------------------------------------------------
    print("\n>>> [STAGE 1] Loading NSL-KDD Benchmark Dataset...")
    train_df, test_df = load_nsl_kdd_datasets(TRAIN_DATA_PATH, TEST_DATA_PATH)
    
    # -------------------------------------------------------------
    # STAGE 2: Exploratory Data Analysis (EDA)
    # -------------------------------------------------------------
    print("\n>>> [STAGE 2] Performing Exploratory Data Analysis...")
    train_summary = generate_dataset_summary(train_df)
    test_summary = generate_dataset_summary(test_df)
    print_eda_report(train_summary, test_summary)

    # Determine train and evaluation partitions
    if use_stratified_split:
        print("\n>>> Option Selected: Using 80:20 Stratified Split on KDDTrain+ (Working Example Specification)")
        eval_train_df, eval_test_df = perform_stratified_split(train_df, test_size=0.20, random_state=42)
    else:
        print("\n>>> Using Standard Train Partition (KDDTrain+) and Held-out Test Partition (KDDTest+)")
        eval_train_df, eval_test_df = train_df, test_df

    # -------------------------------------------------------------
    # STAGE 3: Data Preprocessing & Feature Normalization
    # -------------------------------------------------------------
    print("\n>>> [STAGE 3] Preprocessing and Feature Normalization...")
    preprocessor = DataPreprocessor()
    
    # Fit preprocessor exclusively on training data to avoid data leakage
    preprocessor.fit(eval_train_df)
    X_train_scaled = preprocessor.transform(eval_train_df)
    X_test_scaled = preprocessor.transform(eval_test_df)
    
    y_train = eval_train_df["binary_label"].values
    y_test = eval_test_df["binary_label"].values

    print(f"[+] Feature matrix shape: Train {X_train_scaled.shape}, Test {X_test_scaled.shape}")

    # -------------------------------------------------------------
    # STAGE 4: Model Training
    # -------------------------------------------------------------
    print("\n>>> [STAGE 4] Training Complementary Machine Learning Models...")
    
    # 4.1 Isolation Forest (Unsupervised Anomaly Detection)
    print("\n--- Model 1: Isolation Forest ---")
    iso_forest = IsolationForestDetector()
    iso_forest.train(X_train_scaled)
    iso_preds = iso_forest.predict(X_test_scaled)
    
    # 4.2 K-Means Clustering (Unsupervised Clustering)
    print("\n--- Model 2: K-Means Clustering ---")
    kmeans = KMeansDetector()
    kmeans.train(X_train_scaled, y_train=y_train)
    kmeans_preds = kmeans.predict(X_test_scaled)
    
    # 4.3 Random Forest Classifier (Supervised Ensemble)
    print("\n--- Model 3: Random Forest Classifier ---")
    rf = RandomForestDetector()
    rf.train(X_train_scaled, y_train=y_train, feature_names=list(X_train_scaled.columns))
    rf_preds = rf.predict(X_test_scaled)
    
    # Save trained model artifacts
    joblib.dump(iso_forest.model, MODELS_DIR / "isolation_forest.joblib")
    joblib.dump(kmeans.model, MODELS_DIR / "kmeans_cluster.joblib")
    joblib.dump(rf.model, MODELS_DIR / "random_forest.joblib")
    print(f"[+] Serialized all 3 trained models to: {MODELS_DIR}")

    # -------------------------------------------------------------
    # STAGE 5: Performance Evaluation & Benchmark Ranking
    # -------------------------------------------------------------
    print("\n>>> [STAGE 5] Calculating Model Performance Metrics...")
    eval_iso = evaluate_binary_model("Isolation Forest", y_test, iso_preds, iso_forest.training_time)
    eval_kmeans = evaluate_binary_model("K-Means", y_test, kmeans_preds, kmeans.training_time)
    eval_rf = evaluate_binary_model("Random Forest", y_test, rf_preds, rf.training_time)
    
    results_list = [eval_iso, eval_kmeans, eval_rf]
    print_evaluation_summary(results_list)
    
    # Save metrics summary to CSV
    df_metrics = create_comparative_table(results_list)
    metrics_csv_path = OUTPUTS_DIR / "metrics_summary.csv"
    df_metrics.to_csv(metrics_csv_path, index=False)
    print(f"[+] Exported comparative performance table to: {metrics_csv_path}")

    # Feature Importance Ranking
    df_importance = rf.get_feature_importances()
    importance_csv_path = OUTPUTS_DIR / "feature_importance_ranking.csv"
    df_importance.to_csv(importance_csv_path, index=False)
    print(f"[+] Exported feature importance rankings to: {importance_csv_path}")

    print("\nTop 5 Most Informative Network Features:")
    for idx, row in df_importance.head(5).iterrows():
        print(f"  {idx+1}. {row['Feature']:<25} (Gini Score: {row['Importance']:.4f})")

    # -------------------------------------------------------------
    # STAGE 6: Visual Analytics Dashboard Generation
    # -------------------------------------------------------------
    print("\n>>> [STAGE 6] Generating 6-Panel Visual Analytics Dashboard...")
    rf_probs = rf.predict_proba(X_test_scaled)
    iso_scores = iso_forest.get_anomaly_scores(X_test_scaled)
    kmeans_dists = kmeans.transform(X_test_scaled)

    generate_all_visualizations(
        df_test_raw=eval_test_df,
        df_test_scaled=X_test_scaled,
        rf_preds=rf_preds,
        rf_probs=rf_probs,
        iso_scores=iso_scores,
        kmeans_dists=kmeans_dists,
        results_list=results_list,
        rf_cm=eval_rf["Confusion Matrix"],
        df_importance=df_importance
    )

    total_time = time.time() - overall_start_time
    minutes, seconds = int(total_time // 60), int(total_time % 60)
    print("\n" + "=" * 80)
    print(f"[+] Pipeline execution completed successfully in {minutes}m {seconds}s.")
    print(f"[+] Static PNG Visualizations saved to: {FIGURES_DIR}")
    print(f"[+] Interactive Web Dashboard saved to:  {OUTPUTS_DIR / 'interactive_dashboard.html'}")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Anomaly Detection ML Pipeline")
    parser.add_argument(
        "--stratified-split",
        action="store_true",
        help="Perform 80:20 stratified split on KDDTrain+ as in the working example, instead of evaluating on KDDTest+"
    )
    args = parser.parse_args()
    
    # Run pipeline
    run_pipeline(use_stratified_split=args.stratified_split)
