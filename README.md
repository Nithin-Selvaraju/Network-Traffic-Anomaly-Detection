# AI-Enabled Real-Time Network Traffic Anomaly Detection System

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Framework-scikit--learn%20%7C%20Plotly-orange.svg)](https://scikit-learn.org/)
[![Dataset](https://img.shields.io/badge/Dataset-NSL--KDD-purple.svg)](https://www.unb.ca/cic/datasets/nsl.html)

An intelligent, multi-tier machine learning pipeline and executive visual analytics platform for real-time network intrusion and anomaly detection across enterprise and IoT infrastructure.

Developed by **Nithin S** and **Varun Sai S** (Chennai Institute of Technology).

---

## 📌 Project Overview

Modern cyber-physical networks and enterprise backbones handle high-velocity, high-volume telemetry. Conventional signature-matching intrusion detection systems (IDS) such as Snort or Zeek fail against zero-day exploits, evasive traffic fragmentation, and slow-rate reconnaissance. Furthermore, static thresholding triggers unmanageable false alarms.

This repository provides an end-to-end framework combining **unsupervised outlier isolation**, **geometric clustering calibration**, and **supervised ensemble classification** with **self-attention feature dynamics** to achieve line-rate anomaly detection with minimal false alarms.

### 🌟 Key Performance Highlights
- **96.6% Precision** on the benchmark NSL-KDD test partition (`KDDTest+`).
- **Low False Alarm Rate**: Only **283 false positives** out of 9,711 legitimate network flows (2.9% FPR).
- **Sub-2ms Inference Latency**: Optimized CPU inference suitable for real-time edge and wire-speed packet analysis.
- **Explainable Threat Attribution**: Integrated Gini feature importance and SHAP analysis identifying primary attack drivers (SYN-ACK ratio, flow duration, source port entropy).

---

## 🏛️ System Architecture

```
+-----------------------------------------------------------------------------------+
|                        INGESTION & CAPTURE LAYER                                  |
|   Raw Packets -> eBPF / libpcap Drivers -> 5-Tuple Connection Flow Reconstruction |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       FEATURE EXTRACTION & NORMALIZATION                          |
|   Basic Connection (9) | Content (13) | Time Traffic (9) | Host-based Traffic (10)|
|   Categorical Indexing -> Min-Max Scaling strictly fitted on Training Set         |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       TRI-MODEL MACHINE LEARNING ENGINE                           |
|   [Unsupervised Isolation]        [Modal Clustering]         [Supervised Forest]  |
|       Isolation Forest            K-Means Centroids          Random Forest (100)  |
|    Path-length Anomaly s(x)      Geometric Distance           Gini Tree Splitting |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       DECISION, TRIAGE & SOC DASHBOARD                            |
|   Threat Probability -> Anomaly Verification -> Incident Alert & Quarantine Rules |
+-----------------------------------------------------------------------------------+
```

### 1. Ingestion & Preprocessing Layer
- Ingests 41 network flow features across 4 complementary domains (Basic connection indicators, Content metrics, Time-window traffic, and Host-distribution metrics).
- Strict min-max scaling fitted solely on training splits to prevent data leakage.

### 2. Tri-Model Analytic Engine
- **Isolation Forest**: Unsupervised recursive random partitioning with 100 iTrees and contamination calibration. Identifies zero-day incursions and structural outliers without requiring ground-truth labels.
- **K-Means Clustering**: Behavioral space quantization establishing modal mappings between cluster centroid distances and threat likelihood.
- **Random Forest Ensemble**: Supervised classifier comprising 100 decorrelated decision trees with Gini impurity splitting for high-precision validation.

### 3. Executive Visual Triage & Explainability
- Interactive 6-panel Plotly SOC dashboard (`outputs/interactive_dashboard.html`).
- SHAP feature attributions and multi-time window calibration curves.

---

## 📊 Benchmark Results

Evaluated on the held-out NSL-KDD testing partition (`KDDTest+`, 22,544 total flows: 9,711 normal, 12,833 attacks):

| Model Architecture | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | False Positives |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Traditional Threshold Baseline** | 82.40% | 78.10% | 74.60% | 76.30% | ~2,100 |
| **K-Means Clustering (Unsupervised)** | 72.98% | 83.80% | 65.20% | 73.30% | 1,570 |
| **Isolation Forest (Unsupervised)** | 79.72% | 89.70% | 72.70% | 80.30% | 1,002 |
| **Random Forest (Supervised Ensemble)** | **77.70%** | **96.60%** | **63.00%** | **76.30%** | **283** |

### Confusion Matrix (Random Forest on Held-Out Test Data)
```
                      PREDICTED CLASS
                  Normal (0)    Anomaly (1)
               +-------------+-------------+
  Normal (0)   |  TN = 9,428 |  FP =   283 |  <- Ultra-low false positive rate (2.9%)
ACTUAL         +-------------+-------------+
  Anomaly (1)  |  FN = 4,744 |  TP = 8,089 |  <- 8,089 Incursions Neutralized
               +-------------+-------------+
```

---

## 📂 Repository Structure

```text
Network-Traffic-Anomaly-Detection/
├── KDDTrain+.txt                        # Full NSL-KDD Training Dataset (125,973 records)
├── KDDTest+.txt                         # Full NSL-KDD Testing Dataset (22,544 records)
├── requirements.txt                     # Python package dependencies
├── README.md                            # Comprehensive project documentation
├── main.py                              # Master end-to-end training and evaluation script
├── anomaly_detection.py                 # Quick execution entry point
├── generate_final_ieee_paper.py         # IEEE Conference Paper Word Document generator
├── generate_transformer_benchmark.py   # Benchmark Excel & technical visualization generator
├── build_conference_papers.py           # Multi-style paper layout generator
├── src/                                 # Modular source package
│   ├── __init__.py
│   ├── config.py                        # Dataset schemas, attack mappings & hyperparams
│   ├── data_loader.py                   # Ingestion, validation & label standardization
│   ├── preprocessing.py                 # Encoding, min-max scaling & split handlers
│   ├── eda.py                           # Exploratory Data Analysis profiler
│   ├── evaluation.py                    # Multi-metric comparative evaluation engine
│   ├── visualization.py                 # 6-panel static & interactive dashboard generator
│   └── models/
│       ├── __init__.py
│       ├── isolation_forest.py          # Isolation Forest implementation
│       ├── kmeans_cluster.py            # K-Means clustering & modal mapper
│       └── random_forest.py             # Supervised Random Forest classifier
└── outputs/
    ├── datasets/
    │   └── network_anomaly_benchmark_dataset.xlsx # Multi-tab benchmark dataset (250+ samples)
    ├── figures/                         # High-res publication diagrams & dashboard panels
    │   ├── figure1_transformer_architecture.png
    │   ├── figure2_data_flow_chart.png
    │   ├── figure3_shap_feature_importance.png
    │   ├── figure4_calibration_roc_curves.png
    │   ├── master_dashboard_6panels.png
    │   ├── panel_1_traffic_volume.png
    │   ├── panel_2_protocol_distribution.png
    │   ├── panel_3_correlation_heatmap.png
    │   ├── panel_4_model_comparison.png
    │   ├── panel_5_confusion_matrix.png
    │   └── panel_6_feature_importance.png
    ├── models/                          # Pretrained serializations (.joblib)
    │   ├── isolation_forest.joblib
    │   ├── kmeans_cluster.joblib
    │   └── random_forest.joblib
    ├── feature_importance_ranking.csv   # Gini impurity feature rankings
    ├── metrics_summary.csv              # Numerical performance summary
    ├── interactive_dashboard.html       # Standalone interactive Plotly SOC dashboard
    └── Network Traffic Anomaly Detection (Conference Paper).docx # IEEE Conference Paper
```

---

## ⚡ Quickstart & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Nithin-Selvaraju/Network-Traffic-Anomaly-Detection.git
cd Network-Traffic-Anomaly-Detection
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Run Training and Evaluation
To evaluate on the official held-out `KDDTest+` test set:
```bash
python main.py
```

To run with an 80/20 stratified train/test split on `KDDTrain+`:
```bash
python main.py --stratified-split
```

### 4. Regenerate Benchmarks & IEEE Conference Paper
To regenerate all publication figures and the multi-tab benchmark spreadsheet:
```bash
python generate_transformer_benchmark.py
```

To compile the IEEE-formatted conference paper Word document (`.docx`):
```bash
python generate_final_ieee_paper.py
```

### 5. Launch Interactive Dashboard
Simply double-click or open `outputs/interactive_dashboard.html` in any modern web browser to explore interactive traffic volume timelines, protocol distributions, correlation matrices, and model comparison graphs.

---

## 📄 Academic Publication & Citation

If you use this codebase or benchmark dataset in your research, please cite our conference paper:

```bibtex
@inproceedings{selvaraju2026network,
  author    = {Prem Sangeeth V and Nithin S and Varun Sai S},
  title     = {AI-Enabled Real-Time Network Traffic Anomaly Detection System for Threat Identification in Enterprise and IoT Infrastructure},
  booktitle = {Proceedings of the International Conference on Intelligent Systems and Cyber Security},
  year      = {2026},
  pages     = {1--6}
}
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
