"""
Comprehensive Generator for Network Anomaly Detection:
1. Multi-Tab Benchmark Excel Dataset (Full Dataset 250+ rows, 80% Train, 20% Test)
2. Figure 1: Publication-Grade Detailed Transformer Encoder Architecture Diagram
3. Figure 2: End-to-End Network Data Flow Chart (PCAP to Threat Output)
4. Figure 3: SHAP Feature Importance Summary Plot (matching user reference style)
5. Figure 4: Model Calibration Curve & Multi-Window ROC Analysis (1-min, 5-min, 10-min)
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, ArrowStyle, BoxStyle
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.calibration import calibration_curve
from sklearn.metrics import roc_curve, auc, brier_score_loss
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Ensure output directories exist
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")
DATASETS_DIR = os.path.join(OUTPUTS_DIR, "datasets")
FIGURES_DIR = os.path.join(OUTPUTS_DIR, "figures")
os.makedirs(DATASETS_DIR, exist_ok=True)
os.makedirs(FIGURES_DIR, exist_ok=True)

# Set random seed for scientific reproducibility
np.random.seed(42)


# ==============================================================================
# 1. EXCEL BENCHMARK DATASET GENERATION (3 TABS)
# ==============================================================================

def generate_network_anomaly_excel(num_samples: int = 260) -> str:
    """
    Generates a realistic mock dataset containing:
    - Flow identifiers and temporal metadata
    - Core network flow features (Packet Rate, Byte Count, Flow Duration, Syn-Ack Ratio, Entropy, etc.)
    - Ground truth labels (0: Normal, 1: Anomaly)
    - Multi-window anomaly scores & performance metrics (1-min, 5-min, 10-min)
    Exports to a styled Excel file with 3 tabs: 'Full Dataset', 'Training Set', 'Testing Set'.
    """
    print(f"\n[*] Generating {num_samples} realistic network flow samples across 3 tabs...")
    
    # 1. Generate Timestamps & Flow Identifiers
    start_time = pd.Timestamp("2026-09-17 08:00:00")
    timestamps = [start_time + pd.Timedelta(seconds=int(i * 14.5 + np.random.uniform(0, 5))) for i in range(num_samples)]
    flow_ids = [f"FLOW-2026-XF{i+1001:05d}" for i in range(num_samples)]
    
    # Attack mixture: ~68% Normal, ~32% Anomalies (DoS, PortScan, DDoS, Exfiltration, BruteForce)
    attack_types_pool = ["Normal", "DoS_SYN_Flood", "Port_Scan", "DDoS_UDP_Amp", "Data_Exfiltration", "SSH_Brute_Force"]
    p_attack = [0.68, 0.12, 0.08, 0.05, 0.04, 0.03]
    assigned_attacks = np.random.choice(attack_types_pool, size=num_samples, p=p_attack)
    labels = np.array([0 if a == "Normal" else 1 for a in assigned_attacks])
    
    # Generate Domain-Consistent Flow Features
    protocols = []
    pkt_rates = []
    byte_counts = []
    flow_durs = []
    syn_ack_ratios = []
    src_port_entropies = []
    pkt_len_stds = []
    tcp_win_sizes = []
    
    for atk in assigned_attacks:
        if atk == "Normal":
            proto = np.random.choice(["TCP", "UDP", "ICMP"], p=[0.75, 0.22, 0.03])
            dur = np.random.exponential(scale=12.0) + 0.1
            pkt_rate = np.random.gamma(shape=4.0, scale=8.0) + 2.0
            byte_cnt = int(dur * pkt_rate * np.random.uniform(400, 850)) + 120
            sa_ratio = np.random.normal(loc=1.02, scale=0.08)
            entropy = np.random.uniform(3.4, 4.8)
            std_len = np.random.uniform(180, 420)
            win_sz = int(np.random.choice([16384, 32768, 65535]) + np.random.normal(0, 500))
        elif atk == "DoS_SYN_Flood":
            proto = "TCP"
            dur = np.random.uniform(0.01, 1.8)
            pkt_rate = np.random.uniform(450, 1850)
            byte_cnt = int(pkt_rate * dur * 64) + 64
            sa_ratio = np.random.uniform(15.0, 95.0)  # Huge SYN without ACK
            entropy = np.random.uniform(1.2, 2.1)
            std_len = np.random.uniform(2.0, 15.0)    # Uniform small packet headers
            win_sz = int(np.random.choice([1024, 2048, 4096]))
        elif atk == "Port_Scan":
            proto = "TCP"
            dur = np.random.uniform(0.05, 3.5)
            pkt_rate = np.random.uniform(45, 220)
            byte_cnt = int(pkt_rate * dur * 54) + 40
            sa_ratio = np.random.uniform(4.5, 12.0)
            entropy = np.random.uniform(6.8, 7.9)     # Rapid high source/destination port variance
            std_len = np.random.uniform(4.0, 22.0)
            win_sz = 1024
        elif atk == "DDoS_UDP_Amp":
            proto = "UDP"
            dur = np.random.uniform(1.0, 8.0)
            pkt_rate = np.random.uniform(600, 2400)
            byte_cnt = int(pkt_rate * dur * 1150)
            sa_ratio = 0.0  # UDP stateless
            entropy = np.random.uniform(1.0, 1.8)
            std_len = np.random.uniform(5.0, 28.0)
            win_sz = 0
        elif atk == "Data_Exfiltration":
            proto = "TCP"
            dur = np.random.uniform(45.0, 320.0)
            pkt_rate = np.random.uniform(80, 250)
            byte_cnt = int(pkt_rate * dur * 1380)    # Jumbo payload exfiltration
            sa_ratio = np.random.normal(loc=1.0, scale=0.04)
            entropy = np.random.uniform(4.2, 5.1)
            std_len = np.random.uniform(550, 780)
            win_sz = 65535
        else: # SSH Brute Force
            proto = "TCP"
            dur = np.random.uniform(8.0, 45.0)
            pkt_rate = np.random.uniform(15, 60)
            byte_cnt = int(pkt_rate * dur * 210)
            sa_ratio = np.random.uniform(1.8, 3.2)
            entropy = np.random.uniform(2.8, 3.9)
            std_len = np.random.uniform(110, 260)
            win_sz = 29200

        protocols.append(proto)
        pkt_rates.append(round(pkt_rate, 2))
        byte_counts.append(max(60, byte_cnt))
        flow_durs.append(round(dur, 3))
        syn_ack_ratios.append(round(max(0.0, sa_ratio), 2))
        src_port_entropies.append(round(entropy, 3))
        pkt_len_stds.append(round(std_len, 2))
        tcp_win_sizes.append(max(0, win_sz))

    # Calculate Multi-Window Anomaly Scores & FPR vs TPR metrics
    # Base probability driven by features + realistic stochastic noise
    feat_linear = (
        0.35 * (np.array(syn_ack_ratios) / 25.0) +
        0.25 * (np.array(pkt_rates) / 800.0) +
        0.20 * (np.array(src_port_entropies) / 7.0) +
        0.20 * labels
    )
    base_prob = 1.0 / (1.0 + np.exp(-3.5 * (feat_linear - 0.45)))
    
    # 1-min window: higher variance / quick detection
    score_1m = np.clip(base_prob + np.random.normal(0, 0.09, num_samples), 0.01, 0.99)
    # 5-min window: smoothed feature aggregation
    score_5m = np.clip(base_prob + np.random.normal(0, 0.05, num_samples), 0.01, 0.99)
    # 10-min window: robust high-confidence statistical window
    score_10m = np.clip(base_prob + np.random.normal(0, 0.02, num_samples), 0.01, 0.99)

    pred_1m = (score_1m >= 0.50).astype(int)
    pred_5m = (score_5m >= 0.50).astype(int)
    pred_10m = (score_10m >= 0.50).astype(int)

    # Window-level TPR and FPR progressive metrics
    fpr_1m = np.round(np.where((labels == 0) & (pred_1m == 1), 0.042, 0.015) + np.random.uniform(0, 0.008, num_samples), 4)
    tpr_1m = np.round(np.where((labels == 1) & (pred_1m == 1), 0.938, 0.885) + np.random.uniform(0, 0.012, num_samples), 4)

    fpr_5m = np.round(np.where((labels == 0) & (pred_5m == 1), 0.024, 0.009) + np.random.uniform(0, 0.005, num_samples), 4)
    tpr_5m = np.round(np.where((labels == 1) & (pred_5m == 1), 0.968, 0.920) + np.random.uniform(0, 0.008, num_samples), 4)

    fpr_10m = np.round(np.where((labels == 0) & (pred_10m == 1), 0.012, 0.004) + np.random.uniform(0, 0.003, num_samples), 4)
    tpr_10m = np.round(np.where((labels == 1) & (pred_10m == 1), 0.988, 0.955) + np.random.uniform(0, 0.005, num_samples), 4)

    # Create master dataframe
    df_full = pd.DataFrame({
        "Flow_ID": flow_ids,
        "Timestamp": timestamps,
        "Protocol": protocols,
        "Packet_Rate_pps": pkt_rates,
        "Byte_Count_bytes": byte_counts,
        "Flow_Duration_sec": flow_durs,
        "Syn_Ack_Ratio": syn_ack_ratios,
        "Src_Port_Entropy": src_port_entropies,
        "Pkt_Length_StdDev": pkt_len_stds,
        "TCP_Window_Size": tcp_win_sizes,
        "Ground_Truth_Label": labels,
        "Attack_Subcategory": assigned_attacks,
        "Anomaly_Score_1min": np.round(score_1m, 4),
        "Predicted_Label_1min": pred_1m,
        "FPR_1min": fpr_1m,
        "TPR_1min": tpr_1m,
        "Anomaly_Score_5min": np.round(score_5m, 4),
        "Predicted_Label_5min": pred_5m,
        "FPR_5min": fpr_5m,
        "TPR_5min": tpr_5m,
        "Anomaly_Score_10min": np.round(score_10m, 4),
        "Predicted_Label_10min": pred_10m,
        "FPR_10min": fpr_10m,
        "TPR_10min": tpr_10m
    })

    # Perform 80% / 20% Stratified Split
    train_idx, test_idx = train_test_split(
        df_full.index, test_size=0.20, random_state=42, stratify=df_full["Ground_Truth_Label"]
    )
    df_train = df_full.loc[train_idx].copy().sort_index().reset_index(drop=True)
    df_test = df_full.loc[test_idx].copy().sort_index().reset_index(drop=True)

    # Export to Multi-Tab Styled Excel Workbook
    excel_path = os.path.join(DATASETS_DIR, "network_anomaly_benchmark_dataset.xlsx")
    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        df_full.to_excel(writer, sheet_name="Full Dataset", index=False)
        df_train.to_excel(writer, sheet_name="Training Set", index=False)
        df_test.to_excel(writer, sheet_name="Testing Set", index=False)

    # Apply professional styling via openpyxl
    wb = openpyxl.load_workbook(excel_path)
    
    header_fill_full = PatternFill(start_color="1E3A8A", end_color="1E3A8A", fill_type="solid") # Dark Blue
    header_fill_train = PatternFill(start_color="047857", end_color="047857", fill_type="solid") # Emerald Green
    header_fill_test = PatternFill(start_color="7C3AED", end_color="7C3AED", fill_type="solid") # Purple
    
    header_font = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")
    data_font = Font(name="Segoe UI", size=9.5)
    border_thin = Border(
        left=Side(style="thin", color="E2E8F0"),
        right=Side(style="thin", color="E2E8F0"),
        top=Side(style="thin", color="E2E8F0"),
        bottom=Side(style="thin", color="E2E8F0")
    )

    tab_colors = {
        "Full Dataset": header_fill_full,
        "Training Set": header_fill_train,
        "Testing Set": header_fill_test
    }

    for sheet_name, fill_color in tab_colors.items():
        ws = wb[sheet_name]
        ws.views.sheetView[0].showGridLines = True
        
        # Style Header Row
        for col_num in range(1, ws.max_column + 1):
            cell = ws.cell(row=1, column=col_num)
            cell.fill = fill_color
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            ws.row_dimensions[1].height = 28
            
        # Style Data Rows and auto-fit column width
        for row in range(2, ws.max_row + 1):
            ws.row_dimensions[row].height = 19
            for col in range(1, ws.max_column + 1):
                cell = ws.cell(row=row, column=col)
                cell.font = data_font
                cell.border = border_thin
                if col in [1, 2, 3, 12]:
                    cell.alignment = Alignment(horizontal="center")
                else:
                    cell.alignment = Alignment(horizontal="right")
                    
        for col in ws.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            col_letter = get_column_letter(col[0].column)
            ws.column_dimensions[col_letter].width = max(max_len + 3, 13)

    wb.save(excel_path)
    print(f"[+] Multi-Tab Excel Workbook generated successfully at:\n    {excel_path}")
    print(f"    - Full Dataset: {len(df_full)} rows")
    print(f"    - Training Set (80%): {len(df_train)} rows")
    print(f"    - Testing Set (20%): {len(df_test)} rows")
    return excel_path


# ==============================================================================
# 2. FIGURE 1: DETAILED TRANSFORMER ENCODER ARCHITECTURE DIAGRAM
# ==============================================================================

def render_figure_1_transformer_architecture(save_path: str):
    """
    Renders a comprehensive, publication-ready vector diagram of the Transformer
    Encoder Pipeline adapted specifically for Network Traffic Anomaly Detection.
    Matches the structure and technical fidelity of the user's reference diagram.
    """
    print("\n[*] Rendering Figure 1: Detailed Transformer Encoder Architecture Diagram...")
    
    fig = plt.figure(figsize=(18, 11), dpi=300)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Background canvas
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#f8fafc")

    # Title Banner
    ax.text(50, 97.2, "Detailed Transformer Encoder Block in NetAnomaly-TransNet",
            fontsize=21, fontweight="bold", ha="center", va="center", color="#0f172a", fontfamily="sans-serif")
    ax.text(50, 95.0, "Deep Self-Attention & Contextual Feature Representation for Network Traffic Anomaly Detection",
            fontsize=12, style="italic", ha="center", va="center", color="#475569")

    # -------------------------------------------------------------
    # 1. INPUT TO ENCODER SECTION (Left: x in [2, 16])
    # -------------------------------------------------------------
    input_box = FancyBboxPatch((2, 33), 14, 59, boxstyle="round,pad=0.5,rounding_size=1.2",
                               fc="#ffffff", ec="#1e40af", lw=1.8)
    ax.add_patch(input_box)
    
    # Input Header
    in_header = FancyBboxPatch((2, 88.5), 14, 3.5, boxstyle="round,pad=0.2,rounding_size=0.5",
                               fc="#1e40af", ec="#1e40af")
    ax.add_patch(in_header)
    ax.text(9, 90.2, "INPUT TO ENCODER", color="#ffffff", fontweight="bold", fontsize=10, ha="center", va="center")

    ax.text(9, 86.5, "Embedded Flow Matrix", fontsize=9.5, fontweight="bold", ha="center", color="#1e293b")
    ax.text(9, 84.8, r"$X^{(0)} \in \mathbb{R}^{n \times d_{\mathrm{model}}}$", fontsize=10, ha="center", color="#2563eb")

    # Matrix Grid Graphic (Flow features)
    colors = ["#fed7aa", "#fde047", "#86efac", "#93c5fd", "#c4b5fd", "#f472b6"]
    for row in range(5):
        for col in range(5):
            c_idx = (row * 2 + col) % len(colors)
            rect = patches.Rectangle((4.2 + col * 1.8, 73.5 - row * 1.8), 1.6, 1.6,
                                     fc=colors[c_idx], ec="#64748b", lw=0.6, alpha=0.85)
            ax.add_patch(rect)
    ax.text(3.4, 69.5, r"$n$ (flows)", fontsize=8, rotation=90, va="center", color="#475569")
    ax.text(8.7, 63.8, r"$d_{\mathrm{model}}$ (flow dim)", fontsize=8, ha="center", color="#475569")

    # Plus sign
    circ_plus1 = patches.Circle((9, 60.5), 1.2, fc="#f1f5f9", ec="#3b82f6", lw=1.2)
    ax.add_patch(circ_plus1)
    ax.text(9, 60.5, "+", fontsize=13, fontweight="bold", ha="center", va="center", color="#1e40af")

    # Positional Encoding Box
    ax.text(9, 57.5, "Positional Encoding (Sinusoidal)", fontsize=8.5, fontweight="bold", ha="center", color="#1e293b")
    ax.text(9, 56.0, r"$P \in \mathbb{R}^{n \times d_{\mathrm{model}}}$ (Temporal Sequence)", fontsize=7.5, ha="center", color="#64748b")
    # Waveform lines
    x_wave = np.linspace(4.2, 13.5, 80)
    for idx, ph in enumerate([0, 1.2, 2.5, 3.8]):
        y_wave = 52.5 - idx * 1.5 + 0.5 * np.sin(x_wave * 1.8 + ph)
        ax.plot(x_wave, y_wave, lw=1.2, color=["#0284c7", "#10b981", "#f59e0b", "#8b5cf6"][idx])

    # Plus sign 2
    circ_plus2 = patches.Circle((9, 45.0), 1.2, fc="#f1f5f9", ec="#3b82f6", lw=1.2)
    ax.add_patch(circ_plus2)
    ax.text(9, 45.0, "+", fontsize=13, fontweight="bold", ha="center", va="center", color="#1e40af")

    # Input to layer
    ax.text(9, 42.0, "Input to Encoder Layer", fontsize=8.5, fontweight="bold", ha="center", color="#1e293b")
    ax.text(9, 40.2, r"$H^{(0)} = X^{(0)} + P \in \mathbb{R}^{n \times d_{\mathrm{model}}}$", fontsize=8.5, ha="center", color="#1d4ed8")
    for row in range(3):
        for col in range(5):
            rect = patches.Rectangle((4.2 + col * 1.8, 38.0 - row * 1.5), 1.6, 1.3,
                                     fc="#60a5fa", ec="#1e40af", lw=0.6, alpha=0.75)
            ax.add_patch(rect)

    # Arrow to Stacked Encoder
    ax.annotate("", xy=(18.5, 62.5), xytext=(16.2, 62.5),
                arrowprops=dict(arrowstyle="-|>", lw=2.0, color="#1e293b", mutation_scale=15))

    # -------------------------------------------------------------
    # 2. STACKED ENCODER SECTION (Middle-Left: x in [19, 29])
    # -------------------------------------------------------------
    stack_box = FancyBboxPatch((19, 33), 10, 59, boxstyle="round,pad=0.5,rounding_size=1.0",
                               fc="#f8fafc", ec="#059669", lw=1.8)
    ax.add_patch(stack_box)
    
    stack_hdr = FancyBboxPatch((19, 88.5), 10, 3.5, boxstyle="round,pad=0.2,rounding_size=0.5",
                               fc="#059669", ec="#059669")
    ax.add_patch(stack_hdr)
    ax.text(24, 90.2, "STACKED ENCODER", color="#ffffff", fontweight="bold", fontsize=9, ha="center", va="center")

    layer_names = ["Encoder Layer 1", "Encoder Layer 2", r"$\vdots$", "Encoder Layer L"]
    layer_y = [82, 73, 63, 53]
    for idx, (name, y) in enumerate(zip(layer_names, layer_y)):
        if name == r"$\vdots$":
            ax.text(24, y + 1.5, r"$\vdots$", fontsize=16, ha="center", va="center", color="#059669", fontweight="bold")
        else:
            box = FancyBboxPatch((20.2, y), 7.6, 5.0, boxstyle="round,pad=0.2,rounding_size=0.6",
                                 fc="#ecfdf5", ec="#10b981", lw=1.2)
            ax.add_patch(box)
            ax.text(24, y + 2.5, name, fontsize=8.5, fontweight="bold", ha="center", va="center", color="#065f46")
            if idx < 3 and layer_names[idx+1] != r"$\vdots$":
                ax.annotate("", xy=(24, y - 0.2), xytext=(24, y + 0.1),
                            arrowprops=dict(arrowstyle="-|>", lw=1.5, color="#059669"))

    ax.text(24, 43.0, r"$L$ : Number of Stacked" + "\n" + r"Encoder Layers (e.g., $L=6$)",
            fontsize=8, ha="center", va="center", color="#065f46",
            bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#6ee7b7", lw=1))

    # Zoom dashed lines expanding from Encoder Layer l to Single Encoder Layer
    ax.plot([27.8, 31.0], [75.5, 92.0], color="#059669", lw=1.2, ls="--")
    ax.plot([27.8, 31.0], [70.5, 33.0], color="#059669", lw=1.2, ls="--")

    # -------------------------------------------------------------
    # 3. SINGLE ENCODER LAYER (l) DETAILED BOX (Center: x in [31, 84])
    # -------------------------------------------------------------
    layer_detail_box = FancyBboxPatch((31, 33), 54, 59, boxstyle="round,pad=0.6,rounding_size=1.2",
                                      fc="#ffffff", ec="#059669", lw=2.0)
    ax.add_patch(layer_detail_box)

    layer_detail_hdr = FancyBboxPatch((47, 88.7), 22, 3.2, boxstyle="round,pad=0.2,rounding_size=0.6",
                                      fc="#059669", ec="#059669")
    ax.add_patch(layer_detail_hdr)
    ax.text(58, 90.3, "SINGLE ENCODER LAYER (l)", color="#ffffff", fontweight="bold", fontsize=10, ha="center", va="center")

    # SUB-BLOCK 1: MULTI-HEAD SELF-ATTENTION
    mha_box = FancyBboxPatch((32.5, 59.5), 51.0, 27.5, boxstyle="round,pad=0.4,rounding_size=0.8",
                             fc="#fffbeb", ec="#d97706", lw=1.5)
    ax.add_patch(mha_box)
    ax.text(58, 85.0, "1) MULTI-HEAD SELF-ATTENTION (MHA)", fontsize=10.5, fontweight="bold", ha="center", color="#92400e")

    # Input H^(l-1)
    ax.text(35.5, 80.5, "Input", fontsize=8, ha="center", color="#64748b")
    ax.text(35.5, 78.8, r"$H^{(l-1)} \in \mathbb{R}^{n \times d_{\mathrm{model}}}$", fontsize=8.5, ha="center", color="#1e3a8a", fontweight="bold")
    for r in range(3):
        for c in range(3):
            ax.add_patch(patches.Rectangle((33.8 + c * 1.1, 74.5 - r * 1.1), 1.0, 1.0, fc="#c7d2fe", ec="#4338ca", lw=0.5))

    # Linear Projections W_Q, W_K, W_V
    wp_names = [r"Linear $W_Q$", r"Linear $W_K$", r"Linear $W_V$"]
    wp_colors = ["#dbeafe", "#fef3c7", "#ffedd5"]
    wp_borders = ["#2563eb", "#d97706", "#ea580c"]
    wp_y = [79.5, 74.0, 68.5]
    for name, c, b, y in zip(wp_names, wp_colors, wp_borders, wp_y):
        ax.add_patch(FancyBboxPatch((41.5, y - 1.5), 5.2, 2.8, boxstyle="round,pad=0.2", fc=c, ec=b, lw=1.2))
        ax.text(44.1, y - 0.1, name, fontsize=8, ha="center", va="center", color=b, fontweight="bold")
        # arrows from input
        ax.annotate("", xy=(41.3, y - 0.1), xytext=(37.5, 75.0),
                    arrowprops=dict(arrowstyle="-|>", lw=1.0, color="#64748b"))

    # Q, K, V Vectors & Multi-head split
    for y, label, col_fill in zip(wp_y, ["Q", "K", "V"], ["#93c5fd", "#fde047", "#fdba74"]):
        ax.text(48.5, y + 0.6, label, fontsize=8.5, fontweight="bold", ha="center", color="#1e293b")
        # vector block
        ax.add_patch(patches.Rectangle((47.8, y - 1.6), 1.4, 2.0, fc=col_fill, ec="#475569", lw=0.6))
        ax.text(48.5, y - 2.1, r"$n \times d_k$", fontsize=6.5, ha="center", color="#64748b")
        ax.annotate("", xy=(47.6, y - 0.1), xytext=(46.8, y - 0.1),
                    arrowprops=dict(arrowstyle="-|>", lw=1.0, color="#475569"))

    ax.text(53.0, 81.5, "Split into\n" + r"$h$ heads", fontsize=7.5, fontweight="bold", ha="center", color="#92400e")
    # Stacked heads visual
    for idx, c_head in enumerate(["#c084fc", "#34d399", "#fbbf24"]):
        ax.add_patch(patches.Rectangle((51.5 + idx * 0.7, 76.5 - idx * 2.2), 1.8, 1.8, fc=c_head, ec="#334155", lw=0.6, alpha=0.85))

    # Scaled Dot-Product Box
    sdp_box = FancyBboxPatch((57.0, 68.5), 11.5, 8.5, boxstyle="round,pad=0.3", fc="#fee2e2", ec="#ef4444", lw=1.4)
    ax.add_patch(sdp_box)
    ax.text(62.75, 74.5, "Scaled Dot-Product\nAttention", fontsize=8.5, fontweight="bold", ha="center", color="#991b1b")
    ax.text(62.75, 70.8, r"$\mathrm{Attention}(Q, K, V)$" + "\n" + r"$= \mathrm{softmax}\left(\frac{QK^T}{\sqrt{d_k}}\right)V$",
            fontsize=7.5, ha="center", color="#7f1d1d")

    # Concat Box
    ax.add_patch(FancyBboxPatch((70.5, 68.5), 2.8, 8.5, boxstyle="round,pad=0.2", fc="#ede9fe", ec="#7c3aed", lw=1.2))
    ax.text(71.9, 78.2, "Concat", fontsize=7.5, fontweight="bold", ha="center", color="#6d28d9")
    for i, c_sub in enumerate(["#c084fc", "#34d399", "#fbbf24"]):
        ax.add_patch(patches.Rectangle((70.8, 74.5 - i * 2.0), 2.2, 1.6, fc=c_sub, ec="#475569", lw=0.5))

    # Linear Projection W_O
    ax.add_patch(FancyBboxPatch((74.8, 71.0), 4.5, 3.5, boxstyle="round,pad=0.2", fc="#f1f5f9", ec="#334155", lw=1.2))
    ax.text(77.05, 73.2, "Linear\n" + r"$W_O$", fontsize=8, fontweight="bold", ha="center", va="center", color="#1e293b")

    # Add & Norm 1
    circ_add1 = patches.Circle((81.0, 72.75), 1.2, fc="#f8fafc", ec="#0f172a", lw=1.4)
    ax.add_patch(circ_add1)
    ax.text(81.0, 72.75, "+", fontsize=13, fontweight="bold", ha="center", va="center", color="#0f172a")

    ax.add_patch(FancyBboxPatch((78.5, 62.0), 5.0, 5.5, boxstyle="round,pad=0.2", fc="#e0f2fe", ec="#0284c7", lw=1.2))
    ax.text(81.0, 65.5, "Add & Norm\n(LayerNorm)", fontsize=7.5, fontweight="bold", ha="center", color="#0369a1")
    ax.text(81.0, 63.0, r"$Z^{(l)} \in \mathbb{R}^{n \times d_{\mathrm{model}}}$", fontsize=7.5, ha="center", color="#075985")

    # Residual Connection Arrow (Top)
    ax.plot([36.0, 36.0, 81.0], [80.0, 84.0, 84.0], color="#d97706", lw=1.4, ls="--")
    ax.annotate("", xy=(81.0, 74.2), xytext=(81.0, 84.0),
                arrowprops=dict(arrowstyle="-|>", lw=1.4, color="#d97706", ls="--"))

    # SUB-BLOCK 2: POSITION-WISE FEED-FORWARD NETWORK
    ffn_box = FancyBboxPatch((32.5, 35.0), 51.0, 22.0, boxstyle="round,pad=0.4,rounding_size=0.8",
                             fc="#eff6ff", ec="#2563eb", lw=1.5)
    ax.add_patch(ffn_box)
    ax.text(58, 54.5, "2) POSITION-WISE FEED-FORWARD NETWORK (FFN)", fontsize=10.5, fontweight="bold", ha="center", color="#1e40af")

    # Intermediate Z^(l) input
    ax.text(35.5, 50.0, r"$Z^{(l)}$", fontsize=9, fontweight="bold", ha="center", color="#1e40af")
    for r in range(3):
        for c in range(3):
            ax.add_patch(patches.Rectangle((33.8 + c * 1.1, 46.5 - r * 1.1), 1.0, 1.0, fc="#93c5fd", ec="#1d4ed8", lw=0.5))

    # FFN Operations: Linear W1 -> GELU -> Linear W2
    ax.add_patch(FancyBboxPatch((42.5, 43.0), 8.5, 5.0, boxstyle="round,pad=0.2", fc="#dcfce7", ec="#16a34a", lw=1.2))
    ax.text(46.75, 46.2, r"Linear $W_1$", fontsize=8.5, fontweight="bold", ha="center", color="#15803d")
    ax.text(46.75, 44.2, r"$(d_{\mathrm{model}} \to d_{\mathrm{ff}})$", fontsize=7.5, ha="center", color="#166534")

    ax.annotate("", xy=(53.5, 45.5), xytext=(51.2, 45.5), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#1e293b"))

    ax.add_patch(FancyBboxPatch((54.0, 43.0), 6.5, 5.0, boxstyle="round,pad=0.2", fc="#fef9c3", ec="#ca8a04", lw=1.2))
    ax.text(57.25, 46.2, "GELU", fontsize=9, fontweight="bold", ha="center", color="#854d0e")
    ax.text(57.25, 44.2, "Activation", fontsize=7.5, ha="center", color="#713f12")

    ax.annotate("", xy=(63.0, 45.5), xytext=(60.7, 45.5), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#1e293b"))

    ax.add_patch(FancyBboxPatch((63.5, 43.0), 8.5, 5.0, boxstyle="round,pad=0.2", fc="#dcfce7", ec="#16a34a", lw=1.2))
    ax.text(67.75, 46.2, r"Linear $W_2$", fontsize=8.5, fontweight="bold", ha="center", color="#15803d")
    ax.text(67.75, 44.2, r"$(d_{\mathrm{ff}} \to d_{\mathrm{model}})$", fontsize=7.5, ha="center", color="#166534")

    # Add & Norm 2
    circ_add2 = patches.Circle((75.5, 45.5), 1.2, fc="#f8fafc", ec="#0f172a", lw=1.4)
    ax.add_patch(circ_add2)
    ax.text(75.5, 45.5, "+", fontsize=13, fontweight="bold", ha="center", va="center", color="#0f172a")

    ax.add_patch(FancyBboxPatch((78.5, 42.5), 5.0, 5.5, boxstyle="round,pad=0.2", fc="#e0f2fe", ec="#0284c7", lw=1.2))
    ax.text(81.0, 46.0, "Add & Norm\n(LayerNorm)", fontsize=7.5, fontweight="bold", ha="center", color="#0369a1")
    ax.text(81.0, 43.5, r"$H^{(l)} \in \mathbb{R}^{n \times d_{\mathrm{model}}}$", fontsize=7.5, ha="center", color="#075985")

    # Residual Connection Arrow (Bottom FFN)
    ax.plot([37.5, 37.5, 75.5], [48.0, 51.5, 51.5], color="#2563eb", lw=1.4, ls="--")
    ax.annotate("", xy=(75.5, 47.0), xytext=(75.5, 51.5),
                arrowprops=dict(arrowstyle="-|>", lw=1.4, color="#2563eb", ls="--"))

    # Connecting arrow from MHA LayerNorm to FFN
    ax.annotate("", xy=(81.0, 61.8), xytext=(81.0, 48.2),
                arrowprops=dict(arrowstyle="<-", lw=1.4, color="#059669", ls="--"))

    # Repeat loop note
    ax.text(58, 32.2, r"$\longleftarrow$  Repeat for $L$ Layers ($l = 1, \dots, L$)  $\longrightarrow$",
            fontsize=8.5, fontweight="bold", ha="center", color="#059669",
            bbox=dict(boxstyle="round,pad=0.2", fc="#f0fdf4", ec="#86efac"))

    # -------------------------------------------------------------
    # 4. OUTPUT OF ENCODER SECTION (Right: x in [86, 98])
    # -------------------------------------------------------------
    output_box = FancyBboxPatch((86, 33), 12, 59, boxstyle="round,pad=0.5,rounding_size=1.2",
                                fc="#ffffff", ec="#1e40af", lw=1.8)
    ax.add_patch(output_box)
    
    out_header = FancyBboxPatch((86, 88.5), 12, 3.5, boxstyle="round,pad=0.2,rounding_size=0.5",
                                fc="#1e40af", ec="#1e40af")
    ax.add_patch(out_header)
    ax.text(92, 90.2, "OUTPUT OF ENCODER", color="#ffffff", fontweight="bold", fontsize=9, ha="center", va="center")

    ax.text(92, 85.5, "Contextual Representations", fontsize=8.5, fontweight="bold", ha="center", color="#1e293b")
    ax.text(92, 83.5, r"$H^{(L)} \in \mathbb{R}^{n \times d_{\mathrm{model}}}$", fontsize=9.5, ha="center", color="#2563eb")

    # Output representation grid
    for row in range(5):
        for col in range(5):
            val = 0.3 + 0.6 * np.sin(row + col * 0.8)
            col_hex = plt.cm.Blues(int(val * 255))
            rect = patches.Rectangle((87.5 + col * 1.6, 76.0 - row * 1.6), 1.4, 1.4,
                                     fc=col_hex, ec="#1e40af", lw=0.5)
            ax.add_patch(rect)

    ax.text(92, 64.0, "These context-aware\nrepresentations capture\ncomplex non-linear\ncorrelations among\nnetwork flow features\n(e.g., SYN-ACK ratio,\npacket entropy, jitter).",
            fontsize=7.8, ha="center", color="#334155", style="italic",
            bbox=dict(boxstyle="round,pad=0.3", fc="#f1f5f9", ec="#cbd5e1", lw=0.8))

    # MLP Classification Head at Bottom of Output
    ax.add_patch(FancyBboxPatch((87.0, 43.0), 10.0, 7.5, boxstyle="round,pad=0.2", fc="#fef2f2", ec="#ef4444", lw=1.4))
    ax.text(92, 48.5, "Anomaly Classifier", fontsize=8.5, fontweight="bold", ha="center", color="#991b1b")
    ax.text(92, 46.5, r"MLP $\to$ Softmax", fontsize=7.8, ha="center", color="#b91c1c")
    ax.text(92, 44.5, "Threat Score [0, 1]", fontsize=7.5, fontweight="bold", ha="center", color="#ef4444")

    # Arrow from Layer L to Output
    ax.annotate("", xy=(85.8, 45.5), xytext=(83.7, 45.5),
                arrowprops=dict(arrowstyle="-|>", lw=2.0, color="#1e3a8a", mutation_scale=15))

    # -------------------------------------------------------------
    # 5. BOTTOM SPECIFICATION & MATHEMATICAL DETAIL BOXES
    # -------------------------------------------------------------
    # Box 1: Dimensions
    box1 = FancyBboxPatch((2, 3), 20, 26, boxstyle="round,pad=0.4", fc="#ffffff", ec="#cbd5e1", lw=1.2)
    ax.add_patch(box1)
    ax.text(12, 26.5, "DIMENSIONS", fontsize=9.5, fontweight="bold", ha="center", color="#4338ca")
    dims_text = (
        r"$n$" + "       : Number of network flows in batch\n\n" +
        r"$d_{\mathrm{model}}$" + " : Flow embedding dimension (e.g., 64)\n\n" +
        r"$d_{\mathrm{ff}}$" + "    : Feed-forward hidden dim (typically " + r"$4 \times d_{\mathrm{model}}$" + ")\n\n" +
        r"$h$" + "       : Number of attention heads (e.g., 8)\n\n" +
        r"$d_k$" + "     : Head dimension = " + r"$d_{\mathrm{model}} / h$"
    )
    ax.text(3, 14.5, dims_text, fontsize=8, color="#1e293b", va="center")

    # Box 2: Multi-Head Attention Computation
    box2 = FancyBboxPatch((23.5, 3), 26.5, 26, boxstyle="round,pad=0.4", fc="#ffffff", ec="#cbd5e1", lw=1.2)
    ax.add_patch(box2)
    ax.text(36.75, 26.5, "MULTI-HEAD ATTENTION COMPUTATION", fontsize=9.5, fontweight="bold", ha="center", color="#4338ca")
    math_text = (
        r"$Q = H^{(l-1)}W_Q, \quad K = H^{(l-1)}W_K, \quad V = H^{(l-1)}W_V$" + "\n\n" +
        r"$\mathrm{head}_i = \mathrm{Attention}(Q_i, K_i, V_i)$" + "\n\n" +
        r"where  $Q_i = QW_i^Q, \quad K_i = KW_i^K, \quad V_i = VW_i^V$" + "\n\n" +
        r"$\mathrm{Attention}(Q_i, K_i, V_i) = \mathrm{softmax}\left(\frac{Q_i K_i^T}{\sqrt{d_k}}\right)V_i$" + "\n\n" +
        r"$\mathrm{MultiHead}(Q, K, V) = \mathrm{Concat}(\mathrm{head}_1, \dots, \mathrm{head}_h)W_O$"
    )
    ax.text(24.5, 14.5, math_text, fontsize=7.8, color="#0f172a", va="center")

    # Box 3: Components Legend
    box3 = FancyBboxPatch((51.5, 3), 20, 26, boxstyle="round,pad=0.4", fc="#ffffff", ec="#cbd5e1", lw=1.2)
    ax.add_patch(box3)
    ax.text(61.5, 26.5, "COMPONENTS", fontsize=9.5, fontweight="bold", ha="center", color="#4338ca")
    
    comp_items = [
        ("Multi-Head Self-Attention", "#fffbeb", "#d97706"),
        ("Position-wise Feed-Forward", "#eff6ff", "#2563eb"),
        ("Add & Norm (LayerNorm)", "#e0f2fe", "#0284c7"),
        ("Scaled Dot-Product Attention", "#fee2e2", "#ef4444"),
        ("Linear Projections", "#dbeafe", "#2563eb"),
        ("GELU Activation", "#fef9c3", "#ca8a04"),
        ("Residual Connection", "#94a3b8", "--")
    ]
    for idx, (lbl, fill_c, brd_c) in enumerate(comp_items):
        y_pos = 23.0 - idx * 2.8
        if brd_c == "--":
            ax.plot([53.0, 56.5], [y_pos, y_pos], color=fill_c, lw=1.5, ls="--")
        else:
            ax.add_patch(patches.Rectangle((53.0, y_pos - 0.7), 3.5, 1.4, fc=fill_c, ec=brd_c, lw=1))
        ax.text(58.0, y_pos, lbl, fontsize=7.8, va="center", color="#334155")

    # Box 4: Key Features for Network Security
    box4 = FancyBboxPatch((73, 3), 25, 26, boxstyle="round,pad=0.4", fc="#ffffff", ec="#cbd5e1", lw=1.2)
    ax.add_patch(box4)
    ax.text(85.5, 26.5, "KEY ARCHITECTURAL FEATURES", fontsize=9.5, fontweight="bold", ha="center", color="#4338ca")
    key_features = (
        r"$\bullet$ Multi-head self-attention captures complex cross-feature" + "\n" +
        r"   correlations (e.g., SYN flood bursts with zero byte payloads)." + "\n\n" +
        r"$\bullet$ Position-wise FFN introduces non-linearity and projects" + "\n" +
        r"   features into high-dimensional anomaly manifold." + "\n\n" +
        r"$\bullet$ Layer normalization and residual connections prevent gradient" + "\n" +
        r"   vanishing during deep stacked flow training." + "\n\n" +
        r"$\bullet$ Stacked encoder representation learns robust latent patterns" + "\n" +
        r"   resistant to adversarial feature perturbation and stealth scans."
    )
    ax.text(74.0, 14.5, key_features, fontsize=7.6, color="#1e293b", va="center")

    plt.savefig(save_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved Figure 1 to:\n    {save_path}")


# ==============================================================================
# 3. FIGURE 2: DETAILED DATA FLOW PROCESS CHART
# ==============================================================================

def render_figure_2_data_flow_chart(save_path: str):
    """
    Renders an end-to-end data flow chart showing the progressive transformation:
    Raw PCAP/Flow -> Preprocessing -> Transformer Encoder -> Classification -> Alerting.
    """
    print("\n[*] Rendering Figure 2: Detailed Data Flow Process Chart...")
    
    fig = plt.figure(figsize=(16, 9), dpi=300)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")

    ax.text(50, 96.0, "End-to-End Network Anomaly Detection Data Flow & Pipeline Architecture",
            fontsize=18, fontweight="bold", ha="center", color="#0f172a")
    ax.text(50, 93.2, "From High-Throughput Packet Capture (PCAP) to Real-Time Threat Score Triage",
            fontsize=11, style="italic", ha="center", color="#475569")

    # 5 Major Stages
    stage_data = [
        {
            "num": "STAGE 1", "title": "Raw Traffic Ingestion",
            "desc": "• High-speed libpcap/eBPF capture\n• Continuous flow streaming\n• Protocol demultiplexing\n• Packet buffer queuing",
            "x": 4, "w": 16, "color": "#eff6ff", "border": "#3b82f6", "hdr": "#1d4ed8"
        },
        {
            "num": "STAGE 2", "title": "Flow Aggregation & Features",
            "desc": "• 5-tuple flow reconstruction\n• Sliding windows (1m, 5m, 10m)\n• Entropy & SYN-ACK ratio\n• Packet size std dev & jitter",
            "x": 23.5, "w": 16, "color": "#ecfdf5", "border": "#10b981", "hdr": "#047857"
        },
        {
            "num": "STAGE 3", "title": "Embedding & Normalization",
            "desc": "• Robust quantile scaling\n• Continuous linear projection\n• Positional sequence encoding\n• Flow matrix X^(0) in R^(n x d)",
            "x": 43, "w": 16, "color": "#fefce8", "border": "#eab308", "hdr": "#b45309"
        },
        {
            "num": "STAGE 4", "title": "Transformer Feature Engine",
            "desc": "• Multi-Head Self-Attention\n• Cross-feature dependencies\n• Residual add & LayerNorm\n• Contextual matrix H^(L)",
            "x": 62.5, "w": 16, "color": "#f5f3ff", "border": "#8b5cf6", "hdr": "#6d28d9"
        },
        {
            "num": "STAGE 5", "title": "Inference & Threat Triage",
            "desc": "• MLP classification head\n• Dynamic threshold decision\n• Calibrated threat probability\n• Automated SIEM mitigation",
            "x": 82, "w": 15, "color": "#fef2f2", "border": "#ef4444", "hdr": "#b91c1c"
        }
    ]

    for stage in stage_data:
        # Main container
        box = FancyBboxPatch((stage["x"], 32), stage["w"], 54, boxstyle="round,pad=0.5,rounding_size=1.0",
                             fc=stage["color"], ec=stage["border"], lw=1.6)
        ax.add_patch(box)
        
        # Header banner
        hdr = FancyBboxPatch((stage["x"], 80), stage["w"], 6, boxstyle="round,pad=0.2,rounding_size=0.5",
                             fc=stage["hdr"], ec=stage["hdr"])
        ax.add_patch(hdr)
        ax.text(stage["x"] + stage["w"]/2, 84.0, stage["num"], color="#ffffff", fontsize=9, fontweight="bold", ha="center")
        ax.text(stage["x"] + stage["w"]/2, 81.5, stage["title"], color="#ffffff", fontsize=9.5, fontweight="bold", ha="center")
        
        # Body text
        ax.text(stage["x"] + 1.2, 70.0, stage["desc"], fontsize=9, color="#1e293b", va="top", linespacing=1.6)

    # Connecting Arrows between stages
    for x_arrow in [20.5, 40.0, 59.5, 79.0]:
        ax.annotate("", xy=(x_arrow + 2.5, 60), xytext=(x_arrow, 60),
                    arrowprops=dict(arrowstyle="-|>", lw=2.4, color="#334155", mutation_scale=18))

    # Bottom Callout: Verification & Closed-Loop Feedback Flow
    feedback_box = FancyBboxPatch((4, 8), 93, 18, boxstyle="round,pad=0.5,rounding_size=1.0",
                                  fc="#f8fafc", ec="#94a3b8", lw=1.2, ls="--")
    ax.add_patch(feedback_box)
    ax.text(50, 22.5, "CONTINUOUS FEEDBACK, MODEL RE-CALIBRATION & ACTIVE MITIGATION LOOP",
            fontsize=10.5, fontweight="bold", ha="center", color="#0f172a")

    ax.text(12, 14.5, "1. Incident Ingestion\nLogged flows stored in\nElasticsearch / Parquet lake",
            fontsize=8.5, ha="center", color="#475569", bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#cbd5e1"))
    ax.annotate("", xy=(22.5, 14.5), xytext=(19.0, 14.5), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#64748b"))

    ax.text(32, 14.5, "2. SOC Analyst Feedback\nAnalyst verifies False Positives\nand zero-day attack alerts",
            fontsize=8.5, ha="center", color="#475569", bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#cbd5e1"))
    ax.annotate("", xy=(42.5, 14.5), xytext=(39.0, 14.5), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#64748b"))

    ax.text(52, 14.5, "3. Drift Detection\nKullback-Leibler drift monitoring\nacross time-window metrics",
            fontsize=8.5, ha="center", color="#475569", bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#cbd5e1"))
    ax.annotate("", xy=(62.5, 14.5), xytext=(59.0, 14.5), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#64748b"))

    ax.text(72, 14.5, "4. Online Retraining\nIncremental Transformer weights\nupdate on edge inference cluster",
            fontsize=8.5, ha="center", color="#475569", bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#cbd5e1"))
    ax.annotate("", xy=(82.5, 14.5), xytext=(79.0, 14.5), arrowprops=dict(arrowstyle="-|>", lw=1.2, color="#64748b"))

    ax.text(88.5, 14.5, "5. Rule Update\nDynamic ACL rule push\nto edge firewall / SDN",
            fontsize=8.5, ha="center", color="#475569", bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#cbd5e1"))

    plt.savefig(save_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved Figure 2 to:\n    {save_path}")


# ==============================================================================
# 4. FIGURE 3: SHAP FEATURE IMPORTANCE SUMMARY PLOT (Matches Reference Image)
# ==============================================================================

def render_figure_3_shap_feature_importance(save_path: str):
    """
    Renders an illustrative SHAP summary plot matching the exact visual style
    of the user's reference image (media_1789645107252.png), adapted for
    key Network Anomaly Detection features.
    """
    print("\n[*] Rendering Figure 3: SHAP Summary Plot (Illustrative)...")
    
    fig, ax = plt.subplots(figsize=(10.5, 7.0), dpi=300)
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")

    # Network Security features in ranked order (top = highest impact)
    features = [
        "SYN-ACK Ratio",
        "Flow Duration",
        "Source Port Entropy",
        "Packet Length StdDev",
        "TCP Window Size",
        "Packet Rate (pps)",
        "Byte Count (bytes)",
        "Protocol Type"
    ]
    
    # Palette colors matching reference image
    palette = [
        "#3b82f6",  # Blue (Top: SYN-ACK Ratio)
        "#f97316",  # Orange (Flow Duration)
        "#22c55e",  # Green (Source Port Entropy)
        "#ef4444",  # Red (Packet Length StdDev)
        "#a855f7",  # Purple (TCP Window Size)
        "#854d0e",  # Brown (Packet Rate)
        "#ec4899",  # Pink (Byte Count)
        "#6b7280"   # Gray (Protocol Type)
    ]

    # Reference SHAP value distributions (mean offsets descending)
    means = [0.41, 0.33, 0.27, 0.24, 0.17, 0.14, 0.08, 0.04]
    stds  = [0.045, 0.050, 0.035, 0.040, 0.045, 0.040, 0.035, 0.045]
    n_points = 55

    for idx, (feat, color, m, s) in enumerate(zip(features, palette, means, stds)):
        # y-position in inverted order so top feature is at the top
        y_center = len(features) - 1 - idx
        
        # Generate SHAP value points with realistic tails
        shap_vals = np.random.normal(loc=m, scale=s, size=n_points)
        # Add slight outliers
        shap_vals[0] += s * 2.2
        shap_vals[1] -= s * 1.8
        
        # Vertical jitter
        y_jitter = y_center + np.random.uniform(-0.12, 0.12, size=n_points)
        
        ax.scatter(shap_vals, y_jitter, color=color, alpha=0.75, s=18, edgecolors="none")

    ax.set_yticks(range(len(features)))
    ax.set_yticklabels(list(reversed(features)), fontsize=11, fontweight="semibold", color="#1e293b")
    ax.set_xlabel("SHAP value (impact on model output)", fontsize=12, fontweight="medium", color="#1e293b", labelpad=10)
    ax.set_title("SHAP Summary Plot (Illustrative)", fontsize=14, fontweight="bold", pad=15, color="#0f172a")
    
    # Clean grid styling matching reference image
    ax.grid(axis="x", color="#e2e8f0", linestyle="-", linewidth=0.8, alpha=0.8)
    ax.grid(axis="y", visible=False)
    ax.spines["top"].set_visible(True)
    ax.spines["right"].set_visible(True)
    ax.spines["left"].set_color("#1e293b")
    ax.spines["bottom"].set_color("#1e293b")
    ax.spines["top"].set_color("#1e293b")
    ax.spines["right"].set_color("#1e293b")
    
    ax.set_xlim(-0.08, 0.58)
    ax.set_ylim(-0.6, len(features) - 0.4)

    plt.tight_layout()
    plt.savefig(save_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved Figure 3 to:\n    {save_path}")


# ==============================================================================
# 5. FIGURE 4: MODEL CALIBRATION & MULTI-TIME WINDOW ROC CURVES
# ==============================================================================

def render_figure_4_calibration_roc_curves(save_path: str):
    """
    Renders publication-quality two-panel figure:
    - Subplot A: Model Calibration (Reliability Diagram) comparing predicted vs observed anomaly probabilities
    - Subplot B: Multi-Window ROC Curves (1-min, 5-min, 10-min monitoring windows)
    """
    print("\n[*] Rendering Figure 4: Model Calibration & Multi-Window ROC Curves...")
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15.5, 6.5), dpi=300)
    fig.patch.set_facecolor("#ffffff")
    
    # -------------------------------------------------------------
    # SUBPLOT A: MODEL CALIBRATION CURVE (RELIABILITY DIAGRAM)
    # -------------------------------------------------------------
    ax1.set_facecolor("#f8fafc")
    
    # Simulate ground truth and calibrated predictions for 3 models
    n_eval = 2500
    y_true = np.random.binomial(1, 0.35, size=n_eval)
    
    # 1-min model: slightly under-confident
    probs_1m = np.clip(y_true * 0.72 + (1 - y_true) * 0.18 + np.random.normal(0, 0.16, n_eval), 0.01, 0.99)
    # 5-min model: well calibrated
    probs_5m = np.clip(y_true * 0.85 + (1 - y_true) * 0.08 + np.random.normal(0, 0.10, n_eval), 0.01, 0.99)
    # 10-min model: sharp and highly calibrated
    probs_10m = np.clip(y_true * 0.92 + (1 - y_true) * 0.04 + np.random.normal(0, 0.06, n_eval), 0.01, 0.99)

    # Calculate calibration curves
    fop_1m, mpv_1m = calibration_curve(y_true, probs_1m, n_bins=10)
    fop_5m, mpv_5m = calibration_curve(y_true, probs_5m, n_bins=10)
    fop_10m, mpv_10m = calibration_curve(y_true, probs_10m, n_bins=10)

    # Brier Scores
    brier_1m = brier_score_loss(y_true, probs_1m)
    brier_5m = brier_score_loss(y_true, probs_5m)
    brier_10m = brier_score_loss(y_true, probs_10m)

    # Perfect calibration reference line
    ax1.plot([0, 1], [0, 1], linestyle="--", color="#64748b", lw=1.5, label="Perfect Calibration (Ideal)")
    
    # Plot calibration lines with markers
    ax1.plot(mpv_1m, fop_1m, marker="s", markersize=6, lw=2.0, color="#ef4444",
             label=f"1-min Window (Brier={brier_1m:.3f})")
    ax1.plot(mpv_5m, fop_5m, marker="^", markersize=6, lw=2.2, color="#3b82f6",
             label=f"5-min Window (Brier={brier_5m:.3f})")
    ax1.plot(mpv_10m, fop_10m, marker="o", markersize=6, lw=2.4, color="#10b981",
             label=f"10-min Window (Brier={brier_10m:.3f})")

    ax1.set_title("(A) Model Calibration Curves (Reliability Diagram)", fontsize=13, fontweight="bold", pad=12, color="#0f172a")
    ax1.set_xlabel("Mean Predicted Anomaly Probability", fontsize=11, fontweight="medium", color="#1e293b")
    ax1.set_ylabel("Observed Empirical Frequency", fontsize=11, fontweight="medium", color="#1e293b")
    ax1.set_xlim(-0.02, 1.02)
    ax1.set_ylim(-0.02, 1.02)
    ax1.grid(True, color="#e2e8f0", linestyle="--", alpha=0.7)
    ax1.legend(loc="lower right", frameon=True, facecolor="#ffffff", edgecolor="#cbd5e1", fontsize=9.5)

    # -------------------------------------------------------------
    # SUBPLOT B: MULTI-TIME WINDOW ROC CURVES
    # -------------------------------------------------------------
    ax2.set_facecolor("#f8fafc")

    fpr_1m_curve, tpr_1m_curve, _ = roc_curve(y_true, probs_1m)
    fpr_5m_curve, tpr_5m_curve, _ = roc_curve(y_true, probs_5m)
    fpr_10m_curve, tpr_10m_curve, _ = roc_curve(y_true, probs_10m)

    auc_1m = auc(fpr_1m_curve, tpr_1m_curve)
    auc_5m = auc(fpr_5m_curve, tpr_5m_curve)
    auc_10m = auc(fpr_10m_curve, tpr_10m_curve)

    # Random chance baseline
    ax2.plot([0, 1], [0, 1], linestyle="--", color="#64748b", lw=1.5, label="Random Guess (AUC = 0.500)")

    ax2.plot(fpr_1m_curve, tpr_1m_curve, color="#ef4444", lw=2.0,
             label=f"1-min Window  (AUROC = {auc_1m:.3f})")
    ax2.plot(fpr_5m_curve, tpr_5m_curve, color="#3b82f6", lw=2.2,
             label=f"5-min Window  (AUROC = {auc_5m:.3f})")
    ax2.plot(fpr_10m_curve, tpr_10m_curve, color="#10b981", lw=2.4,
             label=f"10-min Window (AUROC = {auc_10m:.3f})")

    # Optimal operating point annotation on 10-min curve
    opt_idx = np.argmax(tpr_10m_curve - fpr_10m_curve)
    ax2.plot(fpr_10m_curve[opt_idx], tpr_10m_curve[opt_idx], "ro", markersize=8, markeredgecolor="#0f172a", markeredgewidth=1.5)
    ax2.annotate(
        f"Optimal Operating Point\n(TPR={tpr_10m_curve[opt_idx]:.2f}, FPR={fpr_10m_curve[opt_idx]:.2f})",
        xy=(fpr_10m_curve[opt_idx], tpr_10m_curve[opt_idx]),
        xytext=(fpr_10m_curve[opt_idx] + 0.15, tpr_10m_curve[opt_idx] - 0.15),
        arrowprops=dict(facecolor="#0f172a", shrink=0.08, width=1.2, headwidth=6),
        fontsize=8.5, fontweight="bold", color="#0f172a",
        bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#10b981", lw=1.2)
    )

    ax2.set_title("(B) Receiver Operating Characteristic (ROC) Across Time Windows", fontsize=13, fontweight="bold", pad=12, color="#0f172a")
    ax2.set_xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="medium", color="#1e293b")
    ax2.set_ylabel("True Positive Rate (TPR / Recall)", fontsize=11, fontweight="medium", color="#1e293b")
    ax2.set_xlim(-0.02, 1.02)
    ax2.set_ylim(-0.02, 1.02)
    ax2.grid(True, color="#e2e8f0", linestyle="--", alpha=0.7)
    ax2.legend(loc="lower right", frameon=True, facecolor="#ffffff", edgecolor="#cbd5e1", fontsize=9.5)

    plt.tight_layout()
    plt.savefig(save_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved Figure 4 to:\n    {save_path}")


# ==============================================================================
# MAIN EXECUTION ENTRYPOINT
# ==============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("  NETANOMALY-TRANSNET: BENCHMARK DATASET & TECHNICAL FIGURES GENERATOR")
    print("=" * 80)
    
    # 1. Generate Excel Dataset
    excel_file = generate_network_anomaly_excel(num_samples=260)
    
    # 2. Render Figure 1: Architecture Diagram
    fig1_path = os.path.join(FIGURES_DIR, "figure1_transformer_architecture.png")
    render_figure_1_transformer_architecture(fig1_path)
    
    # 3. Render Figure 2: Data Flow Chart
    fig2_path = os.path.join(FIGURES_DIR, "figure2_data_flow_chart.png")
    render_figure_2_data_flow_chart(fig2_path)
    
    # 4. Render Figure 3: SHAP Feature Importance Plot
    fig3_path = os.path.join(FIGURES_DIR, "figure3_shap_feature_importance.png")
    render_figure_3_shap_feature_importance(fig3_path)
    
    # 5. Render Figure 4: Model Calibration & ROC Curves
    fig4_path = os.path.join(FIGURES_DIR, "figure4_calibration_roc_curves.png")
    render_figure_4_calibration_roc_curves(fig4_path)

    print("\n" + "=" * 80)
    print("[SUCCESS] All Benchmark Data and Publication Figures Generated Successfully!")
    print(f"1. Excel Dataset: {excel_file}")
    print(f"2. Architecture Figure: {fig1_path}")
    print(f"3. Data Flow Chart: {fig2_path}")
    print(f"4. SHAP Importance: {fig3_path}")
    print(f"5. Calibration & ROC: {fig4_path}")
    print("=" * 80)
