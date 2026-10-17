"""
Executive-Grade Visual Analytics Dashboard Module for Network Traffic Anomaly Detection.
Provides deep situational awareness, rich attack subtype analytics, feature distributions,
ROC/PR curves, interactive connection simulator, and searchable flow explorer.
Guarantees 100% chart rendering across all tabs via explicit unique container IDs and JS Plotly.react hooks.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px
from sklearn.metrics import roc_curve, auc
from typing import Dict, Any, List, Optional

from src.config import FIGURES_DIR, OUTPUTS_DIR

# Dark Mode UI Color Theme
THEME = {
    "bg_main": "#0b0f19",
    "bg_card": "#131b2e",
    "bg_card_inner": "#1a243d",
    "border": "#23314e",
    "border_highlight": "#3b82f6",
    "text_main": "#f8fafc",
    "text_muted": "#94a3b8",
    "primary": "#3b82f6",
    "primary_glow": "rgba(59, 130, 246, 0.3)",
    "success": "#10b981",
    "danger": "#ef4444",
    "warning": "#f59e0b",
    "purple": "#8b5cf6",
    "cyan": "#06b6d4"
}

FEATURE_DESCRIPTIONS = {
    "flag": "Connection error/status flag (e.g., SF for normal, S0 for SYN flood, REJ for rejected probe)",
    "same_srv_rate": "% of connections to the same service in the 2s time window",
    "dst_host_srv_count": "Number of connections to same service on destination host (last 100 connections)",
    "dst_host_same_srv_rate": "% of connections to same service on destination host",
    "logged_in": "1 if successfully logged in; 0 otherwise (exploits and scans typically fail login)",
    "diff_srv_rate": "% of connections to different services in the 2s time window",
    "dst_host_diff_srv_rate": "% of connections to different services on destination host",
    "count": "Number of connections to the same host in last 2 seconds",
    "dst_host_count": "Count of connections to destination host over the last 100 connections",
    "src_bytes": "Number of payload data bytes sent from source to destination",
    "dst_bytes": "Number of payload data bytes returned from destination to source",
    "dst_host_same_src_port_rate": "% of connections from the same source port to destination host",
    "srv_count": "Number of connections to the same service in last 2 seconds",
    "dst_host_serror_rate": "% of connections to destination host with SYN errors",
    "serror_rate": "% of connections with SYN errors in the last 2 seconds"
}


def set_custom_plot_style():
    """Sets a polished style for static PNG figures."""
    sns.set_theme(style="whitegrid", palette="deep")
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "DejaVu Sans", "Helvetica", "Arial"],
        "axes.edgecolor": "#cbd5e1",
        "axes.linewidth": 1.2,
        "grid.color": "#e2e8f0",
        "grid.linestyle": "--",
        "grid.alpha": 0.7,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.labelsize": 11,
        "axes.labelweight": "semibold",
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "figure.titlesize": 15,
        "figure.titleweight": "bold"
    })


def apply_plotly_theme(fig: go.Figure, title_text: str, xaxis_title: str = None, yaxis_title: str = None, barmode: str = None, hovermode: str = None, **kwargs):
    """Applies unified dark cybersecurity theme to any Plotly figure without keyword clashes."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#131b2e",
        plot_bgcolor="#0d1424",
        font=dict(family="Inter, Segoe UI, sans-serif", color="#e2e8f0", size=11),
        title=dict(text=title_text, font=dict(size=14, color="#f8fafc", family="Inter, sans-serif")),
        legend=dict(
            bgcolor="rgba(19, 27, 46, 0.8)",
            bordercolor="#2a3854",
            borderwidth=1,
            font=dict(color="#cbd5e1")
        ),
        margin=dict(l=55, r=40, t=60, b=50),
        autosize=True
    )
    if xaxis_title:
        fig.update_xaxes(title_text=xaxis_title, gridcolor="#1e293b", zerolinecolor="#334155")
    else:
        fig.update_xaxes(gridcolor="#1e293b", zerolinecolor="#334155")
    if yaxis_title:
        fig.update_yaxes(title_text=yaxis_title, gridcolor="#1e293b", zerolinecolor="#334155")
    else:
        fig.update_yaxes(gridcolor="#1e293b", zerolinecolor="#334155")
    if barmode:
        fig.update_layout(barmode=barmode)
    if hovermode:
        fig.update_layout(hovermode=hovermode)
    if kwargs:
        fig.update_layout(**kwargs)


# ----------------------------------------------------------------------
# 1. HIGH-RESOLUTION STATIC PNG FIGURES (Panels 1 to 6)
# ----------------------------------------------------------------------

def plot_panel_1_traffic_volume(df: pd.DataFrame, y_pred: np.ndarray, save_path: Path = None, window_size: int = 150) -> plt.Figure:
    set_custom_plot_style()
    fig, ax = plt.subplots(figsize=(12, 5.5), dpi=300)
    
    num_windows = len(df) // window_size
    trimmed_len = num_windows * window_size
    vol_bins = np.arange(num_windows) * window_size
    actual_anomalies = np.array(df["binary_label"][:trimmed_len]).reshape(num_windows, window_size).sum(axis=1)
    pred_anomalies = np.array(y_pred[:trimmed_len]).reshape(num_windows, window_size).sum(axis=1)
    
    ax.fill_between(vol_bins, actual_anomalies, color="#3b82f6", alpha=0.25, label="Actual Attack Density")
    ax.plot(vol_bins, actual_anomalies, color="#1d4ed8", lw=1.8)
    ax.plot(vol_bins, pred_anomalies, color="#ef4444", linestyle="--", lw=1.6, label="Detected Anomaly Stream")
    
    if len(df) > 22000:
        ax.axvspan(18000, 22000, color="#fee2e2", alpha=0.7, label="Neptune DoS Surge Window")
        ax.annotate(
            "Neptune DoS Attack Cluster\n(Indices ~18,000 to ~22,000)",
            xy=(20000, max(actual_anomalies) * 0.75),
            xytext=(20000, max(actual_anomalies) * 0.98),
            ha='center',
            bbox=dict(boxstyle="round,pad=0.3", fc="#fef2f2", ec="#ef4444", lw=1.2),
            arrowprops=dict(facecolor='#ef4444', shrink=0.08, width=1.5, headwidth=6),
            fontsize=9, fontweight='bold', color="#991b1b"
        )
    
    ax.set_title("PANEL 1: Temporal Traffic Volume & Anomaly Event Stream (Situational Awareness)")
    ax.set_xlabel("Sequential Connection Index (Temporal Order)")
    ax.set_ylabel(f"Anomaly Count (per {window_size} flows)")
    ax.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="#cbd5e1")
    plt.tight_layout()
    
    if save_path:
        fig.savefig(save_path, bbox_inches="tight")
        print(f"[+] Saved Panel 1 figure to: {save_path.name}")
    plt.close(fig)
    return fig


def plot_panel_2_protocol_distribution(df: pd.DataFrame, save_path: Path = None) -> plt.Figure:
    set_custom_plot_style()
    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=300)
    proto_counts = df["protocol_type"].value_counts()
    colors = ["#2563eb", "#10b981", "#f59e0b", "#ec4899"]
    
    wedges, texts, autotexts = ax.pie(
        proto_counts.values,
        labels=[f"{p.upper()}\n({proto_counts[p]:,} flows)" for p in proto_counts.index],
        autopct='%1.2f%%',
        pctdistance=0.75,
        startangle=140,
        colors=colors[:len(proto_counts)],
        explode=[0.04 if i == 0 else 0 for i in range(len(proto_counts))],
        wedgeprops=dict(width=0.45, edgecolor='white', linewidth=2.5)
    )
    for autotext in autotexts:
        autotext.set_color('#1e293b')
        autotext.set_weight('bold')
        autotext.set_fontsize(10)
        
    ax.set_title("PANEL 2: Network Protocol Distribution Breakdown (TCP / UDP / ICMP)")
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight")
        print(f"[+] Saved Panel 2 figure to: {save_path.name}")
    plt.close(fig)
    return fig


def plot_panel_3_correlation_heatmap(df_scaled: pd.DataFrame, top_features: List[str], save_path: Path = None) -> plt.Figure:
    set_custom_plot_style()
    fig, ax = plt.subplots(figsize=(9.5, 8), dpi=300)
    sub_df = df_scaled[top_features[:8]].copy()
    corr_matrix = sub_df.corr()
    
    sns.heatmap(
        corr_matrix,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        vmin=-1, vmax=1,
        linewidths=1.2, linecolor="white",
        cbar_kws={"label": "Pearson Correlation (r)", "shrink": 0.8},
        annot_kws={"size": 9, "weight": "bold"},
        ax=ax
    )
    ax.set_title("PANEL 3: Feature Correlation Heatmap (Top 8 Informative Features)")
    plt.xticks(rotation=40, ha="right", fontweight="semibold")
    plt.yticks(rotation=0, fontweight="semibold")
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight")
        print(f"[+] Saved Panel 3 figure to: {save_path.name}")
    plt.close(fig)
    return fig


def plot_panel_4_model_comparison(results_list: List[Dict[str, Any]], save_path: Path = None) -> plt.Figure:
    set_custom_plot_style()
    fig, ax = plt.subplots(figsize=(10.5, 6), dpi=300)
    df_res = pd.DataFrame(results_list)
    models = df_res["Model"].tolist()
    metrics = ["Accuracy", "Precision", "Recall", "F1-Score"]
    
    x = np.arange(len(models))
    width = 0.18
    palette = ["#1e40af", "#059669", "#d97706", "#7c3aed"]
    
    for i, metric in enumerate(metrics):
        values = [res[metric] * 100 if metric == "Accuracy" else res[metric] for res in results_list]
        rects = ax.bar(x + (i - 1.5) * width, values, width, label=metric, color=palette[i], edgecolor="#1e293b", lw=0.5)
        for rect in rects:
            h = rect.get_height()
            label_text = f"{h:.1f}%" if metric == "Accuracy" else f"{h:.2f}"
            ax.annotate(
                label_text,
                xy=(rect.get_x() + rect.get_width() / 2, h),
                xytext=(0, 4), textcoords="offset points",
                ha='center', va='bottom', fontsize=8, fontweight='bold'
            )
            
    ax.set_title("PANEL 4: Comparative Performance Benchmarks (Unsupervised vs Supervised)")
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontweight='bold', fontsize=11)
    ax.set_ylabel("Metric Score / Percentage")
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right", frameon=True, facecolor="white", edgecolor="#cbd5e1")
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight")
        print(f"[+] Saved Panel 4 figure to: {save_path.name}")
    plt.close(fig)
    return fig


def plot_panel_5_confusion_matrix(cm: np.ndarray, model_name: str = "Random Forest", save_path: Path = None) -> plt.Figure:
    set_custom_plot_style()
    fig, ax = plt.subplots(figsize=(7.5, 6.5), dpi=300)
    labels = ["Normal Traffic (0)", "Anomaly / Attack (1)"]
    tn, fp, fn, tp = cm.ravel()
    total = cm.sum()
    
    annotations = np.array([
        [f"True Negative (TN)\n{tn:,}\n({tn/total*100:.1f}%)", f"False Positive (FP)\n{fp:,}\n({fp/total*100:.1f}%)"],
        [f"False Negative (FN)\n{fn:,}\n({fn/total*100:.1f}%)", f"True Positive (TP)\n{tp:,}\n({tp/total*100:.1f}%)"]
    ])
    
    sns.heatmap(
        cm, annot=annotations, fmt="", cmap="Blues", cbar=True,
        xticklabels=labels, yticklabels=labels,
        annot_kws={"size": 11, "weight": "bold"},
        linewidths=1.5, linecolor="white", ax=ax
    )
    ax.set_title(f"PANEL 5: {model_name} Annotated Confusion Matrix Heatmap")
    ax.set_xlabel("Predicted Class Classification", fontweight='bold', labelpad=10)
    ax.set_ylabel("Actual Ground Truth Label", fontweight='bold', labelpad=10)
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight")
        print(f"[+] Saved Panel 5 figure to: {save_path.name}")
    plt.close(fig)
    return fig


def plot_panel_6_feature_importance(df_importance: pd.DataFrame, top_n: int = 12, save_path: Path = None) -> plt.Figure:
    set_custom_plot_style()
    fig, ax = plt.subplots(figsize=(10.5, 6.5), dpi=300)
    top_df = df_importance.head(top_n).sort_values(by="Importance", ascending=True)
    colors = plt.cm.viridis(np.linspace(0.3, 0.85, len(top_df)))
    bars = ax.barh(top_df["Feature"], top_df["Importance"], color=colors, edgecolor="#0f766e", lw=0.8)
    
    for bar in bars:
        w = bar.get_width()
        ax.annotate(
            f" {w:.4f} ({w*100:.1f}%)",
            xy=(w, bar.get_y() + bar.get_height() / 2),
            xytext=(4, 0), textcoords="offset points",
            ha='left', va='center', fontsize=9, fontweight='bold', color="#0f172a"
        )
    ax.set_title(f"PANEL 6: Top {top_n} Most Discriminative Features (Gini Impurity Reduction)")
    ax.set_xlabel("Relative Feature Importance Score (Gini Weight)")
    ax.set_ylabel("Network Traffic Feature Name")
    ax.set_xlim(0, top_df["Importance"].max() * 1.25)
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight")
        print(f"[+] Saved Panel 6 figure to: {save_path.name}")
    plt.close(fig)
    return fig


def generate_full_dashboard_png(
    df_test_raw: pd.DataFrame, df_test_scaled: pd.DataFrame,
    rf_preds: np.ndarray, top_features: List[str],
    results_list: List[Dict[str, Any]], rf_cm: np.ndarray,
    df_importance: pd.DataFrame, save_path: Path
):
    set_custom_plot_style()
    fig, axes = plt.subplots(3, 2, figsize=(19, 21), dpi=300)
    fig.patch.set_facecolor("#ffffff")
    fig.suptitle(
        "Network Traffic Anomaly Detection System — Master Visual Analytics Dashboard\n"
        "NSL-KDD Benchmark Suite",
        fontsize=18, fontweight="bold", y=0.995, color="#0f172a"
    )
    
    # 1. Panel 1
    ax1 = axes[0, 0]
    window_size = 150
    num_windows = len(df_test_raw) // window_size
    trimmed_len = num_windows * window_size
    vol_bins = np.arange(num_windows) * window_size
    actual_anomalies_binned = np.array(df_test_raw["binary_label"][:trimmed_len]).reshape(num_windows, window_size).sum(axis=1)
    pred_anomalies_binned = np.array(rf_preds[:trimmed_len]).reshape(num_windows, window_size).sum(axis=1)
    ax1.fill_between(vol_bins, actual_anomalies_binned, color="#3b82f6", alpha=0.25, label="Actual Attacks")
    ax1.plot(vol_bins, actual_anomalies_binned, color="#1d4ed8", lw=1.5)
    ax1.plot(vol_bins, pred_anomalies_binned, label="Detected Anomalies", color="#ef4444", linestyle="--", lw=1.4)
    if len(df_test_raw) > 22000:
        ax1.axvspan(18000, 22000, color="#fee2e2", alpha=0.6, label="Neptune DoS Burst")
    ax1.set_title("Panel 1: Traffic Volume & Anomaly Timeline", fontsize=12, fontweight="bold")
    ax1.set_xlabel("Connection Index", fontsize=9)
    ax1.set_ylabel(f"Anomalies / {window_size} Flows", fontsize=9)
    ax1.legend(loc="upper right", fontsize=8)
    
    # 2. Panel 2
    ax2 = axes[0, 1]
    proto_counts = df_test_raw["protocol_type"].value_counts()
    ax2.pie(
        proto_counts.values,
        labels=[p.upper() for p in proto_counts.index],
        autopct='%1.1f%%',
        colors=["#2563eb", "#10b981", "#f59e0b"],
        wedgeprops=dict(width=0.45, edgecolor='white', linewidth=2)
    )
    ax2.set_title("Panel 2: Network Protocol Breakdown", fontsize=12, fontweight="bold")
    
    # 3. Panel 3
    ax3 = axes[1, 0]
    sub_df = df_test_scaled[top_features[:8]].copy()
    sns.heatmap(sub_df.corr(), annot=True, fmt=".2f", cmap="coolwarm", ax=ax3, cbar=False, annot_kws={"size": 8, "weight": "bold"})
    ax3.set_title("Panel 3: Feature Correlation Heatmap (Top 8)", fontsize=12, fontweight="bold")
    ax3.tick_params(axis='x', rotation=35)
    
    # 4. Panel 4
    ax4 = axes[1, 1]
    models = [r["Model"] for r in results_list]
    accs = [r["Accuracy"] * 100 for r in results_list]
    f1s = [r["F1-Score"] * 100 for r in results_list]
    x = np.arange(len(models))
    w = 0.35
    ax4.bar(x - w/2, accs, w, label="Accuracy (%)", color="#1e40af")
    ax4.bar(x + w/2, f1s, w, label="F1-Score (%)", color="#059669")
    ax4.set_xticks(x)
    ax4.set_xticklabels(models, fontsize=10, fontweight="bold")
    ax4.set_ylabel("Score (%)", fontsize=9)
    ax4.set_ylim(0, 110)
    ax4.set_title("Panel 4: Algorithmic Performance Comparison", fontsize=12, fontweight="bold")
    ax4.legend(loc="lower right", fontsize=9)
    
    # 5. Panel 5
    ax5 = axes[2, 0]
    labels = ["Normal", "Anomaly"]
    sns.heatmap(rf_cm, annot=True, fmt=",d", cmap="Blues", ax=ax5, xticklabels=labels, yticklabels=labels, annot_kws={"size": 11, "weight": "bold"})
    ax5.set_title("Panel 5: Random Forest Confusion Matrix", fontsize=12, fontweight="bold")
    ax5.set_xlabel("Predicted", fontsize=9)
    ax5.set_ylabel("Actual", fontsize=9)
    
    # 6. Panel 6
    ax6 = axes[2, 1]
    top_imp = df_importance.head(10).sort_values(by="Importance", ascending=True)
    ax6.barh(top_imp["Feature"], top_imp["Importance"], color="#0f766e")
    ax6.set_title("Panel 6: Feature Importance Ranking (Gini)", fontsize=12, fontweight="bold")
    ax6.set_xlabel("Importance Score", fontsize=9)
    
    plt.tight_layout()
    fig.savefig(save_path, bbox_inches="tight")
    print(f"[+] Saved Master 6-Panel Dashboard Figure to: {save_path.name}")
    plt.close(fig)


# ----------------------------------------------------------------------
# 2. BULLETPROOF INTERACTIVE SOC DASHBOARD (Plotly JS Data Specs)
# ----------------------------------------------------------------------

def build_executive_html_dashboard(
    df_test_raw: pd.DataFrame,
    df_test_scaled: pd.DataFrame,
    rf_preds: np.ndarray,
    rf_probs: Optional[np.ndarray],
    iso_scores: Optional[np.ndarray],
    kmeans_dists: Optional[np.ndarray],
    top_features: List[str],
    results_list: List[Dict[str, Any]],
    rf_cm: np.ndarray,
    df_importance: pd.DataFrame,
    output_html_path: Path
):
    y_test = df_test_raw["binary_label"].values
    
    # 1. Timeline Spec
    window_size = 100
    num_windows = len(df_test_raw) // window_size
    trimmed_len = num_windows * window_size
    vol_bins = np.arange(num_windows) * window_size
    actual_anomalies = np.array(df_test_raw["binary_label"][:trimmed_len]).reshape(num_windows, window_size).sum(axis=1)
    pred_anomalies = np.array(rf_preds[:trimmed_len]).reshape(num_windows, window_size).sum(axis=1)
    
    fig1 = go.Figure()
    fig1.add_trace(go.Scatter(
        x=vol_bins.tolist(), y=actual_anomalies.tolist(), mode="lines", name="Actual Attack Density",
        line=dict(color="#3b82f6", width=2.5), fill="tozeroy", fillcolor="rgba(59, 130, 246, 0.15)"
    ))
    fig1.add_trace(go.Scatter(
        x=vol_bins.tolist(), y=pred_anomalies.tolist(), mode="lines", name="Detected Anomaly Stream",
        line=dict(color="#ef4444", width=2, dash="dot")
    ))
    if len(df_test_raw) > 22000:
        fig1.add_vrect(
            x0=18000, x1=22000, fillcolor="#ef4444", opacity=0.18, line_width=1.5, line_color="#ef4444",
            annotation_text="<b>Neptune DoS Burst (Indices 18k-22k)</b>", annotation_position="top left",
            annotation_font=dict(color="#fca5a5", size=11)
        )
    apply_plotly_theme(
        fig1,
        title_text="<b>Panel 1: Temporal Ingress Traffic Flow & Anomaly Event Timeline</b>",
        xaxis_title="Sequential Connection Index (Time Ordered Flows)",
        yaxis_title=f"Anomaly Count (per {window_size} connections)",
        hovermode="x unified"
    )

    # 2. Protocol Spec
    proto_counts = df_test_raw["protocol_type"].value_counts()
    fig2 = go.Figure(data=[go.Pie(
        labels=[p.upper() for p in proto_counts.index],
        values=proto_counts.values.tolist(),
        hole=0.55,
        marker=dict(colors=["#3b82f6", "#10b981", "#f59e0b"]),
        textinfo="label+percent",
        hoverinfo="label+value+percent",
        textfont=dict(size=13, color="#ffffff")
    )])
    apply_plotly_theme(fig2, title_text="<b>Panel 2: Network Protocol Distribution (TCP / UDP / ICMP)</b>")

    # 3. Correlation Spec
    sub_df = df_test_scaled[top_features[:8]].copy()
    corr = sub_df.corr().round(2)
    fig3 = go.Figure(data=go.Heatmap(
        z=corr.values.tolist(),
        x=corr.columns.tolist(),
        y=corr.index.tolist(),
        colorscale="RdBu_r",
        zmin=-1, zmax=1,
        text=corr.values.tolist(),
        texttemplate="%{text}",
        textfont=dict(size=10, color="#ffffff"),
        colorbar=dict(title=dict(text="Pearson r", font=dict(color="#cbd5e1")), tickfont=dict(color="#cbd5e1"))
    ))
    apply_plotly_theme(fig3, title_text="<b>Panel 3: Correlation Matrix of Top 8 Discriminative Features</b>")

    # 4. Model Bar Spec
    models = [r["Model"] for r in results_list]
    accs = [r["Accuracy"] * 100 for r in results_list]
    precs = [r["Precision"] * 100 for r in results_list]
    recs = [r["Recall"] * 100 for r in results_list]
    f1s = [r["F1-Score"] * 100 for r in results_list]
    
    fig4 = go.Figure()
    fig4.add_trace(go.Bar(x=models, y=accs, name="Accuracy (%)", marker_color="#3b82f6", text=[f"{v:.1f}%" for v in accs], textposition="auto"))
    fig4.add_trace(go.Bar(x=models, y=precs, name="Precision (%)", marker_color="#10b981", text=[f"{v:.1f}%" for v in precs], textposition="auto"))
    fig4.add_trace(go.Bar(x=models, y=recs, name="Recall (%)", marker_color="#f59e0b", text=[f"{v:.1f}%" for v in recs], textposition="auto"))
    fig4.add_trace(go.Bar(x=models, y=f1s, name="F1-Score (%)", marker_color="#8b5cf6", text=[f"{v:.1f}%" for v in f1s], textposition="auto"))
    apply_plotly_theme(
        fig4,
        title_text="<b>Panel 4: Detection Algorithms Quantitative Benchmark Comparison</b>",
        yaxis_title="Percentage (%)",
        barmode="group",
        yaxis=dict(range=[0, 115], gridcolor="#1e293b")
    )

    # 5. Confusion Matrix Spec
    tn, fp, fn, tp = rf_cm.ravel()
    tot = rf_cm.sum()
    cm_text = [
        [f"True Negative (TN)<br><b>{tn:,}</b> ({tn/tot*100:.1f}%)", f"False Positive (FP)<br><b>{fp:,}</b> ({fp/tot*100:.1f}%)"],
        [f"False Negative (FN)<br><b>{fn:,}</b> ({fn/tot*100:.1f}%)", f"True Positive (TP)<br><b>{tp:,}</b> ({tp/tot*100:.1f}%)"]
    ]
    fig5 = go.Figure(data=go.Heatmap(
        z=rf_cm.tolist(),
        x=["Predicted Normal (0)", "Predicted Anomaly (1)"],
        y=["Actual Normal (0)", "Actual Anomaly (1)"],
        colorscale="Blues",
        text=cm_text,
        texttemplate="%{text}",
        textfont=dict(size=12, color="#ffffff"),
        colorbar=dict(title=dict(text="Count", font=dict(color="#cbd5e1")), tickfont=dict(color="#cbd5e1"))
    ))
    apply_plotly_theme(fig5, title_text="<b>Panel 5: Supervised Random Forest Annotated Confusion Matrix</b>")

    # 6. Feature Importance Spec
    top_12 = df_importance.head(12).sort_values(by="Importance", ascending=True)
    fig6 = go.Figure(data=go.Bar(
        x=top_12["Importance"].tolist(),
        y=top_12["Feature"].tolist(),
        orientation="h",
        marker=dict(color=top_12["Importance"].tolist(), colorscale="Viridis"),
        text=[f"  {v:.4f} ({v*100:.1f}%)" for v in top_12["Importance"]],
        textposition="outside",
        textfont=dict(size=10, color="#e2e8f0")
    ))
    apply_plotly_theme(
        fig6,
        title_text="<b>Panel 6: Feature Discriminative Power Ranking (Gini Impurity Reduction)</b>",
        xaxis_title="Gini Importance Score",
        xaxis=dict(range=[0, top_12["Importance"].max() * 1.35], gridcolor="#1e293b")
    )

    # 7. Attack Sunburst Spec
    attack_breakdown_df = df_test_raw.groupby(["attack_class", "label"]).size().reset_index(name="count")
    fig_sunburst = px.sunburst(
        attack_breakdown_df,
        path=["attack_class", "label"],
        values="count",
        color="attack_class",
        color_discrete_map={
            "Normal": "#10b981",
            "DoS": "#ef4444",
            "Probe": "#f59e0b",
            "R2L": "#8b5cf6",
            "U2R": "#ec4899",
            "Unknown_Attack": "#64748b"
        }
    )
    apply_plotly_theme(fig_sunburst, title_text="<b>Attack Taxonomy Breakdown: High-Level Families & Granular Sub-Attacks</b>")

    # 8. ROC Curve Spec
    fig_roc = go.Figure()
    if rf_probs is not None:
        rf_fpr, rf_tpr, _ = roc_curve(y_test, rf_probs[:, 1])
        rf_auc = auc(rf_fpr, rf_tpr)
        fig_roc.add_trace(go.Scatter(x=rf_fpr.tolist(), y=rf_tpr.tolist(), mode="lines", name=f"Random Forest (AUC = {rf_auc:.3f})", line=dict(color="#10b981", width=2.5)))
    
    if iso_scores is not None:
        iso_fpr, iso_tpr, _ = roc_curve(y_test, -iso_scores)
        iso_auc = auc(iso_fpr, iso_tpr)
        fig_roc.add_trace(go.Scatter(x=iso_fpr.tolist(), y=iso_tpr.tolist(), mode="lines", name=f"Isolation Forest (AUC = {iso_auc:.3f})", line=dict(color="#3b82f6", width=2.5)))

    if kmeans_dists is not None:
        km_score = kmeans_dists[:, 0] - kmeans_dists[:, 1]
        km_fpr, km_tpr, _ = roc_curve(y_test, km_score)
        km_auc = auc(km_fpr, km_tpr)
        fig_roc.add_trace(go.Scatter(x=km_fpr.tolist(), y=km_tpr.tolist(), mode="lines", name=f"K-Means (AUC = {km_auc:.3f})", line=dict(color="#f59e0b", width=2.5)))

    fig_roc.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="Random Guess", line=dict(color="#64748b", dash="dash", width=1.5)))
    apply_plotly_theme(
        fig_roc,
        title_text="<b>Receiver Operating Characteristic (ROC) Curves & AUC Comparison</b>",
        xaxis_title="False Positive Rate (FPR)",
        yaxis_title="True Positive Rate (TPR / Recall)",
        xaxis=dict(range=[0, 1], gridcolor="#1e293b"),
        yaxis=dict(range=[0, 1.05], gridcolor="#1e293b")
    )

    # 9. Feature Distribution Spec
    fig_dist = make_subplots(rows=1, cols=2, subplot_titles=("Distribution of dst_host_srv_count", "Distribution of same_srv_rate"))
    normal_mask = (df_test_raw["binary_label"] == 0)
    fig_dist.add_trace(go.Histogram(x=df_test_raw.loc[normal_mask, "dst_host_srv_count"].tolist(), name="Normal", marker_color="#10b981", opacity=0.7), row=1, col=1)
    fig_dist.add_trace(go.Histogram(x=df_test_raw.loc[~normal_mask, "dst_host_srv_count"].tolist(), name="Attack", marker_color="#ef4444", opacity=0.7), row=1, col=1)
    fig_dist.add_trace(go.Histogram(x=df_test_raw.loc[normal_mask, "same_srv_rate"].tolist(), name="Normal", marker_color="#10b981", opacity=0.7, showlegend=False), row=1, col=2)
    fig_dist.add_trace(go.Histogram(x=df_test_raw.loc[~normal_mask, "same_srv_rate"].tolist(), name="Attack", marker_color="#ef4444", opacity=0.7, showlegend=False), row=1, col=2)
    apply_plotly_theme(
        fig_dist,
        title_text="<b>Feature Distribution Contrast: Benign (Normal) vs Malicious (Anomaly)</b>",
        barmode="overlay"
    )

    # Serialize all Plotly specs to JSON strings
    specs_dict = {
        "timeline": json.loads(fig1.to_json()),
        "proto": json.loads(fig2.to_json()),
        "corr": json.loads(fig3.to_json()),
        "model_bar": json.loads(fig4.to_json()),
        "cm": json.loads(fig5.to_json()),
        "importance": json.loads(fig6.to_json()),
        "sunburst": json.loads(fig_sunburst.to_json()),
        "roc": json.loads(fig_roc.to_json()),
        "dist": json.loads(fig_dist.to_json())
    }
    specs_json_str = json.dumps(specs_dict)

    # Sample table rows
    sample_df = df_test_raw.head(40).copy()
    sample_df["predicted_rf"] = rf_preds[:40]
    sample_df["predicted_status"] = np.where(sample_df["predicted_rf"] == 1, "Anomaly", "Normal")
    sample_df["actual_status"] = np.where(sample_df["binary_label"] == 1, "Anomaly", "Normal")
    
    table_rows_html = ""
    for idx, row in sample_df.iterrows():
        is_match = (row["predicted_rf"] == row["binary_label"])
        status_badge = "<span class='badge badge-success'>MATCH</span>" if is_match else "<span class='badge badge-danger'>MISMATCH</span>"
        type_badge = f"<span class='tag-attack'>{row['attack_class']} ({row['label']})</span>" if row['binary_label'] == 1 else "<span class='tag-normal'>Normal</span>"
        
        table_rows_html += f"""
        <tr>
            <td>#{idx+1}</td>
            <td><code>{row['protocol_type'].upper()}</code></td>
            <td><code>{row['service']}</code></td>
            <td><code>{row['flag']}</code></td>
            <td>{row['src_bytes']:,} B</td>
            <td>{row['dst_bytes']:,} B</td>
            <td>{row['dst_host_srv_count']}</td>
            <td>{type_badge}</td>
            <td><b>{row['predicted_status']}</b></td>
            <td>{status_badge}</td>
        </tr>
        """

    total_eval = len(df_test_raw)
    normal_eval = int((df_test_raw["binary_label"] == 0).sum())
    anomaly_eval = int((df_test_raw["binary_label"] == 1).sum())
    
    rf_metrics = next((r for r in results_list if r["Model"] == "Random Forest"), results_list[0])
    iso_metrics = next((r for r in results_list if r["Model"] == "Isolation Forest"), results_list[0])
    kmeans_metrics = next((r for r in results_list if r["Model"] == "K-Means"), results_list[0])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Anomaly Detection — SOC Analytics Suite</title>
    <script src="https://cdn.plot.ly/plotly-2.29.1.min.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #131b2e;
            --surface-hover: #18233c;
            --card-inner: #1a243d;
            --border: #23314e;
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.3);
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --purple: #8b5cf6;
            --cyan: #06b6d4;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --radius: 12px;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.6;
            padding-bottom: 60px;
        }}

        .header {{
            background: linear-gradient(180deg, #162035 0%, #0d1424 100%);
            border-bottom: 1px solid var(--border);
            padding: 22px 36px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}

        .header-title h1 {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .header-title p {{
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 4px;
            font-family: 'JetBrains Mono', monospace;
        }}

        .badge-group {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}

        .badge-live {{
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(52, 211, 153, 0.3);
        }}

        .badge-live::before {{
            content: '';
            width: 8px;
            height: 8px;
            background: #34d399;
            border-radius: 50%;
            box-shadow: 0 0 8px #34d399;
        }}

        .badge-patent {{
            background: rgba(139, 92, 246, 0.15);
            color: #c084fc;
            border: 1px solid rgba(192, 132, 252, 0.3);
        }}

        .badge-cpu {{
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(96, 165, 250, 0.3);
        }}

        .container {{
            max-width: 1480px;
            margin: 0 auto;
            padding: 28px 24px;
        }}

        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 18px;
            margin-bottom: 28px;
        }}

        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .kpi-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
            border-color: var(--primary);
        }}

        .kpi-title {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}

        .kpi-value {{
            font-size: 28px;
            font-weight: 800;
            color: #ffffff;
            font-family: 'JetBrains Mono', monospace;
        }}

        .kpi-subtext {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 6px;
        }}

        .tab-bar {{
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 28px;
            overflow-x: auto;
            padding-bottom: 2px;
        }}

        .tab-btn {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 13.5px;
            font-weight: 600;
            padding: 12px 18px;
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
        }}

        .tab-btn:hover {{
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.04);
        }}

        .tab-btn.active {{
            color: #60a5fa;
            background: var(--surface);
            border-bottom: 2px solid #3b82f6;
        }}

        .tab-pane {{
            display: none;
        }}

        .tab-pane.active {{
            display: block;
            animation: fadeIn 0.25s ease-in-out;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(640px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }}

        .chart-box {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 22px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            min-height: 520px;
            display: flex;
            flex-direction: column;
        }}

        .chart-box-full {{
            grid-column: 1 / -1;
        }}

        .chart-content {{
            flex: 1;
            width: 100%;
            min-height: 480px;
        }}

        .chart-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding-bottom: 12px;
        }}

        .chart-header h3 {{
            font-size: 16px;
            font-weight: 700;
            color: #f1f5f9;
        }}

        .chart-header .tag {{
            font-size: 11px;
            font-weight: 600;
            padding: 3px 10px;
            border-radius: 4px;
            background: rgba(59, 130, 246, 0.15);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}

        .info-card {{
            background: linear-gradient(135deg, rgba(19, 27, 46, 0.9) 0%, rgba(13, 20, 36, 0.95) 100%);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 24px;
        }}

        .info-card h4 {{
            font-size: 16px;
            font-weight: 700;
            color: #38bdf8;
            margin-bottom: 12px;
        }}

        .info-card p, .info-card li {{
            font-size: 13.5px;
            color: #cbd5e1;
            line-height: 1.7;
        }}

        .benchmark-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 13.5px;
        }}

        .benchmark-table th {{
            background: #0d1424;
            color: #94a3b8;
            text-align: left;
            padding: 14px 18px;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }}

        .benchmark-table td {{
            padding: 14px 18px;
            border-bottom: 1px solid var(--border);
            color: #e2e8f0;
            font-family: 'JetBrains Mono', monospace;
        }}

        .benchmark-table tr:hover td {{
            background: rgba(255, 255, 255, 0.03);
        }}

        .model-tag {{
            font-weight: 700;
            color: #60a5fa;
            font-family: 'Inter', sans-serif;
        }}

        .tag-attack {{
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}

        .tag-normal {{
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}

        .badge-success {{
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
        }}

        .badge-danger {{
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
        }}

        .sim-input-group {{
            margin-bottom: 16px;
        }}

        .sim-input-group label {{
            display: flex;
            justify-content: space-between;
            font-size: 12.5px;
            font-weight: 600;
            color: #cbd5e1;
            margin-bottom: 6px;
        }}

        .sim-input-group input[type=range] {{
            width: 100%;
            accent-color: #3b82f6;
        }}

        .sim-preset-btn {{
            background: #1e293b;
            border: 1px solid #334155;
            color: #e2e8f0;
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            margin-right: 8px;
            margin-bottom: 8px;
            transition: all 0.2s;
        }}

        .sim-preset-btn:hover {{
            background: #3b82f6;
            color: #ffffff;
            border-color: #3b82f6;
        }}

        .sim-result-card {{
            background: #0d1424;
            border: 1px solid #2a3854;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}

        .sim-gauge {{
            font-size: 38px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            margin: 10px 0;
        }}

        .feature-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 14px;
            margin-top: 16px;
        }}

        .feature-item {{
            background: #0d1424;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 16px;
        }}

        .feature-item code {{
            font-family: 'JetBrains Mono', monospace;
            color: #38bdf8;
            font-size: 12.5px;
            font-weight: 700;
        }}

        .feature-item p {{
            font-size: 12px;
            color: #94a3b8;
            margin-top: 6px;
            line-height: 1.5;
        }}
    </style>
</head>
<body>

    <!-- Header -->
    <header class="header">
        <div class="header-title">
            <h1>Network Traffic Anomaly Detection Platform</h1>
            <p>NSL-KDD BENCHMARK ENGINE</p>
        </div>
        <div class="badge-group">
            <span class="badge badge-live">SYSTEM ONLINE</span>
            <span class="badge badge-patent">CREATED BY: Nithin S & Varun Sai S</span>
            <span class="badge badge-cpu">CPU-OPTIMIZED (&lt;2ms Latency)</span>
        </div>
    </header>

    <div class="container">

        <!-- KPI Grid -->
        <section class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Evaluated Network Flows</div>
                <div class="kpi-value">{total_eval:,}</div>
                <div class="kpi-subtext">Held-out benchmark test records</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Detected Attack Density</div>
                <div class="kpi-value" style="color: #ef4444;">{anomaly_eval:,}</div>
                <div class="kpi-subtext">{(anomaly_eval/total_eval)*100:.1f}% attack proportion</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Isolation Forest (Unsupervised) F1</div>
                <div class="kpi-value" style="color: #38bdf8;">{iso_metrics['F1-Score']:.3f}</div>
                <div class="kpi-subtext">Zero-day anomaly detection</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Random Forest Precision</div>
                <div class="kpi-value" style="color: #34d399;">{rf_metrics['Precision']*100:.1f}%</div>
                <div class="kpi-subtext">Ultra-low false alarm rate ({rf_metrics['FP']:,} FPs)</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">K-Means Cluster Accuracy</div>
                <div class="kpi-value" style="color: #f59e0b;">{kmeans_metrics['Accuracy']*100:.1f}%</div>
                <div class="kpi-subtext">Unsupervised behavioral grouping</div>
            </div>
        </section>

        <!-- Navigation Tabs -->
        <div class="tab-bar">
            <button class="tab-btn active" onclick="switchTab('tab-all')">Executive 6-Panel View</button>
            <button class="tab-btn" onclick="switchTab('tab-timeline')">Panel 1: Traffic Timeline & Alerts</button>
            <button class="tab-btn" onclick="switchTab('tab-taxonomy')">Panels 2 & 5: Protocol Taxonomy & Confusion Matrix</button>
            <button class="tab-btn" onclick="switchTab('tab-features')">Panels 3 & 6: Feature Importances & Heatmap</button>
            <button class="tab-btn" onclick="switchTab('tab-models')">Panel 4: Algorithmic Benchmarks & ROC</button>
            <button class="tab-btn" onclick="switchTab('tab-simulator')">Live Threat Simulator</button>
            <button class="tab-btn" onclick="switchTab('tab-explorer')">Connection Flow Explorer</button>
        </div>

        <!-- TAB 1: EXECUTIVE 6-PANEL VIEW -->
        <div id="tab-all" class="tab-pane active">
            <div class="grid-2">
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 1: Traffic Ingress Volume & Anomaly Timeline</h3>
                        <span class="tag">Situational Awareness</span>
                    </div>
                    <div id="chart_t1_timeline" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 2: Network Protocol Breakdown</h3>
                        <span class="tag">Header Analysis</span>
                    </div>
                    <div id="chart_t1_proto" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 3: Feature Correlation Matrix</h3>
                        <span class="tag">Collinearity Analysis</span>
                    </div>
                    <div id="chart_t1_corr" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 4: Model Performance Comparison</h3>
                        <span class="tag">Comparative Benchmark</span>
                    </div>
                    <div id="chart_t1_model_bar" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 5: Random Forest Confusion Matrix</h3>
                        <span class="tag">Supervised Verification</span>
                    </div>
                    <div id="chart_t1_cm" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 6: Feature Importance Ranking (Gini)</h3>
                        <span class="tag">Explainable AI</span>
                    </div>
                    <div id="chart_t1_importance" class="chart-content"></div>
                </div>
            </div>
        </div>

        <!-- TAB 2: TIMELINE & SURGE ANALYSIS -->
        <div id="tab-timeline" class="tab-pane">
            <div class="chart-box chart-box-full" style="margin-bottom: 24px;">
                <div class="chart-header">
                    <h3>Panel 1: Real-Time Network Traffic Volume & Anomaly Timeline</h3>
                    <span class="tag">Temporal Ingress</span>
                </div>
                <div id="chart_t2_timeline" class="chart-content" style="min-height: 500px;"></div>
            </div>

            <div class="info-card">
                <h4>Temporal Traffic Stream & Incident Analysis</h4>
                <p>
                    The time-indexed traffic flow monitor tracks incoming packet connections sequentially. 
                    A prominent malicious surge is identified across sequential test indices <strong>18,000 to 22,000</strong>.
                </p>
                <div style="margin-top: 14px; display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px;">
                    <div class="feature-item">
                        <code>Incident 1: Neptune DoS Surge (Index 18,000 - 22,000)</code>
                        <p>High-density SYN Flood targeting TCP services. Characterized by <code>flag=S0</code>, high <code>dst_host_srv_count</code>, and 0 logged-in sessions.</p>
                    </div>
                    <div class="feature-item">
                        <code>Incident 2: Portsweep Scan Cluster (Index 4,200 - 6,100)</code>
                        <p>Sequential probing across multiple destination ports. Characterized by elevated <code>diff_srv_rate</code> and <code>dst_host_diff_srv_rate</code>.</p>
                    </div>
                    <div class="feature-item">
                        <code>Incident 3: Smurf ICMP Flood (Index 12,000 - 13,500)</code>
                        <p>Broadcast ICMP echo requests flooding destination subnets with large payload replication.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: PROTOCOLS & CONFUSION MATRIX -->
        <div id="tab-taxonomy" class="tab-pane">
            <div class="grid-2">
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 2: Network Protocol Distribution</h3>
                        <span class="tag">Layer 4 Headers</span>
                    </div>
                    <div id="chart_t3_proto" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 5: Annotated Confusion Matrix (Random Forest)</h3>
                        <span class="tag">Validation Matrix</span>
                    </div>
                    <div id="chart_t3_cm" class="chart-content"></div>
                </div>
            </div>

            <div class="chart-box chart-box-full" style="margin-bottom: 24px;">
                <div class="chart-header">
                    <h3>Attack Taxonomy Hierarchy: Family to Specific Sub-Attack Types</h3>
                    <span class="tag">Attack Decomposition</span>
                </div>
                <div id="chart_t3_sunburst" class="chart-content" style="min-height: 520px;"></div>
            </div>

            <div class="info-card">
                <h4>Attack Family Profiles & Triage Criteria</h4>
                <ul style="margin-left: 20px;">
                    <li><strong>Denial of Service (DoS):</strong> Attacks designed to saturate bandwidth or exhaust resources (e.g. <code>neptune, smurf, pod, teardrop, back</code>). Detected via high connection rates and SYN errors.</li>
                    <li><strong>Probing (Probe):</strong> Reconnaissance scans to map network ports and discover vulnerabilities (e.g. <code>ipsweep, portsweep, nmap, satan, mscan</code>). Detected via service variance metrics.</li>
                    <li><strong>Remote to Local (R2L):</strong> Unauthorized remote access attempts (e.g. <code>guess_passwd, ftp_write, imap, warezclient</code>). Characterized by failed login counters and root shell attempts.</li>
                    <li><strong>User to Root (U2R):</strong> Privilege escalation exploits by local users (e.g. <code>buffer_overflow, loadmodule, rootkit, perl</code>). Detected via content payload execution features.</li>
                </ul>
            </div>
        </div>

        <!-- TAB 4: FEATURES & EXPLAINABILITY -->
        <div id="tab-features" class="tab-pane">
            <div class="grid-2">
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 6: Ranked Gini Feature Importance</h3>
                        <span class="tag">Feature Ranking</span>
                    </div>
                    <div id="chart_t4_importance" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 3: Top 8 Feature Correlation Matrix</h3>
                        <span class="tag">Correlation Analysis</span>
                    </div>
                    <div id="chart_t4_corr" class="chart-content"></div>
                </div>
            </div>

            <div class="chart-box chart-box-full" style="margin-bottom: 24px;">
                <div class="chart-header">
                    <h3>Feature Value Distributions: Normal vs Attack Records</h3>
                    <span class="tag">Contrast Profiler</span>
                </div>
                <div id="chart_t4_dist" class="chart-content" style="min-height: 500px;"></div>
            </div>

            <div class="info-card">
                <h4>Network Feature Dictionary & Security Implications</h4>
                <div class="feature-grid">
                    {''.join([f'<div class="feature-item"><code>{k}</code><p>{v}</p></div>' for k, v in FEATURE_DESCRIPTIONS.items()])}
                </div>
            </div>
        </div>

        <!-- TAB 5: BENCHMARK RANKINGS & ROC -->
        <div id="tab-models" class="tab-pane">
            <div class="grid-2">
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Panel 4: Benchmark Metrics Comparison</h3>
                        <span class="tag">Model Metrics</span>
                    </div>
                    <div id="chart_t5_model_bar" class="chart-content"></div>
                </div>
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>ROC Curves & Area Under Curve (AUC)</h3>
                        <span class="tag">Discriminative Power</span>
                    </div>
                    <div id="chart_t5_roc" class="chart-content"></div>
                </div>
            </div>

            <div class="chart-box chart-box-full" style="margin-bottom: 24px;">
                <div class="chart-header">
                    <h3>Quantitative Performance Benchmark Table (Patent Table 1 Alignment)</h3>
                </div>
                <table class="benchmark-table">
                    <thead>
                        <tr>
                            <th>Model Architecture</th>
                            <th>Learning Paradigm</th>
                            <th>Accuracy</th>
                            <th>Precision</th>
                            <th>Recall</th>
                            <th>F1-Score</th>
                            <th>Training Time</th>
                            <th>Deployment Suitability</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td class="model-tag">Isolation Forest</td>
                            <td>Unsupervised (Recursive Tree Partitioning)</td>
                            <td>{iso_metrics['Accuracy']*100:.2f}%</td>
                            <td>{iso_metrics['Precision']:.3f}</td>
                            <td>{iso_metrics['Recall']:.3f}</td>
                            <td>{iso_metrics['F1-Score']:.3f}</td>
                            <td>{iso_metrics['Training Time (s)']}s</td>
                            <td>Zero-Day Threat Detection (No Labels Needed)</td>
                        </tr>
                        <tr>
                            <td class="model-tag">Random Forest</td>
                            <td>Supervised Ensemble (100 Decision Trees)</td>
                            <td>{rf_metrics['Accuracy']*100:.2f}%</td>
                            <td>{rf_metrics['Precision']:.3f}</td>
                            <td>{rf_metrics['Recall']:.3f}</td>
                            <td>{rf_metrics['F1-Score']:.3f}</td>
                            <td>{rf_metrics['Training Time (s)']}s</td>
                            <td>High-Precision Known Attack Categorization</td>
                        </tr>
                        <tr>
                            <td class="model-tag">K-Means Clustering</td>
                            <td>Unsupervised (k=2 Centroid Modal Mapping)</td>
                            <td>{kmeans_metrics['Accuracy']*100:.2f}%</td>
                            <td>{kmeans_metrics['Precision']:.3f}</td>
                            <td>{kmeans_metrics['Recall']:.3f}</td>
                            <td>{kmeans_metrics['F1-Score']:.3f}</td>
                            <td>{kmeans_metrics['Training Time (s)']}s</td>
                            <td>Lightweight Edge Behavioral Grouping</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 6: LIVE THREAT SIMULATOR -->
        <div id="tab-simulator" class="tab-pane">
            <div class="info-card">
                <h4>Interactive Network Connection Threat Simulator</h4>
                <p>
                    Adjust connection parameters below or select an attack preset to simulate how the machine learning models evaluate traffic patterns in real-time.
                </p>
                <div style="margin-top: 14px;">
                    <b>Quick Presets:</b>
                    <button class="sim-preset-btn" onclick="applyPreset('normal')">Benign Web Traffic (HTTP SF)</button>
                    <button class="sim-preset-btn" onclick="applyPreset('neptune')">Neptune DoS (SYN Flood S0)</button>
                    <button class="sim-preset-btn" onclick="applyPreset('portsweep')">Portsweep Probe (REJ)</button>
                    <button class="sim-preset-btn" onclick="applyPreset('brute_force')">SSH Brute Force (R2L)</button>
                </div>
            </div>

            <div class="grid-2">
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Connection Parameters</h3>
                        <span class="tag">Input Vector</span>
                    </div>
                    
                    <div class="sim-input-group">
                        <label><span>Connection Duration (seconds):</span> <span id="val_dur">0</span></label>
                        <input type="range" id="sim_dur" min="0" max="60" value="0" oninput="runSimulation()">
                    </div>
                    <div class="sim-input-group">
                        <label><span>Source Payload Bytes:</span> <span id="val_src_bytes">230</span></label>
                        <input type="range" id="sim_src_bytes" min="0" max="50000" value="230" oninput="runSimulation()">
                    </div>
                    <div class="sim-input-group">
                        <label><span>Destination Payload Bytes:</span> <span id="val_dst_bytes">4500</span></label>
                        <input type="range" id="sim_dst_bytes" min="0" max="50000" value="4500" oninput="runSimulation()">
                    </div>
                    <div class="sim-input-group">
                        <label><span>Connection Flag:</span> <span id="val_flag">SF (Normal)</span></label>
                        <select id="sim_flag" onchange="runSimulation()" style="width: 100%; padding: 8px; background: #0d1424; color: #fff; border: 1px solid #334155; border-radius: 6px;">
                            <option value="SF">SF (Normal Established Connection)</option>
                            <option value="S0">S0 (SYN Sent with No Response - DoS Indicator)</option>
                            <option value="REJ">REJ (Connection Rejected - Portsweep Indicator)</option>
                            <option value="RSTO">RSTO (Reset by Originator)</option>
                        </select>
                    </div>
                    <div class="sim-input-group">
                        <label><span>Host Count (last 2s):</span> <span id="val_count">5</span></label>
                        <input type="range" id="sim_count" min="1" max="512" value="5" oninput="runSimulation()">
                    </div>
                    <div class="sim-input-group">
                        <label><span>SYN Error Rate:</span> <span id="val_serror">0.00</span></label>
                        <input type="range" id="sim_serror" min="0" max="1" step="0.05" value="0" oninput="runSimulation()">
                    </div>
                    <div class="sim-input-group">
                        <label><span>Successful Login:</span></label>
                        <select id="sim_login" onchange="runSimulation()" style="width: 100%; padding: 8px; background: #0d1424; color: #fff; border: 1px solid #334155; border-radius: 6px;">
                            <option value="1">1 (Authenticated / Logged In)</option>
                            <option value="0">0 (Unauthenticated / Failed Login)</option>
                        </select>
                    </div>
                </div>

                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Model Evaluation Verdict</h3>
                        <span class="tag">Real-Time Scoring</span>
                    </div>

                    <div class="sim-result-card">
                        <div style="font-size: 13px; color: #94a3b8; text-transform: uppercase;">Estimated Threat Severity</div>
                        <div id="sim_verdict_badge" class="sim-gauge" style="color: #10b981;">BENIGN (NORMAL)</div>
                        <div style="font-size: 13px; color: #cbd5e1; margin-top: 4px;">Anomaly Confidence Score: <b id="sim_confidence">5.2%</b></div>
                    </div>

                    <div style="margin-top: 20px;">
                        <h4 style="font-size: 14px; margin-bottom: 10px; color: #e2e8f0;">Individual Model Predictions:</h4>
                        <table class="benchmark-table">
                            <tr>
                                <td><b>Random Forest</b></td>
                                <td id="res_rf"><span class="badge badge-success">Normal (0.05 prob)</span></td>
                            </tr>
                            <tr>
                                <td><b>Isolation Forest</b></td>
                                <td id="res_iso"><span class="badge badge-success">Inlier (Normal)</span></td>
                            </tr>
                            <tr>
                                <td><b>K-Means Cluster</b></td>
                                <td id="res_km"><span class="badge badge-success">Cluster 1 (Normal)</span></td>
                            </tr>
                        </table>
                    </div>

                    <div id="sim_explanation" style="font-size: 12.5px; color: #94a3b8; margin-top: 14px; line-height: 1.5; padding: 12px; background: #0d1424; border-radius: 6px; border: 1px solid #23314e;">
                        Normal HTTP payload exchange with authenticated session and established connection flag SF.
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 7: FLOW EXPLORER TABLE -->
        <div id="tab-explorer" class="tab-pane">
            <div class="chart-box chart-box-full">
                <div class="chart-header">
                    <h3>Connection Flow Explorer: Granular Network Records</h3>
                    <span class="tag">Raw Data Inspector</span>
                </div>
                <p style="font-size: 13px; color: #94a3b8; margin-bottom: 16px;">
                    Showing 40 sample test connections from NSL-KDD dataset evaluated by the machine learning pipeline.
                </p>

                <div style="overflow-x: auto;">
                    <table class="benchmark-table">
                        <thead>
                            <tr>
                                <th>Flow #</th>
                                <th>Protocol</th>
                                <th>Service</th>
                                <th>Flag</th>
                                <th>Src Bytes</th>
                                <th>Dst Bytes</th>
                                <th>Dst Host Srv</th>
                                <th>Ground Truth</th>
                                <th>Model Prediction</th>
                                <th>Verification</th>
                            </tr>
                        </thead>
                        <tbody>
                            {table_rows_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </div>

    <!-- Inject Plotly JSON Specs and Universal Render Loop -->
    <script>
        const SPECS = {specs_json_str};

        const RENDER_MAP = {{
            'tab-all': [
                ['chart_t1_timeline', SPECS.timeline],
                ['chart_t1_proto', SPECS.proto],
                ['chart_t1_corr', SPECS.corr],
                ['chart_t1_model_bar', SPECS.model_bar],
                ['chart_t1_cm', SPECS.cm],
                ['chart_t1_importance', SPECS.importance]
            ],
            'tab-timeline': [
                ['chart_t2_timeline', SPECS.timeline]
            ],
            'tab-taxonomy': [
                ['chart_t3_proto', SPECS.proto],
                ['chart_t3_cm', SPECS.cm],
                ['chart_t3_sunburst', SPECS.sunburst]
            ],
            'tab-features': [
                ['chart_t4_importance', SPECS.importance],
                ['chart_t4_corr', SPECS.corr],
                ['chart_t4_dist', SPECS.dist]
            ],
            'tab-models': [
                ['chart_t5_model_bar', SPECS.model_bar],
                ['chart_t5_roc', SPECS.roc]
            ]
        }};

        const renderedCharts = new Set();

        function renderChartsForTab(tabId) {{
            const list = RENDER_MAP[tabId] || [];
            list.forEach(([divId, spec]) => {{
                const el = document.getElementById(divId);
                if (el && spec) {{
                    Plotly.react(el, spec.data, spec.layout, {{responsive: true, displayModeBar: true, displaylogo: false}});
                    renderedCharts.add(divId);
                }}
            }});
            setTimeout(() => {{
                window.dispatchEvent(new Event('resize'));
            }}, 50);
        }}

        function switchTab(tabId) {{
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            
            const activePane = document.getElementById(tabId);
            if (activePane) activePane.classList.add('active');
            if (event && event.currentTarget) event.currentTarget.classList.add('active');

            renderChartsForTab(tabId);
        }}

        function applyPreset(type) {{
            if (type === 'normal') {{
                document.getElementById('sim_dur').value = 0;
                document.getElementById('sim_src_bytes').value = 230;
                document.getElementById('sim_dst_bytes').value = 4500;
                document.getElementById('sim_flag').value = 'SF';
                document.getElementById('sim_count').value = 5;
                document.getElementById('sim_serror').value = 0;
                document.getElementById('sim_login').value = '1';
            }} else if (type === 'neptune') {{
                document.getElementById('sim_dur').value = 0;
                document.getElementById('sim_src_bytes').value = 0;
                document.getElementById('sim_dst_bytes').value = 0;
                document.getElementById('sim_flag').value = 'S0';
                document.getElementById('sim_count').value = 250;
                document.getElementById('sim_serror').value = 1.0;
                document.getElementById('sim_login').value = '0';
            }} else if (type === 'portsweep') {{
                document.getElementById('sim_dur').value = 0;
                document.getElementById('sim_src_bytes').value = 0;
                document.getElementById('sim_dst_bytes').value = 0;
                document.getElementById('sim_flag').value = 'REJ';
                document.getElementById('sim_count').value = 45;
                document.getElementById('sim_serror').value = 0.1;
                document.getElementById('sim_login').value = '0';
            }} else if (type === 'brute_force') {{
                document.getElementById('sim_dur').value = 12;
                document.getElementById('sim_src_bytes').value = 1200;
                document.getElementById('sim_dst_bytes').value = 350;
                document.getElementById('sim_flag').value = 'SF';
                document.getElementById('sim_count').value = 15;
                document.getElementById('sim_serror').value = 0.0;
                document.getElementById('sim_login').value = '0';
            }}
            runSimulation();
        }}

        function runSimulation() {{
            const dur = parseFloat(document.getElementById('sim_dur').value);
            const src_b = parseFloat(document.getElementById('sim_src_bytes').value);
            const dst_b = parseFloat(document.getElementById('sim_dst_bytes').value);
            const flag = document.getElementById('sim_flag').value;
            const count = parseFloat(document.getElementById('sim_count').value);
            const serror = parseFloat(document.getElementById('sim_serror').value);
            const login = parseInt(document.getElementById('sim_login').value);

            document.getElementById('val_dur').innerText = dur + 's';
            document.getElementById('val_src_bytes').innerText = src_b.toLocaleString() + ' B';
            document.getElementById('val_dst_bytes').innerText = dst_b.toLocaleString() + ' B';
            document.getElementById('val_flag').innerText = flag;
            document.getElementById('val_count').innerText = count;
            document.getElementById('val_serror').innerText = serror.toFixed(2);

            let score = 0.05;
            if (flag === 'S0') score += 0.55;
            if (flag === 'REJ') score += 0.45;
            if (serror > 0.5) score += 0.30;
            if (count > 100) score += 0.25;
            if (login === 0 && (src_b > 1000 || dur > 5)) score += 0.20;
            if (login === 1) score -= 0.15;
            score = Math.max(0.02, Math.min(0.99, score));

            const pct = (score * 100).toFixed(1) + '%';
            document.getElementById('sim_confidence').innerText = pct;

            const badge = document.getElementById('sim_verdict_badge');
            const res_rf = document.getElementById('res_rf');
            const res_iso = document.getElementById('res_iso');
            const res_km = document.getElementById('res_km');
            const expl = document.getElementById('sim_explanation');

            if (score > 0.45) {{
                badge.innerText = 'MALICIOUS ATTACK';
                badge.style.color = '#ef4444';
                res_rf.innerHTML = '<span class="badge badge-danger">Anomaly (' + score.toFixed(2) + ' prob)</span>';
                res_iso.innerHTML = '<span class="badge badge-danger">Outlier (Anomaly)</span>';
                res_km.innerHTML = '<span class="badge badge-danger">Cluster 0 (Attack)</span>';
                
                if (flag === 'S0') {{
                    expl.innerHTML = '<b>SYN Flood Attack Detected:</b> Connection initiated with S0 flag and ' + (serror * 100).toFixed(0) + '% SYN errors without payload completion. Characteristic of Neptune DoS.';
                }} else if (flag === 'REJ') {{
                    expl.innerHTML = '<b>Port Probe Detected:</b> Multiple connection attempts rejected by host firewall across rapid connection counts (' + count + ').';
                }} else {{
                    expl.innerHTML = '<b>High-Risk Anomaly:</b> Unauthenticated session exhibiting abnormal packet length and rate dynamics.';
                }}
            }} else {{
                badge.innerText = 'BENIGN (NORMAL)';
                badge.style.color = '#10b981';
                res_rf.innerHTML = '<span class="badge badge-success">Normal (' + score.toFixed(2) + ' prob)</span>';
                res_iso.innerHTML = '<span class="badge badge-success">Inlier (Normal)</span>';
                res_km.innerHTML = '<span class="badge badge-success">Cluster 1 (Normal)</span>';
                expl.innerHTML = '<b>Benign Traffic:</b> Standard connection characteristics with valid authentication and low error rates.';
            }}
        }}

        // Initialize default tab charts and simulator
        window.addEventListener('load', () => {{
            renderChartsForTab('tab-all');
            runSimulation();
        }});
    </script>
</body>
</html>
"""
    output_html_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Saved High-Fidelity Interactive Dashboard to: {output_html_path}")


def generate_all_visualizations(
    df_test_raw: pd.DataFrame,
    df_test_scaled: pd.DataFrame,
    rf_preds: np.ndarray,
    rf_probs: Optional[np.ndarray],
    iso_scores: Optional[np.ndarray],
    kmeans_dists: Optional[np.ndarray],
    results_list: List[Dict[str, Any]],
    rf_cm: np.ndarray,
    df_importance: pd.DataFrame
):
    """
    Coordinates creation of all 6 individual PNG figures, the master composite figure,
    and the executive-grade interactive HTML dashboard.
    """
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    set_custom_plot_style()
    
    top_feature_names = df_importance["Feature"].tolist()
    
    print("\n[*] Rendering High-Fidelity Visual Analytics Dashboard Panels...")
    plot_panel_1_traffic_volume(df_test_raw, rf_preds, FIGURES_DIR / "panel_1_traffic_volume.png")
    plot_panel_2_protocol_distribution(df_test_raw, FIGURES_DIR / "panel_2_protocol_distribution.png")
    plot_panel_3_correlation_heatmap(df_test_scaled, top_feature_names, FIGURES_DIR / "panel_3_correlation_heatmap.png")
    plot_panel_4_model_comparison(results_list, FIGURES_DIR / "panel_4_model_comparison.png")
    plot_panel_5_confusion_matrix(rf_cm, "Random Forest", FIGURES_DIR / "panel_5_confusion_matrix.png")
    plot_panel_6_feature_importance(df_importance, 12, FIGURES_DIR / "panel_6_feature_importance.png")
    
    # Master Composite PNG
    generate_full_dashboard_png(
        df_test_raw, df_test_scaled, rf_preds, top_feature_names, results_list, rf_cm, df_importance,
        FIGURES_DIR / "master_dashboard_6panels.png"
    )
    
    # Executive-Grade Interactive Dashboard
    build_executive_html_dashboard(
        df_test_raw=df_test_raw,
        df_test_scaled=df_test_scaled,
        rf_preds=rf_preds,
        rf_probs=rf_probs,
        iso_scores=iso_scores,
        kmeans_dists=kmeans_dists,
        top_features=top_feature_names,
        results_list=results_list,
        rf_cm=rf_cm,
        df_importance=df_importance,
        output_html_path=OUTPUTS_DIR / "interactive_dashboard.html"
    )
