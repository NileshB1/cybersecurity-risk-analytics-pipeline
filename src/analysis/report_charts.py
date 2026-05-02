"""

Generates charts from the analysis CSVs
and saves them as PNG files to analysis/report_figures/
"""

import os
import sys
import warnings
warnings.filterwarnings("ignore")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mtick
import seaborn as sns

# plotly for some charts then export
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio

plt.ioff()

ANALYSIS_DIR = "analysis/output"
OUTPUT_DIR   = "analysis/report_figures"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# seaborn theme - clean academic look
sns.set_theme(style="whitegrid", palette="muted", font="DejaVu Sans")
plt.rcParams.update({
    "figure.dpi": 150,  "savefig.dpi":300,
    "savefig.bbox": "tight",   "figure.facecolor": "white",
    "axes.facecolor":"white", "axes.spines.top": False,
    "axes.spines.right":  False, "font.size": 11, "axes.titlesize":  13,
    "axes.titleweight": "bold",  "axes.labelsize": 11,
})

# consistent colour palette
PALETTE = {
    "primary": "#1B3A6B", "red": "#C0392B",
    "orange": "#E67E22", "green": "#27AE60", "teal": "#16A085",    
    "grey": "#7F8C8D",  "critical": "#C0392B", "high": "#E67E22",
    "medium": "#F1C40F","low": "#27AE60",
}

SEV_COLOURS = {
    "Critical (9-10)": PALETTE["critical"], "High (7-8.9)": PALETTE["high"],
    "Medium (4-6.9)": PALETTE["medium"], "Low (0.1-3.9)": PALETTE["low"],
    "No Score": PALETTE["grey"],
}


def load(filename):
    path = os.path.join(ANALYSIS_DIR, filename)
    if not os.path.exists(path):
        print(f"SKIP {filename} — not found")
        return pd.DataFrame()
    df = pd.read_csv(path, low_memory=False)
    print(f"Loaded {filename}: {len(df):,} rows")
    return df


def save_fig(fig, name):
    path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white", format="png")
    plt.close(fig)
    size = os.path.getsize(path)
    print(f" Saved: {path}")
    


# Figure 1: Industry Breach count

def fig_industry_breach_count():
    df = load("a1_industry_impact.csv")
    if df.empty:
        return

    df["industry"] = df["industry"].replace({
        "Unknown": "All Other Industries", "Unkn": "All Other Industries",
        "unknown": "All Other Industries", "Bsr": "Business / Services",
    })

    df = df.sort_values("breach_count", ascending=True)
    colours = [PALETTE["primary"]] * len(df)
    colours[-1] = PALETTE["red"]   # highlight top sector

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(df["industry"], df["breach_count"], color=colours, edgecolor="white")

    for bar in bars:
        w = bar.get_width()
        ax.text(w + 50, bar.get_y() + bar.get_height()/2,
                f"{int(w):,}", va="center", ha="left", fontsize=9, color="#333333")

    ax.set_xlabel("Number of Breach Incidents")
    ax.set_title("Figure 1: Data Breach Count by Industry Sector")
    ax.xaxis.set_major_formatter(mtick.FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.set_xlim(right=df["breach_count"].max() * 1.18)

    red_patch = mpatches.Patch(color=PALETTE["red"], label="Highest breach count sector")
    ax.legend(handles=[red_patch], fontsize=9, loc="lower right")

    save_fig(fig, "fig1_industry_breach_count.png")


# Figure 2: Records Exposed by Sector

def fig_records_exposed():
    df = load("a1_industry_impact.csv")
    if df.empty or "total_records_exposed" not in df.columns:
        return

    df = df[df["total_records_exposed"] > 0].sort_values("total_records_exposed", ascending=True)

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(
        df["industry"],
        df["total_records_exposed"],
        color=PALETTE["teal"],
        edgecolor="white",
    )

    for bar in bars:
        w = bar.get_width()
        label = f"{w/1e6:.1f}M" if w >= 1e6 else f"{w:,.0f}"
        ax.text(w * 1.02, bar.get_y() + bar.get_height()/2,
                label, va="center", fontsize=9, color="#333333")

    ax.set_xscale("log")
    ax.set_xlabel("Total Records Exposed (log scale)")
    ax.set_title("Figure 2: Total Records Exposed by Industry Sector")
    ax.xaxis.set_major_formatter(
        mtick.FuncFormatter(lambda x, _: f"{x/1e6:.0f}M" if x >= 1e6 else f"{x:,.0f}")
    )

    save_fig(fig, "fig2_records_exposed_by_sector.png")


# ── Figure 3: CVE Volume by Year — stacked bar ───────────────────────────────

def fig_cve_volume_yearly():
    df = load("a2_yearly_threat_landscape.csv")
    if df.empty:
        return

    df = df.sort_values("year")
    other = (df["total_cves"] - df["critical_count"] - df["high_count"]).clip(lower=0)

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(df["year"], other,             label="Medium / Low", color="#BDC3C7")
    ax.bar(df["year"], df["high_count"],  label="High (7-8.9)", color=PALETTE["high"],
           bottom=other)
    ax.bar(df["year"], df["critical_count"], label="Critical (9-10)", color=PALETTE["critical"],
           bottom=other + df["high_count"])

    ax.set_xlabel("Year")
    ax.set_ylabel("CVE Count")
    ax.set_title("Figure 3: Annual CVE Publication Volume by Severity")
    ax.yaxis.set_major_formatter(mtick.FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.legend(fontsize=9)
    ax.set_xticks(df["year"])
    ax.tick_params(axis="x", rotation=45)

    save_fig(fig, "fig3_cve_volume_yearly.png")


# ── Figure 4: CVE Volume vs Breach Frequency (dual axis) ─────────────────────

def fig_cve_vs_breaches():
    df = load("a2_yearly_threat_landscape.csv")
    if df.empty:
        return

    df = df.sort_values("year")

    fig, ax1 = plt.subplots(figsize=(11, 5))
    ax2 = ax1.twinx()

    bars = ax1.bar(df["year"], df["total_cves"], color="#BDC3C7", alpha=0.7, label="Total CVEs")
    line, = ax2.plot(df["year"], df["total_breaches"], color=PALETTE["red"],
                     linewidth=2.5, marker="o", markersize=5, label="Data Breaches")

    ax1.set_xlabel("Year")
    ax1.set_ylabel("CVE Count", color="#555555")
    ax2.set_ylabel("Breach Count", color=PALETTE["red"])
    ax2.tick_params(axis="y", labelcolor=PALETTE["red"])
    ax1.yaxis.set_major_formatter(mtick.FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax1.set_title("Figure 4: CVE Volume vs Breach Frequency by Year")
    ax1.set_xticks(df["year"])
    ax1.tick_params(axis="x", rotation=45)

    lines = [bars, line]
    labels = ["Total CVEs", "Data Breaches"]
    ax1.legend(lines, labels, fontsize=9, loc="upper left")

    save_fig(fig, "fig4_cve_vs_breach_yearly.png")


#Figure 5: Exploitation Rate by Severity Band 

def fig_exploitation_rate():
    df = load("a3_attack_severity_patterns.csv")
    if df.empty:
        return

    band_order = ["Critical (9-10)", "High (7-8.9)", "Medium (4-6.9)", "Low (0.1-3.9)", "No Score"]
    df["severity_band"] = pd.Categorical(df["severity_band"], categories=band_order, ordered=True)
    df = df.sort_values("severity_band")

    colours = [SEV_COLOURS.get(b, PALETTE["grey"]) for b in df["severity_band"]]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # left: grouped bar total vs exploited
    x     = np.arange(len(df))
    width = 0.35
    axes[0].bar(x - width/2, df["total_cves"],    width, label="Total CVEs",   color="#BDC3C7")
    axes[0].bar(x + width/2, df["exploited_cves"], width, label="Exploited", color=colours)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(df["severity_band"].astype(str), rotation=20, ha="right", fontsize=9)
    axes[0].set_ylabel("CVE Count")
    axes[0].set_title("Total vs Exploited CVEs by Severity Band")
    axes[0].yaxis.set_major_formatter(mtick.FuncFormatter(lambda v, _: f"{int(v):,}"))
    axes[0].legend(fontsize=9)

    # right: exploitation rate bar
    if "exploitation_rate_pct" in df.columns:
        axes[1].bar(df["severity_band"].astype(str), df["exploitation_rate_pct"],
                    color=colours, edgecolor="white")
        axes[1].set_ylabel("Exploitation Rate (%)")
        axes[1].set_title("Exploitation Rate by Severity Band")
        axes[1].set_xticklabels(df["severity_band"].astype(str), rotation=20, ha="right", fontsize=9)
        for i, (_, row) in enumerate(df.iterrows()):
            axes[1].text(i, row["exploitation_rate_pct"] + 0.3,
                         f"{row['exploitation_rate_pct']:.1f}%",
                         ha="center", fontsize=9)

    fig.suptitle("Figure 5: Attack Severity Patterns", fontsize=14, fontweight="bold")
    plt.tight_layout()
    save_fig(fig, "fig5_exploitation_rate_by_severity.png")

#TODO delete think about this later?
# Figure 6: Top Exploited Vendors 

def fig_top_vendors():
    df = load("a4_most_exploited_vendors.csv")
    if df.empty:
        return

    df = df.nlargest(15, "exploited_cves").sort_values("exploited_cves", ascending=True)

    # colour bars by avg_cvss_score
    norm = plt.Normalize(df["avg_cvss_score"].min(), df["avg_cvss_score"].max())
    cmap = matplotlib.colormaps["Reds"]
    colours = [cmap(norm(v)) for v in df["avg_cvss_score"]]

    fig, ax = plt.subplots(figsize=(9, 6))
    bars = ax.barh(df["vendor"], df["exploited_cves"], color=colours, edgecolor="white")

    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.5, bar.get_y() + bar.get_height()/2,
                f"{int(w):,}", va="center", ha="left", fontsize=9)

    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cbar = fig.colorbar(sm, ax=ax, pad=0.01)
    cbar.set_label("Avg CVSS Score", fontsize=9)

    ax.set_xlabel("Number of Exploited CVEs")
    ax.set_title("Figure 6: Top 15 Vendors by Confirmed Exploited CVE Count")
    ax.set_xlim(right=df["exploited_cves"].max() * 1.15)

    save_fig(fig, "fig6_top_exploited_vendors.png")


# Figure 7: Time to Weaponisation: histogram 

def fig_time_to_weaponisation():
    df = load("a5_time_to_weaponisation.csv")
    if df.empty:
        return

    df["days_to_exploit"] = pd.to_numeric(df["days_to_exploit"], errors="coerce")
    df = df[df["days_to_exploit"].between(0, 1500)].copy()

    if df.empty:
        return

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # left: histogram
    axes[0].hist(df["days_to_exploit"], bins=50, color=PALETTE["primary"],
                 edgecolor="white", alpha=0.85)
    median = df["days_to_exploit"].median()
    mean   = df["days_to_exploit"].mean()
    axes[0].axvline(median, color=PALETTE["red"],    linestyle="--", linewidth=2,
                    label=f"Median = {median:.0f} days")
    axes[0].axvline(mean,   color=PALETTE["orange"], linestyle="--", linewidth=2,
                    label=f"Mean = {mean:.0f} days")
    axes[0].set_xlabel("Days from CVE Disclosure to Exploitation")
    axes[0].set_ylabel("Number of CVEs")
    axes[0].set_title("Distribution of Time to Weaponisation")
    axes[0].legend(fontsize=9)

    # right: bracket bar chart
    if "time_bracket" in df.columns:
        bracket_order = [
            "Within a week", "Within a month",
            "1-3 months", "3-12 months", "Over a year"
        ]
        bracket_colours = [
            PALETTE["critical"], PALETTE["high"],
            PALETTE["medium"],   PALETTE["low"], PALETTE["primary"]
        ]
        counts = df["time_bracket"].value_counts()
        counts = counts.reindex(
            [b for b in bracket_order if b in counts.index]
        )
        axes[1].bar(range(len(counts)), counts.values,
                    color=bracket_colours[:len(counts)], edgecolor="white")
        axes[1].set_xticks(range(len(counts)))
        axes[1].set_xticklabels(counts.index, rotation=20, ha="right", fontsize=9)
        axes[1].set_ylabel("Number of CVEs")
        axes[1].set_title("CVEs by Weaponisation Time Window")
        for i, v in enumerate(counts.values):
            axes[1].text(i, v + 0.5, f"{int(v):,}", ha="center", fontsize=9)

    fig.suptitle("Figure 7: Time to Weaponisation Analysis", fontsize=14, fontweight="bold")
    plt.tight_layout()
    save_fig(fig, "fig7_time_to_weaponisation.png")

#TODO Need to this?
# Figure 8: Severity over time heatmap

def fig_severity_heatmap():
    df = load("a2_yearly_threat_landscape.csv")
    if df.empty or "avg_severity" not in df.columns:
        return

    df = df.sort_values("year")
    df["avg_severity"] = pd.to_numeric(df["avg_severity"], errors="coerce")

    pivot = pd.DataFrame({
        "Critical": df.set_index("year")["critical_count"],
        "High": df.set_index("year")["high_count"],
        "Total": df.set_index("year")["total_cves"],
    })

    fig, ax = plt.subplots(figsize=(11, 4))
    sns.heatmap(
        pivot.T, cmap="YlOrRd", ax=ax,  annot=True,fmt=".0f",
        linewidths=0.5,  cbar_kws={"shrink": 0.7, "label": "CVE Count"},
        annot_kws={"size": 7},
    )
    ax.set_xlabel("Year")
    ax.set_title("Figure 8: CVE Severity Heatmap by Year")
    plt.xticks(rotation=45)

    save_fig(fig, "fig8_severity_heatmap.png")


# Runner

class ReportChartGenerator:
    """
    Generates all report figures in one pass. Each figure is saved as a high-resolution PNG.
    """

    def __init__(self):
        self._generators = [
            ("Figure 1: Industry Breach Count", fig_industry_breach_count),
            ("Figure 2: Records Exposed by Sector", fig_records_exposed),("Figure 3: CVE Volume Yearly", fig_cve_volume_yearly),
            ("Figure 4: CVE vs Breach Frequency", fig_cve_vs_breaches),
            ("Figure 5: Exploitation Rate", fig_exploitation_rate), ("Figure 6: Top Exploited Vendors", fig_top_vendors),
            ("Figure 7: Time to Weaponisation", fig_time_to_weaponisation), ("Figure 8: Severity Heatmap", fig_severity_heatmap),
        ]

    def run(self):
        print(f"\nGenerating report figures: {OUTPUT_DIR}/\n")
        passed = 0
        failed = 0

        for label, fn in self._generators:
            print(f"  Generating: {label}")
            try:
                fn()
                passed += 1
            except Exception as e:
                print(f"  ERROR: {e}")
                failed += 1

        print(f"\nDone: {passed} figures saved, {failed} failed")
        print(f"Output folder: {os.path.abspath(OUTPUT_DIR)}")


if __name__ == "__main__":
    generator = ReportChartGenerator()
    generator.run()