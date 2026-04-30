import os
import sys
import json
import logging
import warnings
from typing import Any, Dict, List, Optional, Tuple

warnings.filterwarnings("ignore")  

import pandas as pd
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
from scipy import stats
from dotenv import load_dotenv

load_dotenv()

PLOTS_DIR  = "notebooks/plots"
OUTPUT_DIR = "notebooks/eda_output"


def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(fmt="%(asctime)s [%(levelname)-8s] %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S" )
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    fh = logging.FileHandler("pipeline.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger

# load raw json file
class EDADataLoader:

    def __init__(self):
        self.logger = configure_logger("EDADataLoader")

    def load_from_json(self,
        cve_path: str = "cve_raw.json",
        kev_path: str = "kev_raw.json",
        breach_path: str = "breach_raw.json") -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        self.logger.info("Loading raw JSON files for EDA")

        def _load(path):
            if not os.path.exists(path):
                self.logger.warning(f"File not found: {path}")
                return pd.DataFrame()
            with open(path) as f:
                data = json.load(f)
            df = pd.DataFrame(data)
            self.logger.info(f"{path}: {len(df):,} rows")
            return df

        return _load(cve_path), _load(kev_path), _load(breach_path)

    def load_from_postgres(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        import psycopg2
        self.logger.info("Loading from PostgreSQL for EDA...")
        config = {"host":os.getenv("PG_HOST", "localhost"),
            "port":os.getenv("PG_PORT","5432"),
            "dbname": os.getenv("PG_DB","cybersec_db"),
            "user": os.getenv("PG_USER","postgres"),
            "password": os.getenv("PG_PASSWORD", ""), }
        try:
            conn = psycopg2.connect(**config, connect_timeout=10)
            cve_df = pd.read_sql("SELECT * FROM vulnerabilities LIMIT 50000;", conn)
            kev_df = pd.read_sql("SELECT * FROM exploited_vulnerabilities;", conn)
            breach_df = pd.read_sql("SELECT * FROM breaches;", conn)
            conn.close()
            self.logger.info(f"Loaded from PG: CVE={len(cve_df):,} KEV={len(kev_df):,} Breach={len(breach_df):,}" )
            return cve_df, kev_df, breach_df
        except Exception as e:
            self.logger.error(f"PostgreSQL load failed: {e} - falling back to JSON files")
            return self.load_from_json()


# PlotSaver - to save and close figures consistently

class PlotSaver:

    def __init__(self, plots_dir: str = PLOTS_DIR):
        self.logger = configure_logger("PlotSaver")
        self.plots_dir = plots_dir
        os.makedirs(plots_dir, exist_ok=True)

    def save(self, fig: plt.Figure, filename: str) -> str:
        path = os.path.join(self.plots_dir, filename)
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        self.logger.info(f"Plot saved: {path}")
        return path


# DataProfiler - to print basic stats for each dataset

class DataProfiler:

    def __init__(self):
        self.logger = configure_logger("DataProfiler")

    def profile_dataset(self, df: pd.DataFrame, name: str) -> None: # print shape, dtype and null summary
        if df.empty:
            self.logger.warning(f"{name}: empty - skipping profile")
            return

        self.logger.info(f" DATASET: {name}")
        self.logger.info(f" Rows: {len(df):,} Columns: {len(df.columns)}")
        self.logger.info(f" Columns: {list(df.columns)}")

        # null counts
        nulls = df.isnull().sum()
        non_zero_nulls = nulls[nulls > 0]
        if non_zero_nulls.empty:
            self.logger.info("Nulls: none found")
        else:
            self.logger.info("Null counts (non-zero only):")
            for col, cnt in non_zero_nulls.items():
                self.logger.info(f"{col:<28} {cnt:>7,} ({cnt/len(df)*100:.1f}%)")

        # numeric summaries
        num_cols = df.select_dtypes(include=[np.number]).columns
        if len(num_cols):
            self.logger.info(f"Numeric columns summary:")
            for col in num_cols:
                s = df[col].dropna()
                if len(s):
                    self.logger.info(f"{col:<28} min={s.min():.2f} mean={s.mean():.2f}  max={s.max():.2f}")



# SeverityAnalyser - will looks at CVSS score distribution in the CVE dataset

class SeverityAnalyser:

    def __init__(self, plotter: PlotSaver):
        self.logger  = configure_logger("SeverityAnalyser")
        self._plotter = plotter

    def analyse(self, cve_df: pd.DataFrame, kev_df: pd.DataFrame) -> Dict[str, Any]:
        
        if "severity" not in cve_df.columns:
            self.logger.warning("No severity column in CVE data")
            return {}

        # clean severity - force numeric
        cve_sev = pd.to_numeric(cve_df["severity"], errors="coerce").dropna()

        stats_summary = {"count": len(cve_sev),
            "mean":round(cve_sev.mean(), 2),
            "median": round(cve_sev.median(), 2),
            "std": round(cve_sev.std(), 2), }

        # bin into severity bands
        bins = [0, 3.9, 6.9, 8.9, 10]
        labels = ["Low (0-3.9)", "Medium (4-6.9)", "High (7-8.9)", "Critical (9-10)"]
        cve_df = cve_df.copy()
        cve_df["severity_band"] = pd.cut(pd.to_numeric(cve_df["severity"], errors="coerce"),bins=bins, labels=labels)
        band_counts = cve_df["severity_band"].value_counts().sort_index()

        self.logger.info(f"\n  Severity distribution:")
        for band, count in band_counts.items():
            pct = count /len(cve_df) * 100
            self.logger.info(f"{str(band):<22} {count:>8,}  ({pct:.1f}%)")

        self.logger.info(f"  Mean CVSS: {stats_summary['mean']} Median: {stats_summary['median']}" )

        # histogram of CVSS scores
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.suptitle("CVSS Severity Score Analysis", fontsize=14, fontweight="bold")

        # histogram of all CVE
        axes[0].hist(cve_sev, bins=40, color="steelblue", edgecolor="white", alpha=0.8)
        axes[0].axvline(cve_sev.mean(), color="red", linestyle="--", label=f"Mean = {cve_sev.mean():.2f}")
        axes[0].axvline(cve_sev.median(), color="orange", linestyle="--", label=f"Median = {cve_sev.median():.2f}")
        axes[0].set_title("All CVEs - CVSS Score Distribution")
        axes[0].set_xlabel("CVSS Score")
        axes[0].set_ylabel("Count")
        axes[0].legend()

        # severity band bar chart
        band_counts.plot(kind="bar", ax=axes[1], color=["lightgreen", "yellow", "orange", "red"])
        axes[1].set_title("CVEs by Severity Band")
        axes[1].set_xlabel("Severity Band")
        axes[1].set_ylabel("Count")
        axes[1].tick_params(axis="x", rotation=20)
        for bar in axes[1].patches:
            axes[1].annotate(f"{int(bar.get_height()):,}",(bar.get_x() + bar.get_width() / 2, bar.get_height()),ha="center", va="bottom", fontsize=9)

        plt.tight_layout()
        self._plotter.save(fig, "01_severity_distribution.png")
        return stats_summary

# BreachAnalyser - EDA 

class BreachAnalyser:

    def __init__(self, plotter: PlotSaver):
        self.logger   = configure_logger("BreachAnalyser")
        self._plotter = plotter

    def analyse_by_industry(self, breach_df: pd.DataFrame) -> pd.DataFrame:
        if breach_df.empty or "industry" not in breach_df.columns:
            return pd.DataFrame()

        industry_counts = (breach_df.groupby("industry").agg(breach_count    = ("organisation", "count"),total_records   = ("records_exposed", "sum"),).sort_values("breach_count", ascending=False).head(12).reset_index())

        self.logger.info("\n  Top industries by breach count:")
        for _, row in industry_counts.iterrows():
            self.logger.info(f"{str(row['industry']):<30} {int(row['breach_count']):>6,} breaches")

        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.barh(industry_counts["industry"][::-1],industry_counts["breach_count"][::-1],color="blue" )
        ax.set_title("Number of Data Breaches by Industry Sector", fontsize=13")
        ax.set_xlabel("Breach Count")
        for bar in bars:
            width = bar.get_width()
            ax.text(width + 5, bar.get_y() + bar.get_height()/2,f"{int(width):,}", va="center", fontsize=9)
        plt.tight_layout()
        self._plotter.save(fig, "02_breaches_by_industry.png")
        return industry_counts

    def analyse_breach_trend(self, breach_df: pd.DataFrame) -> pd.DataFrame:
        if breach_df.empty:
            return pd.DataFrame()

        df = breach_df.copy()
        df["breach_date"] = pd.to_datetime(df.get("breach_date"), errors="coerce")
        df["year"] = df["breach_date"].dt.year
        yearly = df.groupby("year")["organisation"].count().reset_index()
        yearly.columns = ["year", "breach_count"]

        # filter to reasonable range
        yearly = yearly[(yearly["year"] >= 2005) & (yearly["year"] <= 2024) ].dropna()

        self.logger.info("\n  Breach count by year (last 10):")
        for _, row in yearly.tail(10).iterrows():
            self.logger.info(f"{int(row['year'])}: {int(row['breach_count']):,}")

        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(yearly["year"], yearly["breach_count"],marker="o", color="pink", linewidth=2, markersize=5)
        ax.fill_between(yearly["year"], yearly["breach_count"], alpha=0.15, color="yellow")
        ax.set_title("Data Breach Count per Year", fontsize=13)
        ax.set_xlabel("Year")
        ax.set_ylabel("Number of Breaches")
        ax.yaxis.set_major_formatter(mtick.FuncFormatter(lambda x, _: f"{int(x):,}"))
        plt.tight_layout()
        self._plotter.save(fig, "03_breach_trend_by_year.png")
        return yearly

    def analyse_records_exposed(self, breach_df: pd.DataFrame) -> None:    #distribution of records exposed per breach.
        if breach_df.empty or "records_exposed" not in breach_df.columns:
            return

        records = pd.to_numeric(breach_df["records_exposed"], errors="coerce").dropna()
        records = records[records > 0]

        self.logger.info(f"Records exposed stats:")
        self.logger.info(f"Count: {len(records):,}")
        self.logger.info(f"Mean : {records.mean():,.0f}")
        self.logger.info(f"Median: {records.median():,.0f}")
        self.logger.info(f"Max : {records.max():,.0f}")
        self.logger.info(f">1M : {(records > 1_000_000).sum():,} breaches")
        self.logger.info(f">100M : {(records > 100_000_000).sum():,} breaches")

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.hist(np.log10(records + 1), bins=40, color="#E05252", edgecolor="white", alpha=0.8)
        ax.set_title("Distribution of Records Exposed per Breach\n(log10 scale - skewed by mega-breaches)",fontsize=12)
        ax.set_xlabel("log10(Records Exposed)")
        ax.set_ylabel("Number of Breaches")
        ticks = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000]
        ax.set_xticks([np.log10(t+1) for t in ticks])
        ax.set_xticklabels([f"{t:,}" for t in ticks], rotation=35, fontsize=7)
        plt.tight_layout()
        self._plotter.save(fig, "04_records_exposed_distribution.png")

# CveVolumeAnalyser - CVE publication trends over time

class CveVolumeAnalyser:

    def __init__(self, plotter: PlotSaver):
        self.logger   = configure_logger("CveVolumeAnalyser")
        self._plotter = plotter

    def analyse(self, cve_df: pd.DataFrame) -> pd.DataFrame: 
        if cve_df.empty:
            return pd.DataFrame()

        df = cve_df.copy()
        df["publish_date"] = pd.to_datetime(df.get("publish_date"), errors="coerce")
        df["year"] = df["publish_date"].dt.year
        yearly = df.groupby("year")["cve_id"].count().reset_index()
        yearly.columns = ["year", "cve_count"]
        yearly = yearly[(yearly["year"] >= 2000) & (yearly["year"] <= 2024)].dropna()

        self.logger.info("\n  CVE count by year (last 10):")
        for _, row in yearly.tail(10).iterrows():
            self.logger.info(f"{int(row['year'])}: {int(row['cve_count']):,}")

        fig, ax = plt.subplots(figsize=(13, 5))
        ax.bar(yearly["year"], yearly["cve_count"], color="lightblue", alpha=0.85)
        ax.set_title("CVE Publication Volume per Year (NVD)", fontsize=13, fontweight="bold")
        ax.set_xlabel("Year")
        ax.set_ylabel("Number of CVEs Published")
        ax.yaxis.set_major_formatter(mtick.FuncFormatter(lambda x, _: f"{int(x):,}"))
        plt.tight_layout()
        self._plotter.save(fig, "05_cve_volume_per_year.png")
        return yearly

# CorrelationAnalyser - to test if higher severity CVE have faster time to exploit

class CorrelationAnalyser:

    def __init__(self, plotter: PlotSaver):
        self.logger   = configure_logger("CorrelationAnalyser")
        self._plotter = plotter

    def severity_vs_exploit_time(self, cve_df: pd.DataFrame,kev_df: pd.DataFrame) -> Dict[str, Any]:
       
        if cve_df.empty or kev_df.empty:
            self.logger.warning("Need both CVE and KEV data for correlation analysis")
            return {}

        # need a shared cve_id column
        if "cve_id" not in cve_df.columns or "cve_id" not in kev_df.columns:
            self.logger.warning("Missing cve_id column in one of the datasets")
            return {}

        merged = cve_df[["cve_id", "severity", "publish_date"]].merge(
            kev_df[["cve_id", "exploitation_date"]],
            on="cve_id",
            how="inner"
        )

        merged["publish_date"] = pd.to_datetime(merged["publish_date"],      errors="coerce")
        merged["exploitation_date"] = pd.to_datetime(merged["exploitation_date"], errors="coerce")
        merged["days_to_exploit"] = (merged["exploitation_date"] - merged["publish_date"]).dt.days
        merged["severity"] = pd.to_numeric(merged["severity"], errors="coerce")

        # only positive exploit times
        clean = merged[ (merged["days_to_exploit"] >= 0) & merged["severity"].notna()].copy()

        if len(clean) < 10:
            self.logger.warning(f"Only {len(clean)} matched records - not enough for correlation")
            return {}

        corr, pval = stats.pearsonr(clean["severity"], clean["days_to_exploit"])
        self.logger.info( f"\n  Severity vs Time-to-exploit correlation= ,  n={len(clean):,}  r={corr:.3f} p={pval:.4f}")
        if abs(corr) < 0.1:
            self.logger.info("Very weak correlation")
        elif abs(corr) < 0.3:
            self.logger.info(" Weak correlation")
        elif abs(corr) < 0.5:
            self.logger.info(" Moderate correlation")
        else:
            self.logger.info("Strong correlation")

        # scatter plot
        fig, ax = plt.subplots(figsize=(9, 6))
        ax.scatter( clean["severity"],clean["days_to_exploit"],alpha=0.3, s=20, color="pink")
        # trend line
        z = np.polyfit(clean["severity"], clean["days_to_exploit"], 1)
        p = np.poly1d(z)
        x_line = np.linspace(clean["severity"].min(), clean["severity"].max(), 100)
        ax.plot(x_line, p(x_line), color="red", linewidth=2, linestyle="--",label=f"Trend line (r={corr:.2f})")
        ax.set_title("CVSS Severity vs Days to First Exploitation", fontsize=12)
        ax.set_xlabel("CVSS Severity Score")
        ax.set_ylabel("Days from CVE Disclosure to First Exploitation")
        ax.set_ylim(bottom=0)
        ax.legend()
        plt.tight_layout()
        self._plotter.save(fig, "06_severity_vs_exploit_time.png")

        return { "n": len(clean),"pearson_r": round(corr, 3),"p_value": round(pval, 4), }

# EDARunner -runs all analyses in sequence

class EDARunner: 

    def __init__(self):
        self.logger   = configure_logger("EDARunner")
        self._plotter = PlotSaver()
        self._loader  = EDADataLoader()

        # all the analysers
        self._profiler   = DataProfiler()
        self._severity   = SeverityAnalyser(self._plotter)
        self._breach     = BreachAnalyser(self._plotter)
        self._cve_volume = CveVolumeAnalyser(self._plotter)
        self._corr       = CorrelationAnalyser(self._plotter)

        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def run(self, use_postgres: bool = False) -> None:
        self.logger.info("Starting EDA...")
        self.logger.info( f"Mode: {'PostgreSQL' if use_postgres else 'Raw JSON files'}" )

        # load data
        if use_postgres:
            cve_df, kev_df, breach_df = self._loader.load_from_postgres()
        else:
            cve_df, kev_df, breach_df = self._loader.load_from_json()

        if cve_df.empty and breach_df.empty:
            self.logger.error( "No data loaded. Run extractors first or check file paths." )
            return

        # profile all three datasets
        self._profiler.profile_dataset(cve_df, "NVD CVE")
        self._profiler.profile_dataset(kev_df, "CISA KEV")
        self._profiler.profile_dataset(breach_df, "Breach Records")

        # analysis
        sev_stats = self._severity.analyse(cve_df, kev_df)
        industry_df = self._breach.analyse_by_industry(breach_df)
        yearly_breach = self._breach.analyse_breach_trend(breach_df)
        self._breach.analyse_records_exposed(breach_df)
        yearly_cve = self._cve_volume.analyse(cve_df)
        corr_stats = self._corr.severity_vs_exploit_time(cve_df, kev_df)

        # write summary text file
        self._write_summary(sev_stats, industry_df, corr_stats)

        self.logger.info( f"EDA complete. Plots saved to {PLOTS_DIR}/" )

    def _write_summary( self,sev_stats:Dict,industry_df: pd.DataFrame, corr_stats: Dict ) -> None:
        path = os.path.join(OUTPUT_DIR, "eda_summary.txt")
        lines = ["EDA Summary - Cybersecurity Risk Analytics", "Author: Shivakshi (24293113)", 
            "CVSS Severity Findings:",
            f" Mean CVSS score : {sev_stats.get('mean', 'N/A')}",
            f" Median CVSS score: {sev_stats.get('median', 'N/A')}",
            f"Total CVEs: {sev_stats.get('count', 'N/A'):,}" if sev_stats.get("count") else "  Total CVEs: N/A",
            "Top 5 Industries by Breach Count:",]

        if not industry_df.empty:
            for _, row in industry_df.head(5).iterrows():
                lines.append(f"  {str(row['industry']):<25} {int(row['breach_count']):>5,} breaches")

        lines += ["Severity vs Time-to-Exploit Correlation:",
            f"Pearson r : {corr_stats.get('pearson_r', 'N/A')}",
            f"p-value : {corr_stats.get('p_value', 'N/A')}",
            f"n: {corr_stats.get('n', 'N/A')}",
            "Key observations for dashboard design:",
            " Healthcare and Financial Services need their own dashboard sections",
            " CVSS score histogram is bimodal - many Medium, many Critical, fewer Low",
            " CVE volume growth from 2017 needs a log scale or separate axis",
            " records_exposed needs log scale due to mega-breach outliers",
            " correlation between severity and exploit speed is weak/moderate",
            " suggesting attackers consider ease-of-exploit not just CVSS score",]

        with open(path, "w") as f:
            f.write("\n".join(lines))
        self.logger.info(f"EDA summary saved to {path}")


# run directly: python notebooks/eda.py
if __name__ == "__main__":
    runner = EDARunner()
    runner.run(use_postgres=False)
