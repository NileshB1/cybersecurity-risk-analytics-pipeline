
import os
import json
import sys
import logging
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import pandas as pd
from dotenv import load_dotenv

load_dotenv()


def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    fh = logging.FileHandler("pipeline.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger



# DatasetLoader

class DatasetLoader:

    def __init__(self):
        self.logger = configure_logger("DatasetLoader")

    def load_json(self, path: str) -> pd.DataFrame:
        """loaded the json file and return as a dataframe"""
        if not os.path.exists(path):
            self.logger.error(
                f"File not found: {path} make sure the extractors have run first"
            )
            return pd.DataFrame()

        self.logger.info(f"Loading {path}...")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        df = pd.DataFrame(data)
        self.logger.info(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")
        return df

    def load_all(
        self,
        cve_path: str = "cve_raw.json",
        kev_path: str = "kev_raw.json",
        breach_path: str = "breach_raw.json"
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """load all three raw datasets at once"""
        cve_df = self.load_json(cve_path)
        kev_df = self.load_json(kev_path)
        breach_df = self.load_json(breach_path)
        return cve_df, kev_df, breach_df


# DatasetProfiler

class DatasetProfiler:

    def __init__(self):
        self.logger = configure_logger("DatasetProfiler")

    def profile(self, df: pd.DataFrame, name: str) -> Dict[str, Any]:
       
        if df.empty:
            self.logger.warning(f"{name}: empty dataframe, nothing to profile")
            return {}

        self.logger.info(f"\n{'='*55}")
        self.logger.info(f"PROFILE: {name}")
        self.logger.info(f"{'='*55}")
        self.logger.info(f"Shape: {df.shape[0]:,} rows x {df.shape[1]} cols")
        self.logger.info(f"Columns: {list(df.columns)}")

        
        null_counts = df.isnull().sum()
        self.logger.info(f"Null counts:")
        for col, cnt in null_counts.items():
            pct = cnt / len(df) * 100
            if cnt > 0:
                self.logger.info(f"{col:<25} {cnt:>6,}  ({pct:.1f}%)")

        profile = {
            "name": name,
            "rows": len(df),
            "cols": list(df.columns),
            "null_counts": null_counts.to_dict(),
        }

        return profile

    def profile_all(
        self,
        cve_df: pd.DataFrame,
        kev_df: pd.DataFrame,
        breach_df: pd.DataFrame
    ) -> None:
        """profile all three datasets in sequence"""
        self.profile(cve_df,"NVD CVE Records")
        self.profile(kev_df,"CISA KEV Records")
        self.profile(breach_df,"Breach Records")



# OverlapAnalyser

class OverlapAnalyser:

    def __init__(self):
        self.logger = configure_logger("OverlapAnalyser")

    def cve_kev_overlap(
        self,
        cve_df: pd.DataFrame,
        kev_df: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Verify how many KEV records have a matching CVE in NVD data.
        It should be close to 100% since KEV IDs come from NVD originally,
        but there could be some  gaps if our NVD pull was partial.
        """
        if cve_df.empty or kev_df.empty:
            self.logger.warning("One or both dataframes empty - cannot check overlap")
            return {}

        cve_ids_in_nvd = set(cve_df["cve_id"].dropna())
        cve_ids_in_kev = set(kev_df["cve_id"].dropna())

        matched = cve_ids_in_kev & cve_ids_in_nvd
        unmatched = cve_ids_in_kev - cve_ids_in_nvd

        overlap_pct = len(matched)/len(cve_ids_in_kev) * 100 if cve_ids_in_kev else 0

        self.logger.info(f"\n  CVE <-> KEV Overlap:")
        self.logger.info(f"KEV records : {len(cve_ids_in_kev):,}")
        self.logger.info(f"Matched in NVD : {len(matched):,}  ({overlap_pct:.1f}%)")
        self.logger.info(f"Not in NVD pull : {len(unmatched):,}")

        if unmatched:
            
            sample = list(unmatched)[:5]
            self.logger.info(f" Sample unmatched IDs : {sample}")

        return {
            "kev_total": len(cve_ids_in_kev),
            "matched": len(matched),
            "unmatched": len(unmatched),
            "overlap_pct": overlap_pct,
        }

    def vendor_name_comparison(
        self,
        cve_df: pd.DataFrame,
        kev_df: pd.DataFrame,
        top_n: int = 20
    ) -> pd.DataFrame:

       
        nvd_vendors: List[str] = []
        for val in cve_df.get("vendors", pd.Series(dtype=object)):
            if isinstance(val, list):
                nvd_vendors.extend(val)
            elif isinstance(val, str):
                nvd_vendors.append(val)

        kev_vendors = kev_df["vendor"].dropna().tolist() if "vendor" in kev_df.columns else []

        nvd_counts = Counter(nvd_vendors).most_common(top_n)
        kev_counts = Counter(kev_vendors).most_common(top_n)

        self.logger.info(f"\n  Top {top_n} vendors in NVD:")
        for v, c in nvd_counts:
            self.logger.info(f"    {v:<35} {c:>6,}")

        self.logger.info(f"\n  Top {top_n} vendors in CISA KEV:")
        for v, c in kev_counts:
            self.logger.info(f"    {v:<35} {c:>6,}")

        
        nvd_df = pd.DataFrame(nvd_counts, columns=["vendor_nvd",  "count_nvd"])
        kev_df_top = pd.DataFrame(kev_counts, columns=["vendor_kev", "count_kev"])

        return pd.concat([nvd_df, kev_df_top], axis=1)

    def industry_breach_summary(self, breach_df: pd.DataFrame) -> pd.DataFrame:
        
        if breach_df.empty or "industry" not in breach_df.columns:
            self.logger.warning("Breach dataframe empty or missing industry column")
            return pd.DataFrame()

        summary = (
            breach_df
            .groupby("industry", dropna=False)
            .agg(
                breach_count = ("organisation", "count"),
                records_exposed = ("records_exposed", "sum"),
            )
            .sort_values("breach_count", ascending=False)
            .reset_index()
        )

        self.logger.info(f"\n  Breach count by industry (top 10):")
        for _, row in summary.head(10).iterrows():
            self.logger.info(
                f"    {str(row['industry']):<30}  "
                f"breaches={int(row['breach_count']):>5,}"
            )

        return summary



# MergeStrategyReport

class MergeStrategyReport:

    def __init__(self):
        self.logger = configure_logger("MergeStrategyReport")

    def generate(
        self,
        overlap_stats: Dict[str, Any],
        output_path:   str = "integration/merge_strategy_report.txt"
    ) -> None:
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        lines = [
            "=" * 60,
            "Dataset Merge Strategy Report",
            "=" * 60,
            "",
            "CVE <-> KEV Join",
            "-" * 30,
            "  Join field : cve_id (exact match)",
            "  Type : LEFT JOIN (keep all CVEs, add KEV fields where matched)",
            f"  Match rate : {overlap_stats.get('overlap_pct', 0):.1f}%",
            f"  Matched : {overlap_stats.get('matched', 0):,} records",
            f"  Unmatched : {overlap_stats.get('unmatched', 0):,} (no KEV entry = not exploited)",
            "",
            "  Key derived field:",
            "  time_to_exploit = exploitation_date - publish_date (in days)",
            "  Negative values = CVE embargoed before public disclosure",
            "  Null values = CVE not in CISA KEV catalog",
            "",
            "CVE/KEV <-> Breach Join",
            "-" * 30,
            "  Join field : vendor (fuzzy / normalised match)",
            "  Approach : after vendor normalisation in transformer.py",
            "                we join on LOWER(vendor) = LOWER(industry)",
            "  Limitation : industry field in breach data is a sector code",
            "                not a company name, so this is an imperfect join at best",
            "  Workaround : Neo4j graph captures vendor-product-org",
            "                many-to-many relationships that a flat join cannot represent cleanly",
            "",
            "Neo4j Graph Model",
            "-" * 30,
            "  Nodes : Vulnerability, Software, Organization, Industry",
            "  Relations : EXPLOITS, AFFECTS, BREACHED, BELONGS_TO",
            "  Purpose : captures many-to-many relationships that a flat",
            "                join cannot represent cleanly",
            "",
            "=" * 60,
        ]

        with open(output_path, "w") as f:
            f.write("\n".join(lines))

        self.logger.info(f"Merge strategy report saved to {output_path}")
        for line in lines:
            self.logger.info(f"  {line}")

# DatasetMerger 

class DatasetMerger:
   

    def __init__(self):
        self.logger = configure_logger("DatasetMerger")
        self._loader = DatasetLoader()
        self._profiler = DatasetProfiler()
        self._analyser = OverlapAnalyser()
        self._reporter = MergeStrategyReport()

    def run_exploration(
        self,
        cve_path: str = "cve_raw.json",
        kev_path: str = "kev_raw.json",
        breach_path: str = "breach_raw.json"
    ) -> None:
        
        self.logger.info("Starting dataset exploration.")

        # load
        cve_df, kev_df, breach_df = self._loader.load_all(
            cve_path, kev_path, breach_path
        )

        if cve_df.empty and kev_df.empty and breach_df.empty:
            self.logger.error(
                "All the three datasets are empty. "
                "Run the extractors first to generate the needed JSON files."
            )
            return

        self._profiler.profile_all(cve_df, kev_df, breach_df)
        overlap = self._analyser.cve_kev_overlap(cve_df, kev_df)
        self._analyser.vendor_name_comparison(cve_df, kev_df)
        self._analyser.industry_breach_summary(breach_df)
        self._reporter.generate(overlap)
        self.logger.info("Exploration complete - check pipeline.log for full output")



if __name__ == "__main__":
    merger = DatasetMerger()
    merger.run_exploration()
