

import os
import sys
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import pandas as pd
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

OUTPUT_DIR = "integration/output"


def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  -  %(message)s",
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


# PostgresReader


class PostgresReader:

    def __init__(self):
        self.logger = configure_logger("PostgresReader")
        self._config = {
            "host": os.getenv("PG_HOST","localhost"),
            "port": os.getenv("PG_PORT","5432"),
            "dbname": os.getenv("PG_DB","cybersec_db"),
            "user": os.getenv("PG_USER","postgres"),
            "password": os.getenv("PG_PASSWORD", ""),
        }

    def read_table(self, sql: str, label: str = "") -> pd.DataFrame:
        """run the SELECT query and return result as a DataFrame"""
        self.logger.info(f"Reading from PostgreSQL: {label or sql[:60]}")
        try:
            conn = psycopg2.connect(**self._config, connect_timeout=10)
            df = pd.read_sql(sql, conn)
            conn.close()
            self.logger.info(f"  Got {len(df):,} rows")
            return df
        except psycopg2.OperationalError as e:
            self.logger.error(f"Cannot connect to PostgreSQL: {e}")
            return pd.DataFrame()
        except Exception as e:
            self.logger.error(f"Query failed [{label}]: {e}")
            return pd.DataFrame()

    def get_vulnerabilities(self) -> pd.DataFrame:
        return self.read_table(
            "SELECT cve_id, severity, vendor, publish_date, description "
            "FROM vulnerabilities;",
            label="vulnerabilities"
        )

    def get_kev(self) -> pd.DataFrame:
        return self.read_table(
            "SELECT cve_id, vendor, product, vulnerability_name, exploitation_date, required_action "
            "FROM "
            "exploited_vulnerabilities;",
            label="exploited_vulnerabilities"
        )

    def get_breaches(self) -> pd.DataFrame:
        return self.read_table(
            "SELECT id, organisation, industry, breach_type, "
            "       breach_date, records_exposed, state "
            "FROM breaches;",
            label="breaches"
        )


# TimeToExploitCalculator

class TimeToExploitCalculator:


    EXPLOIT_WINDOWS = [
        (0,7,"0-7 days (immediate)"),
        (8,30,"8-30 days (fast)"),
        (31,90,"31-90 days (moderate)"),
        (91,365,"91-365 days (slow)"),
        (366,None,"Over 1 year (very slow)"),
    ]

    def __init__(self):
        self.logger = configure_logger("TimeToExploitCalculator")

    def calculate(self, merged_df: pd.DataFrame) -> pd.DataFrame:
        
        df = merged_df.copy()

        df["publish_date"]  = pd.to_datetime(df["publish_date"],      errors="coerce")
        df["exploitation_date"] = pd.to_datetime(df["exploitation_date"], errors="coerce")

    
        df["time_to_exploit_days"] = (
            df["exploitation_date"] - df["publish_date"]
        ).dt.days

        
        neg_count = (df["time_to_exploit_days"] < 0).sum()
        if neg_count > 0:
            self.logger.info(
                f"  {neg_count} records with negative time_to_exploit "
                f"(exploitation before NVD publication - likely zero-days or embargoed CVEs)"
            )

   
        df["exploit_window"] = df["time_to_exploit_days"].apply(self._assign_window)
        self.logger.info(f"time_to_exploit calculated for {len(df):,} records")
        self._log_window_stats(df)

        return df

    def _assign_window(self, days: Optional[float]) -> str:
       
        if pd.isna(days):
            return "Unknown (missing dates)"
        days = int(days)
        if days < 0:
            return "Negative (zero-day / embargoed)"
        for low, high, label in self.EXPLOIT_WINDOWS:
            if high is None or days <= high:
                return label
        return "Over 1 year (very slow)"

    def _log_window_stats(self, df: pd.DataFrame) -> None:
        stats = df.groupby("exploit_window")["time_to_exploit_days"].agg(
            count="count",
            avg_days="mean"
        ).reset_index()

        self.logger.info("\n  Time-to-exploit window distribution:")
        for _, row in stats.sort_values("count", ascending=False).iterrows():
            self.logger.info(
                f"    {str(row['exploit_window']):<40}  "
                f"n={int(row['count']):>5,}  "
                f"avg={row['avg_days']:.0f} days"
            )

    def summary_stats(self, df: pd.DataFrame) -> Dict[str, Any]:
        """return a dict of summary stats for the time_to_exploit column"""
        valid = df["time_to_exploit_days"].dropna()
        valid = valid[valid >= 0]   # exclude negatives from stats

        if valid.empty:
            return {}

        return {
            "count":          len(valid),
            "mean_days":      round(valid.mean(), 1),
            "median_days":    round(valid.median(), 1),
            "min_days":       int(valid.min()),
            "max_days":       int(valid.max()),
            "pct_within_7":   round((valid <= 7).sum()  / len(valid) * 100, 1),
            "pct_within_30":  round((valid <= 30).sum() / len(valid) * 100, 1),
            "pct_within_90":  round((valid <= 90).sum() / len(valid) * 100, 1),
        }


# CveKevJoiner

class CveKevJoiner:

    def __init__(self):
        self.logger = configure_logger("CveKevJoiner")

    def join(
        self,
        cve_df: pd.DataFrame,
        kev_df: pd.DataFrame
    ) -> pd.DataFrame:
        
        if cve_df.empty:
            self.logger.error("CVE dataframe is empty - nothing to join")
            return pd.DataFrame()

        if kev_df.empty:
            self.logger.warning(
                "KEV dataframe is empty - merge will have no exploited the records. "
                "Check if the exploited_vulnerabilities table in PostgreSQL is populated."
            )

        self.logger.info(
            f"Joining CVE ({len(cve_df):,} rows) with KEV ({len(kev_df):,} rows) "
            f"on cve_id..."
        )

        
        kev_renamed = kev_df.rename(columns={"vendor": "kev_vendor"})

        merged = cve_df.merge(
            kev_renamed,
            on="cve_id",
            how="left",
            suffixes=("_cve", "_kev")
        )

    
        merged["is_exploited"] = merged["exploitation_date"].notna()

        exploited_count = merged["is_exploited"].sum()
        not_exploited_count = (~merged["is_exploited"]).sum()
        match_pct = exploited_count / len(merged) * 100 if len(merged) else 0

        self.logger.info(f"Merge complete:")
        self.logger.info(f"Total CVEs : {len(merged):,}")
        self.logger.info(f"Matched (exploited): {exploited_count:,}  ({match_pct:.1f}%)")
        self.logger.info(f"Unmatched: {not_exploited_count:,}")
        return merged



# MergeOutputWriter


class MergeOutputWriter:

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.logger = configure_logger("MergeOutputWriter")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def save_csv(self, df: pd.DataFrame, filename: str) -> str:
        path = os.path.join(self.output_dir, filename)
        df.to_csv(path, index=False)
        self.logger.info(f"Saved {len(df):,} rows -> {path}")
        return path

    def save_exploited_only(self, merged_df: pd.DataFrame) -> pd.DataFrame:
        """extract just the exploited rows and just save separately"""
        exploited = merged_df[merged_df["is_exploited"] == True].copy()
        self.save_csv(exploited, "exploited_cves_enriched.csv")
        return exploited

    def save_time_to_exploit(self, merged_df: pd.DataFrame) -> pd.DataFrame:
        """save just the time_to_exploit analysis columns"""
        cols = [
            "cve_id", "vendor", "severity", "publish_date",
            "exploitation_date", "time_to_exploit_days", "exploit_window",
            "kev_vendor", "product"
        ]
        
        existing_cols = [c for c in cols if c in merged_df.columns]
        subset = merged_df[existing_cols].dropna(subset=["time_to_exploit_days"])
        self.save_csv(subset, "time_to_exploit_analysis.csv")
        return subset



# CveKevMerger
class CveKevMerger:

    def __init__(self):
        self.logger = configure_logger("CveKevMerger")
        self._reader = PostgresReader()
        self._joiner = CveKevJoiner()
        self._tte_calc = TimeToExploitCalculator()
        self._writer = MergeOutputWriter()

    def run(self) -> Optional[pd.DataFrame]:
     
        self.logger.info("CveKevMerger starting...")

        
        cve_df = self._reader.get_vulnerabilities()
        kev_df = self._reader.get_kev()
        breach_df = self._reader.get_breaches()

        if cve_df.empty:
            self.logger.error(
                "CVE table is empty - run the full pipeline first "
                
            )
            return None

        
        merged = self._joiner.join(cve_df, kev_df)

        
        merged = self._tte_calc.calculate(merged)

        
        stats = self._tte_calc.summary_stats(merged)
        if stats:
            self.logger.info("\n  Time-to-exploit summary:")
            for k, v in stats.items():
                self.logger.info(f"{k:<20} : {v}")

     
        self._writer.save_csv(merged, "merged_cve_kev.csv")
        self._writer.save_exploited_only(merged)
        self._writer.save_time_to_exploit(merged)

        self.logger.info("CveKevMerger complete")
        return merged



if __name__ == "__main__":
    merger  = CveKevMerger()
    result  = merger.run()
    if result is not None:
        print(f"\nMerge done: {len(result):,} total CVEs in merged table")
        print(f"Exploited : {result['is_exploited'].sum():,}")
        print(f"CSVs saved to {OUTPUT_DIR}/")
