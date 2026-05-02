"""
Runs the five research question queries against PostgreSQL and saves
results as CSV files in analysis/output/
"""

import os
import sys
import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

OUTPUT_DIR = "analysis/output"

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



# DbConnection
# same pattern as postgres_loader
class DbConnection:

    def __init__(self):
        self.logger = configure_logger("DbConnection")
        self._config = {
            "host": os.getenv("PG_HOST", "localhost"),
            "port": os.getenv("PG_PORT", "5432"),
            "dbname": os.getenv("PG_DB", "cybersecurity_db"),
            "user": os.getenv("PG_USER", "postgres"),
            "password": os.getenv("PG_PASSWORD", ""),
        }
        self._conn: Optional[psycopg2.extensions.connection] = None

    def connect(self) -> "DbConnection":
        try:
            self._conn = psycopg2.connect(**self._config, connect_timeout=10)
            self.logger.info(f"#### DB connected for analysis queries")
        except psycopg2.OperationalError as e:
            raise ConnectionError(f"Exception cannot connect to DB for analysis, error: {e}")
        return self

    def get(self):
        if not self._conn:
            raise RuntimeError("Call connect() first")
        return self._conn

    def close(self):
        if self._conn and not self._conn.closed:
            self._conn.close()

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False



# QueryResult
class QueryResult:

    def __init__(
        self,
        label:str,
        rq:str,
        filename: str,
        df: Optional[pd.DataFrame] = None,
        error: Optional[str] = None
    ):
        self.label = label
        self.rq = rq
        self.filename = filename
        self.df = df
        self.error = error

    @property
    def success(self) -> bool:
        return self.df is not None and self.error is None

    @property
    def row_count(self) -> int:
        return len(self.df) if self.df is not None else 0



# QueryRunner
class QueryRunner:

    def __init__(self, conn):
        self.logger = configure_logger("QueryRunner")
        self._conn  = conn

    def run(self, label: str, sql: str) -> Optional[pd.DataFrame]:
        self.logger.info(f"#### Running query: {label}")
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql)
                rows    = cur.fetchall()
                columns = [desc[0] for desc in cur.description]
            df = pd.DataFrame(rows, columns=columns)
            self.logger.info(f"#### {len(df):,} rows returned")
            return df
        except Exception as e:
            # CRITICAL: must rollback after any failure
            # otherwise PostgreSQL locks the entire connection
            # and every subsequent query in this session also fails
            self._conn.rollback()
            self.logger.error(f"Query failed [{label}], exception: {e}")
            return None



# CsvExporter

class CsvExporter:

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.logger = configure_logger("CsvExporter")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def export(self, df: pd.DataFrame, filename: str) -> str:
        """save df to CSV and return the full path
        """
        path = os.path.join(self.output_dir, filename)
        try:
            df.to_csv(path, index=False)
            self.logger.info(f"Saved -> {path}  ({len(df):,} rows)")
            return path
        except OSError as e:
            self.logger.error(f"#### Could not save to {path}, error: {e}")
            raise



# ResearchQueryDefinitions

class ResearchQueryDefinitions:

    @staticmethod
    def get_all() -> List[Dict[str, str]]:
        return [
            # RQ1 - How do exploited vulnerabilities relate to breach patterns across industries and time?
            # Left join breaches to KEV via vendor name match grouping by industry and year to see trends
            {
                "label": "RQ1: Industry breach trends",
                "rq": "RQ1",
                "filename": "rq1_industry_breach_trends.csv",
                "sql": """
                    SELECT b.industry, EXTRACT(YEAR FROM b.breach_date)::INT AS breach_year,
                        COUNT(DISTINCT b.id) AS breach_count, COUNT(DISTINCT e.cve_id)  AS exploited_cves_linked,
                        COALESCE(SUM(b.records_exposed), 0) AS total_records_exposed
                    FROM breaches b
                    LEFT JOIN exploited_vulnerabilities e ON LOWER(e.vendor) = LOWER(b.industry)
                    WHERE b.breach_date IS NOT NULL AND b.industry   IS NOT NULL  AND b.industry != 'Unknown'
                    GROUP BY b.industry, breach_year
                    ORDER BY breach_year DESC, breach_count DESC;
                """
            },

            # RQ2 - Do breach counts increase in the period following disclosure of high severity CVEs?
            # Looking at 30/60/90 day windows after each CVE severity >= 9 means Critical
            {
                "label": "RQ2: Breach lag after CVE disclosure",
                "rq": "RQ2",
                "filename": "rq2_breach_lag_after_cve.csv",
                "sql": """
                    SELECT
                        v.cve_id, v.vendor, v.severity, v.publish_date, COUNT(CASE
                            WHEN b.breach_date BETWEEN v.publish_date AND v.publish_date + INTERVAL '30 days'
                            THEN 1 END
                        ) AS breaches_within_30_days,
                        COUNT(CASE
                            WHEN b.breach_date BETWEEN v.publish_date AND v.publish_date + INTERVAL '60 days'
                            THEN 1 END) AS breaches_within_60_days,
                        COUNT(CASE
                            WHEN b.breach_date BETWEEN v.publish_date AND v.publish_date + INTERVAL '90 days'
                            THEN 1 END
                        ) AS breaches_within_90_days
                    FROM vulnerabilities v JOIN breaches b ON LOWER(b.industry) LIKE '%' || LOWER(v.vendor) || '%'
                         OR LOWER(v.vendor) LIKE '%' || LOWER(b.industry) || '%' WHERE v.severity >= 9.0
                      AND v.publish_date  IS NOT NULL  AND b.breach_date   IS NOT NULL
                    GROUP BY v.cve_id, v.vendor, v.severity, v.publish_date
                    HAVING COUNT(b.id) > 0  ORDER BY breaches_within_30_days DESC LIMIT 100;
                """
            },

            # RQ3: Can severity scores predict breach risk across industries?
            # Bucketing CVEs into severity bands and counting how many breach events are linked per band
            {
                "label": "RQ3: Severity vs breach rate",
                "rq": "RQ3",
                "filename": "rq3_severity_vs_breach_rate.csv",
                "sql": """
                    SELECT
                        CASE
                            WHEN v.severity >= 9.0 THEN 'Critical (9.0-10.0)'
                            WHEN v.severity >= 7.0 THEN 'High (7.0-8.9)'
                            WHEN v.severity >= 4.0 THEN 'Medium (4.0-6.9)'
                            WHEN v.severity >= 0.1 THEN 'Low (0.1-3.9)'
                            ELSE 'No Score'
                        END                             AS severity_band,
                        COUNT(DISTINCT v.cve_id)        AS cve_count,
                        COUNT(DISTINCT e.cve_id)        AS exploited_count,
                        ROUND(
                            COUNT(DISTINCT e.cve_id)::NUMERIC
                            / NULLIF(COUNT(DISTINCT v.cve_id), 0) * 100
                        , 1)                            AS exploitation_rate_pct
                    FROM vulnerabilities v
                    LEFT JOIN exploited_vulnerabilities e ON v.cve_id = e.cve_id
                    WHERE v.severity IS NOT NULL
                    GROUP BY severity_band
                    ORDER BY MIN(v.severity) DESC;
                """
            },

            # TODO Need to check fix for RQ4 later
            
            # RQ4 - Which vendors are most associated with high severity vulnerabilities AND real breaches?
            # Combined risk rank using both CVSS avg and KEV count HAVING >= 5 filters out vendors with very few CVEs
            # otherwise random obscure vendors top the list
            # {
            #     "label": "RQ4: High risk vendors",
            #     "rq": "RQ4",
            #     "filename": "rq4_high_risk_vendors.csv",
            #     "sql": """
            #         SELECT
            #             v.vendor, COUNT(DISTINCT v.cve_id) AS total_cves, ROUND(AVG(v.severity)::NUMERIC, 2) AS avg_cvss_score,
            #             COUNT(DISTINCT e.cve_id) AS confirmed_exploited,
            #             ROUND(COUNT(DISTINCT e.cve_id)::NUMERIC
            #                 / NULLIF(COUNT(DISTINCT v.cve_id), 0) * 100
            #             , 1)  AS exploitation_rate_pct
            #         FROM vulnerabilities v  LEFT JOIN exploited_vulnerabilities e ON v.cve_id = e.cve_id
            #         WHERE v.vendor   != 'Unknown'
            #         AND v.severity IS NOT NULL
            #         GROUP BY v.vendor HAVING COUNT(DISTINCT v.cve_id) >= 5
            #         ORDER BY confirmed_exploited DESC, avg_cvss_score DESC LIMIT 25;
            #     """
            # },
            

            # RQ5: What is the typical time gap between vulnerability disclosure and confirmed exploitation?
            # Simple date difference: exploitation_date - publish_date
            # negative values mean CISA listed it before NVD published which shouldnt happen but occasionally does with embargoed CVEs
            {
                "label":    "RQ5: Time to exploit gap",
                "rq":       "RQ5",
                "filename": "rq5_time_to_exploit.csv",
                "sql": """
                    SELECT
                        v.cve_id, v.vendor, v.severity,v.publish_date, e.exploitation_date,
                        (e.exploitation_date - v.publish_date) AS days_to_exploit,
                        CASE
                            WHEN (e.exploitation_date-v.publish_date) <= 7 THEN '0-7 days'
                            WHEN (e.exploitation_date - v.publish_date) <= 30 THEN '8-30 days'
                            WHEN (e.exploitation_date - v.publish_date) <= 90 THEN '31-90 days'
                            WHEN (e.exploitation_date-v.publish_date) <= 365 THEN '91-365 days'
                            ELSE 'Over 1 year'
                        END AS exploit_window
                    FROM vulnerabilities v
                    JOIN exploited_vulnerabilities e ON v.cve_id = e.cve_id WHERE v.publish_date IS NOT NULL
                      AND e.exploitation_date  IS NOT NULL AND e.exploitation_date  >= v.publish_date
                    ORDER BY days_to_exploit ASC;
                """
            },
        ]

    @staticmethod
    def get_extra() -> List[Dict[str, str]]:
        """
            Extra queries not in the RQ list but useful for the dashboard.
            Added these after looking at what Shivakshi needed for the charts.
        """
        return [

            # monthly CVE volume over time, line chart in dashboard
            {
                "label": "CVE volume by month",
                "rq": "EXTRA",
                "filename": "extra_cve_monthly_volume.csv",
                "sql": """
                    SELECT
                        DATE_TRUNC('month', publish_date) AS month, COUNT(*)  AS cve_count,
                        COUNT(CASE WHEN severity >= 9 THEN 1 END) AS critical_count,
                        COUNT(CASE WHEN severity >= 7 AND severity < 9 THEN 1 END)  AS high_count
                    FROM vulnerabilities WHERE publish_date IS NOT NULL
                      AND publish_date >= '2015-01-01' GROUP BY month ORDER BY month;
                """
            },

            # top 10 industries by total records exposed, bar chart
            {
                "label": "Top industries by records exposed",
                "rq": "EXTRA",
                "filename": "extra_top_industries_records.csv",
                "sql": """
                    SELECT
                        industry,
                        COUNT(*) AS breach_count,
                        SUM(records_exposed) AS total_records_exposed,
                        ROUND(AVG(records_exposed)) AS avg_per_breach
                    FROM breaches
                    WHERE industry IS NOT NULL AND industry != 'Unknown'
                      AND records_exposed IS NOT NULL GROUP BY industry
                    ORDER BY total_records_exposed DESC LIMIT 10;
                """
            },

            # RQ5 summary stats: mean/median/min/max days to exploit
            {
                "label": "RQ5 summary statistics",
                "rq": "EXTRA",
                "filename": "extra_rq5_exploit_stats.csv",
                "sql": """
                    SELECT
                        COUNT(*) AS total_pairs,
                        ROUND(AVG(e.exploitation_date - v.publish_date))  AS avg_days,
                        PERCENTILE_CONT(0.5) WITHIN GROUP (
                            ORDER BY (e.exploitation_date - v.publish_date))::INT  AS median_days,
                        MIN(e.exploitation_date - v.publish_date) AS min_days, MAX(e.exploitation_date - v.publish_date) as max_days
                    FROM vulnerabilities v JOIN exploited_vulnerabilities e ON v.cve_id = e.cve_id
                    WHERE v.publish_date IS NOT NULL
                      AND e.exploitation_date IS NOT NULL AND e.exploitation_date >= v.publish_date;
                """
            },
        ]



# AnalysisRunReport
# prints a summary of which queries ran ok and which failed
class AnalysisRunReport:

    def __init__(self, logger: logging.Logger):
        self.logger  = logger
        self._results: List[QueryResult] = []

    def add(self, result: QueryResult) -> None:
        self._results.append(result)

    def log(self) -> None:
        passed = sum(1 for r in self._results if r.success)
        failed = sum(1 for r in self._results if not r.success)

        self.logger.info("=" * 40)
        self.logger.info(" SQL ANALYSIS RUN REPORT")
        self.logger.info("=" * 42)
        self.logger.info(f"  {'Query':<35} {'RQ':<6} {'Rows':>8}  {'Status'}")
        self.logger.info("-" * 42)

        for r in self._results:
            status = "OK" if r.success else "FAILED"
            rows   = f"{r.row_count:,}" if r.success else "-"
            self.logger.info(
                f"{r.label:<35} {r.rq:<6} {rows:>8}  {status}"
            )

        self.logger.info("-" * 42)
        self.logger.info(f"{passed} passed   {failed} failed")
        self.logger.info("=" * 42)



# SqlAnalysisRunner

class SqlAnalysisRunner:
    """
    Runs all RQ queries plus the extra dashboard queries against PostgreSQL and 
    saves results to analysis/output/ as CSV files. The DAG task 'run_sql_analysis' calls runner.run_all()
    """

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.logger = configure_logger("SqlAnalysisRunner")
        self._exporter = CsvExporter(output_dir)

    def run_all(self) -> bool:
        """
        Execute all queries and export CSVs.
        Returns True if all queries succeeded, False if any failed.
        """
        self.logger.info("SqlAnalysisRunner starting....")

        report  = AnalysisRunReport(self.logger)
        all_ok  = True

        # combine RQ queries and extra queries into one list
        all_queries = (
            ResearchQueryDefinitions.get_all()
            + ResearchQueryDefinitions.get_extra()
        )

        with DbConnection() as db_mgr:
            conn   = db_mgr.get()
            runner = QueryRunner(conn)

            for q_def in all_queries:
                df = runner.run(q_def["label"], q_def["sql"])

                if df is not None:
                    try:
                        self._exporter.export(df, q_def["filename"])
                        result = QueryResult(
                            label = q_def["label"],
                            rq  = q_def["rq"],
                            filename = q_def["filename"],
                            df = df
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed to save CSV for {q_def['label']}: {e}"
                        )
                        result  = QueryResult(
                            label = q_def["label"],
                            rq  = q_def["rq"],
                            filename = q_def["filename"],
                            error = str(e)
                        )
                        all_ok = False
                else:
                    result = QueryResult(
                        label = q_def["label"],
                        rq  = q_def["rq"],
                        filename = q_def["filename"],
                        error = "Query returned None"
                    )
                    all_ok = False

                report.add(result)

        report.log()
        self.logger.info(
            f"Analysis complete: CSVs saved to '{OUTPUT_DIR}/' "
            f"({'all OK' if all_ok else 'some failures'})"
        )
        return all_ok

    def run_single(self, rq_label: str) -> Optional[pd.DataFrame]:
        """
        Run one specific query by label - useful for testing individual RQs
        without running the whole analysis suite

        example: runner.run_single("RQ4: High risk vendors")
        """
        all_queries = (
            ResearchQueryDefinitions.get_all()
            + ResearchQueryDefinitions.get_extra()
        )
        match = next((q for q in all_queries if q["label"] == rq_label), None)
        if not match:
            self.logger.error(
                f"No query found with label '{rq_label}'. "
                f"Available: {[q['label'] for q in all_queries]}"
            )
            return None

        with DbConnection() as db_mgr:
            df = QueryRunner(db_mgr.get()).run(match["label"], match["sql"])

        if df is not None:
            self._exporter.export(df, match["filename"])
        return df


# run directly to test: python analysis/sql_analysis.py
if __name__ == "__main__":
    runner = SqlAnalysisRunner()
    ok = runner.run_all()
    sys.exit(0 if ok else 1)