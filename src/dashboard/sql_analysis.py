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
            # Analysis 1: Industry Impact
            # which sectors get hit most and how bad is it
            {
                "label":    "Industry Impact Analysis",
                "rq":       "A1",
                "filename": "a1_industry_impact.csv",
                "sql": """
                    SELECT industry, COUNT(id) AS breach_count,
                    COALESCE(SUM(records_exposed), 0) AS total_records_exposed, COALESCE(ROUND(AVG(records_exposed)), 0) AS avg_per_breach,
                        MAX(records_exposed) AS worst_single_breach, COUNT(DISTINCT organisation) AS organisations_hit,
                        MIN(EXTRACT(YEAR FROM breach_date))::INT AS first_breach_year, MAX(EXTRACT(YEAR FROM breach_date))::INT AS latest_breach_year
                    FROM breaches  WHERE industry    IS NOT NULL
                      AND industry    != 'Unknown' AND breach_date IS NOT NULL
                    GROUP BY industry  ORDER BY breach_count DESC;
                """
            },

            ##TODO Need to improve
            #### Analysis 2: Yearly Threat Landscape
            # compares CVE publication volume to breach volume

            {
                "label":    "Yearly Threat Landscape",
                "rq":       "A2",
                "filename": "a2_yearly_threat_landscape.csv",
                "sql": """
                    WITH cve_yearly AS (
                        SELECT  EXTRACT(YEAR FROM publish_date)::INT AS yr,COUNT(*) AS total_cves,
                            COUNT(CASE WHEN severity >= 9  THEN 1 END) AS critical_count,
                            COUNT(CASE WHEN severity >= 7 AND severity < 9  THEN 1 END) AS high_count,
                            ROUND(AVG(severity)::NUMERIC, 2) AS avg_severity
                        FROM vulnerabilities  WHERE publish_date IS NOT NULL
                          AND EXTRACT(YEAR FROM publish_date) BETWEEN 2010 AND 2024 GROUP BY yr
                    ),
                    breach_yearly AS (SELECT
                            EXTRACT(YEAR FROM breach_date)::INT AS yr, COUNT(*) AS total_breaches,
                        COALESCE(SUM(records_exposed), 0)  AS records_exposed
                        FROM breaches WHERE breach_date IS NOT NULL
                          AND EXTRACT(YEAR FROM breach_date) BETWEEN 2010 AND 2024 GROUP BY yr
                    )
                    SELECT
                        c.yr AS year,  c.total_cves, c.critical_count,
                        c.high_count, c.avg_severity, COALESCE(b.total_breaches, 0) AS total_breaches,
                        COALESCE(b.records_exposed, 0) AS total_records_exposed
                    FROM cve_yearly c LEFT JOIN breach_yearly b ON c.yr = b.yr
                    ORDER BY c.yr;
                """
            },

            
            # Analysis 3: Attack Severity Patterns. do attackers prefer high severity CVEs?
            
            {
                "label":    "Attack Severity Patterns",
                "rq":       "A3",
                "filename": "a3_attack_severity_patterns.csv",
                "sql": """
                    WITH all_cves AS (
                        SELECT
                            CASE
                                WHEN severity >= 9.0 THEN 'Critical (9-10)'
                                WHEN severity >= 7.0 THEN 'High (7-8.9)'
                                WHEN severity >= 4.0 THEN 'Medium (4-6.9)'
                                WHEN severity >= 0.1 THEN 'Low (0.1-3.9)'
                                ELSE 'No Score'
                            END AS band,
                            COUNT(*) AS total FROM vulnerabilities GROUP BY band
                    ),
                    exploited AS (
                        SELECT
                            CASE
                                WHEN v.severity >= 9.0 THEN 'Critical (9-10)'
                                WHEN v.severity >= 7.0 THEN 'High (7-8.9)'
                                WHEN v.severity >= 4.0 THEN 'Medium (4-6.9)'
                                WHEN v.severity >= 0.1 THEN 'Low (0.1-3.9)'
                                ELSE                        'No Score'
                            END AS band,
                            COUNT(*) AS exploited_count FROM exploited_vulnerabilities e
                        JOIN vulnerabilities v ON e.cve_id = v.cve_id GROUP BY band
                    )
                    SELECT
                        a.band AS severity_band, a.total AS total_cves,
                        COALESCE(ex.exploited_count, 0) AS exploited_cves,
                        ROUND(COALESCE(ex.exploited_count, 0)::NUMERIC / NULLIF(a.total, 0) * 100
                        , 2) AS exploitation_rate_pct,
                        ROUND(100.0 - (COALESCE(ex.exploited_count, 0)::NUMERIC / NULLIF(a.total, 0) * 100)
                        , 2) AS safe_rate_pct
                    FROM all_cves a LEFT JOIN exploited ex ON a.band = ex.band
                    ORDER BY
                        CASE a.band
                            WHEN 'Critical (9-10)' THEN 1
                            WHEN 'High (7-8.9)'    THEN 2
                            WHEN 'Medium (4-6.9)'  THEN 3
                            WHEN 'Low (0.1-3.9)'   THEN 4
                            ELSE 5
                        END;
                """
            },

        
            # Analysis 4: Most Exploited Vendors. Which vendor software keeps getting exploited?
            {
                "label":    "Most Exploited Vendors",
                "rq":       "A4",
                "filename": "a4_most_exploited_vendors.csv",
                "sql": """
                    SELECT
                        e.vendor,
                        COUNT(DISTINCT e.cve_id) AS exploited_cves,
                    COUNT(DISTINCT e.product) AS products_affected,
                        ROUND(AVG(v.severity)::NUMERIC, 2) AS avg_cvss_score,
                        MAX(v.severity)  AS highest_cvss,  MIN(e.exploitation_date) AS first_exploited,
                    MAX(e.exploitation_date) AS most_recent_exploit,
                    COUNT(DISTINCT  EXTRACT(YEAR FROM e.exploitation_date) )::INT AS years_active
                    FROM exploited_vulnerabilities e LEFT JOIN vulnerabilities v ON e.cve_id = v.cve_id
                    WHERE e.vendor IS NOT NULL AND e.vendor != '' AND e.vendor != 'Unknown'
                    GROUP BY e.vendor  HAVING COUNT(DISTINCT e.cve_id) >= 3
                    ORDER BY exploited_cves DESC  LIMIT 20;
                """
            },

           
            # Analysis 5: Time to Weaponisation
            # How many days from NVD disclosure to first known
           
            {
                "label":    "Time to Weaponisation",
                "rq":       "A5",
                "filename": "a5_time_to_weaponisation.csv",
                "sql": """
                    SELECT
                        v.cve_id, v.vendor, v.severity,
                        v.publish_date, e.exploitation_date, (e.exploitation_date - v.publish_date) AS days_to_exploit,
                        CASE
                            WHEN (e.exploitation_date - v.publish_date) <= 7
                                THEN 'Within a week'
                            WHEN (e.exploitation_date - v.publish_date) <= 30
                                THEN 'Within a month'
                            WHEN (e.exploitation_date - v.publish_date) <= 90
                                THEN '1-3 months'
                            WHEN (e.exploitation_date - v.publish_date) <= 365
                                THEN '3-12 months'
                            ELSE 'Over a year'
                        END AS time_bracket
                    FROM vulnerabilities v  JOIN exploited_vulnerabilities e
                      ON v.cve_id = e.cve_id WHERE v.publish_date IS NOT NULL
                      AND e.exploitation_date IS NOT NULL AND e.exploitation_date >= v.publish_date
                    ORDER BY days_to_exploit ASC;
                """
            },
        ]


    @staticmethod
    def get_extra() -> List[Dict[str, str]]:

        return [
            # breach type breakdown - what kind of breaches happen most
            # HACK, PHYS, PORT, DISC are PRC breach type codes
            {
                "label": "Breach type breakdown",
                "rq": "EXTRA",
                "filename": "extra_breach_types.csv",
                "sql": """
                    SELECT breach_type, COUNT(*)  AS incidents,
                        COALESCE(SUM(records_exposed), 0)   AS total_records,
                        COUNT(DISTINCT industry) AS industries_affected
                    FROM breaches  WHERE breach_type IS NOT NULL
                      AND breach_type != '' GROUP BY breach_type  ORDER BY incidents DESC;
                """
            },

            # monthly CVE publication trend for the line chart
            {
                "label": "CVE monthly trend",
                "rq":"EXTRA",
                "filename": "extra_cve_monthly_volume.csv",
                "sql": """
                    SELECT DATE_TRUNC('month', publish_date) AS month, COUNT(*) AS cve_count, COUNT(CASE WHEN severity >= 9 THEN 1 END) AS critical_count,
                        COUNT(CASE WHEN severity >= 7 AND severity < 9 THEN 1 END)    AS high_count
                    FROM vulnerabilities  WHERE publish_date IS NOT NULL
                      AND publish_date >= '2010-01-01'
                    GROUP BY month  ORDER BY month;
                """
            },

            # industry summary richer version for the KPI tiles
            {
                "label": "Industry summary enriched",
                "rq": "EXTRA",
                "filename": "extra_industry_summary.csv",
                "sql": """
                    SELECT industry, COUNT(id) AS breach_count, COALESCE(SUM(records_exposed), 0) AS total_records,
                ROUND(AVG(records_exposed))::BIGINT AS avg_per_breach, MAX(records_exposed) AS biggest_breach,
                        COUNT(DISTINCT organisation) AS unique_orgs, MIN(EXTRACT(YEAR FROM breach_date))::INT AS from_year,
                        MAX(EXTRACT(YEAR FROM breach_date))::INT AS to_year
                    FROM breaches WHERE industry    IS NOT NULL
                      AND industry != 'Unknown' AND breach_date IS NOT NULL
                    GROUP BY industry ORDER BY breach_count DESC;
                """
            },

            # top exploited products for the vendor drill-down panel
            {
                "label":"Top exploited products",
                "rq": "EXTRA",
                "filename": "extra_top_products.csv",
                "sql": """
                    SELECT
                        e.vendor, e.product, COUNT(DISTINCT e.cve_id)  AS exploited_count,
                ROUND(AVG(v.severity)::NUMERIC, 2) AS avg_cvss,
                        MIN(e.exploitation_date) AS first_seen,  MAX(e.exploitation_date) AS last_seen
                    FROM exploited_vulnerabilities e LEFT JOIN vulnerabilities v ON e.cve_id = v.cve_id
                    WHERE e.product IS NOT NULL AND e.product != ''
                      AND e.product != 'Unknown'  GROUP BY e.vendor, e.product
                    HAVING COUNT(DISTINCT e.cve_id) >= 2 ORDER BY exploited_count DESC LIMIT 25;
                """
            },

            # time to weaponisation summary stats for the stat cards
            {
                "label":    "Weaponisation speed summary",
                "rq":       "EXTRA",
                "filename": "extra_weaponisation_summary.csv",
                "sql": """
                    SELECT COUNT(*)  AS total_matched, ROUND(AVG(e.exploitation_date - v.publish_date)) AS avg_days,
                        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY (e.exploitation_date - v.publish_date))::INT AS median_days,
                    MIN(e.exploitation_date - v.publish_date) AS fastest_days,  MAX(e.exploitation_date - v.publish_date) AS slowest_days,
                        COUNT(CASE WHEN (e.exploitation_date - v.publish_date) <= 7
                              THEN 1 END)    AS within_7_days,
                        COUNT(CASE WHEN (e.exploitation_date - v.publish_date) <= 30
                              THEN 1 END) AS within_30_days,
                        ROUND(COUNT(CASE WHEN (e.exploitation_date - v.publish_date) <= 30
                                  THEN 1 END)::NUMERIC / NULLIF(COUNT(*), 0) * 100
                        , 1)    AS pct_within_30
                    FROM vulnerabilities v  JOIN exploited_vulnerabilities e ON v.cve_id = e.cve_id
                    WHERE v.publish_date  IS NOT NULL  AND e.exploitation_date IS NOT NULL
                      AND e.exploitation_date >= v.publish_date;
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
