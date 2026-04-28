"""

Takes the clean records that came out of transformer.py and
inserts them into the four PostgreSQL tables we created in postgres_schema.sql

"""

import os
import sys
import logging
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
import psycopg2.errors
from dotenv import load_dotenv

load_dotenv()


# logger setup - same format as rest of project
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



# PostgresConnection


class PostgresConnection:

    def __init__(self):
        self.logger = configure_logger("PostgresConnection")

        self._conn: Optional[psycopg2.extensions.connection] = None

        # read creds from .env
        self._config = {
            "host": os.getenv("PG_HOST", "localhost"),
            "port":os.getenv("PG_PORT","5432"),
            "dbname": os.getenv("PG_DB","cybersecurity_db"),
            "user":     os.getenv("PG_USER", "postgres"),
            "password": os.getenv("PG_PASSWORD", ""),
        }

    def connect(self) -> "PostgresConnection":
        self.logger.info(
            f"Connecting to PostgreSQL: "
            f"host={self._config['host']} db={self._config['dbname']}"
        )
        try:
            self._conn = psycopg2.connect(**self._config, connect_timeout=10)
            self.logger.info("############ PostgreSQL connected OK")
        except psycopg2.OperationalError as e:
            # usually wrong password or postgres not running
            self.logger.error(f"Could not connect to PostgreSQL: {e}")
            raise ConnectionError(
                f"PostgreSQL connection failed. Check PG_HOST / PG_USER / PG_PASSWORD in .env\n{e}"
            )
        return self

    def get(self) -> psycopg2.extensions.connection:
        if self._conn is None:
            raise RuntimeError("Not connected: call connect() first")
        return self._conn

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
            self.logger.debug("PostgreSQL connection closed")

    # so we can use  with PostgresConnection() as pg:
    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False



# SchemaManager
class SchemaManager:

    # path relative to project root, adjust if running from a subfolder
    SCHEMA_FILE = "load/postgres_schema.sql"

    EXPECTED_TABLES = [
        "vulnerabilities",
        "exploited_vulnerabilities",
        "breaches",
        "industry_summary",
    ]

    def __init__(self, conn: psycopg2.extensions.connection):
        self.logger=configure_logger("SchemaManager")
        self._conn =conn

    def tables_exist(self) -> bool:
        """returns True if all four pipeline tables are present"""
        with self._conn.cursor() as cur:
            cur.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
            """)
            existing = {row[0] for row in cur.fetchall()}

        missing = [t for t in self.EXPECTED_TABLES if t not in existing]

        if missing:
            self.logger.warning(f"Missing tables: {missing}")
            return False

        self.logger.info("All required tables exist....")
        return True

    def run_schema_file(self) -> None:
        """execute postgres_schema.sql to create tables and indexes
        """
        if not os.path.exists(self.SCHEMA_FILE):
            raise FileNotFoundError(
                f"Schema file not found at '{self.SCHEMA_FILE}'. "
                f"Make sure you run from the project root directory."
            )

        self.logger.info(f"#### Running schema file: {self.SCHEMA_FILE}")
        with open(self.SCHEMA_FILE, "r") as f:
            sql = f.read()

        with self._conn.cursor() as cur:
            cur.execute(sql)
        self._conn.commit()
        self.logger.info("Schema applied successfully .....")

    def ensure_schema(self) -> None:
        """run schema only if tables are missing - safe to call every run"""
        if not self.tables_exist():
            self.logger.info("Tables not found, applying schema....")
            self.run_schema_file()
        else:
            self.logger.debug("Schema already in place, skipping....")



# BaseTableWriter
class BaseTableWriter:

    # subclasses override these
    TABLE_NAME: str= ""
    UNIQUE_KEY: str= ""
    INSERT_SQL: str= ""
    BATCH_SIZE: int= 500  # how many rows per executemany call

    def __init__(self, conn: psycopg2.extensions.connection):
        self.logger = configure_logger(f"Writer.{self.TABLE_NAME}")
        self._conn  = conn

    def _filter_valid(self, records: List[Dict]) -> List[Dict]:
        """drop any record thats missing the unique key - would cause insert error"""
        valid   = [r for r in records if r.get(self.UNIQUE_KEY)]
        dropped = len(records) - len(valid)
        if dropped:
            self.logger.warning(
                f"{dropped} records dropped, missing required field '{self.UNIQUE_KEY}'"
            )
        return valid

    def write(self, records: List[Dict[str, Any]]) -> int:
        """
        Insert records using execute_batch (much faster than row by row).
        ON CONFLICT ... DO UPDATE means re-running never fails, just updates"""
        if not records:
            self.logger.warning(f"No records to write to '{self.TABLE_NAME}'")
            return 0

        valid = self._filter_valid(records)
        if not valid:
            self.logger.error(
                f"All {len(records)} records were invalid for '{self.TABLE_NAME}'"
            )
            return 0

        self.logger.info(
            f"Writing {len(valid):,} records to '{self.TABLE_NAME}'"
        )

        written = 0
        # chunk into batches so we dont send 200k rows in one go
        for start in range(0, len(valid), self.BATCH_SIZE):
            batch = valid[start : start + self.BATCH_SIZE]
            try:
                with self._conn.cursor() as cur:
                    psycopg2.extras.execute_batch(
                        cur,
                        self.INSERT_SQL,
                        batch,
                        page_size=self.BATCH_SIZE
                    )


                self._conn.commit()


                written += len(batch)
                self.logger.debug(
                    f"  batch {start // self.BATCH_SIZE + 1}: "
                    f"{len(batch)} rows committed"
                )

            except psycopg2.Error as e:
                self._conn.rollback()
                self.logger.error(
                    f"Batch insert failed on '{self.TABLE_NAME}' "
                    f"at offset {start}: {e}"
                )
                # keep going with next batch rather than crashing everything
                continue

        self.logger.info(f"'{self.TABLE_NAME}' - wrote {written:,} / {len(valid):,} records")
        return written



# VulnerabilitiesWriter

class VulnerabilitiesWriter(BaseTableWriter):

    TABLE_NAME = "vulnerabilities"
    UNIQUE_KEY = "cve_id"

    # using %(field)s dict-style so its easier to read than %s positional
    INSERT_SQL = """
        INSERT INTO vulnerabilities
            (cve_id, severity, vendor, publish_date, modified_date, description)
        VALUES
            (%(cve_id)s, %(severity)s, %(vendor)s, %(publish_date)s, %(modified_date)s, %(description)s)
        ON CONFLICT (cve_id) DO UPDATE
            SET severity = EXCLUDED.severity,
            vendor = EXCLUDED.vendor,
            publish_date  = EXCLUDED.publish_date,
                    modified_date= EXCLUDED.modified_date,
                description= EXCLUDED.description;
    """



# ExploitedVulnsWriter

class ExploitedVulnsWriter(BaseTableWriter):

    TABLE_NAME = "exploited_vulnerabilities"
    UNIQUE_KEY = "cve_id"

    INSERT_SQL = """
        INSERT INTO exploited_vulnerabilities
            (cve_id, vendor, product, vulnerability_name,exploitation_date, required_action)
        VALUES
            (%(cve_id)s, %(vendor)s, %(product)s, %(vulnerability_name)s, %(exploitation_date)s, %(required_action)s)
        ON CONFLICT (cve_id) DO UPDATE
            SET vendor= EXCLUDED.vendor,
                product = EXCLUDED.product,
            exploitation_date  =EXCLUDED.exploitation_date,
            required_action    = EXCLUDED.required_action;
    """



# BreachesWriter

class BreachesWriter(BaseTableWriter):

    TABLE_NAME = "breaches"
    UNIQUE_KEY = "organisation"    # used only for filtering nulls, not for conflict

    INSERT_SQL = """
        INSERT INTO breaches
            (organisation, industry, breach_type,breach_date, records_exposed, state)
        VALUES
            (%(organisation)s, %(industry)s, %(breach_type)s,
             %(breach_date)s, %(records_exposed)s, %(state)s);
    """

    def write(self, records: List[Dict[str, Any]]) -> int:
        """
        Override parent write() slightly because breaches table has no UNIQUE constraint so we cant use ON CONFLICT.
        Instead we truncate and reload each run to avoid row duplication.
        """
        if not records:
            self.logger.warning("No breach records to write")
            return 0

        valid = self._filter_valid(records)

        # clear existing rows first - fresh load every run
        # this is fine since breach data doesnt change between runs
        self.logger.info("Truncating breaches table before reload....")
        try:
            with self._conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE breaches RESTART IDENTITY;")
            self._conn.commit()
        except psycopg2.Error as e:
            self._conn.rollback()
            self.logger.error(f"Could not truncate breaches table: {e}")
            return 0

        # now do the normal batched insert from parent
        return super().write(valid)



# IndustrySummaryWriter
class IndustrySummaryWriter:

    def __init__(self, conn: psycopg2.extensions.connection):
        self.logger = configure_logger("IndustrySummaryWriter")
        self._conn  = conn

    def rebuild(self) -> None:
        """
        Truncate and repopulate industry_summary by aggregating
        the breaches table and joining to vulnerabilities for avg severity.

        Doing it in pure SQL is much faster than reading into Python
        and writing back, especially once we have 10k+ breach rows
        """
        self.logger.info("#### Rebuilding industry_summary table....")

        truncate_sql = "TRUNCATE TABLE industry_summary;"

        # join breaches to vulnerabilities via vendor/industry to get severity
        # the LOWER() on both sides handles casing mismatches between tables
        # avg_severity will be NULL for industries with no matching CVEs - thats fine
        rebuild_sql = """
            INSERT INTO industry_summary (industry, breach_count, total_records, avg_severity)
            SELECT b.industry, COUNT(b.id) AS breach_count, COALESCE(SUM(b.records_exposed), 0) AS total_records,
                ROUND(AVG(v.severity)::NUMERIC, 1) AS avg_severity
            FROM breaches b
            LEFT JOIN vulnerabilities v ON LOWER(v.vendor) = LOWER(b.industry)
            WHERE b.industry IS NOT NULL AND b.industry != 'Unknown'
            GROUP BY b.industry
            ORDER BY breach_count DESC;
        """

        try:
            with self._conn.cursor() as cur:
                cur.execute(truncate_sql)
                cur.execute(rebuild_sql)
            self._conn.commit()
            self.logger.info("industry_summary rebuilt OK ....")
        except psycopg2.Error as e:
            self._conn.rollback()
            self.logger.error(f"Failed to rebuild industry_summary: {e}")
            raise



# LoadReport
class LoadReport:

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._rows: List[tuple] = []

    def add(self, table: str, attempted: int, written: int) -> None:
        self._rows.append((table, attempted, written, attempted - written))

    def log(self) -> None:
        self.logger.info("=" * 40)
        self.logger.info("  POSTGRES LOAD SUMMARY")
        self.logger.info("=" * 45)
        self.logger.info(
            f"  {'Table':<30} {'Attempted':>10} {'Written':>8} {'Failed':>8}"
        )
        self.logger.info("-" * 40)
        for table, attempted, written, failed in self._rows:
            self.logger.info(
                f"  {table:<30} {attempted:>10,} {written:>8,} {failed:>8,}"
            )
        self.logger.info("=" * 40)



# PostgresLoader
class PostgresLoader:
    """
    Orchestrates loading all three datasets into PostgreSQL.

    """

    def __init__(self):
        self.logger = configure_logger("PostgresLoader")

    def load_all(
        self,
        clean_cves:     List[Dict[str, Any]],
        clean_kev:      List[Dict[str, Any]],
        clean_breaches: List[Dict[str, Any]]
    ) -> bool:
        """
        Main entry point. Takes the three clean lists from DataTransformer
        and writes them to PostgreSQL. Returns True if all writes succeeded.
        """
        self.logger.info("PostgresLoader starting...")
        report  = LoadReport(self.logger)
        success = True

        with PostgresConnection() as pg_mgr:
            conn = pg_mgr.get()

            ####make sure tables exist before trying to insert
            SchemaManager(conn).ensure_schema()

            # write vulnerabilities (NVD CVEs)
            vw = VulnerabilitiesWriter(conn)
            
            written = vw.write(clean_cves)
            report.add("vulnerabilities", len(clean_cves), written)
            if written == 0 and len(clean_cves) > 0:
                success = False

            # write KEV
            ew      = ExploitedVulnsWriter(conn)
            written = ew.write(clean_kev)
            report.add("exploited_vulnerabilities", len(clean_kev), written)
            
            if written == 0 and len(clean_kev) > 0:
                success = False

            # write breaches
            bw      = BreachesWriter(conn)
            written = bw.write(clean_breaches)
            report.add("breaches", len(clean_breaches), written)
            if written == 0 and len(clean_breaches) > 0:
                success = False

            # rebuild summary - has to run after breaches are loaded
            try:
                IndustrySummaryWriter(conn).rebuild()
                report.add("industry_summary", 1, 1)
            except Exception as e:
                self.logger.error(f"industry_summary rebuild failed: {e}")
                report.add("industry_summary", 1, 0)
                success = False

        report.log()
        self.logger.info(
            f"PostgresLoader finished - {'all OK' if success else 'some failures, check logs'}"
        )
        return success



# quick sanity check - run file directly to verify tables and counts
# python load/postgres_loader.py

if __name__ == "__main__":

    # just print row counts so we can check data landed
    with PostgresConnection() as pg:
        conn = pg.get()
        tables = [
            "vulnerabilities", "exploited_vulnerabilities", "breaches",
            "industry_summary",
        ]
        print("\nPostgreSQL row counts:")
        print("-" * 40)
        for t in tables:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {t};")
                count = cur.fetchone()[0]
                print(f"  {t:<30}  {count:>10,} rows")
        print("-" * 40)