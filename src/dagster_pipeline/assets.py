"""
Assets are the Dagster way to run functions
Each asset depends on the previous one - Dagster figures out
the execution order automatically from the dependencies.
1.
read_mongo_raw 
2.transform_data 
3. load_to_postgres 
4.run_analysis
"""
import tempfile
import os
import sys
import logging
from typing import Dict, List

from dagster import asset, AssetExecutionContext
from dotenv import load_dotenv

load_dotenv()

_TMP_DIR = tempfile.gettempdir()
_CVE_TMP_PATH = os.path.join(_TMP_DIR, "dagster_clean_cves.json")
_KEV_TMP_PATH= os.path.join(_TMP_DIR, "dagster_clean_kev.json")
_BREACH_TMP_PATH = os.path.join(_TMP_DIR, "dagster_clean_breaches.json")

def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    import sys
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



# Verifies MongoDB has data before transform runs
@asset(
    group_name="cybersecurity_pipeline",
    description="Verify MongoDB raw collections are populated and return record counts",
)
def read_mongo_raw(context: AssetExecutionContext) -> Dict[str, int]:
    """
    Checks that all three raw MongoDB collections have data.
    
    """
    import pymongo

    logger = configure_logger("asset.read_mongo_raw")

    uri= os.getenv("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGO_DB",  "cybersecurity_db")

    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
    db = client[db_name]

    counts = {}
    for col in ["cve_raw", "kev_raw", "breach_raw"]:
        n         = db[col].count_documents({})
        counts[col] = n
        context.log.info(f"  {col}: {n:,} documents")

    client.close()

    # fail fast if any collection is empty
    empty = [k for k, v in counts.items() if v == 0]
    if empty:
        raise Exception(
            f"Collections are empty: {empty}. "
            f"Run the extractors first before triggering the pipeline."
        )

    context.log.info(
        f"MongoDB verified: CVE={counts['cve_raw']:,} "
        f"KEV={counts['kev_raw']:,} Breach={counts['breach_raw']:,}"
    )
    return counts



# 2: transform_data

@asset(
    group_name="cybersecurity_pipeline",
    description="Clean and normalise raw MongoDB records using DataTransformer",
)
def transform_data(
    context:        AssetExecutionContext,
    read_mongo_raw: Dict[str, int],
) -> bool:
    import json

    logger = configure_logger("asset.transform_data")
    logger.info(f"Starting transform (cve_raw={read_mongo_raw.get('cve_raw', 0):,} docs)")

    from transform.transformer import DataTransformer
    transformer = DataTransformer()
    clean_cves, clean_kev, clean_breaches = transformer.run()

    if len(clean_cves) == 0:
        raise Exception("Transformer returned 0 CVE records")

    # write to fixed temp paths - no dict passing needed
    with open(_CVE_TMP_PATH, "w") as f: json.dump(clean_cves,    f)
    with open(_KEV_TMP_PATH,"w") as f: json.dump(clean_kev,     f)
    with open(_BREACH_TMP_PATH,"w") as f: json.dump(clean_breaches,f)

    context.log.info(
        f"Transform complete: CVE={len(clean_cves):,} KEV={len(clean_kev):,} Breach={len(clean_breaches)}"
    )
    context.log.info(f"Clean records written to {_TMP_DIR}")
    return True


# 3: load_to_postgres


@asset(
    group_name="cybersecurity_pipeline",
    description="Insert cleaned records into PostgreSQL using PostgresLoader",
)
def load_to_postgres(
    context:       AssetExecutionContext,
    transform_data: bool, 
) -> bool:
    import json

    logger = configure_logger("asset.load_to_postgres")

    # read directly from fixed paths - no dict deserialisation
    if not os.path.exists(_CVE_TMP_PATH):
        raise Exception(f"Temp file not found: {_CVE_TMP_PATH}")

    logger.info("Reading clean records from temp files...")
    with open(_CVE_TMP_PATH) as f: clean_cves = json.load(f)
    with open(_KEV_TMP_PATH) as f: clean_kev = json.load(f)
    with open(_BREACH_TMP_PATH) as f: clean_breaches = json.load(f)

    context.log.info(
        f"Loaded from temp files: CVE={len(clean_cves):,} KEV={len(clean_kev):,} Breach={len(clean_breaches):}"
    )

    from load.postgres_loader import PostgresLoader
    loader  = PostgresLoader()
    success = loader.load_all(clean_cves, clean_kev, clean_breaches)

    if not success:
        context.log.warning("PostgresLoader reported some failures")

    context.log.info("PostgreSQL load completed.... ha ha")
    return success


# run_analysis

@asset(
    group_name="cybersecurity_pipeline",
    description="Run RQ SQL analysis queries and export CSVs to analysis/output/",
)
def run_analysis(
    context:          AssetExecutionContext,
    load_to_postgres: bool,     # bool trigger - no change needed here
) -> bool:
    logger = configure_logger("asset.run_analysis")
    logger.info("Running SQL analysis queries....")

    from analysis.sql_analysis import SqlAnalysisRunner
    runner  = SqlAnalysisRunner()
    success = runner.run_all()

    if success:
        context.log.info(f"Analysis complete. CSVs in analysis/output/ ")
    else:
        context.log.warning(f"Some queries failed. Dashboard may show empty panels")

    return success