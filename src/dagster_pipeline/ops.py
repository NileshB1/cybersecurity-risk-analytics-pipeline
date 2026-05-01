"""

Each @op here is the Dagster equivalent of one Airflow PythonOperator task.
The key differences from Airflow:


"""

import os
import json
import logging
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from dagster import op, OpExecutionContext, Out, Output, In
from dotenv import load_dotenv

load_dotenv()


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


# Op 1: verify_connections
# runs first - checks all services are reachable before doing work
# if anything fails the whole job aborts here with a clear message much better than 
# failing 2 hours into an NVD extraction


@op(
    description="Verify MongoDB, PostgreSQL and Kafka are reachable before starting",
    required_resource_keys={"mongo", "postgres", "kafka_cfg"},
)
def verify_connections(context: OpExecutionContext) -> bool:
    logger = configure_logger("op.verify_connections")
    logger.info("Verifying all service connections...")

    mongo_ok   = context.resources.mongo.verify()
    pg_ok      = context.resources.postgres.verify()

    # kafka is optional - warn but dont fail if not running
    # extractors fall back to JSON file output when kafka is down
    try:
        from kafka import KafkaProducer
        from kafka.errors import NoBrokersAvailable
        servers = context.resources.kafka_cfg.server_list()
        p = KafkaProducer(bootstrap_servers=servers,
                          request_timeout_ms=5000)
        p.close()
        kafka_ok = True
        logger.info(f"Kafka OK at {servers}")
    except Exception as e:
        kafka_ok = False
        logger.warning(
            f"Kafka not reachable ({e}). "
            f"Extractors will write JSON backup files only."
        )

    if not mongo_ok:
        raise Exception("MongoDB is not reachable - cannot continue. Check mongod is running.")
    if not pg_ok:
        raise Exception("PostgreSQL is not reachable - cannot continue. Check pg config in .env.")

    context.log.info(
        f"Connection check: MongoDB={'OK' if mongo_ok else 'FAIL'} | "
        f"PostgreSQL={'OK' if pg_ok else 'FAIL'} | "
        f"Kafka={'OK' if kafka_ok else 'WARNING (optional)'}"
    )
    return kafka_ok



# Op 2a: extract_kev
# download CISA KEV catalog - fastest extractor, ~2 seconds runs in PARALLEL 
# with extract_nvd_cve in the job graph


@op(
    description="Download CISA Known Exploited Vulnerabilities catalog",
    required_resource_keys={"kafka_cfg", "pipeline_cfg"},
)
def extract_kev(context: OpExecutionContext, connections_verified: bool) -> int:
    logger = configure_logger("op.extract_kev")
    logger.info("Starting CISA KEV extraction...")

    producer = _try_get_producer(context)

    from extract.kev_extractor import KevExtractor
    extractor = KevExtractor(
        kafka_producer=producer,
        output_dir=context.resources.pipeline_cfg.output_dir
    )
    total = extractor.extract_and_stream()

    if producer:
        producer.close()

    context.log.info(f"KEV extraction complete: {total:,} records")
    return total


# Op 2b: extract_nvd_cve
# pulls all CVE records from NVD API - slowest step, can take hours
# runs in PARALLEL with extract_kev


@op(
    description="Pull all CVE records from NIST National Vulnerability Database API",
    required_resource_keys={"kafka_cfg", "pipeline_cfg"},
)
def extract_nvd_cve(context: OpExecutionContext, connections_verified: bool) -> int:
    logger = configure_logger("op.extract_nvd_cve")

    cfg = context.resources.pipeline_cfg
    logger.info(
        f"Starting NVD CVE extraction "
        f"(quick_test={cfg.quick_test}, page_limit={cfg.nvd_page_limit})"
    )

    producer = _try_get_producer(context)

    from extract.nvd_extractor import NvdExtractor
    extractor = NvdExtractor(
        kafka_producer=producer,
        output_dir=cfg.output_dir
    )

    # quick test mode or page limit set - restrict how many pages we fetch
    if cfg.quick_test:
        logger.warning("QUICK TEST MODE - fetching 100 CVEs only")
        extractor.PAGE_SIZE = 100
    elif cfg.nvd_page_limit > 0:
        logger.info(f"Page limit set to {cfg.nvd_page_limit} pages")

    total = extractor.extract_and_stream()

    if producer:
        producer.close()

    context.log.info(f"NVD CVE extraction complete: {total:,} records")
    return total



# Op 3: extract_breaches
# scrape Privacy Rights Clearinghouse
# runs AFTER both kev and nvd finish (so disk IO doesnt overlap)


@op(
    description="Scrape data breach records from Privacy Rights Clearinghouse",
    required_resource_keys={"kafka_cfg", "pipeline_cfg"},
)
def extract_breaches(
    context:     OpExecutionContext,
    kev_count:   int,
    nvd_count:   int,
) -> int:
    logger = configure_logger("op.extract_breaches")
    cfg    = context.resources.pipeline_cfg

    max_pages = 3 if cfg.quick_test else cfg.scraper_max_pages
    logger.info(f"Starting breach scraper (max_pages={max_pages})")

    producer = _try_get_producer(context)

    from extract.breach_scraper import BreachScraper
    scraper = BreachScraper(
        kafka_producer=producer,
        output_dir=cfg.output_dir,
        max_pages=max_pages,
    )
    total = scraper.extract_and_stream()

    if producer:
        producer.close()

    context.log.info(
        f"Breach scraping complete: {total:,} records. "
        f"All three extractors done — KEV={kev_count:,} NVD={nvd_count:,} Breach={total:,}"
    )
    return total



# Op 4: run_kafka_consumer

@op(
    description="Read Kafka topics and write records to MongoDB raw collections",
    required_resource_keys={"mongo", "kafka_cfg", "pipeline_cfg"},
)
def run_kafka_consumer(
    context:       OpExecutionContext,
    breach_count:  int,
    kafka_running: bool,
) -> str:
    logger      = configure_logger("op.run_kafka_consumer")
    cfg         = context.resources.pipeline_cfg
    max_batches = cfg.kafka_max_batches

    if not kafka_running:
        # Kafka wasnt available - load directly from JSON backup files instead
        logger.warning(
            "Kafka was not running during extraction. "
            "Loading from JSON backup files directly into MongoDB."
        )
        from load.mongo_loader import MongoLoader
        loader = MongoLoader()
        success = loader.load_from_files(
            cve_path    = os.path.join(cfg.output_dir, "cve_raw.json"),
            kev_path    = os.path.join(cfg.output_dir, "kev_raw.json"),
            breach_path = os.path.join(cfg.output_dir, "breach_raw.json"),
        )
        mode = "json_fallback"
        context.log.info(f"JSON fallback load: {'OK' if success else 'FAILED'}")
    else:
        logger.info(f"Starting Kafka consumer (max_batches={max_batches})...")
        try:
            from kafka.cve_consumer import CybersecConsumer
            from kafka.kafka_config import KafkaConfig
            with CybersecConsumer(KafkaConfig()) as consumer:
                consumer.start(max_batches=max_batches)
            mode = "kafka"
            context.log.info(f"Kafka consumer finished successfully ######")
        except Exception as e:
            logger.error(f"Kafka consumer failed: {e}, falling back to JSON files")
            from load.mongo_loader import MongoLoader
            MongoLoader().load_from_files(
                cve_path = os.path.join(cfg.output_dir, "cve_raw.json"),
                kev_path = os.path.join(cfg.output_dir, "kev_raw.json"),
                breach_path = os.path.join(cfg.output_dir, "breach_raw.json"),
            )
            mode = "json_fallback"

    return mode



# Op 5: verify_mongo_raw
# gate check - confirms MongoDB has enough records before transform
# job aborts here with a clear error if any collection is empty

@op(
    description="Verify MongoDB raw collections are populated before transform",
    required_resource_keys={"mongo"},
)
def verify_mongo_raw(
    context:     OpExecutionContext,
    ingest_mode: str,
) -> Dict[str, int]:
    logger = configure_logger("op.verify_mongo_raw")
    logger.info(f"Verifying MongoDB collections (ingest mode was: {ingest_mode})")

    db = context.resources.mongo.get_db()
    MIN_COUNTS = {
        "cve_raw": 100,
        "kev_raw": 100,
        "breach_raw":  10,
    }

    counts   = {}
    all_pass = True

    for col_name, minimum in MIN_COUNTS.items():
        actual = db[col_name].count_documents({})
        counts[col_name] = actual
        if actual >= minimum:
            context.log.info(f"  PASS  {col_name}: {actual:,} docs (min={minimum:,})")
        else:
            context.log.error(f"  FAIL  {col_name}: {actual:,} docs (min={minimum:,})")
            all_pass = False

    if not all_pass:
        raise Exception(
            "One or more MongoDB collections are below the minimum threshold. "
            "Check extraction and consumer logs."
        )

    logger.info("All MongoDB collections verified OK")
    return counts



# Op 6: run_transform
# reads raw records from MongoDB, cleans and normalises them
# passes clean data to next op via temp JSON files

@op(
    description="Clean and normalise raw records from MongoDB",
    required_resource_keys={"pipeline_cfg"},
)
def run_transform(
    context:     OpExecutionContext,
    mongo_counts: Dict[str, int],
) -> Dict[str, str]:
    logger = configure_logger("op.run_transform")
    logger.info(
        f"Starting transform "
        f"(cve_raw={mongo_counts.get('cve_raw',0):,} docs)"
    )

    from transform.transformer import DataTransformer
    transformer = DataTransformer()
    clean_cves, clean_kev, clean_breaches = transformer.run()

    logger.info(
        f"Transform done: CVE={len(clean_cves):,} "
        f"KEV={len(clean_kev):,} Breach={len(clean_breaches):,}"
    )

    # write clean records to temp files
    # passing large lists as dagster outputs can hit serialisation limits
    # temp files are a cleaner hand-off between ops
    tmp_dir = tempfile.gettempdir()

    paths = {
        "cve_path": os.path.join(tmp_dir, "clean_cves.json"),
        "kev_path": os.path.join(tmp_dir, "clean_kev.json"),
        "breach_path": os.path.join(tmp_dir, "clean_breaches.json"),
    }

    with open(paths["cve_path"],"w") as f: json.dump(clean_cves, f)
    with open(paths["kev_path"], "w") as f: json.dump(clean_kev, f)
    with open(paths["breach_path"], "w") as f: json.dump(clean_breaches,f)

    context.log.info(f"Clean records written to temp files in {tmp_dir}")
    return paths



# Op 7: load_postgres
# reads temp JSON files from run_transform and inserts into PostgreSQL
----------------------------------------------------------------

@op(
    description="Insert cleaned records into PostgreSQL structured tables",
    required_resource_keys={"postgres"},
)
def load_postgres(
    context:    OpExecutionContext,
    clean_paths: Dict[str, str],
) -> bool:
    logger = configure_logger("op.load_postgres")
    logger.info("Loading clean records into PostgreSQL..")

    # load from temp files
    with open(clean_paths["cve_path"]) as f: clean_cves=json.load(f)
    with open(clean_paths["kev_path"])  as f: clean_kev = json.load(f)
    with open(clean_paths["breach_path"]) as f: clean_breaches = json.load(f)

    from load.postgres_loader import PostgresLoader
    loader  = PostgresLoader()
    success = loader.load_all(clean_cves, clean_kev, clean_breaches)

    if not success:
        raise Exception(
            "PostgreSQL load had failures. "
            "Check pipeline.log for details."
        )

    context.log.info(
        f"PostgreSQL load complete: "
        f"CVE={len(clean_cves):,} KEV={len(clean_kev):,} "
        f"Breach={len(clean_breaches):,}"
    )
    return success


# ----------------------
# Op 8: run_sql_analysis


@op(
    description="Run RQ analysis queries and export CSVs to analysis/output/",
    required_resource_keys={"postgres"},
)
def run_sql_analysis(
    context:     OpExecutionContext,
    pg_loaded:   bool,
) -> bool:
    logger = configure_logger("op.run_sql_analysis")
    logger.info("Running SQL analysis queries...")

    from analysis.sql_analysis import SqlAnalysisRunner
    runner  = SqlAnalysisRunner()
    success = runner.run_all()

    if not success:
        # dont raise - some queries failing is not fatal
        # the dashboard will show empty panels for failed ones
        context.log.warning(
            "Some analysis queries failed. "
            "Dashboard may have empty panels. Check pipeline.log."
        )

    context.log.info(
        "SQL analysis complete. "
        "CSVs saved to analysis/output/"
    )
    return success



# helper: _try_get_producer

def _try_get_producer(context: OpExecutionContext):
    """
    Try to create a Kafka producer using the kafka_cfg resource.
    Returns None if Kafka is not reachable so extractors fall back
    to writing JSON files only.
    """
    try:
        from kafka.cve_producer import CybersecProducer
        from kafka.kafka_config import KafkaConfig
        # override bootstrap servers from dagster resource
        cfg = KafkaConfig()
        servers = context.resources.kafka_cfg.server_list()
        cfg.bootstrap_servers = servers
        return CybersecProducer(cfg)
    except Exception as e:
        context.log.warning(f"Kafka producer not available: {e}")
        return None