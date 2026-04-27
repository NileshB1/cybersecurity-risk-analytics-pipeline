"""

Defines the Airflow Directed Acyclic Graph (DAG) that orchestrates the
full cybersecurity data pipeline from extraction through to analysis

"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Dict

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.empty import EmptyOperator
from airflow.utils.dates import days_ago

# Project root must be on sys.path so Airflow workers can import modules
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from extract.nvd_extractor import NvdExtractor

from extract.breach_scraper import BreachScraper
from kafka.cve_producer import CybersecProducer
from kafka.cve_consumer import CybersecConsumer
from kafka.kafka_config import KafkaConfig, configure_logger
from transform.transformer import DataTransformer

from load.postgres_loader import PostgresLoader
from analysis.sql_analysis import SqlAnalysisRunner
from extract.kev_extractor import KevExtractor

logger = configure_logger("CybersecDAG")


# 
# Default Task Arguments
# 

DEFAULT_ARGS: Dict[str, Any] = {
    "owner": "nilesh_barge",
    "depends_on_past":  False,
    "email_on_failure": False,
    "email_on_retry":  False,
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
    "execution_timeout":timedelta(hours=4),   # NVD full pull can take 2-3 hrs
}


# 
# Task Functions
# 

class PipelineTasks:
    """
    Namespace class that groups all Airflow task callables.
    """

    # Extraction Tasks 

    @staticmethod
    def extract_nvd_cve(**context) -> None:
        """
        Pull all CVE records from the NVD API and stream them into the
        nvd_cve_stream Kafka topic page by page

        XCom push: publishes total_fetched so downstream tasks can log
        how many records to expect in MongoDB.
        """
        logger.info(f"Task: extract_nvd_cve - starting NVD extraction")

        kafka_cfg = KafkaConfig()

        with CybersecProducer(kafka_cfg) as producer:
            extractor= NvdExtractor(kafka_producer=producer)
            total= extractor.extract_and_stream()

        context["ti"].xcom_push(key="nvd_total_fetched", value=total)
        logger.info(f"Task: extract_nvd_cve - complete. {total:,} records streamed to Kafka.")

    @staticmethod
    def extract_kev(**context) -> None:
        """
        Download the CISA KEV catalog and stream all records into the kev_stream Kafka topic as a 
            single batch
        """
        logger.info(f"Task: extract_kev - starting KEV extraction")

        kafka_cfg = KafkaConfig()

        with CybersecProducer(kafka_cfg) as producer:
            extractor = KevExtractor(kafka_producer=producer)
            total = extractor.extract_and_stream()

        context["ti"].xcom_push(key="kev_total_fetched", value=total)
        logger.info(f"Task: extract_kev - complete. {total:,} records streamed to Kafka.")

    @staticmethod
    def extract_breaches(**context) -> None:
        """
        Scrape Privacy Rights Clearinghouse and stream breach records
        into the breach_stream Kafka topic page by page.
        """
        logger.info(f"Task: extract_breaches - starting breach scraping")

        kafka_cfg = KafkaConfig()

        with CybersecProducer(kafka_cfg) as producer:
            scraper = BreachScraper(kafka_producer=producer)
            total= scraper.extract_and_stream()

        context["ti"].xcom_push(key="breach_total_fetched", value=total)
        logger.info(f"Task: extract_breaches - complete. {total:,} records streamed to Kafka.")

    # Kafka Consumer Task

    @staticmethod
    def run_kafka_consumer(**context) -> None:
        """
        Start the Kafka consumer to read all three topics and write
        records to MongoDB raw collections
        """
        logger.info(f"Task: running kafka consumer ")

        kafka_cfg = KafkaConfig()
        with CybersecConsumer(kafka_cfg) as consumer:
            consumer.start(max_batches=500)

        logger.info("Task: running kafka consumer - completed")

    # Verification Task

    @staticmethod
    def verify_mongo_raw(**context) -> None:
        """
        Confirm that all three MongoDB raw collections are populated
        before the transform step begins
        """
        import pymongo
        from dotenv import load_dotenv
        load_dotenv()

        logger.info(f"checking MongoDB collections")

        client = pymongo.MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"))
        db = client[os.getenv("MONGO_DB", "cybersecurity_db")]

        counts = {
            "cve_raw":db["cve_raw"].count_documents({}),
            "kev_raw": db["kev_raw"].count_documents({}),
            "breach_raw": db["breach_raw"].count_documents({}),
        }
        client.close()

        for collection, count in counts.items():
            logger.info(f" {collection}: {count:,} documents")
            if count == 0:
                raise ValueError(
                    f"Collection '{collection}' is empty. "
                    f"Check that the extractor and consumer tasks succeeded."
                )

        logger.info("checking MongoDB collections -done")

    # Transform Task 

    @staticmethod
    def run_transform(**context) -> None:
        """
        Read raw records from MongoDB, apply the full cleaning and
        normalisation pipeline, and store cleaned DataFrames in XCom
        so the load task can access them.
        """
        import json, tempfile
        logger.info("run_transform: starting transformation")

        transformer = DataTransformer()
        clean_cves, clean_kev, clean_breaches = transformer.run()

        tmp_dir = tempfile.gettempdir()

        cve_path = os.path.join(tmp_dir, "clean_cves.json")
        kev_path = os.path.join(tmp_dir, "clean_kev.json")
        breach_path= os.path.join(tmp_dir, "clean_breaches.json")

        with open(cve_path,"w") as f: json.dump(clean_cves,f)
        with open(kev_path, "w") as f: json.dump(clean_kev, f)
        with open(breach_path, "w") as f: json.dump(clean_breaches,f)

        context["ti"].xcom_push(key="cve_path",value=cve_path)
        context["ti"].xcom_push(key="kev_path", value=kev_path)
        context["ti"].xcom_push(key="breach_path", value=breach_path)

        logger.info(
            f"Task: run_transform done"
            f"CVEs={len(clean_cves):,}, KEV={len(clean_kev):,}, "
            f"Breaches={len(clean_breaches):,}"
        )

    # PostgreSQL Load Task

    @staticmethod
    def load_postgres(**context) -> None:
        """
        Read cleaned records from the temp JSON files written by the
        transform task and insert them into PostgreSQL.
        """
        import json
        logger.info("load_postgres, loading clean data into PostgreSQL")

        ti = context["ti"]
        cve_path = ti.xcom_pull(task_ids="run_transform", key="cve_path")
        kev_path = ti.xcom_pull(task_ids="run_transform", key="kev_path")
        breach_path = ti.xcom_pull(task_ids="run_transform", key="breach_path")

        with open(cve_path) as f: clean_cves = json.load(f)
        
        with open(kev_path) as f: clean_kev = json.load(f)

        with open(breach_path) as f: clean_breaches= json.load(f)

        loader = PostgresLoader()
        loader.load_all(clean_cves, clean_kev, clean_breaches)

        logger.info("load_postgres completed.")

    # Analysis Task 

    @staticmethod
    def run_sql_analysis(**context):
        
        logger.info(f"Task: running queries")
        runner = SqlAnalysisRunner()
        runner.run_all()
        logger.info("Task: running queries, done")


# 
# DAG Definition
# 

with DAG(
    dag_id="cybersec_risk_analytics_pipeline",
    description=(
        "Full ETL pipeline: NVD CVE API -> CISA KEV -> Breach scraper "
        "-> Kafka -> MongoDB -> Transform -> PostgreSQL -> RQ Analysis"
    ),
    default_args=DEFAULT_ARGS,
    schedule_interval="@daily",
    start_date=days_ago(1),
    catchup=False,
    max_active_runs=1,          # only one pipeline run at a time
    tags=["cybersecurity", "etl", "kafka", "mongodb", "postgres", "nci", "group-e"],
) as dag:

    # Bookend tasks, visual clarity in Airflow UI

    pipeline_start = EmptyOperator(task_id="pipeline_start")
    pipeline_end = EmptyOperator(task_id="pipeline_end")

    # Extraction layer (NVD and KEV run in parallel)

    t_extract_nvd = PythonOperator(
        task_id="extract_nvd_cve",
        python_callable=PipelineTasks.extract_nvd_cve,
        doc_md=(
            "Pulls all CVE records from the NIST NVD API and publishes "
            "them page-by-page to the nvd_cve_stream Kafka topic"
        )
    )

    t_extract_kev = PythonOperator(
        task_id="extract_kev",  python_callable=PipelineTasks.extract_kev,
        doc_md=(
            "Downloads the CISA Known Exploited Vulnerabilities JSON feed "
            "and publishes all records to the kev_stream Kafka topic."
        )
    )
    t_extract_breaches = PythonOperator(
        task_id="extract_breaches", python_callable=PipelineTasks.extract_breaches,
        doc_md=(
            "Scrapes Privacy Rights Clearinghouse breach records "
            "and publishes them to the breach_stream Kafka topic."
        )
    )

    # Kafka consumer

    t_kafka_consumer = PythonOperator(
        task_id="run_kafka_consumer",python_callable=PipelineTasks.run_kafka_consumer,
        doc_md=(
            "Subscribes to nvd_cve_stream, kev_stream, and breach_stream "
            "and writes incoming records to MongoDB raw collections."
        )
    )

    # Verification 

    t_verify_mongo = PythonOperator(
        task_id="verify_mongo_raw",
        python_callable=PipelineTasks.verify_mongo_raw,
        doc_md="Asserts that all three MongoDB raw collections are non-empty."
    )

    #Transform 

    t_transform = PythonOperator(
        task_id="run_transform",python_callable=PipelineTasks.run_transform,
        doc_md=(
            "Reads raw MongoDB records, applies date standardisation, "
            "vendor normalisation, deduplication, and industry mapping."
        )
    )

    # PostgreSQL Load 
    t_load_postgres = PythonOperator(
        task_id="load_postgres",python_callable=PipelineTasks.load_postgres,
        doc_md="Inserts cleaned records into PostgreSQL structured tables"
    )

    #RQ Analysis 
    t_analysis = PythonOperator(
        task_id="run_sql_analysis",
        python_callable=PipelineTasks.run_sql_analysis,
        doc_md=(
            "Runs the five research question SQL queries and exports "
            "results to analysis/output/ as CSV files."
        )
    )

    # Task Dependencies

    pipeline_start >> [t_extract_nvd, t_extract_kev]
    [t_extract_nvd, t_extract_kev] >> t_extract_breaches
    t_extract_breaches >> t_kafka_consumer
    t_kafka_consumer >> t_verify_mongo
    t_verify_mongo >> t_transform
    t_transform >> t_load_postgres
    t_load_postgres    >> t_analysis
    t_analysis >> pipeline_end