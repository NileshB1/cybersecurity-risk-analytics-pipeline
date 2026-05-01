"""
In Dagster, a "resource" is a shared object that ops can use
without each op having to set up its own connection.

"""

import os
import sys
import logging
from typing import Any, Optional

import pymongo
import psycopg2
from dagster import resource, InitResourceContext, ConfigurableResource
from pydantic import Field
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



# MongoResource

class MongoResource(ConfigurableResource):
    """
    MongoDB connection resource.
    """

    uri:     str = Field(default_factory=lambda: os.getenv("MONGO_URI", "mongodb://localhost:27017"))
    db_name: str = Field(default_factory=lambda: os.getenv("MONGO_DB",  "cybersec_db"))

    def get_client(self) -> pymongo.MongoClient:
        return pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=5000)

    def get_db(self):
        return self.get_client()[self.db_name]

    def verify(self) -> bool:
        """test the connection - called at start of job to fail fast"""
        logger = configure_logger("MongoResource")
        try:
            client = self.get_client()
            client.server_info()
            client.close()
            logger.info(f"MongoDB OK at {self.uri}")
            return True
        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            return False



# PostgresResource

class PostgresResource(ConfigurableResource):
    """
    PostgreSQL connection config resource
    """

    host: str = Field(default_factory=lambda: os.getenv("PG_HOST",  "localhost"))
    port: str = Field(default_factory=lambda: os.getenv("PG_PORT",  "5432"))
    dbname:  str = Field(default_factory=lambda: os.getenv("PG_DB","cybersec_db"))
    user:  str = Field(default_factory=lambda: os.getenv("PG_USER", "postgres"))
    password: str = Field(default_factory=lambda: os.getenv("PG_PASSWORD", ""))

    def get_connection(self):
        """open and return a psycopg2 connection"""
        return psycopg2.connect(
            host=self.host,  port=self.port,
            dbname=self.dbname,
            user=self.user,  password=self.password,
            connect_timeout=10
        )

    def to_dict(self) -> dict:
        """return config as a dict - useful for pd.read_sql"""
        return {
            "host": self.host,    "port": self.port,
            "dbname": self.dbname,
            "user": self.user,         "password": self.password,
        }

    def verify(self) -> bool:
        """test connection - called at start of job"""
        logger = configure_logger("PostgresResource")
        try:
            conn = self.get_connection()
            conn.close()
            logger.info(f"PostgreSQL OK at {self.host}/{self.dbname}")
            return True
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            return False



# KafkaResource


class KafkaResource(ConfigurableResource):
    """
    Kafka connection config resource.

    """

    bootstrap_servers: str = Field(
        default_factory=lambda: os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    )
    topic_nvd_cve: str = "nvd_cve_stream"
    topic_kev:  str = "kev_stream"
    topic_breach:  str = "breach_stream"

    def server_list(self) -> list:
        """return bootstrap_servers as a list"""
        return [s.strip() for s in self.bootstrap_servers.split(",")]

    def all_topics(self) -> list:
        return [self.topic_nvd_cve, self.topic_kev, self.topic_breach]



# PipelineConfig
# general pipeline settings - controls quick_test mode,
# max pages for scraper, max_batches for kafka consumer etc


class PipelineConfig(ConfigurableResource):
    """
    General pipeline configuration.
    Set quick_test=True in dagster UI or run config to do a fast
    end-to-end test without pulling all 200k NVD records.
    """

    quick_test:  bool = Field(default=False,
        description="If True, pull small sample instead of full datasets")
    nvd_page_limit:  int  = Field(default=0,
        description="Max NVD pages to fetch (0 = no limit = fetch all)")
    scraper_max_pages: int  = Field(default=100,
        description="Max pages to scrape from Privacy Rights Clearinghouse")
    kafka_max_batches: int  = Field(default=500,
        description="Max Kafka consumer poll batches before stopping")
    output_dir: str  = Field(default=".",
        description="Directory for raw JSON backup files")