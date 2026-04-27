"""
Defines the contract that every extractor must follow. All three data
source extractors (NVD, CISA KEV, Privacy Rights Clearinghouse) inherit from this class and 
implement its abstract methods.
"""

import json
import logging
import os
import sys
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")


#
# Logger Factory
#

def configure_logger(name):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  —  %(message)s",
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


# Extraction Statistics
# 

class ExtractionStats:
    """
    Tracks how many records were fetched, published to Kafka, and saved locally during a single extractor run.
    Used for logging and for XCom reporting in the DAG. """

    def __init__(self):
        self.fetched:int = 0
        self.published: int = 0
        self.skipped: int=0
        self.errors: int=0

    def increment_fetched(self, n: int = 1) -> None: self.fetched += n
    def increment_published(self, n: int = 1) -> None: self.published += n
    def increment_skipped(self, n: int = 1) -> None: self.skipped += n
    def increment_errors(self, n: int = 1) -> None: self.errors += n

    def summary(self) -> str:
        return (
            f"fetched={self.fetched:,}  "
            f"published={self.published:,}  "
            f"skipped={self.skipped:,}  "
            f"errors={self.errors:,}"
        )


# 
# Abstract Base Extractor
# 

class BaseExtractor(ABC):
    """
    Abstract base class for all data source extractors.
    """

    def __init__(
        self,
        kafka_producer=None,
        output_dir: str = "."
    ):
       
        self.kafka_producer = kafka_producer
        self.output_dir= output_dir
        self.stats = ExtractionStats()
        self.logger = configure_logger(f"Extractor.{self.source_name}")

    #Abstract Interface 

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Human-readable name of the data source"""
        ...

    @property
    @abstractmethod
    def output_filename(self) -> str:
        """Filename for the raw JSON backup"""
        ...

    @abstractmethod
    def _fetch_records(self):
        """
        Generator that yields one batch (list of raw dicts) at a time.
        """
        ...

    @abstractmethod
    def _parse_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert one raw record from the source format to the normalised dict the pipeline 
        expects. Return None to skip a record
        """
        ...

    @abstractmethod
    def _publish_batch(self, batch: List[Dict[str, Any]]):
        """
            Call the appropriate producer method for this data source. Each subclass knows which Kafka 
            topic its records belong to.
        """
        ...

    # Shared Implementation 

    def extract_and_stream(self):
        """
        Main entry point called by the Airflow DAG task
        """
        self.logger.info(f"Starting extraction from: {self.source_name}")
        all_records: List[Dict[str, Any]] = []

        for raw_batch in self._fetch_records():
            parsed_batch: List[Dict[str, Any]]=[]

            for raw_record in raw_batch:
                try:
                    parsed=self._parse_record(raw_record)
                    if parsed:
                        parsed_batch.append(parsed)
                        self.stats.increment_fetched()
                    else:
                        self.stats.increment_skipped()
                
                except Exception as exc:
                    self.logger.warning(f"Failed to parse record: {exc}", exc_info=False)
                    self.stats.increment_errors()
            if parsed_batch:
                all_records.extend(parsed_batch)
                if self.kafka_producer:
                    self._publish_batch(parsed_batch)
                    self.stats.increment_published(len(parsed_batch))

        self._save_json_backup(all_records)
        self.logger.info(f"Extraction complete — {self.stats.summary()}")
        return self.stats.fetched

    def _save_json_backup(self, records: List[Dict[str, Any]]):
        """
        Write all extracted records to a local JSON file.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, self.output_filename)

        with open(path, "w", encoding="utf-8") as file:
            json.dump(records, file, indent=2, ensure_ascii=False, default=str)

        self.logger.info(f"Raw backup saved: {path} ({len(records):,} records)")