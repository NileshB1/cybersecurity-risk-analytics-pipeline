"""

Loads the three raw JSON backup files produced by the extractors into
MongoDB raw collections. Also exposes a verify_only() method used by
the Airflow DAG gate task to confirm all collections are populated
before the transform stage begins.


"""

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pymongo
import pymongo.errors
from dotenv import load_dotenv

load_dotenv()



# Logger Factory


def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  —  %(message)s",
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



# Collection Load Result

@dataclass
class CollectionLoadResult:
    """
    Structured result from loading one MongoDB collection
    """
    collection: str
    records_in: int
    inserted: int        # net new documents (upserted)
    modified:int        # existing documents updated
    skipped:int        # records missing the unique key
    errors: int
    success:bool = True
    error_detail: str  = ""

    @property
    def written(self) -> int:
        return self.inserted + self.modified


# 
# Mongo Connection Manager
# 

class MongoConnectionManager:
    """
    Manages the MongoDB client connection lifecycle.

    """

    def __init__(self):
        self.logger = configure_logger("MongoConnectionManager")
        self._uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        self._db_name = os.getenv("MONGO_DB",  "cybersec_db")
        self._client: Optional[pymongo.MongoClient] = None

    def connect(self) -> "MongoConnectionManager":
        """Open the MongoDB connection. Returns self for method chaining."""
        self.logger.info(f"Connecting to MongoDB: {self._uri}")
        try:
            self._client = pymongo.MongoClient(
                self._uri,
                serverSelectionTimeoutMS=5000
            )
            self._client.server_info()   # forces connection: surfaces errors early
            self.logger.info(f"MongoDB connected: database: '{self._db_name}'")
        except pymongo.errors.ServerSelectionTimeoutError as exc:
            raise ConnectionError(
                f"Cannot reach MongoDB at {self._uri}. "
                f"Is mongod running???? Detail: {exc}"
            )
        return self

    def get_db(self) -> pymongo.database.Database:
        if not self._client:
            raise RuntimeError("Call connect() before get_db()")
        return self._client[self._db_name]

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
            self.logger.debug("MongoDB connection closed")

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# 
# JSON File Reader
# 

class JsonFileReader:
    """
    Reads the local JSON backup files written by the extractors.

    """

    def __init__(self):
        self.logger = configure_logger("JsonFileReader")

    def read(self, path: str) -> List[Dict[str, Any]]:
        """Read a JSON file and return its contents as a list of dicts
        """
        file_path = Path(path)

        if not file_path.exists():
            self.logger.error(
                f"File not found: '{path}' Run the extractor to generate this file first."
            )
            return []

        size_kb = file_path.stat().st_size / 1024
        self.logger.info(f"Reading '{path}' ({size_kb:,.1f} KB)...")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as jexc:
            self.logger.error(f"Exception occurred while parsing JSON, eror : {jexc}")
            return []
        except OSError as ex:
            self.logger.error(f"Exception, cannot open '{path}': {ex}")
            return []

        if not isinstance(data, list):
            self.logger.error(
                f"Expected a JSON array in '{path}' — "
                f"got {type(data).__name__}. Skipping."
            )
            return []

        self.logger.info(f"{len(data):,} records loaded from '{path}'")
        return data


# 
# Collection Writer
# 

class CollectionWriter:
    """
    Writes records to one MongoDB collection using batched bulk upsert.

    """

    BATCH_SIZE = 500

    def __init__(self, db: pymongo.database.Database):
        self.logger = configure_logger("CollectionWriter")
        self._db = db

    def write(
        self,
        collection_name: str,
        records:List[Dict[str, Any]],
        unique_key: str
    ) -> CollectionLoadResult:
        """
        Upsert all records into the named collection.

        
        """
        if not records:
            self.logger.warning(f"No records provided for '{collection_name}' — skipping.")
            return CollectionLoadResult(
                collection=collection_name,
                records_in=0, inserted=0, modified=0, skipped=0, errors=0
            )

        self.logger.info(
            f"Writing {len(records):,} records to '{collection_name}' "
            f"(key='{unique_key}', batch_size={self.BATCH_SIZE})"
        )

        collection     = self._db[collection_name]
        total_inserted = 0
        total_modified = 0
        total_skipped = 0
        total_errors= 0

        for batch_start in range(0, len(records), self.BATCH_SIZE):
            batch = records[batch_start: batch_start + self.BATCH_SIZE]
            operations=[]

            for record in batch:
                key_value = record.get(unique_key)
                if not key_value:
                    total_skipped += 1
                    continue
                operations.append(
                    pymongo.UpdateOne(
                        {unique_key: key_value},
                        {"$set": record},
                        upsert=True
                    )
                )

            if not operations:
                continue
            try:
                result = collection.bulk_write(operations, ordered=False)
                total_inserted += result.upserted_count
                total_modified += result.modified_count
                self.logger.debug(
                    f"  Batch {batch_start // self.BATCH_SIZE + 1}: "
                    f"inserted={result.upserted_count}  modified={result.modified_count}"
                )

            except pymongo.errors.BulkWriteError as bwe:
                details= bwe.details
                total_inserted += details.get("nUpserted",  0)
                total_modified += details.get("nModified",  0)
                batch_errors= len(details.get("writeErrors", []))
                total_errors+= batch_errors
                self.logger.error(
                    f"Bulk write partial failure on '{collection_name}': "
                    f"{batch_errors} write errors in batch starting at {batch_start}"
                )

        result_obj = CollectionLoadResult(
            collection=collection_name,
            records_in=len(records),
            inserted=total_inserted,
            modified=total_modified,
            skipped=total_skipped,
            errors=total_errors,
        )
        self.logger.info(
            f"'{collection_name}' done, inserted={total_inserted:,}  modified={total_modified:,}  "
            f"skipped={total_skipped:,}  errors={total_errors:,}"
        )
        return result_obj


# 
# Mongo Verifier
# 

class MongoVerifier:
    """
    Validates that the three raw MongoDB collections are populated
    above minimum thresholds before the transform stage begins.

    
    """

    MIN_COUNTS: Dict[str, int] = {
        "cve_raw": 100,
        "kev_raw": 100,
        "breach_raw": 10,
    }

    def __init__(self, db: pymongo.database.Database):
        self.logger = configure_logger("MongoVerifier")
        self._db=db

    def verify(self) -> Tuple[bool, Dict[str, int]]:
        """
        Count documents in each collection and compare against minimums
        """
        counts:   Dict[str, int] = {}
        all_pass: bool = True

        self.logger.info(f"Verifying MongoDB raw collection document counts....")

        for col_name, minimum in self.MIN_COUNTS.items():
            actual = self._db[col_name].count_documents({})
            counts[col_name] = actual

            if actual >= minimum:
                self.logger.info(
                    f"PASS{col_name:<15} {actual:>8,} docs  (min={minimum:,})"
                )
            else:
                self.logger.error(
                    f" FAIL {col_name:<15} {actual:>8,} docs  "
                    f"(min={minimum:,}): check extractor/consumer logs"
                )
                all_pass = False

        status = "All collections OK" if all_pass else "One or more collections below minimum"
        self.logger.info(f"Verification result: {status}")
        return all_pass, counts



# Load Summary Reporter


class LoadSummaryReporter:
    """
    Prints a structured table of all CollectionLoadResult objects.
    Kept separate from MongoLoader so the orchestrator stays clean.
    """

    def __init__(self, logger: logging.Logger):
        self.logger   = logger
        self._results: List[CollectionLoadResult] = []

    def add(self, result: CollectionLoadResult) -> None:
        self._results.append(result)

    def log(self) -> None:
        self.logger.info("=" * 42)
        self.logger.info("  MONGODB LOAD SUMMARY")
        self.logger.info("=" * 40)
        self.logger.info(
            f"  {'Collection':<18} {'In':>8} {'Inserted':>10} "
            f"{'Modified':>10} {'Skipped':>8} {'Errors':>7}"
        )
        self.logger.info("-" * 42)
        for r in self._results:
            self.logger.info(
                f"  {r.collection:<18} {r.records_in:>8,} {r.inserted:>10,} "
                f"{r.modified:>10,} {r.skipped:>8,} {r.errors:>7,}"
            )
        self.logger.info("=" * 44)



# Mongo Loader (Orchestrator)


class MongoLoader:
    """
    Orchestrates the full MongoDB raw data load process.

    """

    DEFAULT_PATHS: Dict[str, str] = {
        "cve": "cve_raw.json",
        "kev": "kev_raw.json",
        "breach": "breach_raw.json",
    }

    def __init__(self):
        self.logger = configure_logger("MongoLoader")
        self._reader = JsonFileReader()
        self._reporter = LoadSummaryReporter(self.logger)

    def load_from_files(
        self,
        cve_path: Optional[str] = None,
        kev_path: Optional[str] = None,
        breach_path: Optional[str] = None,
    ) -> bool:
        """
        Read local JSON backup files and upsert records into MongoDB
        """
        cve_path = cve_path or self.DEFAULT_PATHS["cve"]
        kev_path= kev_path or self.DEFAULT_PATHS["kev"]
        breach_path = breach_path or self.DEFAULT_PATHS["breach"]

        self.logger.info("MongoLoader.load_from_files() starting...")

        #1: Read JSON backups
        cve_records    = self._reader.read(cve_path)
        kev_records    = self._reader.read(kev_path)
        breach_records = self._reader.read(breach_path)

        #2 : Connect, write, verify
        with MongoConnectionManager() as mgr:
            db = mgr.get_db()
            writer = CollectionWriter(db)

            cve_result = writer.write("cve_raw", cve_records, "cve_id")
            kev_result = writer.write("kev_raw", kev_records, "cve_id")
            breach_result = writer.write("breach_raw", breach_records, "organisation")

            self._reporter.add(cve_result)
            self._reporter.add(kev_result)
            self._reporter.add(breach_result)

            verifier  = MongoVerifier(db)
            all_ok, _ = verifier.verify()

        #3 : Print summary
        self._reporter.log()

        if all_ok:
            self.logger.info("MongoLoader complete. all collections verified successfully.....")
        else:
            self.logger.error(
                "MongoLoader complete but one or more collection did not meet the minimum count threshold."
            )
        return all_ok

    def verify_only(self) -> bool:
        """
        Run the verification step without loading any files.
        """
        self.logger.info("MongoLoader.verify_only(), checking existing collections...")
        with MongoConnectionManager() as mgr:
            verifier  = MongoVerifier(mgr.get_db())
            all_ok, _ = verifier.verify()
        return all_ok



# Entry Point
if __name__ == "__main__":
    loader  = MongoLoader()
    success = loader.load_from_files()
    sys.exit(0 if success else 1)