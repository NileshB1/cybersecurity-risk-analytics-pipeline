"""
Reads raw records from MongoDB (the output of the Kafka consumer), applies
the full cleaning and normalisation pipeline, and returns three clean
lists of records ready for PostgreSQL insertion."""

import os
import re
import logging
import sys
from abc import ABC, abstractmethod

from typing import Any, Dict, List, Optional, Tuple

import pymongo
from dotenv import load_dotenv

from transform.date_parser       import DateParser
from transform.vendor_normaliser import VendorNormaliser

load_dotenv()
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



# MongoDB Raw Reader
class MongoRawReader:
    """
    Reads raw records from MongoDB collections into Python lists.
    """

    def __init__(self):
        self.logger = configure_logger("MongoRawReader")
        self._client = pymongo.MongoClient(
            os.getenv("MONGO_URI", "mongodb://localhost:27017"),
            serverSelectionTimeoutMS=5000
        )
        
        self._db = self._client[os.getenv("MONGO_DB", "cybersec_db")]

    def read_collection(self, collection_name: str) -> List[Dict[str, Any]]:
        """
        Read all documents from one MongoDB collection.
        
        """
        self.logger.info(f"Reading MongoDB collection: '{collection_name}'")
        try:
            records = list(self._db[collection_name].find({}, {"_id": 0}))
            self.logger.info(f"  {len(records):,} documents read from '{collection_name}'")
            return records
        except pymongo.errors.PyMongoError as exc:
            self.logger.error(f"MongoDB read error on '{collection_name}': {exc}")
            return []

    def read_all(self) -> Tuple[List, List, List]:
        """Read all three raw collections and return them as a tuple."""
        cve_records    = self.read_collection("cve_raw")
        kev_records    = self.read_collection("kev_raw")
        breach_records = self.read_collection("breach_raw")
        return cve_records, kev_records, breach_records

    def close(self) -> None:
        self._client.close()
        self.logger.debug("MongoRawReader connection closed.")



# Industry Mapper


class IndustryMapper:
    """
    Converts Privacy Rights Clearinghouse sector codes and free-text
    strings to human-readable industry labels used in PostgreSQL
    and the Plotly dashboard.

    """

    # Official Privacy Rights Clearinghouse sector codes
    CODE_MAP: Dict[str, str] = {
        "MED": "Healthcare",
        "BSF": "Financial Services",
        "BSO":"Business / Other",
        "EDU":"Education",
        "GOV":"Government / Military",
        "NGO":"Non-Profit",
        "RET": "Retail",
        "TEC": "Technology",
        "TECH": "Technology",
        "INS": "Insurance",
        "LEG": "Legal",
        "ENE": "Energy / Utilities",
        "TRA": "Transportation",
        "HOS": "Hospitality",
        "MFG":"Manufacturing",
    }

    KEYWORD_MAP: Dict[str, str] = {
        "health":"Healthcare",
        "hospital": "Healthcare",
        "medical": "Healthcare",
        "clinic": "Healthcare",
        "pharma": "Healthcare",
        "bank":"Financial Services",
        "financial": "Financial Services",
        "finance":"Financial Services",
        "insurance": "Insurance",
        "credit":"Financial Services",
        "school": "Education",
        "university": "Education",
        "college": "Education",
        "education": "Education",
        "government": "Government / Military",
        "federal":    "Government / Military",
        "retail": "Retail",
        "store": "Retail",
        "tech": "Technology",
        "software": "Technology",
        "telecom":"Technology",
        "military": "Government / Military",
    }

    @classmethod
    def map(cls, raw: Optional[str]) -> str:
        """
        Return a readable industry label. Returns 'Unknown' for null inputs"""
        if not raw or not str(raw).strip():
            return "Unknown"

        cleaned = str(raw).strip()

        #1:exact code lookup
        if cleaned.upper() in cls.CODE_MAP:
            return cls.CODE_MAP[cleaned.upper()]
        #2: keyword substring scan
        lower = cleaned.lower()
        for keyword, industry in cls.KEYWORD_MAP.items():
            if keyword in lower:
                return industry

        #3: title-case fallback
        return cleaned.title()


#
# Records Exposed Parser
#

class RecordsExposedParser:
    """
    Converts raw records_exposed strings from the breach scraper to integers.

    """

    SANITY_LIMIT = 10_000_000_000

    _MULTIPLIERS: Dict[str, int] = {
        "k": 1_000,
        "thousand": 1_000,
        "m": 1_000_000,
        "million": 1_000_000,
        "b": 1_000_000_000,
        "billion": 1_000_000_000,
    }

    @classmethod
    def parse(cls, raw: Optional[str]) -> Optional[int]:
        """
            Return integer record count, or None if not parseable
        """
        if not raw:
            return None
        cleaned = str(raw).strip().lower().replace(",", "")

        if not cleaned or cleaned in ("unknown", "n/a", "not available", "-", "?"):
            return None

        # Direct numeric pars
        try:
            return cls._cap(int(float(cleaned)))
        except ValueError:
            pass

        # Check multiplier suffixes
        for suffix, multiplier in cls._MULTIPLIERS.items():
            match = re.match(rf"^([\d.]+)\s*{suffix}", cleaned)
            if match:
                try:
                    return cls._cap(int(float(match.group(1)) * multiplier))
                except ValueError:
                    continue

        # Last resort
        digits = re.sub(r"[^\d]", "", cleaned)
        return cls._cap(int(digits)) if digits else None

    @classmethod
    def _cap(cls, value: int) -> Optional[int]:
        if value <= 0:
            return None
        return value if value <= cls.SANITY_LIMIT else None



# Deduplicator

class Deduplicator:
    """
    Removes duplicate records from a list using a caller-supplied key function.

    """

    def __init__(self):
        self.logger = configure_logger("Deduplicator")

    def deduplicate(
        self,
        records: List[Dict[str, Any]],
        key_fn,
        label:   str = "records"
    ) -> List[Dict[str, Any]]:
        """
        Remove duplicates and return unique records in original order.

        """
        seen:   set       = set()
        unique: List[Dict] = []
        dupes:  int        = 0

        for record in records:
            try:
                key = key_fn(record)
            except (KeyError, TypeError):
                # Cannot extract key - keep the record rather than silently drop it
                unique.append(record)
                continue

            if key not in seen:
                seen.add(key)
                unique.append(record)
            else:
                dupes += 1

        if dupes:
            self.logger.info(
                f"[{label}] Removed {dupes:,} duplicates — "
                f"{len(unique):,} unique records remain"
            )
        else:
            self.logger.info(f"[{label}] No duplicates found")

        return unique


# 
# Abstract Base Record Cleaner
# 

class BaseRecordCleaner(ABC):
    """
    Abstract base class for dataset-specific cleaners.

    """

    def __init__(self):
        self.logger = configure_logger(f"Cleaner.{self.dataset_name}")
        self.date_parser= DateParser()
        self.vendor_norm =VendorNormaliser()
        self._dropped=0

    @property
    @abstractmethod
    def dataset_name(self) -> str:
        """Label used in log messages. For example 'CVE', 'KEV', 'Breach'."""
        ...

    @abstractmethod
    def clean_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Transform one raw dict to a clean dict, or return None to drop it"""
        ...

    def clean_all(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply clean_record() to the full list.
        Logs per-record warnings on error so one bad record never
        stops the rest of the batch from being processed
        """
        self.logger.info(f"Cleaning {len(records):,} raw {self.dataset_name} records....")
        self._dropped=0
        cleaned: List[Dict] = []

        for raw in records:
            try:
                result = self.clean_record(raw)
                if result:
                    cleaned.append(result)
                else:
                    self._dropped += 1
            except Exception as exc:
                self.logger.warning(
                    f"Error cleaning {self.dataset_name} record: {exc}",
                    exc_info=False
                )
                self._dropped += 1

        self.logger.info(
            f"{self.dataset_name} cleaning done — "
            f"kept={len(cleaned):,}  dropped={self._dropped:,}"
        )
        return cleaned


#
# CVE Cleaner
#

class CveCleaner(BaseRecordCleaner):
    """
    Cleans raw NVD CVE records from the cve_raw MongoDB collection  """

    MAX_DESCRIPTION_LEN = 2000

    @property
    def dataset_name(self) -> str:
        return "CVE"

    def clean_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cve_id = str(raw.get("cve_id", "")).strip()
        if not cve_id:
            return None

        # Severity validation
        severity = None
        raw_sev  = raw.get("severity")
        if raw_sev is not None:
            try:
                score    = float(raw_sev)
                severity = round(score, 1) if 0.0 <= score <= 10.0 else None
            except (ValueError, TypeError):
                severity = None

        #Primary vendor
        vendors_raw = raw.get("vendors", [])
        if isinstance(vendors_raw, list) and vendors_raw:
            primary_vendor = self.vendor_norm.normalise(vendors_raw[0])
        elif isinstance(vendors_raw, str) and vendors_raw:
            primary_vendor = self.vendor_norm.normalise(vendors_raw)
        else:
            primary_vendor = "Unknown"

        # Description cap

        description = str(raw.get("description", "")).strip()
        if len(description) > self.MAX_DESCRIPTION_LEN:
            description = description[:self.MAX_DESCRIPTION_LEN]

        return {
            "cve_id": cve_id,
            "severity": severity,
            "vendor": primary_vendor,
            "publish_date": self.date_parser.parse(raw.get("publish_date")),
            "modified_date":self.date_parser.parse(raw.get("modified_date")),
            "description":  description,
        }


# 
# KEV Cleaner
# 

class KevCleaner(BaseRecordCleaner):
    """
        Cleans raw CISA KEV records from the kev_raw MongoDB collection.

    """

    MAX_ACTION_LEN = 1000

    @property
    def dataset_name(self) -> str:
        return "KEV"

    def clean_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cve_id = str(raw.get("cve_id", "")).strip()
        if not cve_id:
            return None

        exploit_date = self.date_parser.parse(
            raw.get("exploitation_date") or raw.get("date_added")
        )

        required_action = str(raw.get("required_action", "")).strip()
        if len(required_action) > self.MAX_ACTION_LEN:
            required_action = required_action[:self.MAX_ACTION_LEN]

        return {
            "cve_id": cve_id,
            "vendor": self.vendor_norm.normalise(raw.get("vendor")),
            "product":str(raw.get("product","")).strip(),
            "vulnerability_name": str(raw.get("vulnerability_name", "")).strip(),
            "exploitation_date": exploit_date,
            "required_action": required_action,
        }


# 
# Breach Cleaner
# 

class BreachCleaner(BaseRecordCleaner):
    """
    Cleans raw breach records from the breach_raw MongoDB collection

    """

    MAX_ORG_LEN = 500

    def __init__(self):
        super().__init__()
        self._industry_mapper = IndustryMapper()
        self._records_parser = RecordsExposedParser()

    @property
    def dataset_name(self) -> str:
        return "Breach"

    def clean_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        organisation = str(raw.get("organisation", "")).strip()
        if not organisation or organisation.lower() in ("unknown", "n/a", "-"):
            return None

        if len(organisation) > self.MAX_ORG_LEN:
            organisation = organisation[:self.MAX_ORG_LEN]

        # Prefer breach_date; fall back to breach_year for partial dates
        raw_date = raw.get("breach_date") or raw.get("breach_year")
        breach_date = self.date_parser.parse(raw_date)

        industry_raw = raw.get("industry") or raw.get("breach_type")

        return {
            "organisation": organisation,
            "industry": self._industry_mapper.map(industry_raw),
            "breach_type": str(raw.get("breach_type", "")).strip(),
            "breach_date": breach_date,
            "records_exposed": self._records_parser.parse(raw.get("records_exposed")),
            "state":str(raw.get("state", "")).strip(),
        }


#
# Transform Run Report
#

class TransformReport:
    """
    Collects counts from all three cleaners and prints a single
    structured summary table at the end of a transform run.

    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._rows: List[Tuple] = []

    def record(
        self,
        dataset:     str,

        raw_count:   int,
        clean_count: int,
        final_count: int
    ) -> None:
        self._rows.append((dataset, raw_count, clean_count, final_count))

    def log(self) -> None:
        self.logger.info("=" * 40)
        self.logger.info("  TRANSFORM SUMMARY")
        self.logger.info("=" * 45)
        self.logger.info(
            f"  {'Dataset':<12} {'Raw':>8} {'Cleaned':>10} "
            f"{'Dropped':>10} {'Dupes':>8} {'Final':>8}"
        )
        self.logger.info("-" * 40)
        for dataset, raw, clean, final in self._rows:
            dropped = raw   - clean
            dupes   = clean - final
            self.logger.info(
                f"  {dataset:<12} {raw:>8,} {clean:>10,} "
                f"{dropped:>10,} {dupes:>8,} {final:>8,}"
            )
        self.logger.info("=" * 45)


# 
# Master Data Transformer
# 

class DataTransformer:
    """
    Orchestrates the full transformation pass over all three datasets.


    Called by:
        -Airflow DAG task 'run_transform' (dags/cybersec_pipeline_dag.py)
        -run_pipeline.py for standalone execution

    """

    def __init__(self):
        self.logger = configure_logger("DataTransformer")
        self._reader = MongoRawReader()
        self._cve_cleaner = CveCleaner()
        self._kev_cleaner= KevCleaner()
        self._breach_cleaner = BreachCleaner()
        self._deduplicator= Deduplicator()
        self._report= TransformReport(self.logger)

    def run(self) -> Tuple[List, List, List]:
        """
        Execute the full transform pipeline and return clean records
        Below are the steps:

        1: Read all raw records from MongoDB
        2 : Clean each dataset with its dedicated cleaner
        3: Deduplicate each cleaned dataset
        4: Log sub-module statistics (dates, vendor normalisation)
        5: Print the transform summary report
        """
        self.logger.info("DataTransformer starting full transform run....")

        #1: Read raw data
        raw_cves, raw_kev, raw_breaches = self._reader.read_all()
        self._reader.close()

        #2: Clean the data
        clean_cves= self._cve_cleaner.clean_all(raw_cves)
        clean_kev= self._kev_cleaner.clean_all(raw_kev)
        clean_breaches = self._breach_cleaner.clean_all(raw_breaches)

        #3: Deduplicate the cleaned data
        final_cves = self._deduplicator.deduplicate(
            clean_cves,
            key_fn=lambda r: r["cve_id"],
            label="CVE"
        )
        final_kev = self._deduplicator.deduplicate(
            clean_kev,
            key_fn=lambda r: r["cve_id"],
            label="KEV"
        )
        # Breach composite key: same organisation can have multiple breach events
        # but (organisation + date) should be unique per incident
        final_breaches = self._deduplicator.deduplicate(
            clean_breaches,
            key_fn=lambda r: (
                r.get("organisation", "").lower().strip(),
                r.get("breach_date", "")
            ),
            label="Breach"
        )

        # 4: Sub module statistics 
        self._cve_cleaner.date_parser.log_summary()
        self._cve_cleaner.vendor_norm.log_summary()

        #5: Summary report
        self._report.record("CVE", len(raw_cves), len(clean_cves), len(final_cves))
        self._report.record("KEV",len(raw_kev), len(clean_kev), len(final_kev))
        self._report.record("Breach", len(raw_breaches),len(clean_breaches),len(final_breaches))
        self._report.log()

        self.logger.info("DataTransformer complete")
        return final_cves, final_kev, final_breaches


# 
# Main method


if __name__ == "__main__":
    transformer = DataTransformer()
    cves, kev, breaches = transformer.run()
    print(f"\nTransform complete:")
    print(f"CVE records: {len(cves):,}")
    print(f"KEV records : {len(kev):,}")
    print(f"Breach records: {len(breaches):,}")