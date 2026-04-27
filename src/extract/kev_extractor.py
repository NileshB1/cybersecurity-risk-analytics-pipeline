"""
Downloads the CISA Known Exploited Vulnerabilities (KEV) catalog from the official CISA JSON feed 
and streams all records into the kev_stream
Kafka topic as a single batch.

"""

import time
from typing import Any, Dict, Generator, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from extract.base_extractor import BaseExtractor, configure_logger



# KEV HTTP Fetcher
class KevHttpFetcher:
    """
    Downloads the CISA KEV JSON feed and returns the parsed payload as a dict
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    TIMEOUT_SEC= 30
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 2
    REQUIRED_KEYS  = {"vulnerabilities", "catalogVersion", "dateReleased"}

    def __init__(self):
        self.logger=configure_logger("KevHttpFetcher")
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry   = Retry(
            total=self.MAX_RETRIES,  backoff_factor=self.BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.headers.update({"Accept": "application/json"})
        return session

    def fetch(self) -> Optional[dict]:
        """
        Download and return the full KEV JSON payload.
        Returns None if the request fails or the JSON is malformed
        """
        self.logger.info(f"Downloading CISA KEV catalog from {self.KEV_URL}")
        try:
            response = self.session.get(self.KEV_URL, timeout=self.TIMEOUT_SEC)
            response.raise_for_status()

        except requests.exceptions.HTTPError as error:
            self.logger.error(f"HTTP error downloading KEV catalog: {error}")
            return None
        except requests.exceptions.ConnectionError as conn:
            self.logger.error(f"Connection error downloading KEV catalog: {conn}")
            return None
        except requests.exceptions.Timeout:
            self.logger.error(f"KEV download timed out after {self.TIMEOUT_SEC} seconds")
            return None

        try:
            payload = response.json()
        except ValueError as json_err:
            self.logger.error(f"KEV response is not valid JSON: {json_err}")
            return None

        missing_keys = self.REQUIRED_KEYS - set(payload.keys())
        if missing_keys:
            self.logger.error(
                f"KEV payload is missing expected keys: {missing_keys}. "
                f"CISA may have changed the feed structure."
            )
            return None

        version = payload.get("catalogVersion", "unknown")
        released = payload.get("dateReleased", "unknown")
        count = len(payload.get("vulnerabilities", []))
        self.logger.info(
            f"KEV catalog downloaded version={version}, "
            f"released={released}, records={count:,}"
        )
        return payload

    def close(self) -> None:
        self.session.close()



# KEV Record Parser
# 

class KevRecordParser:
    """
    Converts one raw CISA KEV entry into the flat dict the pipeline expects
    """

    @staticmethod
    def parse(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Map a raw CISA KEV entry to the pipeline schema.
        """
        cve_id = entry.get("cveID", "").strip()
        if not cve_id:
            return None

        return {
            "cve_id":cve_id,
            "vendor":entry.get("vendorProject", "").strip(),
            "product": entry.get("product", "").strip(),
            "vulnerability_name": entry.get("vulnerabilityName", "").strip(),
            "date_added": entry.get("dateAdded", ""),
            "exploitation_date": entry.get("dateAdded", ""),   # first confirmed exploitation
            "required_action": entry.get("requiredAction", "").strip(),
            "due_date": entry.get("dueDate", ""),
            "source": "CISA_KEV",
        }


# 
# KEV Extractor
# 

class KevExtractor(BaseExtractor):
    """
    Extracts Known Exploited Vulnerability records from the CISA KEV feed.

    """

    def __init__(self, kafka_producer=None, output_dir: str = "."):
        super().__init__(kafka_producer=kafka_producer, output_dir=output_dir)
        self._fetcher = KevHttpFetcher()
        self._parser = KevRecordParser()

    #BaseExtractor contract 

    @property
    def source_name(self) -> str:
        return "CISA_KEV_FEED"

    @property
    def output_filename(self) -> str:
        return "kev_raw.json"

    def _fetch_records(self) -> Generator[List[Dict[str, Any]], None, None]:
        """
        Downloads the full CISA KEV catalog and yields all records as
        a single batch.  Closes the HTTP session when done.
        """
        payload = self._fetcher.fetch()
        if not payload:
            self.logger.error("KEV fetch returned nothing, skipping extraction.")
            return

        raw_records = payload.get("vulnerabilities", [])
        self.logger.info(f"Yielding {len(raw_records):,} raw KEV records for parsing")
        yield raw_records

        self._fetcher.close()

    def _parse_record(self, raw: Dict[str, Any]):
        return self._parser.parse(raw)

    def _publish_batch(self, batch: List[Dict[str, Any]]):
        self.kafka_producer.publish_kev_batch(batch)


# 
# Entry Point
# 

if __name__ == "__main__":
    extractor=KevExtractor(kafka_producer=None, output_dir=".")
    total= extractor.extract_and_stream()
    print(f"\nDone. {total:,} KEV records written to kev_raw.json")