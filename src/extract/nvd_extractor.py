import os
import time
from typing import Any, Dict, Generator, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from extract.base_extractor import BaseExtractor, configure_logger

# HTTP Session Builder

class NvdHttpSession:
    """Builds a requests.Session pre-configured for the NVD API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 2

    def __init__(self, api_key: Optional[str] = None):
        self.logger = configure_logger("NvdHttpSession")
        self.api_key = api_key
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()

        retry_strategy = Retry(total=self.MAX_RETRIES,backoff_factor=self.BACKOFF_FACTOR, status_forcelist=[429, 500, 502, 503, 504],allowed_methods=["GET"])

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://",  adapter)

        session.headers.update({"Accept": "application/json"})
        if self.api_key:
            session.headers.update({"apiKey": self.api_key})
            self.logger.info("NVD session configured with API key (50 req/30 s limit).")
        else:
            self.logger.warning("NVD_API_KEY not set. rate limit is 5 req/30 seconds")
        return session

    def get_page(self, start_index, page_size, timeout=30):
        """Fetch one page of CVE records. Returns parsed JSON or None on failure."""
        params = {"resultsPerPage": page_size, "startIndex": start_index}
        try:
            response=self.session.get(self.BASE_URL, params=params, timeout = timeout)
            response.raise_for_status()
            
            return response.json()
        except requests.exceptions.HTTPError as err:
            self.logger.error(f"HTTP error at index {start_index}: {err}")
        except requests.exceptions.ConnectionError as conn:
            self.logger.error(f"Connection error at index {start_index}: {conn}")
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timed out at index {start_index}")
        return None

    def close(self) -> None:
        self.session.close()

# CVE Record Parser
class CveRecordParser:
    """Converts one raw NVD API vulnerability record into the flat dict
    the pipeline expects"""
    @staticmethod
    def extract_cvss_score(cve_item: dict):
        """Walk the metrics block"""
        metrics=cve_item.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                try:
                    return float(entries[0]["cvssData"]["baseScore"])
                except (KeyError, TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def extract_vendors(cve_item: dict) -> List[str]:
        """Pull vendor names from the CPE configuration block"""
        vendors: set = set()
        try:
            for config in cve_item.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        parts = match.get("criteria", "").split(":")
                        if len(parts) > 3 and parts[3] not in ("*", "-", ""):
                            vendors.add(parts[3].lower())
        except Exception:
            pass
        return sorted(vendors) if vendors else ["unknown"]

    @staticmethod
    def extract_english_description(cve_data: dict) -> str:
        """Return the first English description """
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "").strip()
        return ""

    @classmethod
    def parse(cls, cve_item: dict):
        """Convert a raw NVD vulnerability item to a pipeline-ready dict"""
        cve_data = cve_item.get("cve", {})
        cve_id = cve_data.get("id", "").strip()

        if not cve_id:
            return None

        return { "cve_id": cve_id,"severity": cls.extract_cvss_score(cve_item),"vendors": cls.extract_vendors(cve_item),"publish_date": cve_data.get("published", ""),"modified_date":cve_data.get("lastModified", ""), "description": cls.extract_english_description(cve_data),"source":"NVD",}

# NVD Extractor
class NvdExtractor(BaseExtractor):
    """ Extracts CVE records from the NIST National Vulnerability Database """

    PAGE_SIZE=2000     # NVD API maximum per request

    def __init__(self, kafka_producer=None, output_dir: str = "."):
        super().__init__(kafka_producer=kafka_producer, output_dir = output_dir)

        api_key = os.getenv("NVD_API_KEY", "").strip() or None
        self._session = NvdHttpSession(api_key= api_key)
        self._parser  = CveRecordParser()

        self._sleep_sec = 0.7 if api_key else 6.5 # Sleep between pages to stay inside NVD rate limits

    #BaseExtractor contract 

    @property
    def source_name(self) -> str:
        return "NVD_CVE_API"

    @property
    def output_filename(self) -> str:
        return "cve_raw.json"

    def _fetch_records(self) -> Generator[List[Dict[str, Any]], None, None]:
        
        first_page = self._session.get_page(start_index=0, page_size=self.PAGE_SIZE)
        if not first_page:
            self.logger.error("First NVD API page failed, aborting")
            return

        total = first_page.get("totalResults", 0)
        self.logger.info(f"NVD reports {total:,} total CVE records to fetch.")

        #Yield the records from the first page we already have
        first_batch=first_page.get("vulnerabilities", [])
        if first_batch:
            yield first_batch

        # Fetch remaining pages
        start_index = self.PAGE_SIZE
        while start_index < total:
            self.logger.info( f"Fetching NVD page: records {start_index:,} to {min(start_index + self.PAGE_SIZE, total):,} of {total:,}")
            page = self._session.get_page(start_index=start_index, page_size=self.PAGE_SIZE)

            if page:
                batch = page.get("vulnerabilities", [])
                if batch:
                    yield batch
            else:
                self.logger.warning(f"Skipping failed page at startIndex={start_index}")

            start_index += self.PAGE_SIZE
            time.sleep(self._sleep_sec)

        self._session.close()

    def _parse_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self._parser.parse(raw)

    def _publish_batch(self, batch: List[Dict[str, Any]]) -> None:
        self.kafka_producer.publish_cve_batch(batch)

# Entry Point

if __name__ == "__main__":
    extractor = NvdExtractor(kafka_producer=None, output_dir=".")
    total = extractor.extract_and_stream()
    print(f"\nDone. {total:,} CVE records written to cve_raw.json")
