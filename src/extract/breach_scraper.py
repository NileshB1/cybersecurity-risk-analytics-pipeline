"""
Scrape data breach records from the Privacy Rights Clearinghouse
(https://privacyrights.org/data-breaches) and stream them into the
`breach_stream` Kafka topic.

Data is pulled primarily from the Tableau CSV export.
"""

import csv
import io
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from extract.base_extractor import BaseExtractor, configure_logger


# 
# Column Mapper
# 

class ColumnMapper:
    """

    Figures out column positions dynamically by inspecting table headers.
    """

    HEADER_MAP: Dict[str, str] = {
        "organization": "organisation",
        "organisation": "organisation",
        "name of": "organisation",
        "type": "breach_type",
        "year": "breach_date",
        "date": "breach_date",
        "records": "records_exposed",
        "state": "state",
        "city": "city",
        "industry": "industry",
        "sector": "industry",
    }

    def __init__(self):
        self.logger = configure_logger("ColumnMapper")
        self._positions: Dict[str, int] = {}

    def build_from_header_row(self, header_cells: List) -> None:
        """
        Read the header row and map column names to their index.
        """
        self._positions.clear()

        for idx, cell in enumerate(header_cells):
            text = cell.get_text(strip=True).lower()

            for keyword, field_name in self.HEADER_MAP.items():
                if keyword in text and field_name not in self._positions:
                    self._positions[field_name] = idx
                    break

        self.logger.debug(f"Resolved column positions: {self._positions}")

    def get(self, field: str, cells: List, default: str = "") -> str:
        """
        Safely extract a value from a row using the mapped column index.
        """
        idx = self._positions.get(field)

        if idx is None or idx >= len(cells):
            return default

        return cells[idx].get_text(strip=True)

    def is_ready(self) -> bool:
        """Check if essential columns are available."""
        return "organisation" in self._positions


# 
# Page Fetcher
# 

class BreachPageFetcher:
    """
    Handles HTTP requests and page parsing.
    """

    BASE_URL = "https://privacyrights.org/data-breaches"
    CSV_URL = (
        "https://public.tableau.com/views/"
        "DataBreachChronologyArchive-PRCHistoricalData2005-2019/"
        "SearchBreaches.csv?:showVizHome=no"
    )

    TIMEOUT_SEC = 20
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 2
    #TODO: Need to check alternative later 
    USER_AGENT = "Mozilla/5.0" #Need  a user agent. Avoiding 403, 

    def __init__(self):
        self.logger = configure_logger("BreachPageFetcher")
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic"""
        session = requests.Session()

        retry = Retry(
            total=self.MAX_RETRIES,
            backoff_factor=self.BACKOFF_FACTOR,
            
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )

        adapter = HTTPAdapter(max_retries=retry)

        session.mount("https://", adapter)

        session.mount("http://", adapter)
        session.headers.update({"User-Agent": self.USER_AGENT})

        return session

    def fetch_page(self, url: str):
        """Fetch a single HTML page.
        Returns (soup, next_page_url) or (None, None) if failed.
        """
        self.logger.info(f"Fetching page: {url}")

        try:
            response = self.session.get(url, timeout=self.TIMEOUT_SEC)
            response.raise_for_status()

        except requests.exceptions.HTTPError as err:
            self.logger.error(f"HTTP error for {url}: {err}")
            return None, None

        except requests.exceptions.ConnectionError as err:
            self.logger.error(f"Connection error for {url}: {err}")
            return None, None

        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout while fetching {url}")
            return None, None

        soup = BeautifulSoup(response.text, "lxml")
        next_url = self._find_next_page(soup, url)

        return soup, next_url

    def fetch_csv_records(self) -> List[Dict[str, str]]:
        """
        Download and parse the Tableau CSV export.
        """
        self.logger.info(f"Fetching CSV: {self.CSV_URL}")

        try:
            response = self.session.get(self.CSV_URL, timeout=self.TIMEOUT_SEC)
            response.raise_for_status()

        except requests.exceptions.HTTPError as err:
            self.logger.error(f"HTTP error fetching CSV: {err}")
            return []

        except requests.exceptions.ConnectionError as err:
            self.logger.error(f"Connection error fetching CSV: {err}")
            return []

        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout fetching CSV: {self.CSV_URL}")
            return []

        text = response.content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))

        records = list(reader)
        self.logger.info(f"Downloaded {len(records):,} rows from CSV")

        return records

    def _find_next_page(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
        """
        Find the "next" pagination link if it exists
        """
        next_link = soup.find("a", string=lambda t: t and "next" in t.lower())

        if not next_link:
            next_link = soup.find(
                "a",
                attrs={"aria-label": lambda v: v and "next" in v.lower()},
            )

        if next_link and next_link.get("href"):
            href = next_link["href"]

            if href.startswith("http"):
                return href

            return urljoin(current_url, href)

        return None

    def start_url(self):
        return self.BASE_URL

    def close(self):
        self.session.close()


# 
# Row Parser
# 

class BreachRowParser:
    """Converts table rows into structured breach records
    """

    def __init__(self, column_mapper: ColumnMapper):
        self.mapper = column_mapper
        self.logger = configure_logger("BreachRowParser")

    def parse_row(self, cells: List) -> Optional[Dict[str, Any]]:
        """Convert a row of <td> elements into a dictionary"""
        if not self.mapper.is_ready():
            self.logger.warning("ColumnMapper not ready.")
            return None

        organisation = self.mapper.get("organisation", cells)

        if not organisation:
            return None  # skip empty/header rows

        return {
            "organisation": organisation,
            "industry": self.mapper.get("industry", cells),
            "breach_type": self.mapper.get("breach_type", cells),
            "breach_date": self.mapper.get("breach_date", cells),
            "records_exposed": self.mapper.get("records_exposed", cells),
            "state": self.mapper.get("state", cells),
            "city": self.mapper.get("city", cells),
            "source": "Privacy Rights Clearinghouse",
        }


# ------------
# Main Scraper
# 

class BreachScraper(BaseExtractor):
    """
    
    Main scraper class responsible for fetching and publishing breach data.
    """

    DEFAULT_SLEEP_SEC = 2
    DEFAULT_MAX_PAGES = 100

    def __init__(
        self,
        kafka_producer=None,
        output_dir: str = ".",
        max_pages: int = DEFAULT_MAX_PAGES,
        sleep_sec: float = DEFAULT_SLEEP_SEC,
    ):
        super().__init__(kafka_producer=kafka_producer, output_dir=output_dir)

        self._fetcher = BreachPageFetcher()
        self._column_mapper = ColumnMapper()
        
        self._row_parser = BreachRowParser(self._column_mapper)

        self._max_pages = max_pages
        self._sleep_sec = sleep_sec

    @property
    def source_name(self):
        return "PrivacyRights_Breaches"

    @property
    def output_filename(self) -> str:
        return "breach_raw.json"

    def _fetch_records(self):
        """
        Fetch records from the CSV export and yield them as a single batch.
        """
        raw_rows = self._fetcher.fetch_csv_records()

        if not raw_rows:
            self.logger.warning("No data returned from CSV.")
            self._fetcher.close()
            return

        records = []

        for row in raw_rows:
            organisation = row.get("Organization Name", "").strip()

            if not organisation:
                continue

            records.append({
                "organisation": organisation,
                "industry": row.get("Organization Type", "").strip(),
                "breach_type": row.get("Type of Breach", "").strip(),
                "breach_date": row.get("Month, Day, Year of Reported Date", "").strip(),
                "records_exposed": row.get("Records Impacted", "").strip(),
                "state": "",
                "city": "",
                "source": row.get("Source", "Privacy Rights Clearinghouse").strip()
                          or "Privacy Rights Clearinghouse",
                "pdf_url": row.get("PDF", "").strip(),
                "description": row.get("Description", "").strip(),
                "verification_status": row.get("In / Out of Verified?", "").strip(),
                "explanation_for_type_of_breach": row.get(
                    "Explanation for Type of Breach", ""
                ).strip(),
            })

        if records:
            self.logger.info(f"Parsed {len(records):,} records from CSV")
            yield records

        self._fetcher.close()
        self.logger.info("Finished processing CSV batch.")

    def _parse_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Records are already normalized at this stage."""
        return raw if raw.get("organisation") else None

    def _publish_batch(self, batch: List[Dict[str, Any]]) -> None:
        self.kafka_producer.publish_breach_batch(batch)


# 
# Entry Point
# 

if __name__ == "__main__":
    scraper = BreachScraper(
        kafka_producer=None,
        output_dir=".",
        max_pages=5
    )

    total = scraper.extract_and_stream()

    print(f"\nDone. {total:,} breach records written to breach_raw.json")