"""Centralises all date parsing logic for the pipeline. """

import re
import logging
import sys
from datetime import datetime
from typing import Optional

from dateutil import parser as dateutil_parser
from dateutil.parser import ParserError

def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  —  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    fh = logging.FileHandler("pipeline.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)

    return logger
class DateFormatDetector:
    """Identifies which date format pattern a raw string matches"""

    #Matches ISO 8601 full datetime: 2023-10-10T14:15:09 
    _ISO_DATETIME_RE = re.compile( r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}" )

    _ISO_DATE_RE = re.compile( r"^\d{4}-\d{2}-\d{2}$" )

    # Matches US slash format:  10/15/2023 
    _US_SLASH_RE = re.compile( r"^\d{1,2}/\d{1,2}/\d{4}$")

    # Matches month/year only:  01/2019  or  1/2019
    _MONTH_YEAR_SLASH_RE = re.compile(r"^\d{1,2}/\d{4}$")

    # Matches textual month + year: January 2019  or  Jan 2019
    _TEXT_MONTH_YEAR_RE = re.compile( r"^[A-Za-z]+ \d{4}$")

    # Matches year only: 2019
    _YEAR_ONLY_RE = re.compile( r"^\d{4}$")

    @classmethod
    def detect(cls, raw: str) -> str:
        """Returns a format label string"""
        raw = raw.strip()
        if cls._ISO_DATETIME_RE.match(raw): return "iso_datetime"

        if cls._ISO_DATE_RE.match(raw): return "iso_date"
        if cls._US_SLASH_RE.match(raw): return "us_slash"

        if cls._MONTH_YEAR_SLASH_RE.match(raw):return "month_year_slash"
        if cls._TEXT_MONTH_YEAR_RE.match(raw): return "text_month_year"
        if cls._YEAR_ONLY_RE.match(raw): return "year_only"

        return "unknown"
class DateParseStats:
    """Tracks how many dates were successfully parsed vs failed across a run."""

    def __init__(self):
        self.success: int = 0
        self.failed: int = 0
        self.skipped: int = 0   # null

    def record_success(self) -> None: self.success += 1
    def record_failed(self)  -> None: self.failed  += 1
    def record_skipped(self) -> None: self.skipped += 1

    def summary(self) -> str:
        total = self.success + self.failed + self.skipped
        return (f"DateParser — total={total:,} success={self.success:,} failed={self.failed:,} skipped(null)={self.skipped:,}" )

    def reset(self) -> None:
        self.success = self.failed = self.skipped = 0
class DateParser:
    """Converts date strings to YYYY-MM-DD strings suitable for PostgreSQL DATE columns."""

    OUTPUT_FORMAT = "%Y-%m-%d"

    def __init__(self):
        self.logger   = configure_logger("DateParser")
        self.stats    = DateParseStats()
        self._detector = DateFormatDetector()

    def parse(self, raw_date) -> Optional[str]:
        """Always returns a YYYY-MM-DD string or None."""

        if raw_date is None:
            self.stats.record_skipped()
            return None

        raw_str = str(raw_date).strip()

        if not raw_str or raw_str.lower() in ("none", "null", "n/a", "unknown", "-"):
            self.stats.record_skipped()
            return None

        fmt = self._detector.detect(raw_str)

        result = None

        if fmt == "iso_datetime":
            result = self._parse_iso_datetime(raw_str)
        elif fmt == "iso_date":
            result = raw_str      

        elif fmt == "us_slash":
            result = self._parse_with_dateutil(raw_str, dayfirst=False)
        elif fmt == "month_year_slash":
            result = self._parse_month_year_slash(raw_str)

        elif fmt == "text_month_year":
            result = self._parse_with_dateutil(raw_str + " 1", dayfirst=False)

        elif fmt == "year_only":
            result = f"{raw_str}-01-01"

        else:
            result = self._parse_with_dateutil(raw_str)

        if result:
            self.stats.record_success()
        else:
            self.stats.record_failed()
            self.logger.debug(f"Could not parse date: '{raw_str}' (detected format: '{fmt}')")

        return result

    def _parse_iso_datetime(self, raw: str) -> Optional[str]:
        try:
            date_part = raw.split("T")[0]
            datetime.strptime(date_part, "%Y-%m-%d")   # validate the date part
            return date_part
        except ValueError:
            return None

    def _parse_month_year_slash(self, raw: str) -> Optional[str]:

        try:
            parts = raw.split("/")
            month = int(parts[0])
            year  = int(parts[1])
            return datetime(year, month, 1).strftime(self.OUTPUT_FORMAT)
        except (ValueError, IndexError):
            return None

    def _parse_with_dateutil(self, raw: str, dayfirst: bool = True) -> Optional[str]:
        try:
            dt = dateutil_parser.parse(raw, dayfirst=dayfirst)
            return dt.strftime(self.OUTPUT_FORMAT)
        except (ParserError, ValueError, OverflowError):
            return None

    def log_summary(self) -> None:
        """Log a final statistics summary"""
        self.logger.info(self.stats.summary())

    def reset_stats(self) -> None:
        self.stats.reset()
