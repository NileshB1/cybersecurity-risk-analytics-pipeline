#!/usr/bin/env python
"""
Simple JSON to MongoDB loader.

Reads:
    - kev_raw.json
    - cve_raw.json
    - breach_raw.json

(from the repo root) and loads them into MongoDB using upsert logic
"""

import json
import sys
from pathlib import Path

import ijson
from dotenv import load_dotenv


# Environment setup

# Load environment variables from src/.env
load_dotenv(dotenv_path=Path("src")/".env")

# Allow imports from src/
sys.path.insert(0, str(Path("src")))

from kafka.cve_consumer import MongoWriter
from kafka.kafka_config import configure_logger

logger = configure_logger("JsonToMongoLoader")


# File loading helpers

def load_json_file(file_path: Path) -> list:
    """
    Load records from a JSON file.

    Strategy:
    - If file is small (<10MB): load normally
    - If large: try streaming as JSON array
    - Fallback: treat file as newline-delimited JSON (JSONL)
    """

    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return []

    try:
        file_size = file_path.stat().st_size

        # Small file -> standard json.load
        if file_size < 10 * 1024 * 1024:  # <10MB
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            records = data if isinstance(data, list) else [data]
            logger.info(f"Loaded {len(records)} records from {file_path.name}")
            return records

        
        # Large file -> streaming
        logger.info(
            f"{file_path.name} is {file_size / (1024 * 1024):.1f}MB — using streaming parser"
        )

        records = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                # Peek first non-whitespace character
                start_pos = f.tell()
                first_char = f.read(1)

                while first_char and first_char.isspace():
                    first_char = f.read(1)

                f.seek(start_pos)

                # Case 1: JSON array
                if first_char == "[":
                    for item in ijson.items(f, "item"):
                        records.append(item)

                    logger.info(
                        f"Streamed {len(records)} records from JSON array in {file_path.name}"
                    )
                    return records

                # Case 2: JSONL (newline-delimited JSON)
                logger.info("Detected JSONL format")

                skipped_lines = 0
                f.seek(0)

                for line_no, line in enumerate(f, start=1):
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        skipped_lines += 1

                        if skipped_lines <= 5:
                            logger.debug(f"Skipping malformed JSON at line {line_no}")

                if skipped_lines:
                    logger.warning(
                        f"Skipped {skipped_lines} malformed lines in {file_path.name}"
                    )

                logger.info(f"Loaded {len(records)} records from {file_path.name}")
                return records

        except Exception as err:
            logger.error("Streaming parse failed", exc_info=True)
            return []

    except Exception as err:
        logger.error(f"Failed to load {file_path}: {err}", exc_info=True)
        return []


# 
# Data loaders (per dataset)


def load_kev_data(writer: MongoWriter, file_path: Path) -> int:
    """Load KEV records into MongoDB."""
    logger.info(f"Loading KEV data from {file_path.name}")

    records = load_json_file(file_path)

    for idx, record in enumerate(records, start=1):
        writer.write_kev(record)

        if idx % 5000 == 0:
            logger.info(f"  Processed {idx:,}/{len(records):,} KEV records")

    logger.info(f"KEV load complete: {len(records)} records queued")
    return len(records)


def load_cve_data(writer: MongoWriter, file_path: Path) -> int:
    """
        Load CVE records into MongoDB
    """
    logger.info(f"Loading CVE data from {file_path.name}")

    records = load_json_file(file_path)

    for idx, record in enumerate(records, start=1):
        writer.write_cve(record)

        if idx % 5000 == 0:
            logger.info(f"  Processed {idx:,}/{len(records):,} CVE records")

    logger.info(f"CVE load complete: {len(records)} records queued")
    return len(records)


def load_breach_data(writer: MongoWriter, file_path: Path) -> int:
    """
        Load breach records into MongoDB
    """
    logger.info(f"Loading breach data from {file_path.name}")

    records = load_json_file(file_path)

    for idx, record in enumerate(records, start=1):
        writer.write_breach(record)

        if idx % 5000 == 0:
            logger.info(f"  Processed {idx:,}/{len(records):,} breach records")

    logger.info(f"Breach load complete: {len(records)} records queued")
    return len(records)


# 
# Main entry point
# 

def main():
    """Run the full load process
    """
    repo_root = Path.cwd()

    logger.info("=" * 50)
    logger.info("MongoDB Raw Data Loader")
    logger.info("=" * 50)

    # 
    # Initialize MongoDB writer
    try:
        writer = MongoWriter()
    except Exception as err:
        logger.error(f"Could not initialize MongoWriter: {err}")
        sys.exit(1)

    # 
    # File locations
    # 
    kev_file = repo_root/"kev_raw.json"
    cve_file = repo_root /"cve_raw.json"
    breach_file = repo_root/"breach_raw.json"

    totals = {"kev": 0, "cve": 0, "breach": 0}
    failures = []

    try:
        # Load each dataset independently so one bad file does not block the others.
        for label, loader, file_path in (
            ("kev", load_kev_data, kev_file),
            ("cve", load_cve_data, cve_file),
            ("breach", load_breach_data, breach_file),
        ):
            try:
                totals[label] = loader(writer, file_path)
            except Exception as err:
                failures.append(f"{label}: {err}")
                logger.error(f"{label.upper()} load failed, continuing with remaining files", exc_info=True)

        logger.info("All records queued. Flushing to MongoDB...")
        writer.flush_all()


        # Summary
        written = writer.total_written()

        logger.info("=" * 60)
        logger.info("LOAD COMPLETE")
        logger.info("=" * 60)

        logger.info(f"kev_raw: {written.get('kev_raw', 0):,} documents written")
        logger.info(f"cve_raw: {written.get('cve_raw', 0):,} documents written")
        logger.info(f"breach_raw:{written.get('breach_raw', 0):,} documents written")

        if failures:
            logger.warning("Some datasets failed during load:")
            for failure in failures:
                logger.warning(f"  - {failure}")

        logger.info("=" * 60)

    except Exception as err:
        logger.error("Error during load", exc_info=True)
        sys.exit(1)

    finally:
        writer.close()


# ---------------------------------------------------------------------

if __name__ == "__main__":
    main()