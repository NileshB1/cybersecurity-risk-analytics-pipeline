#!/usr/bin/env python
"""
Simple JSON to MongoDB loader.

Reads:
    - kev_raw.json
    - cve_raw.json
    - breach_raw.json

"""

import json
import argparse
import sys
from pathlib import Path

import ijson
from dotenv import load_dotenv



load_dotenv(dotenv_path=Path("src")/".env")

sys.path.insert(0, str(Path("src")))

from kafka.cve_consumer import MongoWriter
from kafka.kafka_config import configure_logger

logger = configure_logger("JsonToMongoLoader")



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

        
        if file_size < 10 * 1024 * 1024:  # <10MB
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            records = data if isinstance(data, list) else [data]
            logger.info(f"Loaded {len(records)} records from {file_path.name}")
            return records

        
        
        logger.info(
            f"{file_path.name} is {file_size / (1024 * 1024):.1f}MB — using streaming parser"
        )

        records = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                
                start_pos = f.tell()
                first_char = f.read(1)

                while first_char and first_char.isspace():
                    first_char = f.read(1)

                f.seek(start_pos)

                
                if first_char == "[":
                    for item in ijson.items(f, "item"):
                        records.append(item)

                    logger.info(
                        f"Streamed {len(records)} records from JSON array in {file_path.name}"
                    )
                    return records

                
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


def prepare_cve_chunk_files(source_file: Path, chunk_count: int = 10) -> list[Path]:
    """
    Split the large CVE export into smaller files so they can be loaded one by one.

    If the chunk files already exist, reuse them.
    """

    chunk_files = [
        source_file.with_name(f"{source_file.stem}{index}{source_file.suffix}")
        for index in range(1, chunk_count + 1)
    ]

    if all(chunk_file.exists() for chunk_file in chunk_files):
        logger.info("Using existing CVE chunk files")
        return chunk_files

    logger.info(
        f"Splitting {source_file.name} into {chunk_count} files before loading"
    )

    records = load_json_file(source_file)
    if not records:
        return [source_file]

    chunk_size = max(1, (len(records) + chunk_count - 1) // chunk_count)
    created_files = []

    for index, chunk_file in enumerate(chunk_files, start=0):
        start = index * chunk_size
        end = min(start + chunk_size, len(records))

        if start >= len(records):
            break

        chunk_records = records[start:end]

        with open(chunk_file, "w", encoding="utf-8") as f:
            json.dump(chunk_records, f, ensure_ascii=False, indent=2)

        logger.info(
            f"Created {chunk_file.name} with {len(chunk_records):,} CVE records"
        )
        created_files.append(chunk_file)

    return created_files or [source_file]


def resolve_loader_for_file(file_path: Path):
    """Return the dataset loader that matches the provided file name."""

    file_name = file_path.name.lower()

    if file_name.startswith("cve_raw"):
        return load_cve_data

    if file_name.startswith("kev_raw"):
        return load_kev_data

    if file_name.startswith("breach_raw"):
        return load_breach_data

    return load_cve_data



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

 

def main():
    """Run the full load process
    """
    parser = argparse.ArgumentParser(description="Load JSON files into MongoDB")
    parser.add_argument(
        "-file",
        dest="file",
        help="Load a single JSON file (for example, cve_raw1.json) instead of all files",
    )
    parser.add_argument(
        "-batch",
        dest="batch",
        type=int,
        default=1000,
        help="MongoDB flush threshold for this run (for example, 1000 or 5000)",
    )
    args = parser.parse_args()

    repo_root = Path.cwd()

    logger.info("=" * 50)
    logger.info("MongoDB Raw Data Loader")
    logger.info("=" * 50)

    try:
        MongoWriter.BATCH_THRESHOLD = args.batch
        writer = MongoWriter()
    except Exception as err:
        logger.error(f"Could not initialize MongoWriter: {err}")
        sys.exit(1)

    
    kev_file = repo_root/"kev_raw.json"
    cve_file = repo_root /"cve_raw.json"
    breach_file = repo_root/"breach_raw.json"
    cve_chunk_files = [] if args.file else prepare_cve_chunk_files(cve_file, 10)

    totals = {"kev": 0, "cve": 0, "breach": 0}
    failures = []

    try:
        if args.file:
            file_path = Path(args.file)
            if not file_path.is_absolute():
                file_path = repo_root / file_path

            loader = resolve_loader_for_file(file_path)

            try:
                dataset_name = file_path.name.lower().split("_raw", 1)[0]
                if dataset_name in totals:
                    totals[dataset_name] = loader(writer, file_path)
                else:
                    totals["cve"] = loader(writer, file_path)
            except Exception as err:
                failures.append(f"{file_path.name}: {err}")
                logger.error(f"Single-file load failed for {file_path.name}", exc_info=True)
        else:
            
            for label, loader, file_path in (
                ("kev", load_kev_data, kev_file),
                ("breach", load_breach_data, breach_file),
            ):
                try:
                    totals[label] = loader(writer, file_path)
                except Exception as err:
                    failures.append(f"{label}: {err}")
                    logger.error(f"{label.upper()} load failed, continuing with remaining files", exc_info=True)

            for cve_chunk_file in cve_chunk_files:
                try:
                    totals["cve"] += load_cve_data(writer, cve_chunk_file)
                    writer.flush_all()
                except Exception as err:
                    failures.append(f"cve:{cve_chunk_file.name}: {err}")
                    logger.error(
                        f"CVE chunk load failed for {cve_chunk_file.name}, continuing with remaining files",
                        exc_info=True,
                    )

        logger.info("All records queued. Flushing to MongoDB...")
        writer.flush_all()


        
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


if __name__ == "__main__":
    main()