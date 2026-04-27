"""
Repository-root compatibility package for the local Kafka pipeline modules.

This makes `python -c "from kafka.cve_consumer import CybersecConsumer"`
work from the project root without requiring `PYTHONPATH=src` or venv
activation. The package also re-exports the `kafka-python` client symbols
used by the pipeline.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
SRC_KAFKA_DIR = PACKAGE_DIR.parent / "src" / "kafka"

# Make submodule imports like `kafka.cve_consumer` resolve to the real source.
if SRC_KAFKA_DIR.is_dir():
    __path__ = [str(SRC_KAFKA_DIR)]


def _load_kafka_python():
    """Import the installed `kafka-python` package without shadowing this package."""
    repo_root = PACKAGE_DIR.parent.resolve()
    src_root = SRC_KAFKA_DIR.parent.resolve()

    filtered_paths = []
    for entry in sys.path:
        if not entry:
            continue

        try:
            if Path(entry).resolve() in {repo_root, src_root}:
                continue
        except OSError:
            pass

        filtered_paths.append(entry)

    saved_sys_path = sys.path[:]
    saved_module = sys.modules.get("kafka")

    sys.path = filtered_paths
    try:
        sys.modules.pop("kafka", None)
        external_module = importlib.import_module("kafka")
        errors_module = importlib.import_module("kafka.errors")
    finally:
        sys.path = saved_sys_path
        if saved_module is not None:
            sys.modules["kafka"] = saved_module
        else:
            sys.modules.pop("kafka", None)

    return external_module, errors_module


_external_kafka, _external_errors = _load_kafka_python()

KafkaProducer = _external_kafka.KafkaProducer
KafkaConsumer = _external_kafka.KafkaConsumer
KafkaError = _external_errors.KafkaError
NoBrokersAvailable = _external_errors.NoBrokersAvailable
errors = _external_errors

sys.modules[__name__ + ".errors"] = _external_errors

__all__ = [
    "KafkaProducer",
    "KafkaConsumer",
    "KafkaError",
    "NoBrokersAvailable",
    "errors",
]