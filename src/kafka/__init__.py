"""
Compatibility helpers for the local `kafka` package.

The project stores its own pipeline modules under `src/kafka/`, which would
otherwise collide with the third-party `kafka-python` package used for
`KafkaProducer` and `KafkaConsumer`.
"""

from __future__ import annotations

import importlib
import sys
from importlib.machinery import PathFinder
from importlib.util import module_from_spec
from pathlib import Path


def _load_kafka_python():
	"""Import the installed `kafka-python` package without shadowing this package."""
	package_dir = Path(__file__).resolve().parent
	package_root = package_dir.parent

	filtered_paths = []
	for entry in sys.path:
		if not entry:
			filtered_paths.append(entry)
			continue

		try:
			if Path(entry).resolve() == package_root.resolve():
				continue
		except OSError:
			pass

		filtered_paths.append(entry)

	spec = PathFinder.find_spec("kafka", filtered_paths)
	if spec is None or spec.loader is None:
		raise ImportError(
			"The kafka-python package could not be located. "
			"Install dependencies with the project requirements file."
		)

	external_module = module_from_spec(spec)
	saved_module = sys.modules.get("kafka")
	sys.modules["kafka"] = external_module
	try:
		spec.loader.exec_module(external_module)
		errors_module = importlib.import_module("kafka.errors")
	finally:
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
