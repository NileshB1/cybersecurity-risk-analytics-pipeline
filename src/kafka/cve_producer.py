import json
import logging
import sys
import time
from typing import List, Dict, Any, Optional
 
from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable
 
from kafka.kafka_config import KafkaConfig, configure_logger

#
# Serialiser Helper
# 
 
class RecordSerialiser:
    """
    Converts Python dictionaries to UTF-8 encoded JSON bytes for Kafka transport
    """
 
    @staticmethod
    def serialise(record: Dict[str, Any]) -> bytes:
        """
        Serialise a dictionary to compact JSON bytes.
        """
        return json.dumps(
            record,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str       # handle datetime objects gracefully
        ).encode("utf-8")
 
    @staticmethod
    def deserialise(data: bytes) -> Dict[str, Any]:
        """Decode bytes back to a Python dict, used by the consumer."""
        return json.loads(data.decode("utf-8"))
 

# 
# Delivery Callback
# 
 
class DeliveryCallback:
    """
    Tracks per-message delivery outcomes reported by the Kafka broker.

    """
 
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.delivered = 0
        self.failed = 0
 
    def on_send_success(self, record_metadata) -> None:
        self.delivered += 1
        self.logger.debug(
            f"Delivered to {record_metadata.topic} "
            f"[partition {record_metadata.partition}] "
            f"offset {record_metadata.offset}"
        )
 
    def on_send_error(self, exc: Exception):
        self.failed += 1
        self.logger.error(f"Delivery failed: {exc}")
 
    def reset(self) -> None:
        self.delivered = 0
        self.failed = 0
 
    def summary(self):
        total = self.delivered + self.failed
        return f"{self.delivered}/{total} messages delivered ({self.failed} failed)"
 
 
# 
# Producer
# 
 
class CybersecProducer:
    """
    Publishes cybersecurity records to Kafka topics.
 
    Retry-on-startup Logic
    ----------------------
    Airflow starts the producer task as soon as the extractor task
    finishes. 
    """
 
    MAX_CONNECT_RETRIES = 5
    CONNECT_RETRY_SEC = 5
 
    def __init__(self, config: Optional[KafkaConfig] = None):
        self.logger = configure_logger("CybersecProducer")
        self.config = config or KafkaConfig()
        self.callback = DeliveryCallback(self.logger)
        self._producer: Optional[KafkaProducer] = None
        self._connect_with_retry()
 
    # Connection 
 
    def _connect_with_retry(self):
        """
        Attempt to connect to Kafka, retrying up to MAX_CONNECT_RETRIES
        times with a fixed back-off between attempts.
        """
        for attempt in range(1, self.MAX_CONNECT_RETRIES + 1):
            try:
                self.logger.info(
                    f"Connecting to Kafka (attempt {attempt}/{self.MAX_CONNECT_RETRIES}) "
                    f"- {self.config.bootstrap_servers}"
                )
                self._producer = KafkaProducer(
                    value_serializer=RecordSerialiser.serialise,
                    **self.config.producer_kwargs()
                )
                self.logger.info("Kafka producer is  connected successfully now....")
                return
 
            except NoBrokersAvailable:
                self.logger.warning(
                    f"No Kafka brokers available. "
                    f"Retrying in {self.CONNECT_RETRY_SEC}s.... "
                )
                if attempt < self.MAX_CONNECT_RETRIES:
                    time.sleep(self.CONNECT_RETRY_SEC)
 
        raise ConnectionError(
            f"Could not connect to Kafka after {self.MAX_CONNECT_RETRIES} attempts. "
            f"Is Kafka running at {self.config.bootstrap_servers}?"
        )
 
    # Core Publish Method 
 
    def _publish_batch(
        self,
        topic: str,
        records: List[Dict[str, Any]],
        label: str
    ) -> None:
        """
        Send a list of records to a single Kafka topic.
        """
        if not records:
            self.logger.warning(f"No {label} records to publish - skipping.")
            return
 
        self.callback.reset()
        self.logger.info(f"Publishing {len(records):,} {label} records to topic '{topic}'")
 
        for record in records:
            try:
                (
                    self._producer
                    .send(topic, value=record)
                    .add_callback(self.callback.on_send_success)
                    .add_errback(self.callback.on_send_error)
                )
            except KafkaError as kafka_err:
                self.logger.error(f"KafkaError on record {record.get('cve_id', '?')}: {kafka_err}")
                self.callback.failed += 1
 
        # Block until all in-flight messages are acknowledged
        self._producer.flush()
        self.logger.info(f"{label} batch complete - {self.callback.summary()}")
 
    # Public Topic Methods
 
    def publish_cve_batch(self, records: List[Dict[str, Any]]) -> None:
        """
        Publish a batch of NVD CVE records to the nvd_cve_stream topic.
        Called once per NVD API page by the extractor (every 2,000 records).
        """
        self._publish_batch(
            topic=self.config.topics.nvd_cve,
            records=records,
            label="CVE"
        )
 
    def publish_kev_batch(self, records: List[Dict[str, Any]]) -> None:
        """
        Publish CISA KEV records to the kev_stream topic.
        """
        self._publish_batch(
            topic=self.config.topics.kev,
            records=records,
            label="KEV"
        )
 
    def publish_breach_batch(self, records: List[Dict[str, Any]]) -> None:
        """
        Publish scraped breach records to the breach_stream topic.
        Called once per scraped page by the breach scraper.
        """
        self._publish_batch(
            topic=self.config.topics.breach,
            records=records,
            label="Breach"
        )
 
    # Lifecycle 
 
    def close(self) -> None:
        """Flush any remaining messages and close the Kafka connection cleanly."""
        if self._producer:
            self._producer.flush()
            self._producer.close()
            self.logger.info("Kafka producer closed....")
 
    def __enter__(self):
        return self
 
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False