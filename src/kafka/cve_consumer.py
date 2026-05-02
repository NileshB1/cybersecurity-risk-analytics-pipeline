"""

Subscribes to all three Kafka topics (nvd_cve_stream, kev_stream,
breach_stream), deserialises incoming messages, and writes them to the
corresponding MongoDB raw collections (cve_raw, kev_raw, breach_raw).
"""

import os
import logging
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any, Callable

import pymongo
from kafka import KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable

from kafka.kafka_config import KafkaConfig, configure_logger
from kafka.cve_producer import RecordSerialiser
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")


# 
# MongoDB Writer
# 

class MongoWriter:
    """
    Handles all MongoDB write operations for the consumer.
    """

    # Batch flush threshold for writes. Default is 5000 to reduce flush
    # frequency during large imports. Can be overridden with the
    # environment variable `MONGO_BATCH_THRESHOLD` (int).
    BATCH_THRESHOLD = int(os.getenv("MONGO_BATCH_THRESHOLD", "5000"))

    def __init__(self):
        self.logger = configure_logger("MongoWriter")
        self._client = pymongo.MongoClient(
            os.getenv("MONGO_URI", "mongodb://localhost:27017"),
            serverSelectionTimeoutMS=5000
        )
        self._db = self._client[os.getenv("MONGO_DB", "cybersecurity_db")]
        self._batches: Dict[str, list] = {
            "cve_raw": [],
            "kev_raw": [],
            "breach_raw":[],
        }
        self._counters: Dict[str, int] = {k: 0 for k in self._batches}
        self.logger.info(f"MongoWriter connected to database '{os.getenv('MONGO_DB')}'")

    def _flush_collection(self, collection_name: str, key_field: str):
        """Write all buffered records for one collection to MongoDB"""
        records = self._batches[collection_name]
        if not records:
            return

        collection = self._db[collection_name]
        operations = [
            pymongo.UpdateOne(
                {key_field: r.get(key_field)},
                {"$set": r},
                upsert=True
            )
            for r in records
            if r.get(key_field)     # skip records missing the unique key
        ]

        if operations:
            result = collection.bulk_write(operations, ordered=False)
            inserted = result.upserted_count
            modified = result.modified_count
            self._counters[collection_name] += len(operations)
            self.logger.info(
                f"[{collection_name}] flushed {len(operations)} records "
                f"(upserted={inserted}, modified={modified}, "
                f"total so far={self._counters[collection_name]})"
            )

        self._batches[collection_name].clear()

    def write_cve(self, record: Dict[str, Any]):
        """Buffer a CVE record. Flushes to MongoDB when buffer is full."""
        self._batches["cve_raw"].append(record)
        if len(self._batches["cve_raw"]) >= self.BATCH_THRESHOLD:
            self._flush_collection("cve_raw", "cve_id")

    def write_kev(self, record: Dict[str, Any]):
        """Buffer a KEV record. Flushes to MongoDB when buffer is full"""
        self._batches["kev_raw"].append(record)
        if len(self._batches["kev_raw"]) >= self.BATCH_THRESHOLD:
            self._flush_collection("kev_raw", "cve_id")

    def write_breach(self, record: Dict[str, Any]) -> None:
        self._batches["breach_raw"].append(record)
        if len(self._batches["breach_raw"]) >= self.BATCH_THRESHOLD:
            self._flush_collection("breach_raw", "organisation")

    def flush_all(self) -> None:
        """Force-flush all remaining buffered records across all collections."""
        self.logger.info(f"Flushing all remaining buffered records to MongoDB....")
        self._flush_collection("cve_raw","cve_id")
        self._flush_collection("kev_raw", "cve_id")
        self._flush_collection("breach_raw", "organisation")

    def total_written(self) -> Dict[str, int]:
        return dict(self._counters)

    def close(self) -> None:
        self.flush_all()
        self._client.close()
        self.logger.info("MongoWriter closed.")


# 
# Message Router
# 

class MessageRouter:
    """
    Dispatches a Kafka message to the correct MongoWriter method based on which 
    topic it arrived from.
    """

    def __init__(self, writer: MongoWriter, topics):
        self.logger = configure_logger("MessageRouter")
        self._routes: Dict[str, Callable] = {
            topics.nvd_cve: writer.write_cve,
            topics.kev: writer.write_kev,
            topics.breach: writer.write_breach,
        }

    def route(self, topic: str, record: Dict[str, Any]):
        """
            Find and call the appropriate writer method for this topic
        """
        handler = self._routes.get(topic)
        if handler:
            handler(record)
        else:
            self.logger.warning(f"No route configured for topic '{topic}' — message dropped.")


# 
# Consumer
# 

class CybersecConsumer:
    """
    Polls all three Kafka topics and writes incoming records to MongoDB.
    """

    POLL_TIMEOUT_MS = 1000
    MAX_CONNECT_RETRIES = 5
    CONNECT_RETRY_SEC = 5

    def __init__(self, config: Optional[KafkaConfig] = None):
        self.logger = configure_logger("CybersecConsumer")
        self.config= config or KafkaConfig()
        self.writer = MongoWriter()
        self.router = MessageRouter(self.writer, self.config.topics)
        self._consumer: Optional[KafkaConsumer] = None
        self._running = False
        self._connect_with_retry()

    # Connection 

    def _connect_with_retry(self) -> None:
        for attempt in range(1, self.MAX_CONNECT_RETRIES + 1):
            try:
                self.logger.info(
                    f"Connecting Kafka consumer (attempt {attempt}/{self.MAX_CONNECT_RETRIES})"
                )
                self._consumer = KafkaConsumer(
                    *self.config.topics.all_topics(),
                    value_deserializer=RecordSerialiser.deserialise,
                    **self.config.consumer_kwargs()
                )
                self.logger.info(
                    f"Consumer subscribed to topics: {self.config.topics.all_topics()}"
                )
                return

            except NoBrokersAvailable:
                self.logger.warning(
                    f"No Kafka brokers available. "
                    f"Retrying in {self.CONNECT_RETRY_SEC}s...."
                )
                if attempt < self.MAX_CONNECT_RETRIES:
                    time.sleep(self.CONNECT_RETRY_SEC)

        raise ConnectionError(
            f"Kafka consumer could not connect after {self.MAX_CONNECT_RETRIES} attempts."
        )

    #Poll Loop

    def start(self, max_batches: Optional[int] = None) -> None:
        """
        Begin polling Kafka topics and writing records to MongoDB

        """
        self._running = True
        batches_polled = 0
        total_processed = 0

        self.logger.info(
            f"Consumer started. max_batches={max_batches or 'unlimited'}"
        )

        try:
            while self._running:
                # poll() returns a dict: {TopicPartition -> [ConsumerRecord, ...]}
                message_batch = self._consumer.poll(timeout_ms=self.POLL_TIMEOUT_MS)

                if not message_batch:
                    self.logger.debug("No new messages — poll returned empty.")
                else:
                    batch_count = 0
                    for topic_partition, messages in message_batch.items():
                        for msg in messages:
                            try:
                                self.router.route(topic_partition.topic, msg.value)
                                batch_count += 1
                            except Exception as exc:
                                self.logger.error(
                                    f"Error processing message from "
                                    f"{topic_partition.topic}: {exc}",
                                    exc_info=True
                                )

                    # Commit offsets only after the whole batch is routed
                    self._consumer.commit()
                    total_processed += batch_count
                    self.logger.info(
                        f"Poll #{batches_polled + 1} — processed {batch_count} messages "
                        f"(total: {total_processed:,})"
                    )

                batches_polled += 1
                if max_batches and batches_polled >= max_batches:
                    self.logger.info(f"Reached max_batches={max_batches}. Stopping consumer.")
                    break

        except KeyboardInterrupt:
            self.logger.info("Consumer interrupted by keyboard — shutting down.")
        finally:
            self.close()

        self.logger.info(f"Consumer finished. Total records processed: {total_processed:,}")
        self.logger.info(f"MongoDB write summary: {self.writer.total_written()}")

    # Lifecycle 

    def stop(self) -> None:
        """
        Signal the poll loop to exit cleanly on the next iteration"""
        self._running = False

    def close(self) -> None:
        """
            flush MongoDB buffers, close consumer and MongoDB connections
        """
        self.writer.close()
        if self._consumer:
            self._consumer.close()
            self.logger.info("Kafka consumer closed.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# 
# Entry Point
# 

if __name__ == "__main__":
    with CybersecConsumer() as consumer:
        consumer.start() 