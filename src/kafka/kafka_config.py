import os
from dotenv import load_dotenv
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

def config_logger(name) -> logging.Logger:
    """
    Return Loggers that writes to pipeline.log
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  —  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    fh = logging.FileHandler("pipeline.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


def configure_logger(name) -> logging.Logger:
    """Backward-compatible alias used by the producer and consumer modules."""
    return config_logger(name)


@dataclass(frozen=True)
class KafkaTopics:
    """
    Immutable registry of all Kafka configuration details. 
    Using a dataclass (frozen) prevents accidental reassignment at runtime.
    """
    nvd_cve= "nvd_cve_stream"
    kev = "kev_stream"
    breach = "breach_stream"

    def all_topics(self):
        return [self.nvd_cve, self.kev, self.breach]
    

@dataclass
class KafkaProducerConfig:
    """
    All settings passed to the Kafka producer client

    acks: "all"
    retiries: 
        How many times to retry a failed send before giving up.
    batch_size_bytes/linger_ms:
        Control micro-batching.
    compression_type: "gzip"
        CVE JSON records are text-heavy and compress well.
    """
    acks = "all"
    retries = 5
    retry_backoff_ms = 300
    batch_size_bytes= 32768          
    linger_ms = 20
    compression_type = "gzip"
    request_timeout_ms = 30000

@dataclass
class KafkaConsumerConfig:
    """
    All settings passed to the Kafka consumer client.
    group_id:
        All consumers sharing a group_id form a consumer group.
    auto_offset_reset="earliest"
        When a consumer group starts for the first time, start reading
        from beginning of the topic.
    enable_auto_commit=False
        manually commit offsets after successfully writing a batch
        to MongoDB
    max_poll_records
        Cap on how many records are returned per poll() call
    """
    group_id= "cybersec_pipeline_group"
    auto_offset_reset= "earliest"
    enable_auto_commit = False
    max_poll_records= 100
    session_timeout_ms= 30000
    heartbeat_interval_ms = 10000


class KafkaConfig:
    """
    Single entry point for all Kafka configuration
    """
    DEFAULT_BOOTSTRAP = "localhost:9092"

    def __init__(self):
        self.logger = config_logger("KafkaConfig")

        raw_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", self.DEFAULT_BOOTSTRAP)
        self.bootstrap_servers: List[str] = [s.strip() for s in raw_servers.split(",")]
 
        self.topics = KafkaTopics()
        self.producer= KafkaProducerConfig()
        self.consumer = KafkaConsumerConfig()
 
        self._log_summary()

    def _log_summary(self):
        self.logger.info(f"Kafka bootstrap servers : {self.bootstrap_servers}")
        self.logger.info(f"Topics registered : {self.topics.all_topics()}")

    def producer_kwargs(self) -> dict:
        """
        Return a dict of keyword arguments ready to be unpacked into
        the KafkaProducer constructor.
        """
        return {
            "bootstrap_servers": self.bootstrap_servers,
            "acks": self.producer.acks,
            "retries":self.producer.retries,
            "retry_backoff_ms":self.producer.retry_backoff_ms,
            "batch_size": self.producer.batch_size_bytes,
            "linger_ms": self.producer.linger_ms,
            "compression_type": self.producer.compression_type,
            "request_timeout_ms": self.producer.request_timeout_ms,
        }
 
    def consumer_kwargs(self) -> dict:
        """
        Return a dict of keyword arguments ready to be unpacked into
        the KafkaConsumer constructor.
        """
        return {
            "bootstrap_servers": self.bootstrap_servers,
            "group_id": self.consumer.group_id,
            "auto_offset_reset": self.consumer.auto_offset_reset,
            "enable_auto_commit": self.consumer.enable_auto_commit,
            "max_poll_records": self.consumer.max_poll_records,
            "session_timeout_ms": self.consumer.session_timeout_ms,
            "heartbeat_interval_ms": self.consumer.heartbeat_interval_ms,
        }