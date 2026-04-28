"""
Single script that runs the entire pipeline end to end.
Useful for testing without Airflow or for doing a manual full run.

"""

import logging
import sys
import time
import os
from datetime import datetime
from typing import List, Tuple, Optional

from dotenv import load_dotenv

load_dotenv()

RUN_EXTRACT = True # pull from NVD, CISA, PRC and send to Kafka
RUN_KAFKA = True # start consumer, drain Kafka topics to MongoDB
RUN_TRANSFORM = True    # clean + normalise from MongoDB
RUN_PG_LOAD= True# insert clean records into PostgreSQL
RUN_ANALYSIS = True# run RQ SQL queries, export CSVs

# NVD extraction is slow without an API key (6.5s sleep between pages)
# set this to True to only pull 1 page (2000 CVEs) for a quick test run
QUICK_TEST_MODE = False


def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  -  %(message)s",
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



# PipelineTimer
class PipelineTimer:

    def __init__(self):
        self.logger = configure_logger("PipelineTimer")
        self._steps: List[Tuple[str, float]] = []
        self._start: Optional[float]= None
        self._step_start: Optional[float]=None

    def start_pipeline(self) -> None:
        self._start = time.time()
        self.logger.info("Pipeline timer started....")

    def start_step(self, step_name: str) -> None:
        self._current_step = step_name
        self._step_start = time.time()
        self.logger.info(f"#### Starting step: {step_name}")

    def end_step(self) -> float:
        if not self._step_start:
            return 0.0
        elapsed = time.time() - self._step_start
        self._steps.append((self._current_step, elapsed))
        self.logger.info(
            f"Step done: {self._current_step} "
            f"({elapsed:.1f}s / {elapsed/60:.1f}min)"
        )
        return elapsed

    def log_summary(self) -> None:
        total = time.time() - (self._start or time.time())
        self.logger.info("=" * 40)
        self.logger.info("  PIPELINE TIMING SUMMARY")
        self.logger.info("=" * 42)
        for step, secs in self._steps:
            bar   = "#" * min(int(secs / 30), 30)  # rough visual bar
            self.logger.info(f"  {step:<25}  {secs:>7.1f}s  {bar}")
        self.logger.info("-" * 42)
        self.logger.info(f"  {'TOTAL':<25}  {total:>7.1f}s")
        self.logger.info("=" * 42)



# PipelineResult
class PipelineResult:

    def __init__(self):
        self.success: bool = True
        self.steps_run: List[str] = []
        self.steps_skip: List[str]  = []
        self.errors: List[str] = []

    def mark_run(self, step: str) -> None:
        self.steps_run.append(step)

    def mark_skipped(self, step: str) -> None:
        self.steps_skip.append(step)

    def mark_failed(self, step: str, reason: str) -> None:
        self.success = False
        self.errors.append(f"{step}: {reason}")

    def __str__(self) -> str:
        lines = [
            f" Ran: {', '.join(self.steps_run)  or 'none'}",
            f" Skipped: {', '.join(self.steps_skip) or 'none'}",
        ]
        if self.errors:
            lines.append(f" Errors : {'; '.join(self.errors)}")
        lines.append(f"Overall: {'SUCCESS' if self.success else 'FAILED'}")
        return "\n".join(lines)



# ExtractionOrchestrator
class ExtractionOrchestrator:

    def __init__(self, quick_test: bool = False):
        self.logger  = configure_logger("ExtractionOrchestrator")
        self.quick_test = quick_test

    def run(self) -> Tuple[int, int, int]:
        """
        Run all three extractors.
        Returns (cve_count, kev_count, breach_count)

        Tries to use Kafka producer, if Kafka isnt running it logs a warning and 
        falls back to JSON file output only
        """
        from extract.nvd_extractor import NvdExtractor
        from extract.kev_extractor import KevExtractor
        from extract.breach_scraper import BreachScraper

        # try to get a Kafka producer - optional
        producer = self._try_get_producer()

        #KEV (fastest - single download, ~1200 records)
        self.logger.info("Extracting CISA KEV....")
        kev_extractor = KevExtractor(kafka_producer=producer, output_dir=".")
        kev_count = kev_extractor.extract_and_stream()

        # Breach scraper (medium speed - depends on pages)
        self.logger.info("Extracting breach records....")
        max_pages = 3 if self.quick_test else 100
        breach_scraper = BreachScraper(
            kafka_producer=producer, output_dir=".", max_pages=max_pages
        )
        breach_count = breach_scraper.extract_and_stream()

        # NVD (100+ API pages)
        self.logger.info("#### Extracting NVD CVE records (this takes a while)....")
        nvd_extractor = NvdExtractor(kafka_producer=producer, output_dir=".")

        #in quick test mode override page size to pull just 100 records
        if self.quick_test:
            self.logger.warning("QUICK TEST MODE: pulling 100 CVEs only")
            nvd_extractor.PAGE_SIZE = 100

        cve_count = nvd_extractor.extract_and_stream()

        if producer:
            producer.close()

        self.logger.info(
            f"Extraction done - CVE={cve_count:,} KEV={kev_count:,} "
            f"Breach={breach_count:,}"
        )
        return cve_count, kev_count, breach_count

    def _try_get_producer(self):
        """
        Try to create a Kafka producer. Returns None if Kafka 
        isnt available so extraction still works.
        """
        try:
            from kafka.cve_producer import CybersecProducer
            from kafka.kafka_config import KafkaConfig
            producer = CybersecProducer(KafkaConfig())
            self.logger.info("#### Kafka producer connected: will stream to topics")
            return producer
        except Exception as e:
            self.logger.warning(
                f"Kafka not available, error: ({e}) - "
                f"extractors will write JSON files only"
            )
            return None



# KafkaConsumerOrchestrator
class KafkaConsumerOrchestrator:

    def __init__(self):
        self.logger = configure_logger("KafkaConsumerOrchestrator")

    def run(self, max_batches: int = 500) -> bool:
        """
        Start the Kafka consumer and drain all three topics into MongoDB
        """
        try:
            from kafka.cve_consumer import CybersecConsumer
            from kafka.kafka_config import KafkaConfig

            self.logger.info(f"Starting Kafka consumer (max_batches={max_batches})....")
            with CybersecConsumer(KafkaConfig()) as consumer:
                consumer.start(max_batches=max_batches)

            self.logger.info(f"Kafka consumer finished")
            return True

        except Exception as e:
            self.logger.error(f"Kafka consumer failed, errot: {e}")
            self.logger.warning("Falling back to loading from JSON files directly")
            return False



# MongoLoadOrchestrator
class MongoLoadOrchestrator:

    def __init__(self):
        self.logger = configure_logger("MongoLoadOrchestrator")

    def load_from_json_files(self) -> bool:
        from load.mongo_loader import MongoLoader
        self.logger.info(f"Loading JSON backup files into MongoDB....")
        loader = MongoLoader()
        return loader.load_from_files(
            cve_path  = "cve_raw.json",
            kev_path  = "kev_raw.json",
            breach_path = "breach_raw.json"
        )

    def verify(self) -> bool:
        from load.mongo_loader import MongoLoader
        return MongoLoader().verify_only()


# PipelineRunner
# wires all the orchestrators together: main class

class PipelineRunner:
    """
    Master pipeline runner. Reads the control flags defined at the top of this file and runs or 
    skips each step accordingly.

    Prints a timing summary and result report at the end.
    """

    def __init__(self):
        self.logger = configure_logger("PipelineRunner")
        self.timer  = PipelineTimer()
        self.result = PipelineResult()

    def run(self) -> bool:
        run_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.logger.info("=" * 42)
        self.logger.info(" CYBERSECURITY RISK ANALYTICS PIPELINE")
        self.logger.info(f" Run started: {run_date}")
        self.logger.info(f" Quick test mode: {QUICK_TEST_MODE}")
        self.logger.info("=" * 42)

        self.timer.start_pipeline()

        # 1: Extract
        if RUN_EXTRACT:
            self.timer.start_step("EXTRACT")
            try:
                extractor = ExtractionOrchestrator(quick_test=QUICK_TEST_MODE)
                cve_n, kev_n, breach_n = extractor.run()
                self.logger.info(
                    f"Extraction counts - CVE={cve_n:,} KEV={kev_n:,} "
                    f"Breach={breach_n:,}"
                )
                self.result.mark_run("EXTRACT")
            except Exception as e:
                self.logger.error(f"Extraction step failed: {e}", exc_info=True)
                self.result.mark_failed("EXTRACT", str(e))
                # cant continue if extraction failed
                self._finish()
                return False
            finally:
                self.timer.end_step()
        else:
            self.logger.info("EXTRACT: skipped (RUN_EXTRACT=False)")
            self.result.mark_skipped("EXTRACT")

        # 2: Kafka consumer + MongoDB load
        if RUN_KAFKA:
            self.timer.start_step("KAFKA -> MONGO")
            try:
                kafka_orch = KafkaConsumerOrchestrator()
                kafka_ok   = kafka_orch.run(max_batches=500)

                if not kafka_ok:
                    # Kafka consumer failed - load from JSON files instead
                    self.logger.warning(
                        "Kafka consumer did not complete - "
                        "loading directly from JSON backup files"
                    )
                    mongo_orch = MongoLoadOrchestrator()
                    mongo_orch.load_from_json_files()

                self.result.mark_run("KAFKA -> MONGO")
            except Exception as e:
                self.logger.error(f"Kafka/Mongo step failed: {e}", exc_info=True)
                self.result.mark_failed("KAFKA -> MONGO", str(e))
            finally:
                self.timer.end_step()
        else:
            self.logger.info("KAFKA: skipped (RUN_KAFKA=False)")
            self.result.mark_skipped("KAFKA -> MONGO")

        #3: Verify MongoDB 
        self.timer.start_step("VERIFY MONGO")
        try:
            mongo_orch = MongoLoadOrchestrator()
            verify_ok = mongo_orch.verify()
            if not verify_ok:
                self.logger.error("MongoDB verification failed, one or more collections are empty. Check extraction logs.")
                self.result.mark_failed("VERIFY MONGO", "empty collections")
                self._finish()
                return False
            self.result.mark_run("VERIFY MONGO")
        except Exception as e:
            self.logger.error(f"MongoDB verify failed, error: {e}", exc_info=True)
            self.result.mark_failed("VERIFY MONGO", str(e))
        finally:
            self.timer.end_step()

        # 4:Transform
        clean_cves= []
        clean_kev = []
        clean_breaches = []

        if RUN_TRANSFORM:
            self.timer.start_step("TRANSFORM")
            try:
                from transform.transformer import DataTransformer
                transformer = DataTransformer()
                clean_cves, clean_kev, clean_breaches = transformer.run()
                self.logger.info(f"Transform output - CVE={len(clean_cves):,} KEV={len(clean_kev):,}"
                                 f"Breach={len(clean_breaches):,}"
                )
                self.result.mark_run("TRANSFORM")
            except Exception as e:
                self.logger.error(f"Transform steo failed: {e}", exc_info=True)
                self.result.mark_failed("TRANSFORM", str(e))
                self._finish()
                return False
            finally:
                self.timer.end_step()
        else:
            self.logger.info("TRANSFORM: skipped (RUN_TRANSFORM=False)")
            self.result.mark_skipped("TRANSFORM")

        # 5: PostgreSQL load
        if RUN_PG_LOAD:
            self.timer.start_step("POSTGRES LOAD")
            try:
                from load.postgres_loader import PostgresLoader
                loader  = PostgresLoader()
                load_ok = loader.load_all(clean_cves, clean_kev, clean_breaches)
                if not load_ok:
   
                    self.result.mark_failed("POSTGRES LOAD", "some tables failed")
   
                else:
                    self.result.mark_run("POSTGRES LOAD")
            except Exception as e:
                self.logger.error(f"PostgreSQL  load failed: {e}", exc_info=True)
                self.result.mark_failed("POSTGRES LOAD", str(e))
            finally:
                self.timer.end_step()
        else:
            self.logger.info("POSTGRES LOAD: skipped (RUN_PG_LOAD=False)")
            self.result.mark_skipped("POSTGRES LOAD")

        # 6: SQL Analysis
        if RUN_ANALYSIS:
            self.timer.start_step("SQL ANALYSIS")
            try:
                from analysis.sql_analysis import SqlAnalysisRunner
                analysis_ok = SqlAnalysisRunner().run_all()
                if not analysis_ok:
                    self.result.mark_failed("SQL ANALYSIS", "some queries failed")
                else:
                    self.result.mark_run("SQL ANALYSIS")
            except Exception as e:
                self.logger.error(f"SQL analysis failed, error: {e}", exc_info=True)
                self.result.mark_failed("SQL ANALYSIS", str(e))
            finally:
                self.timer.end_step()
        else:
            self.logger.info("SQL ANALYSIS: skipped RUN_ANALYSIS=False")
            self.result.mark_skipped("SQL ANALYSIS")

        self._finish()
        return self.result.success

    def _finish(self) -> None:
        self.timer.log_summary()
        self.logger.info("=" * 65)
        self.logger.info("  PIPELINE RESULT")
        self.logger.info("=" * 65)
        self.logger.info(str(self.result))
        self.logger.info("=" * 65)

        if self.result.success:
            self.logger.info(
                "Pipeline finished successfully. CSVs are in analysis/output/"
            )
        else:
            self.logger.error(
                "Pipeline finished with errors. Check pipeline.log for details...."
            )


# main method
# python run_pipeline.py


if __name__ == "__main__":
    runner  = PipelineRunner()
    success = runner.run()
    sys.exit(0 if success else 1)