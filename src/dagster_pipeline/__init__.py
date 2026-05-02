"""
Entry point for Dagster
"""

from dagster import Definitions

from dagster_pipeline.assets  import (
    read_mongo_raw,
    transform_data,
    load_to_postgres,
    run_analysis,
)
from dagster_pipeline.jobs import cybersec_full_pipeline, cybersec_quick_test
from dagster_pipeline.schedules import daily_full_pipeline, weekly_test_run
from dagster_pipeline.resources import MongoResource, PostgresResource, KafkaResource, PipelineConfig

defs = Definitions(
    assets=[
        read_mongo_raw,
        transform_data,
        load_to_postgres,
        run_analysis,
    ],
    jobs=[
        cybersec_full_pipeline,
        cybersec_quick_test,
    ],
    schedules=[
        daily_full_pipeline,
        weekly_test_run,
    ],
    resources={
        "mongo": MongoResource(),
        "postgres": PostgresResource(),
        "kafka_cfg": KafkaResource(),
        "pipeline_cfg": PipelineConfig(),
    }
)