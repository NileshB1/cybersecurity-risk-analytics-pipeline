"""


This is the file Dagster reads when you run:
    dagster dev
    dagster job execute ...
    dagster schedule ...

"""

from dagster import Definitions

from dagster_pipeline.jobs import (
    cybersec_full_pipeline,
    cybersec_quick_test,
)
from dagster_pipeline.schedules import (
    daily_full_pipeline,
    weekly_test_run,
)
from dagster_pipeline.resources import (
    MongoResource,
    PostgresResource,
    KafkaResource,
    PipelineConfig,
)

# register everything with Dagster
# Dagster UI reads this on startup to display jobs, schedules etc
defs = Definitions(
    jobs=[
        cybersec_full_pipeline,
        cybersec_quick_test,
    ],
    schedules=[
        daily_full_pipeline,
        weekly_test_run,
    ],
    # resources listed here are available to all jobs
    # individual jobs can override these in their resource_defs
    resources={
        "mongo":  MongoResource(),
        "postgres":  PostgresResource(),
        "kafka_cfg":  KafkaResource(),
        "pipeline_cfg": PipelineConfig(),
    }
)
