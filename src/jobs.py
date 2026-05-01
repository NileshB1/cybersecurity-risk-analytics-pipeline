"""


A Dagster "job" is equivalent to an Airflow DAG.
It defines the execution graph - which ops run in what order,
and which ones can run in parallel.


"""

from dagster import (
    graph,
    job,
    GraphDefinition,
    RunConfig,
    multiprocess_executor,
    in_process_executor,
)

from dagster_pipeline.ops import (
    verify_connections,
    extract_kev,
    extract_nvd_cve,
    extract_breaches,
    run_kafka_consumer,
    verify_mongo_raw,
    run_transform,
    load_postgres,
    run_sql_analysis,
)

from dagster_pipeline.resources import (
    MongoResource,
    PostgresResource,
    KafkaResource,
    PipelineConfig,
)


# 
# @graph  cybersec_pipeline_graph
# defines the execution graph, wiring between ops
#
# NVD and KEV extractors run in PARALLEL because they have no
# dependency on each other - both just need connections_verified.
# Breaches runs after both finish so disk IO doesnt overlap
#
# In Dagster parallel ops run concurrently when the executor  supports it (multiprocess_executor does).
# 

@graph(
    description=(
        "Full cybersecurity ETL pipeline: "
        "NVD CVE + CISA KEV + Breach scraping "
        "-> Kafka -> MongoDB -> Transform -> PostgreSQL -> RQ Analysis"
    )
)
def cybersec_pipeline_graph():
    # Step 1: check all services are up before doing any work
    kafka_running = verify_connections()

    # Steps 2a + 2b: NVD and KEV run in parallel
    # Dagster sees that both only depend on kafka_running
    # and runs them concurrently automatically
    kev_count = extract_kev(connections_verified=kafka_running)
    nvd_count = extract_nvd_cve(connections_verified=kafka_running)

    # Step 3: breaches wait for both extractors above to finish
    breach_count = extract_breaches(
        kev_count=kev_count,
        nvd_count=nvd_count,
    )

    # Step 4: drain Kafka topics into MongoDB
    # passes breach_count just to create the dependency
    # also passes kafka_running so it knows whether to use Kafka or JSON fallback
    ingest_mode = run_kafka_consumer(
        breach_count=breach_count,
        kafka_running=kafka_running,
    )

    # Step 5: verify MongoDB is populated before transform
    mongo_counts = verify_mongo_raw(ingest_mode=ingest_mode)

    # Step 6: clean and normalise
    clean_paths = run_transform(mongo_counts=mongo_counts)

    # Step 7: load into PostgreSQL
    pg_loaded = load_postgres(clean_paths=clean_paths)

    # Step 8: run RQ analysis queries, export CSVs
    run_sql_analysis(pg_loaded=pg_loaded)


# 
# Full pipeline job
# uses multiprocess executor so NVD + KEV ops actually run in parallel
# 

cybersec_full_pipeline = cybersec_pipeline_graph.to_job(
    name="cybersec_full_pipeline",
    description="Full daily pipeline run - all datasets, all steps",
    resource_defs={
        "mongo":        MongoResource(),
        "postgres":     PostgresResource(),
        "kafka_cfg":    KafkaResource(),
        "pipeline_cfg": PipelineConfig(),
    },
    executor_def=multiprocess_executor.configured({"max_concurrent": 2}),
    # multiprocess allows NVD + KEV to truly run in parallel processes
    # max_concurrent=2 because we only have 2 parallel extraction ops
    # increase if you add more parallel extractors later
    tags={
        "project": "cybersec_analytics",
        "team":    "group_e",
        "env":     "production",
    }
)


# 
# Quick test job
# uses in_process executor (simpler, no subprocess overhead)
# overrides pipeline_cfg to enable quick_test mode
# 

cybersec_quick_test = cybersec_pipeline_graph.to_job(
    name="cybersec_quick_test",
    description=(
        "Quick test run - pulls 100 CVEs and 3 breach pages "
        "to verify pipeline works end-to-end in ~10 minutes"
    ),
    resource_defs={
        "mongo":     MongoResource(),
        "postgres":  PostgresResource(),
        "kafka_cfg": KafkaResource(),
        "pipeline_cfg": PipelineConfig(
            quick_test=True,
            scraper_max_pages=3,
            kafka_max_batches=50,
        ),
    },
    executor_def=in_process_executor,
    tags={
        "project": "cybersec_analytics",
        "team":    "group_e",
        "env":     "test",
    }
)