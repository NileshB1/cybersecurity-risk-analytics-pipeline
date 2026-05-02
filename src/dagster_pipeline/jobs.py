"""

Defines the two pipeline jobs using the asset graph.
"""

from dagster import (
    define_asset_job,
    AssetSelection,
)

# full pipeline: runs all four assets in order
cybersec_full_pipeline = define_asset_job(
    name="cybersec_full_pipeline",
    description="Full daily pipeline: 1. MongoDB verify 2.Transform 3. PostgreSQL 4. Analysis",
    selection=AssetSelection.groups("cybersecurity_pipeline"),
    tags={
        "project": "cybersec_analytics",
        "team":    "group_e",
    }
)

# quick test: same assets, pipeline_cfg controls sample size
cybersec_quick_test = define_asset_job(
    name="cybersec_quick_test",
    description="Quick test run to verify pipeline works end to end",
    selection=AssetSelection.groups("cybersecurity_pipeline"),
    tags={
        "project": "cybersec_analytics",
        "team":    "group_e",
        "env":     "test",
    }
)