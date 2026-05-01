"""
Replaces the schedule_interval="@daily" setting from the Airflow DAG.

"""

from dagster import schedule, RunRequest, ScheduleEvaluationContext

from dagster_pipeline.jobs import (
    cybersec_full_pipeline,
    cybersec_quick_test,
)


# 
# Daily full pipeline schedule
# 2am every day - runs the full NVD + KEV + breach extraction
# 

@schedule(
    cron_schedule="0 2 * * *",
    job=cybersec_full_pipeline,
    description="Run full cybersecurity ETL pipeline daily at 2am",
    execution_timezone="Europe/Dublin", 
)
def daily_full_pipeline(context: ScheduleEvaluationContext):
    """
    Triggered every day at 2am Dublin time.
    Returns a RunRequest which tells Dagster to start a job run.
    Could add run config overrides here if needed e.g. different
    page limits on certain days.
    """
    scheduled_date = context.scheduled_execution_time.strftime("%Y-%m-%d")

    return RunRequest(
        run_key=f"daily_full_{scheduled_date}",
        # run_key prevents duplicate runs if the schedule triggers twice
        # (can happen if scheduler restarts during the trigger window)
        tags={
            "scheduled_date": scheduled_date,
            "trigger":  "schedule",
        }
    )


# 
# Weekly quick test schedule
# every Monday 8am - quick sanity check without full extraction
# 

@schedule(
    cron_schedule="0 8 * * 1",
    job=cybersec_quick_test,
    description="Weekly quick test run every Monday at 8am",
    execution_timezone="Europe/Dublin",
)
def weekly_test_run(context: ScheduleEvaluationContext):
    scheduled_date = context.scheduled_execution_time.strftime("%Y-%m-%d")

    return RunRequest(
        run_key=f"weekly_test_{scheduled_date}",
        tags={
            "scheduled_date": scheduled_date,
            "trigger":        "weekly_test",
        }
    )