import os
import pandas as pd
import psycopg2
from psycopg2.extras import execute_values
from pymongo import MongoClient
from dotenv import load_dotenv
from dagster import asset, Definitions, define_asset_job

load_dotenv()

# ============================================================
# ASSET 1 — Already have this (READ from MongoDB)
# ============================================================
@asset
def read_cve_data():
    client = MongoClient(os.getenv("MONGO_URI"))
    db = client[os.getenv("MONGO_DB")]
    data = list(db["cve_raw"].find({}, {"_id": 0}))
    client.close()
    print(f"[INFO] read_cve_data — {len(data)} documents read")
    return data


# ============================================================
# ASSET 2 — Already have this (PROCESS / basic clean)
# ============================================================
@asset
def process_cve_data(read_cve_data):
    # your existing cleaning code here
    return read_cve_data  # or whatever you already return


# ============================================================
# ASSET 3 — ADD THIS (TRANSFORM into PostgreSQL-ready rows)
# ============================================================
@asset
def transform_cve_data(process_cve_data):
    records = []
    for doc in process_cve_data:
        records.append({
            "cve_id":         doc.get("cve_id") or doc.get("id"),
            "description":    doc.get("description", ""),
            "severity":       doc.get("severity", "UNKNOWN"),
            "cvss_score":     float(doc.get("cvss_score", 0.0)),
            "vendor":         doc.get("vendor", ""),
            "product":        doc.get("product", ""),
            "published_date": doc.get("published_date"),
            "last_modified":  doc.get("last_modified"),
        })

    df = pd.DataFrame(records)
    df = df.drop_duplicates(subset=["cve_id"])
    df = df.dropna(subset=["cve_id"])
    print(f"[INFO] transform_cve_data — {len(df)} rows ready")
    return df


# ============================================================
# ASSET 4 — ADD THIS (LOAD into PostgreSQL)
# ============================================================
@asset
def load_cve_to_postgres(transform_cve_data):
    df = transform_cve_data
    conn = psycopg2.connect(
        host=os.getenv("PG_HOST"),
        port=os.getenv("PG_PORT"),
        dbname=os.getenv("PG_DB"),
        user=os.getenv("PG_USER"),
        password=os.getenv("PG_PASSWORD")
    )
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id         TEXT PRIMARY KEY,
            description    TEXT,
            severity       TEXT,
            cvss_score     FLOAT,
            vendor         TEXT,
            product        TEXT,
            published_date TEXT,
            last_modified  TEXT
        )
    """)
    rows = [tuple(row) for row in df.itertuples(index=False)]
    execute_values(cur, """
        INSERT INTO vulnerabilities
            (cve_id, description, severity, cvss_score, vendor, product, published_date, last_modified)
        VALUES %s
        ON CONFLICT (cve_id) DO NOTHING
    """, rows)
    conn.commit()
    print(f"[INFO] load_cve_to_postgres — rows written successfully")
    cur.close()
    conn.close()


# ============================================================
# REGISTER ALL ASSETS & JOB
# ============================================================
cve_etl_job = define_asset_job("cve_etl_job", selection="*")

defs = Definitions(
    assets=[
        read_cve_data,
        process_cve_data,
        transform_cve_data,    # new
        load_cve_to_postgres,  # new
    ],
    jobs=[cve_etl_job],
)