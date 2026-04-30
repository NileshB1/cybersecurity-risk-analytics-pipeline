

import os
import sys
import logging
from typing import Any, Dict, List, Optional

import pandas as pd
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
from dotenv import load_dotenv

load_dotenv()

MERGE_OUTPUT_DIR = "integration/output"


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


# Neo4jConnection


class Neo4jConnection:

    def __init__(self):
        self.logger   = configure_logger("Neo4jConnection")
        self._uri     = os.getenv("NEO4J_URI","bolt://localhost:7687")
        self._user    = os.getenv("NEO4J_USER","neo4j")
        self._password = os.getenv("NEO4J_PASSWORD","")
        self._driver  = None

    def connect(self) -> "Neo4jConnection":
        self.logger.info(f"Connecting to Neo4j at {self._uri}")
        try:
            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._user,self._password)
            )
           
            self._driver.verify_connectivity()
            self.logger.info("Neo4j connected OK")
        except ServiceUnavailable:
            raise ConnectionError(
                f"Neo4j not reachable at {self._uri}. "
                f"Is Neo4j Desktop running?"
            )
        except AuthError:
            raise ConnectionError(
                f"Neo4j auth failed. "
                f"Check NEO4J_USER and NEO4J_PASSWORD in .env"
            )
        return self

    def get_driver(self):
        if not self._driver:
            raise RuntimeError("Not connected - call connect() first")
        return self._driver

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self.logger.debug("Neo4j connection closed")

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False



# GraphDataLoader


class GraphDataLoader:

    def __init__(self):
        self.logger = configure_logger("GraphDataLoader")

    def load_merged_cve_kev(self) -> pd.DataFrame:
        path = os.path.join(MERGE_OUTPUT_DIR, "merged_cve_kev.csv")
        if not os.path.exists(path):
            self.logger.error(
                f"File not found: {path}."
                f"Run CveKevMerger first (cve_kev_merge.py)"
            )
            return pd.DataFrame()
        df = pd.read_csv(path, low_memory=False)
        self.logger.info(f"Loaded merged_cve_kev: {len(df):,} rows")
        return df

    def load_breaches_csv(self) -> pd.DataFrame:
    
        import psycopg2
        try:
            config = {
                "host":     os.getenv("PG_HOST","localhost"),
                "port":     os.getenv("PG_PORT","5432"),
                "dbname":   os.getenv("PG_DB","cybersec_db"),
                "user":     os.getenv("PG_USER","postgres"),
                "password": os.getenv("PG_PASSWORD", ""),
            }
            conn = psycopg2.connect(**config, connect_timeout=10)
            df   = pd.read_sql(
                "SELECT id, organisation, industry, breach_date, "
                "       records_exposed, state FROM breaches;",
                conn
            )
            conn.close()
            self.logger.info(f"Loaded breaches from PostgreSQL: {len(df):,} rows")
            return df
        except Exception as e:
            self.logger.error(f"Could not load breaches: {e}")
            return pd.DataFrame()


# ConstraintManager


class ConstraintManager:

    CONSTRAINTS = [
        ("Vulnerability","cve_id"),
        ("Software","software_id"),   
        ("Organization","org_name"),
        ("Industry","name"),
    ]

    def __init__(self, driver):
        self.logger = configure_logger("ConstraintManager")
        self._driver = driver

    def apply_all(self) -> None:
        self.logger.info("Applying Neo4j uniqueness constraints...")
        with self._driver.session() as session:
            for label, prop in self.CONSTRAINTS:
                
                cypher = (
                    f"CREATE CONSTRAINT IF NOT EXISTS "
                    f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
                )
                try:
                    session.run(cypher)
                    self.logger.debug(f"  Constraint OK: ({label}).{prop}")
                except Exception as e:
                    self.logger.warning(
                        f"  Could not create constraint ({label}).{prop}: {e}"
                    )
        self.logger.info("Constraints applied")



# NodeLoader

class NodeLoader:

    
    BATCH_SIZE = 500

    def __init__(self, driver):
        self.logger = configure_logger("NodeLoader")
        self._driver = driver

    def _run_batch(self, session, cypher: str, batch: List[Dict]) -> int:
        """run one batched MERGE query, and then return count of rows processed"""
        try:
            session.run(cypher, {"batch": batch})
            return len(batch)
        except Exception as e:
            self.logger.error(f"Batch failed: {e}")
            return 0

    def load_vulnerability_nodes(self, merged_df: pd.DataFrame) -> int:
        """
        Create one Vulnerability node per unique CVE ID.
        """
        if merged_df.empty:
            return 0


        cve_subset = merged_df.drop_duplicates(subset=["cve_id"])

        rows = []
        for _, row in cve_subset.iterrows():
            rows.append({
                "cve_id":str(row.get("cve_id", "")),
                "severity":float(row["severity"]) if pd.notna(row.get("severity")) else None,
                "publish_date":str(row["publish_date"]) if pd.notna(row.get("publish_date")) else None,
                "vendor":str(row.get("vendor", "Unknown")),
                "is_exploited":bool(row.get("is_exploited", False)),
            })

        cypher = """
            UNWIND $batch AS row
            MERGE (v:Vulnerability {cve_id: row.cve_id})
            SET v.severity = row.severity,
                v.publish_date = row.publish_date,
                v.vendor = row.vendor,
                v.is_exploited = row.is_exploited
        """

        total = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), self.BATCH_SIZE):
                total += self._run_batch(session, cypher, rows[i:i+self.BATCH_SIZE])

        self.logger.info(f"Vulnerability nodes loaded: {total:,}")
        return total

    def load_software_nodes(self, merged_df: pd.DataFrame) -> int:
      
        exploited = merged_df[merged_df.get("is_exploited", False) == True].copy()
        if exploited.empty:
            self.logger.warning("No exploited records found in merged data - no Software nodes to create")
            return 0

        sw_df = exploited[["kev_vendor", "product"]].dropna(
            subset=["kev_vendor"]
        ).drop_duplicates()

        rows = []
        for _, row in sw_df.iterrows():
            vendor  = str(row.get("kev_vendor", "Unknown"))
            product = str(row.get("product", "Unknown"))
            rows.append({
                "software_id": f"{vendor}::{product}",
                "vendor":      vendor,
                "product":     product,
            })

        cypher = """
            UNWIND $batch AS row
            MERGE (s:Software {software_id: row.software_id})
            SET s.vendor  = row.vendor,
                s.product = row.product
        """

        total = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), self.BATCH_SIZE):
                total += self._run_batch(session, cypher, rows[i:i+self.BATCH_SIZE])

        self.logger.info(f"Software nodes loaded: {total:,}")
        return total

    def load_industry_nodes(self, breach_df: pd.DataFrame) -> int:
       
        if breach_df.empty or "industry" not in breach_df.columns:
            return 0

        industries = breach_df["industry"].dropna().unique()
        rows = [{"name": str(ind)} for ind in industries if str(ind) != "Unknown"]

        cypher = """
            UNWIND $batch AS row
            MERGE (i:Industry {name: row.name})
        """

        total = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), self.BATCH_SIZE):
                total += self._run_batch(session, cypher, rows[i:i+self.BATCH_SIZE])

        self.logger.info(f"Industry nodes loaded: {total:,}")
        return total

    def load_organization_nodes(self, breach_df: pd.DataFrame) -> int:
        """Create one Organization node per unique organisation name"""
        if breach_df.empty:
            return 0

        org_df = breach_df[["organisation", "industry", "state"]].drop_duplicates(
            subset=["organisation"]
        )

        rows = []
        for _, row in org_df.iterrows():
            rows.append({
                "org_name": str(row.get("organisation", "")),
                "industry": str(row.get("industry",     "Unknown")),
                "state":    str(row.get("state",        "")),
            })

        cypher = """
            UNWIND $batch AS row
            MERGE (o:Organization {org_name: row.org_name})
            SET o.industry = row.industry,
                o.state    = row.state
        """

        total = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), self.BATCH_SIZE):
                total += self._run_batch(session, cypher, rows[i:i+self.BATCH_SIZE])

        self.logger.info(f"Organization nodes loaded: {total:,}")
        return total



# RelationshipLoader

class RelationshipLoader:

    BATCH_SIZE = 500

    def __init__(self, driver):
        self.logger  = configure_logger("RelationshipLoader")
        self._driver = driver

    def _run_batch(self, session, cypher: str, batch: List[Dict]) -> int:
        try:
            session.run(cypher, {"batch": batch})
            return len(batch)
        except Exception as e:
            self.logger.error(f"Relationship batch failed: {e}")
            return 0

    def create_exploits_relationships(self, merged_df: pd.DataFrame) -> int:
        
        exploited = merged_df[merged_df.get("is_exploited", False) == True].copy()
        if exploited.empty:
            return 0

        rows = []
        for _, row in exploited.iterrows():
            vendor  = str(row.get("kev_vendor", "Unknown"))
            product = str(row.get("product",    "Unknown"))
            tte     = row.get("time_to_exploit_days")
            rows.append({
                "cve_id":       str(row["cve_id"]),
                "software_id":  f"{vendor}::{product}",
                "days_to_exploit": int(tte) if pd.notna(tte) else None,
                "exploit_date": str(row["exploitation_date"]) if pd.notna(row.get("exploitation_date")) else None,
            })

        cypher = """
            UNWIND $batch AS row
            MATCH (v:Vulnerability {cve_id:      row.cve_id})
            MATCH (s:Software {software_id: row.software_id})
            MERGE (v)-[r:EXPLOITS]->(s)
            SET r.days_to_exploit = row.days_to_exploit,
                r.exploitation_date = row.exploit_date
        """

        total = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), self.BATCH_SIZE):
                total += self._run_batch(session, cypher, rows[i:i+self.BATCH_SIZE])

        self.logger.info(f"EXPLOITS relationships created: {total:,}")
        return total

    def create_breached_in_relationships(self, breach_df: pd.DataFrame) -> int:
        """
        (:Organization)-[:BREACHED_IN]->(:Industry)
        Links each breached organisation to its sector.
        """
        if breach_df.empty:
            return 0

        rows = []
        for _, row in breach_df.iterrows():
            industry = str(row.get("industry", "Unknown"))
            if industry == "Unknown":
                continue
            rows.append({
                "org_name":str(row["organisation"]),
                "industry_name":industry,
                "breach_date":str(row["breach_date"]) if pd.notna(row.get("breach_date")) else None,
                "records_exposed": int(row["records_exposed"]) if pd.notna(row.get("records_exposed")) else None,
            })

        cypher = """
            UNWIND $batch AS row
            MATCH (o:Organization {org_name:  row.org_name})
            MATCH (i:Industry {name:      row.industry_name})
            MERGE (o)-[r:BREACHED_IN]->(i)
            SET r.breach_date = row.breach_date,
                r.records_exposed = row.records_exposed
        """

        total = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), self.BATCH_SIZE):
                total += self._run_batch(session, cypher, rows[i:i+self.BATCH_SIZE])

        self.logger.info(f"BREACHED_IN relationships created: {total:,}")
        return total

    def create_affects_relationships(self, merged_df: pd.DataFrame, breach_df: pd.DataFrame) -> int:
        """
        (:Software)-[:AFFECTS]->(:Organization)
        For each exploited CVE, find the vendor and then link to any breached orgs in the same industry sector.
        """
        if merged_df.empty or breach_df.empty:
            return 0

        exploited = merged_df[merged_df.get("is_exploited", False) == True].copy()
        if exploited.empty:
            return 0

        rows = []
        for _, kev_row in exploited.drop_duplicates(subset=["kev_vendor"]).iterrows():
            vendor= str(kev_row.get("kev_vendor", "Unknown"))
            product = str(kev_row.get("product", "Unknown"))
            sw_id = f"{vendor}::{product}"

        
            industry = str(kev_row.get("vendor","Unknown"))
            matching_orgs = breach_df[
                breach_df["industry"].str.lower() == industry.lower()
            ]["organisation"].dropna().unique()

            for org in matching_orgs[:10]:    
                rows.append({
                    "software_id": sw_id,
                    "org_name": str(org),
                })

        if not rows:
            self.logger.info("No AFFECTS relationships to create - no matching software and breached orgs found")
            return 0

        cypher = """
            UNWIND $batch AS row
            MATCH (s:Software {software_id: row.software_id})
            MATCH (o:Organization {org_name: row.org_name})
            MERGE (s)-[:AFFECTS]->(o)
        """

        total = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), self.BATCH_SIZE):
                total += self._run_batch(session, cypher, rows[i:i+self.BATCH_SIZE])

        self.logger.info(f"AFFECTS relationships created:{total:,}")
        return total



# GraphInsightQueries

class GraphInsightQueries:

    OUTPUT_DIR = "graph/output"

    def __init__(self, driver):
        self.logger  = configure_logger("GraphInsightQueries")
        self._driver = driver
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def _run_query(self, cypher: str, label: str) -> List[Dict]:
        """run a Cypher query and return results as a list of dicts"""
        self.logger.info(f"Running Cypher query: {label}")
        try:
            with self._driver.session() as session:
                result = session.run(cypher)
                rows   = [dict(record) for record in result]
            self.logger.info(f"  -> {len(rows)} rows returned")
            return rows
        except Exception as e:
            self.logger.error(f"Cypher query failed [{label}]: {e}")
            return []

    def most_connected_vulnerabilities(self, top_n: int = 20) -> pd.DataFrame:
       
        cypher = f"""
            MATCH (v:Vulnerability)-[r:EXPLOITS]->()
            RETURN v.cve_id AS cve_id,
                   v.severity AS severity,
                   v.vendor AS vendor,
                   COUNT(r) AS exploit_degree
            ORDER BY exploit_degree DESC
            LIMIT {top_n}
        """
        rows = self._run_query(cypher, "Most connected vulnerabilities")
        df   = pd.DataFrame(rows)

        if not df.empty:
            path = os.path.join(self.OUTPUT_DIR, "top_central_vulnerabilities.csv")
            df.to_csv(path, index=False)
            self.logger.info(f"Saved -> {path}")

        return df

    def most_breached_industries(self) -> pd.DataFrame:
       
        cypher = """
            MATCH (o:Organization)-[r:BREACHED_IN]->(i:Industry)
            RETURN i.name AS industry, COUNT(DISTINCT o)  AS org_count, COUNT(r)  AS breach_events, SUM(r.records_exposed)  AS total_records_exposed ORDER BY breach_events DESC
        """
        rows = self._run_query(cypher, "Most breached industries")
        df = pd.DataFrame(rows)

        if not df.empty:
            path = os.path.join(self.OUTPUT_DIR, "most_breached_industries.csv")
            df.to_csv(path, index=False)
            self.logger.info(f"Saved -> {path}")

        return df

    def shortest_path_cve_to_org(
        self,
        cve_id: str,
        org_name: str
    ) -> List[Dict]:
      
        cypher = """
            MATCH path = shortestPath(
                (v:Vulnerability {cve_id: $cve_id})-[*..6]-(o:Organization {org_name: $org_name})
            )
            RETURN [node IN nodes(path) | labels(node)[0] + ': ' + coalesce(
                node.cve_id, node.software_id, node.org_name, node.name, '?'
            )] AS path_nodes,
            length(path) AS path_length
        """
        self.logger.info(f"Shortest path: {cve_id} -> {org_name}")
        return self._run_query(
            cypher,
            f"Shortest path {cve_id} to {org_name}"
        )

    def high_risk_vendors_graph(self, top_n: int = 15) -> pd.DataFrame:
        """
        Vendors with the most exploited CVEs in the graph.
        For each vendor, also return the average severity of their exploited CVEs and the number of distinct products affected.
        """
        cypher = f"""
            MATCH (v:Vulnerability {{is_exploited: true}})-[:EXPLOITS]->(s:Software)
            RETURN s.vendor  AS vendor,  COUNT(DISTINCT v) AS exploited_cve_count, AVG(v.severity)  AS avg_severity, COUNT(DISTINCT s.product)   AS distinct_products_affected,
            ORDER BY exploited_cve_count DESC
            LIMIT {top_n}
        """
        rows = self._run_query(cypher, "High risk vendors (graph)")
        df = pd.DataFrame(rows)

        if not df.empty:
            path = os.path.join(self.OUTPUT_DIR, "high_risk_vendors_graph.csv")
            df.to_csv(path, index=False)
            self.logger.info(f"Saved -> {path}")

        return df

    def run_all_insights(self) -> Dict[str, pd.DataFrame]:
        """run all four insight queries and return results as a dict of DataFrames"""
        self.logger.info("Running all graph insight queries...")
        results = {
            "central_vulns": self.most_connected_vulnerabilities(),
            "breached_industry":self.most_breached_industries(),
            "high_risk_vendors":self.high_risk_vendors_graph(),
        }
        self.logger.info("All graph insight queries complete")
        return results


# Neo4jLoader 

class Neo4jLoader:
    """
    Full graph load pipeline.
    Reads from:
        - integration/output/merged_cve_kev.csv
        - PostgreSQL breaches table
    Writes to:
        - Neo4j graph database
        - graph/output/*.csv (insight query results)
    """

    def __init__(self):
        self.logger = configure_logger("Neo4jLoader")
        self._data_loader = GraphDataLoader()

    def run(self) -> bool:
        self.logger.info("Neo4jLoader starting full graph load.")

        # load source data
        merged_df = self._data_loader.load_merged_cve_kev()
        breach_df = self._data_loader.load_breaches_csv()

        if merged_df.empty:
            self.logger.error(
                "No merged CVE-KEV data found. "
                "Run CveKevMerger first."
            )
            return False

        with Neo4jConnection() as neo4j:
            driver = neo4j.get_driver()
            
            ConstraintManager(driver).apply_all()

            node_loader = NodeLoader(driver)
            node_loader.load_vulnerability_nodes(merged_df)
            node_loader.load_software_nodes(merged_df)
            node_loader.load_industry_nodes(breach_df)
            node_loader.load_organization_nodes(breach_df)

            rel_loader = RelationshipLoader(driver)
            rel_loader.create_exploits_relationships(merged_df)
            rel_loader.create_breached_in_relationships(breach_df)
            rel_loader.create_affects_relationships(merged_df, breach_df)

  
            GraphInsightQueries(driver).run_all_insights()

        self.logger.info("Neo4jLoader complete - graph populated and insights exported")
        return True



if __name__ == "__main__":
    loader  = Neo4jLoader()
    success = loader.run()
    sys.exit(0 if success else 1)
