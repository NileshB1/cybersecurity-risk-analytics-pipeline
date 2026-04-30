

import os
import sys
import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import numpy as np
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
from dotenv import load_dotenv

load_dotenv()

OUTPUT_DIR = "graph/output"


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



# Neo4jSessionRunner


class Neo4jSessionRunner:

    def __init__(self):
        self.logger = configure_logger("Neo4jSessionRunner")
        self._uri = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
        self._user = os.getenv("NEO4J_USER",     "neo4j")
        self._password  = os.getenv("NEO4J_PASSWORD", "")
        self._driver = None

    def connect(self) -> "Neo4jSessionRunner":
        try:
            self._driver = GraphDatabase.driver(
                self._uri, auth=(self._user, self._password)
            )
            self._driver.verify_connectivity()
            self.logger.info(f"Neo4j connected at {self._uri}")
        except ServiceUnavailable:
            raise ConnectionError(
                f"Neo4j not reachable at {self._uri}. "
                f"Is Neo4j Desktop running?"
            )
        except AuthError:
            raise ConnectionError("Neo4j auth failed - check .env credentials")
        return self

    def run(self, cypher: str, params: dict = None) -> List[Dict]:
        if not self._driver:
            raise RuntimeError("Not connected - call connect() first")
        with self._driver.session() as session:
            result = session.run(cypher, params or {})
            return [dict(r) for r in result]

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self.logger.debug("Neo4j driver closed")

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# InsightOutputWriter


class InsightOutputWriter:

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.logger     = configure_logger("InsightOutputWriter")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def save(self, df: pd.DataFrame, filename: str) -> str:
        if df.empty:
            self.logger.warning(f"Empty dataframe - skipping save for {filename}")
            return ""
        path = os.path.join(self.output_dir, filename)
        df.to_csv(path, index=False)
        self.logger.info(f"Saved {len(df):,} rows -> {path}")
        return path

# DegreeCentralityAnalyser


class DegreeCentralityAnalyser:

    def __init__(self, runner: Neo4jSessionRunner):
        self.logger  = configure_logger("DegreeCentralityAnalyser")
        self._runner = runner

    def vulnerability_centrality(self, top_n: int = 30) -> pd.DataFrame:
        
        cypher = f"""
            MATCH (v:Vulnerability)
            OPTIONAL MATCH (v)-[e:EXPLOITS]->()
            WITH v,
                 COUNT(e) AS exploits_degree,
                 v.severity AS severity,
                 v.vendor AS vendor,
                 v.publish_date AS publish_date,
                 v.is_exploited AS is_exploited
            ORDER BY exploits_degree DESC
            LIMIT {top_n}
            RETURN v.cve_id AS cve_id,
                   severity,
                   vendor,
                   publish_date,
                   is_exploited,
                   exploits_degree
        """
        rows = self._runner.run(cypher)
        df   = pd.DataFrame(rows)

        if not df.empty:
            self.logger.info(
                f"Vulnerability centrality: top CVE has "
                f"degree {df['exploits_degree'].max()} connections"
            )

        return df

    def software_centrality(self, top_n: int = 20) -> pd.DataFrame:
       
        cypher = f"""
            MATCH (s:Software)
            OPTIONAL MATCH (v:Vulnerability)-[:EXPLOITS]->(s)
            OPTIONAL MATCH (s)-[:AFFECTS]->(o:Organization)
            WITH s,
                 COUNT(DISTINCT v) AS incoming_cves,
                 COUNT(DISTINCT o) AS affected_orgs
            ORDER BY (incoming_cves + affected_orgs) DESC
            LIMIT {top_n}
            RETURN s.vendor AS vendor,
                   s.product AS product,
                   incoming_cves,
                   affected_orgs,
                   (incoming_cves + affected_orgs) AS total_degree
        """
        rows = self._runner.run(cypher)
        df   = pd.DataFrame(rows)

        if not df.empty:
            self.logger.info(
                f"Software centrality: top product has "
                f"total degree {df['total_degree'].max()}"
            )

        return df

    def organisation_centrality(self, top_n: int = 20) -> pd.DataFrame:
        
        cypher = f"""
            MATCH (o:Organization)-[r:BREACHED_IN]->()
            WITH o,
                 COUNT(r) AS breach_events,
                 SUM(r.records_exposed) AS total_records
            ORDER BY breach_events DESC
            LIMIT {top_n}
            RETURN o.org_name AS organisation,
                   o.industry AS industry,
                   breach_events,
                   total_records
        """
        rows = self._runner.run(cypher)
        return pd.DataFrame(rows)


# CommunityDetector

class CommunityDetector:

    JACCARD_THRESHOLD = 0.3   
    def __init__(self, runner: Neo4jSessionRunner):
        self.logger = configure_logger("CommunityDetector")
        self._runner = runner

    def _get_industry_vendor_sets(self) -> Dict[str, set]:
       
        cypher = """
            MATCH (o:Organization)-[:BREACHED_IN]->(i:Industry)
            MATCH (s:Software)-[:AFFECTS]->(o)
            RETURN i.name AS industry, s.vendor AS vendor
        """
        rows = self._runner.run(cypher)
        if not rows:
            
            cypher_fallback = """
                MATCH (o:Organization)-[:BREACHED_IN]->(i:Industry)
                RETURN i.name AS industry, o.industry AS vendor
            """
            rows = self._runner.run(cypher_fallback)

        industry_vendors: Dict[str, set] = {}
        for row in rows:
            ind    = str(row.get("industry", "Unknown"))
            vendor = str(row.get("vendor",   "Unknown"))
            if ind not in industry_vendors:
                industry_vendors[ind] = set()
            industry_vendors[ind].add(vendor)

        return industry_vendors

    def _jaccard(self, set_a: set, set_b: set) -> float:
      
        if not set_a and not set_b:
            return 0.0
        intersection = len(set_a & set_b)
        union        = len(set_a | set_b)
        return intersection / union if union else 0.0

    def detect_communities(self) -> pd.DataFrame:
      
        self.logger.info("Running community detection (Jaccard similarity)...")

        industry_vendors = self._get_industry_vendor_sets()

        if len(industry_vendors) < 2:
            self.logger.warning(
                "Fewer than 2 industries in graph - "
                "not enough for community detection"
            )
            return pd.DataFrame()

        industries = sorted(industry_vendors.keys())
        n          = len(industries)
        matrix     = np.zeros((n, n))

        for i, ind_a in enumerate(industries):
            for j, ind_b in enumerate(industries):
                if i == j:
                    matrix[i][j] = 1.0
                elif j > i:
                    sim = self._jaccard(
                        industry_vendors[ind_a],
                        industry_vendors[ind_b]
                    )
                    matrix[i][j] = sim
                    matrix[j][i] = sim

        sim_df = pd.DataFrame(matrix, index=industries, columns=industries)

        self.logger.info(f"Similarity matrix computed: {n}x{n} industries")
        self._log_top_pairs(sim_df, industries)

        return sim_df

    def _log_top_pairs(
        self, sim_df: pd.DataFrame, industries: List[str]
    ) -> None:
        """log the top 5 most similar industry pairs"""
        pairs = []
        for i in range(len(industries)):
            for j in range(i+1, len(industries)):
                pairs.append((
                    industries[i],
                    industries[j],
                    sim_df.iloc[i, j]
                ))
        pairs.sort(key=lambda x: x[2], reverse=True)

        self.logger.info("  Top 5 most similar industry pairs (Jaccard):")
        for a, b, sim in pairs[:5]:
            self.logger.info(f"    {a:<25} <-> {b:<25}  sim={sim:.3f}")

    def get_community_assignments(self, sim_df: pd.DataFrame) -> pd.DataFrame:
       
        if sim_df.empty:
            return pd.DataFrame()

        industries    = list(sim_df.index)
        community_map = {}
        community_id  = 0

        for ind in industries:
            if ind in community_map:
                continue
            # find all similar industries
            similar = [
                other for other in industries
                if other != ind
                and sim_df.loc[ind, other] >= self.JACCARD_THRESHOLD
                and other not in community_map
            ]
            community_map[ind] = community_id
            for s in similar:
                community_map[s] = community_id
            community_id += 1

        result_df = pd.DataFrame([
            {"industry": ind, "community_id": cid}
            for ind, cid in community_map.items()
        ]).sort_values("community_id")

        self.logger.info(
            f"Community detection complete: "
            f"{result_df['community_id'].nunique()} communities found"
        )
        for cid in result_df["community_id"].unique():
            members = result_df[result_df["community_id"] == cid]["industry"].tolist()
            self.logger.info(f"  Community {cid}: {members}")

        return result_df


# VendorRiskRanker


class VendorRiskRanker:

    WEIGHTS = {
        "exploited_cves": 0.5,
        "avg_severity":   0.3,
        "affected_orgs":  0.2,
    }

    def __init__(self, runner: Neo4jSessionRunner):
        self.logger = configure_logger("VendorRiskRanker")
        self._runner = runner

    def compute_risk_scores(self, top_n: int = 20) -> pd.DataFrame:
        
        cypher = f"""
            MATCH (s:Software)
            OPTIONAL MATCH (v:Vulnerability {{is_exploited: true}})-[:EXPLOITS]->(s)
            OPTIONAL MATCH (s)-[:AFFECTS]->(o:Organization)
            WITH s.vendor AS vendor,
                 COUNT(DISTINCT v) AS exploited_cves,
                 AVG(v.severity) AS avg_severity,
                 COUNT(DISTINCT o) AS affected_orgs
            WHERE vendor IS NOT NULL
            RETURN vendor, exploited_cves, avg_severity, affected_orgs
            ORDER BY exploited_cves DESC
            LIMIT {top_n}
        """
        rows = self._runner.run(cypher)
        if not rows:
            self.logger.warning("No vendor data in graph - check neo4j_loader ran")
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df["avg_severity"] = pd.to_numeric(df["avg_severity"], errors="coerce").fillna(0)

       
        for col in ["exploited_cves", "avg_severity", "affected_orgs"]:
            col_min = df[col].min()
            col_max = df[col].max()
            rng     = col_max - col_min
            df[f"{col}_norm"] = (df[col] - col_min) / rng if rng > 0 else 0

        df["composite_risk_score"] = (
            df["exploited_cves_norm"] * self.WEIGHTS["exploited_cves"]
            + df["avg_severity_norm"] * self.WEIGHTS["avg_severity"]
            + df["affected_orgs_norm"] * self.WEIGHTS["affected_orgs"]
        ).round(4)

        df = df.sort_values("composite_risk_score", ascending=False)

        self.logger.info(f"\n  Top 5 vendors by composite risk score:")
        for _, row in df.head(5).iterrows():
            self.logger.info(
                f"    {str(row['vendor']):<25}  "
                f"score={row['composite_risk_score']:.3f}  "
                f"exploited={int(row['exploited_cves'])}  "
                f"avg_cvss={row['avg_severity']:.1f}"
            )

        return df


# GraphStatsCollector


class GraphStatsCollector:

    def __init__(self, runner: Neo4jSessionRunner):
        self.logger  = configure_logger("GraphStatsCollector")
        self._runner = runner

    def collect(self) -> Dict[str, int]:
        """count nodes and relationships by type"""
        queries = {
            "vulnerability_nodes": "MATCH (n:Vulnerability) RETURN COUNT(n) AS n",
            "software_nodes": "MATCH (n:Software) RETURN COUNT(n) AS n",
            "organization_nodes": "MATCH (n:Organization) RETURN COUNT(n) AS n",
            "industry_nodes": "MATCH (n:Industry) RETURN COUNT(n) AS n",
            "exploits_rels": "MATCH ()-[r:EXPLOITS]->() RETURN COUNT(r) AS n",
            "breached_in_rels": "MATCH ()-[r:BREACHED_IN]->() RETURN COUNT(r) AS n",
            "affects_rels": "MATCH ()-[r:AFFECTS]->()  RETURN COUNT(r) AS n",
        }

        stats = {}
        self.logger.info("\n  Graph statistics:")
        for label, cypher in queries.items():
            try:
                rows = self._runner.run(cypher)
                count = rows[0]["n"] if rows else 0
                stats[label] = count
                self.logger.info(f"{label:<25} {count:>8,}")
            except Exception as e:
                self.logger.warning(f"{label}: query failed ({e})")
                stats[label] = -1

        return stats

# GraphInsightsRunner  

class GraphInsightsRunner:
    

    def __init__(self):
        self.logger = configure_logger("GraphInsightsRunner")
        self._writer = InsightOutputWriter()

    def run(self) -> Dict[str, pd.DataFrame]:
        
        self.logger.info("GraphInsightsRunner starting...")
        results = {}

        with Neo4jSessionRunner() as runner:

            
            stats_collector = GraphStatsCollector(runner)
            stats = stats_collector.collect()
            stats_df  = pd.DataFrame([stats])
            self._writer.save(stats_df, "graph_stats.csv")
            results["stats"] = stats_df

            centrality = DegreeCentralityAnalyser(runner)

            vuln_central = centrality.vulnerability_centrality(top_n=30)
            self._writer.save(vuln_central, "vulnerability_centrality.csv")
            results["vuln_centrality"] = vuln_central

            sw_central = centrality.software_centrality(top_n=20)
            self._writer.save(sw_central, "software_centrality.csv")
            results["sw_centrality"] = sw_central

            org_central = centrality.organisation_centrality(top_n=20)
            self._writer.save(org_central, "organisation_centrality.csv")
            results["org_centrality"] = org_central

            detector    = CommunityDetector(runner)
            sim_matrix  = detector.detect_communities()
            communities = detector.get_community_assignments(sim_matrix)

            if not sim_matrix.empty:
                self._writer.save(sim_matrix.reset_index(), "industry_similarity_matrix.csv")
            self._writer.save(communities, "industry_communities.csv")
            results["communities"] = communities

          
            ranker    = VendorRiskRanker(runner)
            risk_df   = ranker.compute_risk_scores(top_n=20)
            self._writer.save(risk_df, "vendor_risk_scores.csv")
            results["vendor_risk"] = risk_df

        self.logger.info(
            f"GraphInsightsRunner complete. "
            f"Results saved to {OUTPUT_DIR}/"
        )
        return results


if __name__ == "__main__":
    runner  = GraphInsightsRunner()
    results = runner.run()
    print(f"\nGraph insights complete:")
    for key, df in results.items():
        if isinstance(df, pd.DataFrame) and not df.empty:
            print(f"  {key:<25} {len(df):>6,} rows")
