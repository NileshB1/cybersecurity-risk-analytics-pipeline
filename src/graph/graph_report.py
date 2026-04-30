

import os
import sys
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd
import numpy as np
from dotenv import load_dotenv

load_dotenv()

INPUT_DIR = "graph/output"
REPORT_DIR = "graph/reports"


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


# InsightCsvReader

class InsightCsvReader:

    def __init__(self, input_dir: str = INPUT_DIR):
        self.logger = configure_logger("InsightCsvReader")
        self.input_dir = input_dir

    def read(self, filename: str) -> pd.DataFrame:
        path = os.path.join(self.input_dir, filename)
        if not os.path.exists(path):
            self.logger.warning(
                f"File not found: {path} - "
                f"run graph_insights.py first"
            )
            return pd.DataFrame()
        df = pd.read_csv(path, low_memory=False)
        self.logger.debug(f"Loaded {path}: {len(df):,} rows")
        return df

    def read_all(self) -> Dict[str, pd.DataFrame]:
        return {
            "stats":self.read("graph_stats.csv"),
            "vuln":self.read("vulnerability_centrality.csv"),
            "software": self.read("software_centrality.csv"),
            "orgs":self.read("organisation_centrality.csv"),
            "communities": self.read("industry_communities.csv"),
            "vendor_risk": self.read("vendor_risk_scores.csv"),
        }


# GraphScaleSection

class GraphScaleSection:

    def __init__(self):
        self.logger = configure_logger("GraphScaleSection")

    def generate(self, stats_df: pd.DataFrame) -> List[str]:
        
        lines = [
            "4.1  Graph Scale",
            "-" * 50,
        ]

        if stats_df.empty:
            lines.append(" [No graph statistics available - run graph_insights.py]")
            return lines

        row = stats_df.iloc[0]

        total_nodes = sum([
            int(row.get("vulnerability_nodes",0)),
            int(row.get("software_nodes",0)),
            int(row.get("organization_nodes",0)),
            int(row.get("industry_nodes",0)),
        ])
        total_rels = sum([
            int(row.get("exploits_rels",0)),
            int(row.get("breached_in_rels",0)),
            int(row.get("affects_rels",0)),
        ])

        lines += [
            f"",
            f"The Neo4j property graph contains {total_nodes:,} nodes across",
            f"four node labels and {total_rels:,} relationships across three",
            f"relationship types.",
            f"",
            f"Node counts:",
            f"Vulnerability nodes:{int(row.get('vulnerability_nodes',0)):>8,}",
            f"Software nodes : {int(row.get('software_nodes',0)):>8,}",
            f"Organization nodes : {int(row.get('organization_nodes',0)):>8,}",
            f"Industry nodes : {int(row.get('industry_nodes',0)):>8,}",
            f"TOTAL : {total_nodes:>8,}",
            f"",
            f"Relationship counts:",
            f"EXPLOITS : {int(row.get('exploits_rels',0)):>8,}",
            f"BREACHED_IN : {int(row.get('breached_in_rels',0)):>8,}",
            f"AFFECTS : {int(row.get('affects_rels',0)):>8,}",
            f"TOTAL : {total_rels:>8,}",
            f"",
        ]

        self.logger.info(
            f"Graph scale: {total_nodes:,} nodes, {total_rels:,} relationships"
        )
        return lines



# CentralitySection
class CentralitySection:

    def __init__(self):
        self.logger = configure_logger("CentralitySection")

    def generate(
        self,
        vuln_df:pd.DataFrame,
        software_df:pd.DataFrame,
        org_df:pd.DataFrame
    ) -> List[str]:

        lines = [
            "4.2  Degree Centrality Analysis",
            "-" * 50,
            "",
            "  Degree centrality measures how many direct connections,each node has in the graph. Higher degree indicates greater",
            "  connectivity and therefore greater risk or exposure.",
            "",
        ]

        # top vulnerability nodes
        lines.append("  The top 10 Most Connected Vulnerability Nodes:")
        if not vuln_df.empty and "exploits_degree" in vuln_df.columns:
            for _, row in vuln_df.head(10).iterrows():
                lines.append(
                    f"{str(row.get('cve_id','?')):<18}  "
                    f"degree={int(row.get('exploits_degree',0)):>3}  "
                    f"severity={str(row.get('severity','?')):<5}  "
                    f"vendor={str(row.get('vendor','?'))}"
                )
        else:
            lines.append("    [No data available]")

        lines += [""]

        # top software nodes
        lines.append("  The top 10 Most Connected Software Nodes:")
        if not software_df.empty and "total_degree" in software_df.columns:
            for _, row in software_df.head(10).iterrows():
                lines.append(
                    f"{str(row.get('vendor','?')):<20} / "
                    f"{str(row.get('product','?')):<20}  "
                    f"total_degree={int(row.get('total_degree',0)):>4}"
                )
        else:
            lines.append("[No data available]")

        lines += [""]

        # centrality interpretation
        lines += [
            "  Interpretation:",
            "  Vulnerability nodes with high EXPLOITS degree represent CVEs, that affect a wide range of software products simultaneously.",
            "  These are particularly dangerous in heterogeneous enterprise,environments where many different products are in use.",
            "  Software nodes with high total degree are either widely exploited, or used by many organisations - patching these should be prioritised.",
            "",
        ]

        return lines



# CommunitySection


class CommunitySection:

    def __init__(self):
        self.logger = configure_logger("CommunitySection")

    def generate(self, communities_df: pd.DataFrame) -> List[str]:
        lines = [
            "4.3  Community Detection - Industry Clustering",
            "-" * 50,
            "",
            "Method: Jaccard similarity on shared vendor exposure sets.",
            "  Industries with similarity >= 0.30 were grouped together. This approximates "
            "the Louvain algorithm without requiring, the Neo4j Graph Data Science plugin.",
            "",
        ]

        if communities_df.empty:
            lines.append("  [No community data - check graph_insights.py output]")
            return lines

        community_count = communities_df["community_id"].nunique()
        lines.append(
            f"  {community_count} communities detected across "
            f"{len(communities_df)} industry sectors."
        )
        lines.append("")

        for cid in sorted(communities_df["community_id"].unique()):
            members = communities_df[
                communities_df["community_id"] == cid
            ]["industry"].tolist()
            lines.append(f"  Community {cid}  ({len(members)} sectors):")
            for m in members:
                lines.append(f"    - {m}")
            lines.append("")

        lines += [
            "  Interpretation:",
            "  Industries in the same community share vulnerability exposure, through common software vendors. A breach or patch in one sector",
            "  may have cascading implications for co-clustered sectors. This finding is relevant to RQ1 which asks how vulnerability",
            "  patterns relate to breach patterns across industry sectors.",
            "",
        ]

        return lines



# VendorRiskSection


class VendorRiskSection:

    def __init__(self):
        self.logger = configure_logger("VendorRiskSection")

    def generate(self, risk_df: pd.DataFrame) -> List[str]:
        lines = [
            "4.4  Vendor Risk Ranking  (Answers RQ4)",
            "-" * 50,
            "",
            "  Composite risk score = 0.5 * normalised(exploited_cve_count)",
            "                       + 0.3 * normalised(avg_cvss_severity)",
            "                       + 0.2 * normalised(affected_organisation_count)",
            "",
            "  Weights rationale:",
            "    Confirmed exploitation carries most weight (0.5) because it, represents real-world active threats rather than theoretical risk.",
            "    CVSS severity (0.3) captures potential damage if exploited. Organisation exposure (0.2) reflects breadth of impact.",
            "",
        ]

        if risk_df.empty:
            lines.append("  [No vendor risk data available]")
            return lines

        lines.append("  Top 10 Vendors by Composite Risk Score:")
        lines.append(
            f"  {'Rank':<5} {'Vendor':<25} {'Score':>6}  "
            f"{'Exploited':>10}  {'Avg CVSS':>9}  {'Orgs':>5}"
        )
        lines.append("  " + "-" * 65)

        for rank, (_, row) in enumerate(risk_df.head(10).iterrows(), 1):
            lines.append(
                f"  {rank:<5} {str(row.get('vendor','?')):<25} "
                f"{row.get('composite_risk_score',0):>6.3f}  "
                f"{int(row.get('exploited_cves',0)):>10,}  "
                f"{float(row.get('avg_severity',0)):>9.2f}  "
                f"{int(row.get('affected_orgs',0)):>5,}"
            )

        top_vendor = risk_df.iloc[0].get("vendor", "Unknown") if not risk_df.empty else "Unknown"
        lines += [
            "",
            f"  Finding: {top_vendor} has the highest composite risk score.",
            "  This aligns with SQL analysis (RQ4 query) confirming consistency, between relational and graph-based approaches.",
            "",
        ]

        return lines


# RQ5GraphSection

class RQ5GraphSection:

    def __init__(self):
        self.logger = configure_logger("RQ5GraphSection")

    def generate(self, vuln_df: pd.DataFrame) -> List[str]:
        
        lines = [
            "4.5  Time-to-Exploit Insights from Graph  (Contributes to RQ5)",
            "-" * 50,
            "",
            "  The graph model adds a network perspective to SQL, time-to-exploit analysis by examining whether high-centrality",
            "  vulnerabilities are exploited faster than low-centrality ones.",
            "",
        ]

        if vuln_df.empty or "exploits_degree" not in vuln_df.columns:
            lines.append("  [No centrality data for RQ5 supplement]")
            return lines

        
        exploited_mask = vuln_df["is_exploited"] == True
        if exploited_mask.sum() > 0 and (~exploited_mask).sum() > 0:
            avg_deg_exploited     = vuln_df[exploited_mask]["exploits_degree"].mean()
            avg_deg_not_exploited = vuln_df[~exploited_mask]["exploits_degree"].mean()

            lines += [
                f"  Avg degree - exploited CVEs     : {avg_deg_exploited:.2f}",
                f"  Avg degree - non-exploited CVEs : {avg_deg_not_exploited:.2f}",
                "",
            ]

            if avg_deg_exploited > avg_deg_not_exploited:
                lines.append(
                    "  Observation: Exploited CVEs have higher average degree than",
                    )
                lines.append(
                    "  non-exploited ones, suggesting attackers preferentially target",
                )
                lines.append(
                    "  vulnerabilities that affect multiple products simultaneously.",
                )
            else:
                lines.append(
                    "  Observation: No strong degree difference between exploited and"
                )
                lines.append(
                    "  non-exploited CVEs in this graph sample."
                )

        lines += [
            "",
            "  This graph-level finding complements the temporal analysis, (days to exploit) in the SQL layer by showing which structural",
            "  graph properties correlate with exploitation likelihood.",
            "",
        ]

        return lines



# DashboardSummaryExporter

class DashboardSummaryExporter:

    def __init__(self, output_dir: str = INPUT_DIR):
        self.logger = configure_logger("DashboardSummaryExporter")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def export(
        self,
        stats_df: pd.DataFrame,
        risk_df: pd.DataFrame,
        comm_df: pd.DataFrame
    ) -> pd.DataFrame:
       
        summary = {}

        if not stats_df.empty:
            row = stats_df.iloc[0]
            summary["total_nodes"]   = int(row.get("vulnerability_nodes", 0)) + \
                                       int(row.get("software_nodes",      0)) + \
                                       int(row.get("organization_nodes",  0)) + \
                                       int(row.get("industry_nodes",      0))
            summary["total_rels"]    = int(row.get("exploits_rels",    0)) + \
                                       int(row.get("breached_in_rels", 0)) + \
                                       int(row.get("affects_rels",     0))

        if not risk_df.empty:
            summary["top_risk_vendor"] = str(risk_df.iloc[0].get("vendor", "Unknown"))
            summary["top_risk_score"]  = float(risk_df.iloc[0].get("composite_risk_score", 0))

        if not comm_df.empty:
            summary["community_count"] = int(comm_df["community_id"].nunique())

        df = pd.DataFrame([summary])
        path = os.path.join(self.output_dir, "dashboard_graph_summary.csv")
        df.to_csv(path, index=False)
        self.logger.info(f"Dashboard summary exported -> {path}")
        return df


# ---------------------------------------------------------------
# GraphReportGenerator  (main class)
# assembles all sections into one text file
# ---------------------------------------------------------------

class GraphReportGenerator:
    """
    Reads all insight CSVs and generates a structured text report.
    Output: graph/reports/graph_analytics_report.txt

    Sections:
        4.1  Graph Scale
        4.2  Degree Centrality
        4.3  Community Detection
        4.4  Vendor Risk Ranking (RQ4)
        4.5  Time-to-Exploit Graph Supplement (RQ5)
    """

    def __init__(self):
        self.logger   = configure_logger("GraphReportGenerator")
        self._reader  = InsightCsvReader()
        self._exporter = DashboardSummaryExporter()

        # section generators
        self._scale     = GraphScaleSection()
        self._centrality = CentralitySection()
        self._community  = CommunitySection()
        self._vendor     = VendorRiskSection()
        self._rq5        = RQ5GraphSection()

        os.makedirs(REPORT_DIR, exist_ok=True)

    def generate(self) -> str:
       
        self.logger.info("Generating graph analytics report...")

        data = self._reader.read_all()

        # export dashboard summary
        self._exporter.export(
            data.get("stats",        pd.DataFrame()),
            data.get("vendor_risk",  pd.DataFrame()),
            data.get("communities",  pd.DataFrame()),
        )

        # build all sections
        all_lines = [
            "=" * 65,
            "  SECTION 4: GRAPH ANALYTICS REPORT",
            "  Cybersecurity Incident and Vulnerability Risk Analytics",
            "  Author: Teena (25141970)",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "=" * 65,
            "",
        ]

        all_lines += self._scale.generate(data.get("stats", pd.DataFrame()))
        all_lines += self._centrality.generate(
            data.get("vuln",     pd.DataFrame()),
            data.get("software", pd.DataFrame()),
            data.get("orgs",     pd.DataFrame()),
        )
        all_lines += self._community.generate(data.get("communities", pd.DataFrame()))
        all_lines += self._vendor.generate(data.get("vendor_risk", pd.DataFrame()))
        all_lines += self._rq5.generate(data.get("vuln", pd.DataFrame()))

        all_lines += [
            "=" * 65,
            "  END OF GRAPH ANALYTICS SECTION",
            "=" * 65,
        ]

        output_path = os.path.join(REPORT_DIR, "graph_analytics_report.txt")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(all_lines))

        self.logger.info(f"Report written to {output_path}")
        self.logger.info(f"Total lines: {len(all_lines)}")

        # also print to console
        for line in all_lines:
            self.logger.info(f"  {line}")

        return output_path


if __name__ == "__main__":
    generator = GraphReportGenerator()
    path      = generator.generate()
    print(f"\nReport saved to: {path}")
