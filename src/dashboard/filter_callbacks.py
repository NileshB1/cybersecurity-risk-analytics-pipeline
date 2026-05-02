import os
import sys
import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import numpy as np
import psycopg2
from dotenv import load_dotenv

from dash import Input, Output, State, callback_context
import plotly.graph_objects as go
import plotly.express as px

load_dotenv()

ANALYSIS_DIR = "analysis/output"
GRAPH_DIR = "graph/output"

def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(fmt="%(asctime)s  [%(levelname)-8s]  %(name)s  -  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    fh = logging.FileHandler("pipeline.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger

COLOURS = {
    "primary": "steelblue",
    "secondary": "peach",
    "accent": "mustard",
    "grey": "grey",
    "critical": "red",
    "high": "orange",
    "medium":"yellow",
    "low": "lightgreen",
    "card_bg": "lightred",
}

CHART_TEMPLATE = "plotly_white"

class FilterDataProvider:

    def __init__(self):
        self.logger = configure_logger("FilterDataProvider")
        self._config = {
            "host": os.getenv("PG_HOST","localhost"),
            "port": os.getenv("PG_PORT","5432"),
            "dbname": os.getenv("PG_DB","cybersec_db"),
            "user": os.getenv("PG_USER","postgres"),
            "password": os.getenv("PG_PASSWORD", ""),
        }

    def _query(self, sql: str) -> pd.DataFrame:
        try:
            conn = psycopg2.connect(**self._config, connect_timeout=10)
            df = pd.read_sql(sql, conn)
            conn.close()
            return df
        except Exception as e:
            self.logger.error(f"Filter query failed: {e}")
            return pd.DataFrame()

    def get_year_range(self) -> Tuple[int, int]:
       
        df = self._query("SELECT EXTRACT(YEAR FROM breach_date)::INT AS yr FROM breaches WHERE breach_date IS NOT NULL;")
        if df.empty:
            return 2005, 2024
        return int(df["yr"].min()), int(df["yr"].max())

    def get_industry_options(self) -> List[Dict[str, str]]:
        """It will get all distinct industries for the multi-select dropdown"""
        df = self._query("SELECT DISTINCT industry FROM breaches WHERE industry IS NOT NULL AND industry != 'Unknown' ORDER BY industry;")
        if df.empty:
            return []
        return [{"label": ind, "value": ind} for ind in df["industry"].tolist()]

    def get_severity_range(self) -> Tuple[float, float]:
       
        df = self._query("SELECT MIN(severity) AS mn, MAX(severity) AS mx FROM vulnerabilities WHERE severity IS NOT NULL;")
        if df.empty:
            return 0.0, 10.0
        return float(df["mn"].iloc[0]), float(df["mx"].iloc[0])

    def get_all_options(self) -> Dict[str, Any]:
        """It will load all filter option data at once"""
        self.logger.info("Loading filter options from PostgreSQL...")
        yr_min, yr_max = self.get_year_range()
        return {"year_min": yr_min,"year_max": yr_max,"industry_options": self.get_industry_options(),"severity_min": 0.0,"severity_max": 10.0,}


class FilteredDataLoader:

    def __init__(self):
        self.logger = configure_logger("FilteredDataLoader")
        self._config = {"host": os.getenv("PG_HOST", "localhost"),"port": os.getenv("PG_PORT", "5432"),"dbname": os.getenv("PG_DB", "cybersec_db"),"user": os.getenv("PG_USER", "postgres"),"password": os.getenv("PG_PASSWORD", ""),}

    def _query(self, sql: str, params: tuple = None) -> pd.DataFrame:
        try:
            conn = psycopg2.connect(**self._config, connect_timeout=10)
            df = pd.read_sql(sql, conn, params=params)
            conn.close()
            return df
        except Exception as e:
            self.logger.error(f"Filtered query failed: {e}")
            return pd.DataFrame()

    def breach_trend_filtered(self,year_range: List[int],industries: List[str]) -> pd.DataFrame:
        """The breach count per year filtered by year range and industries"""
        yr_min = year_range[0] if year_range else 2005
        yr_max = year_range[1] if len(year_range) > 1 else 2024

        if industries:
            # industry filter active
            industry_placeholders = ",".join(["%s"] * len(industries))
            sql = f"""SELECT EXTRACT(YEAR FROM breach_date)::INT AS year, industry, COUNT(*) AS breach_count,COALESCE(SUM(records_exposed), 0)   AS records_exposed
                FROM breaches WHERE breach_date IS NOT NULL AND EXTRACT(YEAR FROM breach_date) BETWEEN %s AND %s AND industry IN ({industry_placeholders}) GROUP BY year, industry ORDER BY year;"""
            params = tuple([yr_min, yr_max] + industries)
        else:
            sql = """SELECT EXTRACT(YEAR FROM breach_date)::INT AS year, industry, COUNT(*) AS breach_count, COALESCE(SUM(records_exposed), 0)   AS records_exposed
                FROM breaches WHERE breach_date IS NOT NULL AND EXTRACT(YEAR FROM breach_date) BETWEEN %s AND %s GROUP BY year, industry ORDER BY year;"""
            params = (yr_min, yr_max)

        return self._query(sql, params)

    def severity_filtered(self, min_severity: float) -> pd.DataFrame:
        
        return self._query(
            "SELECT severity, vendor, publish_date FROM vulnerabilities WHERE severity >= %s AND severity IS NOT NULL ORDER BY severity DESC;",
            (min_severity,)
        )

    def vendor_filtered(
        self, min_severity: float,
        industries:   List[str]
    ) -> pd.DataFrame:
        
        
        path = os.path.join(ANALYSIS_DIR, "rq4_high_risk_vendors.csv")
        if not os.path.exists(path):
            self.logger.warning(f"RQ4 CSV not found at {path}")
            return pd.DataFrame()
        df = pd.read_csv(path)

        if min_severity and "avg_cvss_score" in df.columns:
            df = df[df["avg_cvss_score"] >= min_severity]

        return df

    def kpis_filtered(
        self,year_range: List[int], industries: List[str]
    ) -> Dict[str, int]:
        """recalculate KPI tile values based on active filters"""
        yr_min = year_range[0] if year_range else 2005
        yr_max = year_range[1] if len(year_range) > 1 else 2024

        cve_df = self._query("SELECT COUNT(*) AS n FROM vulnerabilities;")
        kev_df = self._query("SELECT COUNT(*) AS n FROM exploited_vulnerabilities;")

        if industries:
            industry_placeholders = ",".join(["%s"] * len(industries))
            breach_sql = f"""
                SELECT COUNT(*) AS n, COALESCE(SUM(records_exposed),0) AS r FROM breaches WHERE EXTRACT(YEAR FROM breach_date) BETWEEN %s AND %s
                  AND industry IN ({industry_placeholders}); """
            params  = tuple([yr_min, yr_max] + industries)
            b_df    = self._query(breach_sql, params)
        else:
            b_df = self._query(
                "SELECT COUNT(*) AS n, COALESCE(SUM(records_exposed),0) AS r FROM breaches WHERE EXTRACT(YEAR FROM breach_date) BETWEEN %s AND %s;",
                (yr_min, yr_max))

        return {
            "total_cves": int(cve_df["n"].iloc[0]) if not cve_df.empty else 0,
            "total_exploited": int(kev_df["n"].iloc[0]) if not kev_df.empty else 0,
            "total_breaches": int(b_df["n"].iloc[0]) if not b_df.empty  else 0,
            "total_records": int(b_df["r"].iloc[0]) if not b_df.empty  else 0,
        }


class FilteredChartBuilder:

    def __init__(self):
        self.logger = configure_logger("FilteredChartBuilder")

    @staticmethod
    def _empty(message: str = "No data for selected filters") -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(text=message, xref="paper", yref="paper",x=0.5, y=0.5, showarrow=False,font=dict(size=13, color=COLOURS["grey"]))
        fig.update_layout(template=CHART_TEMPLATE,xaxis={"visible": False},yaxis={"visible": False},)
        return fig

    def breach_trend_filtered(
        self,
        df: pd.DataFrame,
        industries: List[str]
    ) -> go.Figure:
       
        if df.empty:
            return self._empty()

        fig = go.Figure()

        if industries and "industry" in df.columns and len(industries) <= 6:
            for ind in industries:
                ind_data = df[df["industry"] == ind].sort_values("year")
                if ind_data.empty:
                    continue
                fig.add_trace(go.Scatter(x=ind_data["year"],y=ind_data["breach_count"],mode="lines+markers",name=ind,line=dict(width=2),))
            title = f"Breach Trend — {', '.join(industries[:3])}{'...' if len(industries) > 3 else ''}"
        else:
            # aggregate all industries into one line
            agg = df.groupby("year")["breach_count"].sum().reset_index()
            agg = agg.sort_values("year")
            fig.add_trace(go.Scatter(x=agg["year"],y=agg["breach_count"],mode="lines+markers",line=dict(color=COLOURS["secondary"], width=2.5),fill="tozeroy",fillcolor="rgba(224,82,82,0.1)",name="All Industries"))
            title = "Breach Count per Year (All Industries)"

        fig.update_layout(title=title, xaxis_title="Year",yaxis_title="Breach Count",template=CHART_TEMPLATE,hovermode="x unified",legend=dict(orientation="h", y=-0.2),)
        return fig

    def severity_dist_filtered(
        self,
        df: pd.DataFrame,
        min_severity: float
    ) -> go.Figure:
        """severity histogram showing only CVEs above the threshold"""
        if df.empty or "severity" not in df.columns:
            return self._empty()

        sev = pd.to_numeric(df["severity"], errors="coerce").dropna()

        if sev.empty:
            return self._empty(f"No CVEs with severity >= {min_severity}")

        colours_list = []
        for s in sev:
            if s >= 9: colours_list.append(COLOURS["critical"])
            elif s >= 7: colours_list.append(COLOURS["high"])
            elif s >= 4: colours_list.append(COLOURS["medium"])
            else: colours_list.append(COLOURS["low"])

        fig = go.Figure(go.Histogram(
            x=sev,
            nbinsx=30,
            marker=dict(
                color=sev,
                colorscale=[[0, COLOURS["low"]], [0.4, COLOURS["medium"]],
                            [0.7, COLOURS["high"]], [1, COLOURS["critical"]]],
                cmin=0, cmax=10,
                line=dict(width=0.5, color="white"),
            ),
        ))
        fig.add_vline(
            x=sev.mean(), line_dash="dash", line_color="black",
            annotation_text=f"Mean = {sev.mean():.1f}",
            annotation_position="top right"
        )
        fig.update_layout(title=f"CVSS Severity Distribution (>= {min_severity})",xaxis_title="CVSS Score",yaxis_title="CVE Count",template=CHART_TEMPLATE,)
        return fig

    def vendor_risk_filtered(self, df: pd.DataFrame) -> go.Figure:
        """top vendors bar chart using filtered vendor data"""
        if df.empty or "vendor" not in df.columns:
            return self._empty()

        col = "confirmed_exploited" if "confirmed_exploited" in df.columns else df.columns[1]
        top = df.nlargest(10, col)

        # colour bars by exploitation rate if available
        bar_colours = COLOURS["critical"]
        if "exploitation_rate_pct" in top.columns:
            bar_colours = [
                COLOURS["critical"] if r >= 50
                else COLOURS["high"] if r >= 25
                else COLOURS["medium"]
                for r in top["exploitation_rate_pct"].fillna(0)
            ]

        fig = go.Figure(go.Bar(x=top["vendor"],y=top[col],marker_color=bar_colours,text=top[col].apply(lambda x: f"{int(x):,}"),textposition="outside",))
        fig.update_layout(title="Top 10 Vendors — Confirmed Exploited CVEs", xaxis_title="Vendor", yaxis_title="Exploited CVEs", template=CHART_TEMPLATE,xaxis={"tickangle": -30},)
        return fig

    def graph_vendor_risk_chart(self) -> go.Figure:
        path = os.path.join(GRAPH_DIR, "vendor_risk_scores.csv")
        if not os.path.exists(path):
            return self._empty(
                "Graph vendor risk data not available.\n"
                "Run graph/graph_insights.py first."
            )

        df = pd.read_csv(path)
        top = df.head(10)

        fig = go.Figure(go.Bar(
            x=top["vendor"],
            y=top["composite_risk_score"],
            marker=dict(color=top["composite_risk_score"],colorscale="Reds",showscale=True,colorbar=dict(title="Risk Score"),),
            text=top["composite_risk_score"].apply(lambda x: f"{x:.3f}"),
            textposition="outside",
        ))
        fig.update_layout(title="Vendor Composite Risk Score ",xaxis_title="Vendor",yaxis_title="Composite Risk Score",template=CHART_TEMPLATE,xaxis={"tickangle": -30},)
        return fig

    def industry_community_chart(self) -> go.Figure:
        
        path = os.path.join(GRAPH_DIR, "industry_communities.csv")
        if not os.path.exists(path):
            return self._empty(
                "Community detection data not available.\n"
                "Run graph/graph_insights.py first."
            )

        df   = pd.read_csv(path)
        if df.empty:
            return self._empty("No community data found")

        
        community_colours = [
            COLOURS["primary"], COLOURS["secondary"], COLOURS["accent"],
            "purple", "green", "red", "orange"
        ]

        fig = go.Figure()
        for cid in sorted(df["community_id"].unique()):
            members = df[df["community_id"] == cid]["industry"].tolist()
            colour  = community_colours[cid % len(community_colours)]
            fig.add_trace(go.Bar(name=f"Community {cid}",x=members,y=[1] * len(members),marker_color=colour,showlegend=True,))

        fig.update_layout(
title="Industry Sector Communities ",xaxis_title="Industry Sector",yaxis={"visible": False},template=CHART_TEMPLATE,barmode="stack",xaxis={"tickangle": -25},legend=dict(orientation="h", y=-0.3),)
        return fig

class FilterManager:

    def __init__(self, app, options: Dict[str, Any] = None):
        self.logger = configure_logger("FilterManager")
        self._app = app
        self._data_loader = FilteredDataLoader()
        self._chart_builder = FilteredChartBuilder()
        self._options = options or {}

    def register_all(self) -> None:
        """register all callbacks"""
        self._register_breach_trend_callback()
        self._register_severity_callback()
        self._register_vendor_callback()
        self._register_graph_callbacks()
        self._register_kpi_callback()
        self.logger.info("All filter callbacks registered")

    def _register_breach_trend_callback(self) -> None:
        @self._app.callback(Output("breach-trend-chart", "figure"),
            Input("year-range-slider", "value"),
            Input("industry-dropdown", "value"),)
        def update_breach_trend(year_range, industries):
            industries = industries or []
            df  = self._data_loader.breach_trend_filtered(year_range or [2005, 2024], industries)
            return self._chart_builder.breach_trend_filtered(df, industries)

    def _register_severity_callback(self) -> None:
        @self._app.callback(Output("severity-hist-chart", "figure"),Input("severity-min-slider", "value"), )
        def update_severity(min_sev):
            min_sev = min_sev or 0.0
            df = self._data_loader.severity_filtered(min_sev)
            return self._chart_builder.severity_dist_filtered(df, min_sev)

    def _register_vendor_callback(self) -> None:
        @self._app.callback(Output("vendor-bar-chart", "figure"),Input("severity-min-slider", "value"),Input("industry-dropdown", "value"),)
        def update_vendor(min_sev, industries):
            df = self._data_loader.vendor_filtered( min_sev or 0.0, industries or [])
            return self._chart_builder.vendor_risk_filtered(df)

    def _register_graph_callbacks(self) -> None:
        @self._app.callback(Output("graph-vendor-risk-chart", "figure"),Output("industry-community-chart", "figure"),Input("breach-trend-chart","id"), )
        def update_graph_charts(_):
            return (self._chart_builder.graph_vendor_risk_chart(),self._chart_builder.industry_community_chart(),)

    def _register_kpi_callback(self) -> None:
        @self._app.callback(Output("kpi-cve-value", "children"),
            Output("kpi-kev-value", "children"),
            Output("kpi-breach-value", "children"),
            Output("kpi-records-value", "children"),
            Input("year-range-slider", "value"),
            Input("industry-dropdown", "value"),)
        def update_kpis(year_range, industries):
            kpis = self._data_loader.kpis_filtered(
                year_range or [2005, 2024],
                industries or [])

            def fmt(n: int) -> str:
                if n >= 1_000_000_000: return f"{n/1_000_000_000:.1f}B"
                if n >= 1_000_000: return f"{n/1_000_000:.1f}M"
                if n >= 1_000: return f"{n/1_000:.1f}K"
                return str(n)

            return (fmt(kpis.get("total_cves", 0)),fmt(kpis.get("total_exploited", 0)),fmt(kpis.get("total_breaches", 0)),fmt(kpis.get("total_records", 0)),)
