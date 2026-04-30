import os
import sys
import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import numpy as np
import psycopg2
from dotenv import load_dotenv

import dash
from dash import dcc, html, Input, Output, callback
import plotly.graph_objects as go
import plotly.express as px

load_dotenv()

ANALYSIS_DIR   = "analysis/output"
INTEGRATION_DIR = "integration/output"


def configure_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(fmt="%(asctime)s [%(levelname)-8s]  %(name)s  -  %(message)s",datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    fh = logging.FileHandler("pipeline.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


# colour palette - blues for CVE/vulnerability data, reds for breach data

COLOURS = { "primary": "steelblue",
    "secondary":"peach",
    "accent": "mustard",
    "light_blue": "blue",
    "dark": "darkblue",
    "grey":"grey",
    "green": "green",
    "bg": "lightblue",
    "card_bg":"lightred",
    "critical":"red",
    "high": "orange",
    "medium":"yellow",
    "low":"lightgreen",}

CHART_TEMPLATE = "plotly_white"


# DashboardDataLoader

class DashboardDataLoader:

    def __init__(self):
        self.logger = configure_logger("DashboardDataLoader")
        self._pg_config = { "host": os.getenv("PG_HOST", "localhost"),
            "port": os.getenv("PG_PORT", "5432"),
            "dbname": os.getenv("PG_DB", "cybersec_db"),
            "user": os.getenv("PG_USER","postgres"),
            "password": os.getenv("PG_PASSWORD", ""), }

    def _pg_query(self, sql: str, label: str = "") -> pd.DataFrame:
        try:
            conn = psycopg2.connect(**self._pg_config, connect_timeout=10)
            df   = pd.read_sql(sql, conn)
            conn.close()
            return df
        except Exception as e:
            self.logger.error(f"PG query failed [{label}]: {e}")
            return pd.DataFrame()

    def _load_csv(self, filename: str, folder: str = ANALYSIS_DIR) -> pd.DataFrame:
        path = os.path.join(folder, filename)
        if not os.path.exists(path):
            self.logger.warning(f"CSV not found: {path}")
            return pd.DataFrame()
        df = pd.read_csv(path, low_memory=False)
        self.logger.debug(f"Loaded {path}: {len(df):,} rows")
        return df

    #KPI data

    def get_kpi_counts(self) -> Dict[str, Any]:
        """total count of 4 KPI tiles"""
        total_cve = self._pg_query("SELECT COUNT(*) AS n FROM vulnerabilities;", "kpi_cve" )
        total_kev = self._pg_query( "SELECT COUNT(*) AS n from exploited_vulnerabilities;", "kpi_kev" )
        total_breach = self._pg_query( "SELECT COUNT(*) AS n from breaches;", "kpi_breach" )
        total_records = self._pg_query("SELECT COALESCE(sum(records_exposed), 0) AS n from breaches;", "kpi_records")

        return { "total_cves": int(total_cve["n"].iloc[0]) if not total_cve.empty else 0,
            "total_exploited":int(total_kev["n"].iloc[0])  if not total_kev.empty else 0,
            "total_breaches":int(total_breach["n"].iloc[0]) if not total_breach.empty else 0,
            "total_records": int(total_records["n"].iloc[0]) if not total_records.empty else 0,  }

    # Chart data 

    def get_breach_trend(self) -> pd.DataFrame:
        return self._load_csv("rq1_industry_breach_trends.csv")

    def get_industry_data(self) -> pd.DataFrame:
        return self._load_csv("extra_top_industries_records.csv")

    def get_vendor_data(self) -> pd.DataFrame:
        return self._load_csv("rq4_high_risk_vendors.csv")

    def get_severity_data(self) -> pd.DataFrame:
        return self._pg_query("SELECT severity FROM vulnerabilities WHERE severity IS NOT NULL;", "severity_hist")

    def get_time_to_exploit(self) -> pd.DataFrame:
        return self._load_csv("rq5_time_to_exploit.csv")

    def get_all(self) -> Dict[str, Any]:
        """load and then call on dashboard"""
        self.logger.info("Loading all dashboard data...")
        data = {  "kpis":self.get_kpi_counts(),
            "breach_trend":self.get_breach_trend(),
            "industry": self.get_industry_data(),
            "vendors": self.get_vendor_data(),
            "severity": self.get_severity_data(),
            "time_to_exploit":self.get_time_to_exploit(), }
        self.logger.info("Dashboard data loaded")
        return data

# KpiTileBuilder -create 4 summary tiles 

class KpiTileBuilder:

    def __init__(self):
        self.logger = configure_logger("KpiTileBuilder")

    @staticmethod
    def _format_number(n: int) -> str:
        """large no. format"""
        if n >= 1_000_000_000:
            return f"{n/1_000_000_000:.1f}B"
        if n >= 1_000_000:
            return f"{n/1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n/1_000:.1f}K"
        return str(n)

    def build_tile( self, title: str,value: int,subtitle: str,colour: str = COLOURS["primary"],icon: str = "" ) -> html.Div:
        """ will get single styled KPI tile"""
        return html.Div(
            className="kpi-tile",
            style={  "backgroundColor": COLOURS["card_bg"],
                "borderRadius": "10px",
                "padding": "20px 24px",
                "boxShadow": "0 2px 8px rgba(0,0,0,0.08)",
                "borderLeft": f"4px solid {colour}",
                "minWidth":"200px",
                "flex": "1", },
            children=[
                html.P(title,style={"color": COLOURS["grey"], "fontSize": "13px","margin": "0 0 6px 0", "fontWeight": "500"} ),
                html.H2( f"{icon} {self._format_number(value)}",style={"color": colour, "fontSize": "32px", "margin": "0 0 4px 0", "fontWeight": "700"} ),
                html.P(subtitle,style={"color": COLOURS["grey"], "fontSize": "12px", "margin": "0"}),])

    def build_all(self, kpis: Dict[str, int]) -> html.Div:
        """build all four tiles in a row"""
        return html.Div(
            style={"display": "flex", "gap": "16px", "flexWrap": "wrap","marginBottom": "24px"},
            children=[ self.build_tile( "Total CVEs (NVD)", kpis.get("total_cves", 0), "All publicly disclosed vulnerabilities", colour=COLOURS["primary"] ),
                self.build_tile("Exploited (CISA KEV)", kpis.get("total_exploited", 0), "Confirmed active exploitation",colour=COLOURS["critical"]),
                self.build_tile("Data Breaches",kpis.get("total_breaches", 0),"Breach incidents across all sectors",colour=COLOURS["secondary"]),
                self.build_tile("Records Exposed",kpis.get("total_records", 0),"Total individual records compromised",colour=COLOURS["accent"]),  ] )

# ChartBuilder

class ChartBuilder:

    def __init__(self):
        self.logger = configure_logger("ChartBuilder")

    def breach_trend_line(self, df: pd.DataFrame) -> go.Figure:
        """Panel 2 - breach count (yearly)"""
        if df.empty or "breach_year" not in df.columns:
            return self._empty_figure("No breach trend data available")

        yearly = (df.groupby("breach_year")["breach_count"] .sum() .reset_index() .sort_values("breach_year") )
        # filter to sensible range
        yearly = yearly[ (yearly["breach_year"] >= 2005) & (yearly["breach_year"] <= 2024) ].dropna()

        fig = go.Figure()
        fig.add_trace(go.Scatter( x=yearly["breach_year"],
            y=yearly["breach_count"],
            mode="lines+markers",
            line=dict(color=COLOURS["secondary"], width=2.5),
            marker=dict(size=6),
            fill="tozeroy",
            fillcolor=f"rgba(224, 82, 82, 0.12)",
            name="Breach Count"))
        
        fig.update_layout( title="Data Breach Count per Year",
            xaxis_title="Year",
            yaxis_title="Number of Breaches",
            template=CHART_TEMPLATE,
            hovermode="x unified",)
        return fig

    def industry_bar(self, df: pd.DataFrame) -> go.Figure:
        """Panel 3 - breaches by industry horizontal bar"""
        if df.empty:
            return self._empty_figure("No industry data available")

        ind_col = "industry" if "industry" in df.columns else df.columns[0]
        cnt_col = "breach_count" if "breach_count" in df.columns else df.columns[1]

        top = df.nlargest(10, cnt_col)

        fig = go.Figure(go.Bar( x=top[cnt_col],y=top[ind_col], orientation="h",marker_color=COLOURS["primary"],
            text=top[cnt_col].apply(lambda x: f"{int(x):,}"), textposition="outside", ))
        fig.update_layout( title="Data Breaches by Industry Sector (Top 10)",xaxis_title="Number of Breaches",yaxis_title="",
            template=CHART_TEMPLATE,yaxis={"categoryorder": "total ascending"},margin={"l": 160},)
        return fig

    def severity_histogram(self, df: pd.DataFrame) -> go.Figure:
        """Panel 4 - CVSS score histogram with severity band shading"""
        if df.empty or "severity" not in df.columns:
            return self._empty_figure("No severity data available")

        sev = pd.to_numeric(df["severity"], errors="coerce").dropna()

        # colour each bar by severity band
        colours_map = { (0,3.9): COLOURS["low"], (4,6.9): COLOURS["medium"],(7,8.9): COLOURS["high"],(9,10): COLOURS["critical"], }

        fig = go.Figure()
        fig.add_trace(go.Histogram( x=sev,nbinsx=40,marker=dict(
            color=sev,colorscale=[[0, COLOURS["low"]], [0.4, COLOURS["medium"]], [0.7, COLOURS["high"]], [1,COLOURS["critical"]],],
                cmin=0, cmax=10,line=dict(width=0.5, color="white"), ), name="CVEs", ))
        fig.add_vline( x=sev.mean(), line_dash="dash", line_color="black",
            annotation_text=f"Mean={sev.mean():.1f}",
            annotation_position="top right")
        fig.update_layout( title="CVSS Severity Score Distribution", xaxis_title="CVSS Score", yaxis_title="Number of CVEs",template=CHART_TEMPLATE,)
        return fig

    def top_vendors_bar(self, df: pd.DataFrame) -> go.Figure:
        """Panel 5 - top 10 vendors (confirmed exploited CVE)"""
        if df.empty or "vendor" not in df.columns:
            return self._empty_figure("No vendor data available")

        col = "confirmed_exploited" if "confirmed_exploited" in df.columns else df.columns[1]
        top = df.nlargest(10, col)

        fig = go.Figure(go.Bar( x=top["vendor"], y=top[col],
            marker_color=COLOURS["critical"],
            text=top[col].apply(lambda x: f"{int(x):,}"),
            textposition="outside", ))
        fig.update_layout(title="Top 10 Vendors by Confirmed Exploited CVEs (CISA KEV)",
            xaxis_title="Vendor", yaxis_title="Exploited CVE Count",
            template=CHART_TEMPLATE,
            xaxis={"tickangle": -30},)
        return fig

    def time_to_exploit_bar(self, df: pd.DataFrame) -> go.Figure:
        """Panel 6 - exploit window distribution -bar chart"""
        if df.empty or "exploit_window" not in df.columns:
            return self._empty_figure("No time-to-exploit data available")

        counts = df["exploit_window"].value_counts().reset_index()
        counts.columns = ["window","count"]

        # sort by logical order
        order = [ "0-7 days (immediate)",
            "8-30 days (fast)",
            "31-90 days (moderate)",
            "91-365 days (slow)",
            "Over 1 year (very slow)",
            "Negative (zero-day / embargoed)",]
        counts["_order"] = counts["window"].apply(lambda w: order.index(w) if w in order else 99 )
        counts = counts.sort_values("_order")

        bar_colours = [ COLOURS["critical"], COLOURS["high"], COLOURS["medium"], COLOURS["low"], COLOURS["primary"], COLOURS["grey"]]

        fig = go.Figure(go.Bar( x=counts["window"],
            y=counts["count"],
            marker_color=bar_colours[:len(counts)],
            text=counts["count"].apply(lambda x: f"{int(x):,}"),
            textposition="outside", ))
        fig.update_layout( title="Time from CVE Disclosure to First Exploitation (RQ5)",
            xaxis_title="Exploit Time Window",
            yaxis_title="Number of CVEs",
            template=CHART_TEMPLATE,
            xaxis={"tickangle": -20}, )
        return fig

    @staticmethod
    def _empty_figure(message: str) -> go.Figure:
        """placeholder figure shown when data is missing"""
        fig = go.Figure()
        fig.add_annotation(text=message, xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(size=14, color=COLOURS["grey"]) )
        fig.update_layout( template=CHART_TEMPLATE, xaxis={"visible": False}, yaxis={"visible": False},)
        return fig

# DashboardLayout

class DashboardLayout:

    def __init__(self):
        self.logger = configure_logger("DashboardLayout")
        self._kpi_builder = KpiTileBuilder()

    def _chart_card(self, chart_id: str, title: str) -> html.Div:
        """wraps dcc.Graph in styled card div"""
        return html.Div(
            style={"backgroundColor": COLOURS["card_bg"],"borderRadius":"10px","padding":"16px","boxShadow":"0 2px 8px rgba(0,0,0,0.08)","marginBottom":"16px",},
            children=[dcc.Graph(id=chart_id, config={"displayModeBar": True, "displaylogo": False},style={"height": "380px"},)])

    def build(self, data: Dict[str, Any]) -> html.Div:
        """build the full page layout with all panels"""
        return html.Div(
            style={"backgroundColor": COLOURS["bg"],"minHeight":"100vh","padding": "24px","fontFamily":"Segoe UI, Arial, sans-serif",},
            children=[
                 # header
                html.Div(
                    style={"marginBottom": "24px"},
                    children=[
                        html.H1( "Cybersecurity Risk Analytics Dashboard",
                            style={"color": COLOURS["dark"], "fontSize": "24px",
                                   "fontWeight": "700", "margin": "0 0 4px 0"}
                        ),
                        html.P("Group E | NCI MS Data Analytics | NVD CVE + CISA KEV + Privacy Rights Clearinghouse",
                            style={"color": COLOURS["grey"], "fontSize": "13px", "margin": "0"}
                        ),] ),

                # KPI tiles
                self._kpi_builder.build_all(data.get("kpis", {})),

                # chart grid - two columns
                html.Div(
                    style={"display": "grid", "gridTemplateColumns": "1fr 1fr", "gap": "16px"},
                    children=[
                        self._chart_card("breach-trend-chart","Breach Trend"),
                        self._chart_card("industry-bar-chart","Industry Breakdown"),
                        self._chart_card("severity-hist-chart", "Severity Distribution"),
                        self._chart_card("vendor-bar-chart", "High Risk Vendors"),
                        self._chart_card("time-to-exploit-chart", "Time to Exploit"), ]  ),

                # footer
                html.P( "Data refreshes on each pipeline run. Last updated by run_pipeline.py",
                    style={"color": COLOURS["grey"], "fontSize": "11px", "textAlign": "center", "marginTop": "24px"}), ] )

# DashboardApp -wires layout + callbacks + server together

class DashboardApp:
    """
    Creates and configures the Dash application. Loads data on startup and populates all charts.
    Callbacks handle interactivity"""

    def __init__(self):
        self.logger=configure_logger("DashboardApp")
        self._loader = DashboardDataLoader()
        self._charts = ChartBuilder()
        self._layout = DashboardLayout()
        self._data= {}
        self._app = dash.Dash( __name__,title="Cybersec Risk Analytics | Group E", update_title=None,)

    def _load_data(self) -> None:
        """load all data """
        self.logger.info("Loading dashboard data on startup...")
        self._data = self._loader.get_all()
        self.logger.info(f"KPIs: CVEs={self._data['kpis'].get('total_cves', 0):,} "
            f"Exploited={self._data['kpis'].get('total_exploited', 0):,} "
            f"Breaches={self._data['kpis'].get('total_breaches', 0):,}" )

    def _setup_layout(self) -> None:
        """set the app layout"""
        self._app.layout = self._layout.build(self._data)

    def _setup_callbacks(self) -> None:
        """ Register Dash callbacks to populate each chart.
        Using server-side callbacks so charts update when data changes. """
        data = self._data      
        
        @self._app.callback(
            Output("breach-trend-chart", "figure"),
            Output("industry-bar-chart", "figure"),
          
            Output("severity-hist-chart", "figure"),
          
            Output("vendor-bar-chart", "figure"),
            Output("time-to-exploit-chart", "figure"),
            Input("breach-trend-chart", "id"), )
        def populate_all_charts(_):
            """populate all five charts from pre-loaded data"""
            return ( self._charts.breach_trend_line(data.get("breach_trend", pd.DataFrame())),
                self._charts.industry_bar(data.get("industry",  pd.DataFrame())),
                    
                self._charts.severity_histogram(data.get("severity", pd.DataFrame())),
                self._charts.top_vendors_bar(data.get("vendors", pd.DataFrame())),
                    
                self._charts.time_to_exploit_bar(data.get("time_to_exploit", pd.DataFrame())),)

    def run(self, host: str = "0.0.0.0", port: int = 8050, debug: bool = False) -> None:
        """start the Dash development server"""
        self._load_data()
        self._setup_layout()
        self._setup_callbacks()

        self.logger.info(f"Dashboard starting at http://localhost:{port}")
        self._app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    app = DashboardApp()
    app.run(debug=True)
