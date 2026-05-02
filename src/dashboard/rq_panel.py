import os
import sys
import logging
from typing import Any, Dict, List, Optional

import pandas as pd
import numpy as np
from dotenv import load_dotenv

import dash
from dash import dcc, html, Input, Output
import plotly.graph_objects as go
import plotly.express as px
import psycopg2

from dashboard.filter_callbacks import ( FilterDataProvider,FilteredDataLoader,FilteredChartBuilder,FilterManager,configure_logger,)

load_dotenv()

ANALYSIS_DIR = "analysis/output"
GRAPH_DIR = "graph/output"

COLOURS = { "primary":"steelblue",  "secondary":"tomato",   "accent":"mustard",   "grey": "grey",
    "dark":"darkblue",  "critical": "red",   "high": "orange",   "medium":"yellow",
    "low": "lightgreen",  "green": "green",
    "card_bg": "lightred", "bg": "lightblue",}

CHART_TEMPLATE = "plotly_white"

# CsvChartLoader

class CsvChartLoader:

    def __init__(self):
        self.logger = configure_logger("CsvChartLoader")

    def load(self, filename: str, folder: str = ANALYSIS_DIR) -> pd.DataFrame:
        path = os.path.join(folder, filename)
        if not os.path.exists(path):
            self.logger.warning(f"CSV not found: {path}")
            return pd.DataFrame()
        df = pd.read_csv(path, low_memory=False)
        self.logger.debug(f"Loaded {path}: {len(df):,} rows")
        return df

# RQ Chart Builders

class RQ1ChartBuilder:
    """
    RQ1: How do actively exploited vulnerabilities relate to breach
    patterns across industry sectors and time?
    Chart: heatmap of breach count per industry per year
    Interpretation: which sectors have consistently high breach rates
    """

    def __init__(self, loader: CsvChartLoader):
        self.logger = configure_logger("RQ1ChartBuilder")
        self._loader = loader

    def build_chart(self) -> go.Figure:
        df = self._loader.load("rq1_industry_breach_trends.csv")
        if df.empty:
            return self._empty("RQ1 data not available - run sql_analysis.py")

        if "breach_year" not in df.columns or "industry" not in df.columns:
            return self._empty("Unexpected column structure in RQ1 CSV")

        df = df[df["breach_year"].notna() & df["industry"].notna()]
        df["breach_year"] = df["breach_year"].astype(int)

        # pivot for heatmap: rows = industry, cols = year
        pivot = df.pivot_table( index="industry",columns="breach_year",values="breach_count",aggfunc="sum",fill_value=0)

        # keep top 10 industries by total breach count
        pivot["total"] = pivot.sum(axis=1)
        pivot = pivot.nlargest(10, "total").drop(columns="total")

        fig = go.Figure(go.Heatmap(z=pivot.values,
            x=[str(c) for c in pivot.columns],
            y=pivot.index.tolist(),
            colorscale="Blues",
            text=pivot.values,
            texttemplate="%{text}",
            hovertemplate="Industry: %{y}<br>Year: %{x}<br>Breaches: %{z}<extra></extra>",
            colorbar=dict(title="Breach Count"),))
        
        fig.update_layout(title="RQ1 — Breach Count per Industry Sector per Year",
            xaxis_title="Year",
            yaxis_title="Industry",
            template=CHART_TEMPLATE,
            margin=dict(l=180),)
        return fig

    def get_key_finding(self, df: pd.DataFrame = None) -> str:
        if df is None:
            loader = CsvChartLoader()
            df = loader.load("rq1_industry_breach_trends.csv")
        if df.empty:
            return "No data available."
        top_industry = df.groupby("industry")["breach_count"].sum().idxmax()
        total_top = df.groupby("industry")["breach_count"].sum().max()
        return (f"{top_industry} has the highest cumulative breach count "
            f"({int(total_top):,} breaches), suggesting it is the most "
            f"persistently targeted sector across the study period." )

    @staticmethod
    def _empty(msg: str) -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(text=msg, xref="paper", yref="paper",x=0.5, y=0.5, showarrow=False,font=dict(size=13, color=COLOURS["grey"]))
        fig.update_layout(template=CHART_TEMPLATE,xaxis={"visible": False}, yaxis={"visible": False})
        return fig


class RQ2ChartBuilder:
    """
    RQ2: Do breach counts increase in the period after disclosure of
    high severity CVEs?
    Chart: grouped bar - breaches within 30/60/90 days of CVE disclosure
    """

    def __init__(self, loader: CsvChartLoader):
        self.logger = configure_logger("RQ2ChartBuilder")
        self._loader = loader

    def build_chart(self) -> go.Figure:
        df = self._loader.load("rq2_breach_lag_after_cve.csv")
        if df.empty:
            return self._empty("RQ2 data not available")

        needed = ["cve_id", "breaches_within_30_days", "breaches_within_60_days", "breaches_within_90_days"]
        if not all(c in df.columns for c in needed):
            return self._empty("Unexpected column structure in RQ2 CSV")

        # top 15 CVEs by 90-day breach count
        top = df.nlargest(15, "breaches_within_90_days").head(15)

        fig = go.Figure()
        fig.add_trace(go.Bar(name="Within 30 days", x=top["cve_id"],y=top["breaches_within_30_days"],marker_color=COLOURS["critical"], ))
        fig.add_trace(go.Bar(  name="Within 60 days", x=top["cve_id"], y=top["breaches_within_60_days"], marker_color=COLOURS["high"],))
        fig.add_trace(go.Bar( name="Within 90 days", x=top["cve_id"], y=top["breaches_within_90_days"], marker_color=COLOURS["medium"],  ))
        fig.update_layout( title="RQ2 — Breach Count in 30/60/90 Days After High-Severity CVE Disclosure",xaxis_title="CVE ID", yaxis_title="Linked Breaches",
            template=CHART_TEMPLATE, barmode="group", xaxis={"tickangle": -35}, legend=dict(orientation="h", y=-0.25), )
        return fig

    def get_key_finding(self) -> str:
        df = CsvChartLoader().load("rq2_breach_lag_after_cve.csv")
        if df.empty:
            return "No data available."
        avg_30 = df["breaches_within_30_days"].mean()
        avg_90 = df["breaches_within_90_days"].mean()
        increase = ((avg_90 - avg_30) / avg_30 * 100) if avg_30 > 0 else 0
        return ( f"On average {avg_30:.1f} breaches occur within 30 days and {avg_90:.1f} within 90 days of a high-severity CVE disclosure ({increase:.0f}% increase over the 30-90 day window).")

    @staticmethod
    def _empty(msg: str) -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(text=msg, xref="paper", yref="paper",x=0.5, y=0.5, showarrow=False,font=dict(size=13, color=COLOURS["grey"]))
        fig.update_layout(template=CHART_TEMPLATE,xaxis={"visible": False}, yaxis={"visible": False})
        return fig


class RQ3ChartBuilder:
    """
    RQ3: Can severity scores and exploitation status predict breach risk?
    Chart: scatter plot - exploitation rate vs average severity per industry
    """

    def __init__(self, loader: CsvChartLoader):
        self.logger = configure_logger("RQ3ChartBuilder")
        self._loader = loader

    def build_chart(self) -> go.Figure:
        df = self._loader.load("rq3_severity_vs_breach_rate.csv") # TODO Need to generate csv?
        if df.empty:
            return self._empty("RQ3 data not available")

        needed = ["severity_band", "industry", "breach_count", "cve_count"]
        if not all(c in df.columns for c in needed):
            return self._empty("Unexpected column structure in RQ3 CSV")

        # aggregate by severity band
        agg = df.groupby("severity_band").agg(total_breaches = ("breach_count", "sum"),
            total_cves = ("cve_count", "sum"),
            total_exploited = ("exploited_count", "sum"),
            avg_exploit_rate= ("exploitation_rate_pct", "mean"), ).reset_index()

        band_order = [ "Critical (9.0-10.0)", "High (7.0-8.9)", "Medium (4.0-6.9)", "Low (0.1-3.9)", "No Score"]
        agg["_order"] = agg["severity_band"].apply(lambda b: band_order.index(b) if b in band_order else 99 )
        agg = agg.sort_values("_order")

        bar_colours = [COLOURS["critical"], COLOURS["high"], COLOURS["medium"],COLOURS["low"], COLOURS["grey"] ]

        fig = go.Figure()
        fig.add_trace(go.Bar(name="Total Breaches",x=agg["severity_band"],y=agg["total_breaches"],
                             marker_color=bar_colours[:len(agg)],yaxis="y",))
        fig.add_trace(go.Scatter( name="Avg Exploitation Rate (%)",
            x=agg["severity_band"], y=agg["avg_exploit_rate"],
            mode="lines+markers",
            line=dict(color=COLOURS["dark"], width=2, dash="dash"),
            marker=dict(size=8), yaxis="y2",))
        
        fig.update_layout(title="RQ3 — Breach Count and Exploitation Rate by Severity Band",
            xaxis_title="Severity Band",  yaxis=dict(title="Total Linked Breaches", side="left"),
            yaxis2=dict(title="Avg Exploitation Rate (%)", side="right", overlaying="y", showgrid=False),
            template=CHART_TEMPLATE,
            legend=dict(orientation="h", y=-0.2),)
        return fig

    def get_key_finding(self) -> str:
        df = CsvChartLoader().load("rq3_severity_vs_breach_rate.csv")
        if df.empty:
            return "No data available."
        if "exploitation_rate_pct" in df.columns and "severity_band" in df.columns:
            top = df.groupby("severity_band")["exploitation_rate_pct"].mean().idxmax()
            rate = df.groupby("severity_band")["exploitation_rate_pct"].mean().max()
            return ( f"'{top}' CVEs have the highest average exploitation rate "
                f"({rate:.1f}%), supporting the hypothesis that severity "
                f"score is a useful leading indicator of breach risk." )
        return "Exploitation rate data not available for RQ3."

    @staticmethod
    def _empty(msg: str) -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(text=msg, xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(size=13, color=COLOURS["grey"]))
        fig.update_layout(template=CHART_TEMPLATE, xaxis={"visible": False}, yaxis={"visible": False})
        return fig


class RQ4ChartBuilder:
    """
    RQ4: Which vendors are most consistently associated with high-severity
    vulnerabilities and real breach incidents?
    Chart: bubble chart - exploited CVEs vs avg CVSS, bubble size = breach count
    """

    def __init__(self, loader: CsvChartLoader):
        self.logger = configure_logger("RQ4ChartBuilder")
        self._loader = loader

    def build_chart(self) -> go.Figure:
        df = self._loader.load("rq4_high_risk_vendors.csv")
        if df.empty:
            return self._empty("RQ4 data not available")

        needed = ["vendor", "confirmed_exploited", "avg_cvss_score"]
        if not all(c in df.columns for c in needed):
            return self._empty("Unexpected column structure in RQ4 CSV")

        df = df.dropna(subset=["vendor", "confirmed_exploited", "avg_cvss_score"])
        df["confirmed_exploited"] = pd.to_numeric(df["confirmed_exploited"], errors="coerce").fillna(0)
        df["avg_cvss_score"] = pd.to_numeric(df["avg_cvss_score"], errors="coerce").fillna(0)

        bubble_size = df.get("linked_breaches", pd.Series([10]*len(df))).fillna(5) + 5
        bubble_size = (bubble_size / bubble_size.max() * 50).clip(lower=5)

        fig = go.Figure(go.Scatter( x=df["avg_cvss_score"], y=df["confirmed_exploited"],
            mode="markers+text",
            marker=dict(size=bubble_size,color=df["avg_cvss_score"],colorscale="Reds",showscale=True,
                        colorbar=dict(title="Avg CVSS"),line=dict(width=1, color="white"),),
            text=df["vendor"],
            textposition="top center", textfont=dict(size=9),
            hovertemplate=("<b>%{text}</b><br>"
                "Avg CVSS: %{x:.2f}<br>"
                "Exploited CVEs: %{y:,}<extra></extra>"),))

        # quadrant lines
        fig.add_hline(y=df["confirmed_exploited"].median(), line_dash="dot", line_color=COLOURS["grey"], opacity=0.5)
        fig.add_vline(x=7.0, line_dash="dot", line_color=COLOURS["grey"], opacity=0.5)

        fig.update_layout(title=("RQ4 — Vendor Risk: Avg CVSS vs Confirmed Exploited CVEs\n (Bubble size = linked breach count)"),
            xaxis_title="Average CVSS Score",yaxis_title="Confirmed Exploited CVEs (CISA KEV)",template=CHART_TEMPLATE, )
        return fig

    def get_key_finding(self) -> str:
        df = CsvChartLoader().load("rq4_high_risk_vendors.csv")
        if df.empty:
            return "No data available."
        if "confirmed_exploited" in df.columns and "vendor" in df.columns:
            top = df.nlargest(1, "confirmed_exploited").iloc[0]
            return (f"{top['vendor']} leads with {int(top['confirmed_exploited']):,} confirmed exploited CVEs and an average CVSS of "
                    f"{float(top.get('avg_cvss_score', 0)):.1f}, making it the highest-risk vendor in the dataset." )
        return "No vendor ranking data available."

    @staticmethod
    def _empty(msg: str) -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(text=msg, xref="paper", yref="paper",x=0.5, y=0.5, showarrow=False,font=dict(size=13, color=COLOURS["grey"]))
        fig.update_layout(template=CHART_TEMPLATE,xaxis={"visible": False}, yaxis={"visible": False})
        return fig


class RQ5ChartBuilder:
    """  RQ5: What is the typical time gap between vulnerability disclosure
    and a linked breach incident?
    Chart: box plot of days_to_exploit grouped by severity band + summary stat cards"""

    def __init__(self, loader: CsvChartLoader):
        self.logger = configure_logger("RQ5ChartBuilder")
        self._loader = loader

    def build_chart(self) -> go.Figure:
        df = self._loader.load("rq5_time_to_exploit.csv")
        if df.empty:
            return self._empty("RQ5 data not available")

        if "days_to_exploit" not in df.columns:
            return self._empty("days_to_exploit column missing from RQ5 CSV")

        df["days_to_exploit"] = pd.to_numeric(df["days_to_exploit"], errors="coerce")
        df = df[df["days_to_exploit"] >= 0].copy()

        if df.empty:
            return self._empty("No valid (positive) time-to-exploit values found")

        # box plot by severity band if available, else single box
        if "exploit_window" in df.columns:
            order = [ "0-7 days (immediate)","8-30 days (fast)","31-90 days (moderate)", "91-365 days (slow)","Over 1 year (very slow)",]
            window_colours = { "0-7 days (immediate)":COLOURS["critical"],
                "8-30 days (fast)": COLOURS["high"], "31-90 days (moderate)": COLOURS["medium"],
                "91-365 days (slow)": COLOURS["low"], "Over 1 year (very slow)":COLOURS["primary"],}
            fig = go.Figure()
            for window in order:
                subset = df[df["exploit_window"] == window]["days_to_exploit"]
                if subset.empty:
                    continue
                fig.add_trace(go.Box( y=subset,name=window,marker_color=window_colours.get(window, COLOURS["grey"]),boxpoints="outliers", ))
        else:
            fig = go.Figure(go.Box( y=df["days_to_exploit"], name="All CVEs", marker_color=COLOURS["primary"], boxpoints="outliers", ))

        median_days = df["days_to_exploit"].median()
        fig.add_hline( y=median_days, line_dash="dash", line_color="black", annotation_text=f"Overall median = {median_days:.0f} days",annotation_position="top right")

        fig.update_layout( title="RQ5 — Days from CVE Disclosure to First Exploitation",
            yaxis_title="Days to Exploit", template=CHART_TEMPLATE,showlegend=True,legend=dict(orientation="h", y=-0.3),)
        return fig

    def get_key_finding(self) -> str:
        df = CsvChartLoader().load("rq5_time_to_exploit.csv")
        if df.empty:
            return "No data available."
        df["days_to_exploit"] = pd.to_numeric(df.get("days_to_exploit"), errors="coerce")
        valid = df[df["days_to_exploit"] >= 0]["days_to_exploit"]
        if valid.empty:
            return "No valid exploit time data."
        pct_30 = (valid <= 30).sum() / len(valid) * 100
        return ( f"Median time to exploitation is {valid.median():.0f} days. "
            f"{pct_30:.1f}% of exploited CVEs are weaponised within 30 days of public disclosure, underlining the urgency of rapid patching." )

    @staticmethod
    def _empty(msg: str) -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(text=msg, xref="paper", yref="paper",x=0.5, y=0.5, showarrow=False,font=dict(size=13, color=COLOURS["grey"]))
        fig.update_layout(template=CHART_TEMPLATE,xaxis={"visible": False}, yaxis={"visible": False})
        return fig


# RQDashboardLayout - final full dashboard layout with all panels including RQ sections

class RQDashboardLayout:

    CARD_STYLE = { "backgroundColor": COLOURS["card_bg"],
        "borderRadius": "10px",
        "padding": "16px", "boxShadow":"0 2px 8px rgba(0,0,0,0.08)",
        "marginBottom": "16px", }

    def __init__(self):
        self.logger = configure_logger("RQDashboardLayout")

    def _chart_card(self, chart_id: str, height: str = "400px") -> html.Div:
        return html.Div(
            style=self.CARD_STYLE,
            children=[
                dcc.Graph(
                    id=chart_id, config={"displayModeBar": True, "displaylogo": False},
                    style={"height": height},
                )
            ]
        )

    def _finding_card(self, card_id: str, rq_label: str, colour: str) -> html.Div:
        """small card showing the key finding text for one RQ"""
        return html.Div(
            style={
                **self.CARD_STYLE,
                "borderLeft": f"4px solid {colour}",
                "padding": "12px 16px",
            },
            children=[
                html.P(
                    rq_label,
                    style={"color": colour, "fontWeight": "700","fontSize": "12px", "margin": "0 0 6px 0"}
                ),
                html.P(
                    id=card_id,
                    style={"color": COLOURS["dark"], "fontSize": "13px", "margin": "0"}
                ),
            ]
        )

    def _filter_sidebar(self, options: Dict[str, Any]) -> html.Div:
        yr_min = options.get("year_min", 2005)
        yr_max = options.get("year_max", 2024)
        inds = options.get("industry_options", [])

        return html.Div(
            style={
                **self.CARD_STYLE, "position": "sticky",
                "top": "16px", "height": "fit-content",
            },
            children=[
                html.H4(
                    "Filters",
                    style={"color": COLOURS["dark"], "margin": "0 0 16px 0","fontSize": "15px", "fontWeight": "700"}
                ),

                html.Label("Year Range", style={"fontSize": "12px", "color": COLOURS["grey"]}),
                dcc.RangeSlider(
                    id="year-range-slider", min=yr_min, max=yr_max,
                    value=[max(yr_min, 2015), yr_max],
                    marks={y: str(y) for y in range(yr_min, yr_max+1, 5)},
                    tooltip={"placement": "bottom", "always_visible": False},
                    step=1,
                ),
                html.Div(style={"height": "16px"}),

                html.Label("Industry", style={"fontSize": "12px", "color": COLOURS["grey"]}),
                dcc.Dropdown(
                    id="industry-dropdown",
                    options=inds,  multi=True,
                    placeholder="All industries....",  style={"fontSize": "13px"},
                ),
                html.Div(style={"height": "16px"}),

                html.Label("Min CVSS Severity", style={"fontSize": "12px", "color": COLOURS["grey"]}),
                dcc.Slider(
                    id="severity-min-slider",
                    min=0, max=10, step=0.5,
                    value=0,  marks={0: "0", 4: "4", 7: "7", 9: "9", 10: "10"},
                    tooltip={"placement": "bottom", "always_visible": False},
                ),
            ]
        )

    def _kpi_tile(
        self, title:   str,
        value_id: str,  subtitle: str,
        colour:  str
    ) -> html.Div:
        return html.Div(
            style={
                "backgroundColor": COLOURS["card_bg"],
                "borderRadius": "10px", "padding": "18px 22px",
                "boxShadow": "0 2px 8px rgba(0,0,0,0.08)", "borderLeft": f"4px solid {colour}",
                "flex": "1",
                "minWidth": "160px", },
            children=[
                html.P(title, style={"color": COLOURS["grey"], "fontSize": "12px","margin": "0 0 4px 0", "fontWeight": "500"}),
                html.H2(id=value_id, style={"color": colour, "fontSize": "28px", "margin": "0 0 4px 0", "fontWeight": "700"}, children="..."),
                html.P(subtitle, style={"color": COLOURS["grey"], "fontSize": "11px","margin": "0"}),]
        )

    def build(self, options: Dict[str, Any]) -> html.Div:
        """build the complete final dashboard layout"""
        return html.Div(
            style={"backgroundColor": COLOURS["bg"], "minHeight": "100vh",
                   "fontFamily": "Segoe UI, Arial, sans-serif"},
            children=[

                # sticky header bar
                html.Div(
                    style={"backgroundColor": COLOURS["dark"], "padding": "14px 28px",
                           "display": "flex", "alignItems": "center", "gap": "16px"},
                    children=[
                        html.H1(
                            "Cybersecurity Risk Analytics",
                            style={"color": "white", "fontSize": "20px", "fontWeight": "700", "margin": "0"}
                        ),
                        html.Span(
                            "Group E  |  NCI MS Data Analytics",
                            style={"color": "blue", "fontSize": "13px"}
                        ),
                    ]
                ),

                # main body: sidebar + content
                html.Div(
                    style={"display": "flex", "gap": "20px",
                           "padding": "20px 24px", "alignItems": "flex-start"},
                    children=[

                        # left sidebar: filters
                        html.Div(
                            style={"width": "240px", "flexShrink": "0"},
                            children=[self._filter_sidebar(options)]
                        ),

                        # right content area
                        html.Div(
                            style={"flex": "1", "minWidth": "0"},
                            children=[

                                # KPI row
                                html.Div(
                                    style={"display": "flex", "gap": "14px",
                                           "flexWrap": "wrap", "marginBottom": "20px"},
                                    children=[
                                        self._kpi_tile("Total CVEs (NVD)", "kpi-cve-value",
                                                       "All disclosed vulnerabilities", COLOURS["primary"]),
                                        self._kpi_tile("Exploited (KEV)",  "kpi-kev-value",
                                                       "Confirmed active exploitation", COLOURS["critical"]),
                                        self._kpi_tile("Data Breaches",    "kpi-breach-value",
                                                       "Breach incidents in filtered range", COLOURS["secondary"]),
                                        self._kpi_tile("Records Exposed",  "kpi-records-value",
                                                       "Total individual records", COLOURS["accent"]),
                                    ]
                                ),

                                # key finding cards row
                                html.Div(
                                    style={"display": "grid",
                                           "gridTemplateColumns": "1fr 1fr 1fr",
                                           "gap": "12px", "marginBottom": "20px"},
                                    children=[
                                        self._finding_card("rq1-finding", "RQ1", COLOURS["primary"]),
                                      
                                        self._finding_card("rq2-finding", "RQ2", COLOURS["secondary"]),
                                        self._finding_card("rq3-finding", "RQ3", COLOURS["accent"]),
                                      
                                        self._finding_card("rq4-finding", "RQ4", COLOURS["critical"]),
                                        self._finding_card("rq5-finding", "RQ5", COLOURS["green"]),
                                    ]
                                ),

                                # chart grid: 2 columns
                                html.Div(
                                    style={"display": "grid",
                                           "gridTemplateColumns": "1fr 1fr",
                                           "gap": "16px"},
                                    children=[
                                        self._chart_card("rq1-chart", "380px"),  self._chart_card("rq2-chart", "380px"),
                                        self._chart_card("rq3-chart", "380px"),
                                        self._chart_card("rq4-chart", "420px"),  self._chart_card("rq5-chart", "380px"),
                                        self._chart_card("graph-vendor-risk-chart", "380px"),
                                        # full width community chart
                                        html.Div(
                                            style={**self.CARD_STYLE, "gridColumn": "1 / -1"},
                                            children=[
                                                dcc.Graph(
                                                    id="industry-community-chart",
                                                    config={"displayModeBar": True, "displaylogo": False},
                                                    style={"height": "300px"},
                                                )
                                            ]
                                        ),
                                    ]
                                ),

                                html.P(
                                    "Nilesh (25168304) · Shivakshi (24293113) · Teena (25141970)  |  "
                                    "Data sources: NVD CVE API · CISA KEV · Privacy Rights Clearinghouse",
                                    style={"color": COLOURS["grey"], "fontSize": "11px",
                                           "textAlign": "center", "marginTop": "20px"}
                                ),
                            ]
                        ),
                    ]
                ),
            ]
        )


# RQDashboardApp 

class RQDashboardApp:
    """
    Includes all five RQ panels
    """

    def __init__(self):
        self.logger = configure_logger("RQDashboardApp")
        self._loader = CsvChartLoader()
        self._layout = RQDashboardLayout()
        self._app = dash.Dash(__name__,title="Cybersec Risk Analytics | Group E",update_title=None,)

        # RQ chart builders
        self._rq1 = RQ1ChartBuilder(self._loader)
        self._rq2 = RQ2ChartBuilder(self._loader)
        self._rq3 = RQ3ChartBuilder(self._loader)
        self._rq4 = RQ4ChartBuilder(self._loader)
        self._rq5 = RQ5ChartBuilder(self._loader)
        self._filtered_charts = FilteredChartBuilder()

    def _setup_layout(self, options: Dict[str, Any]) -> None:
        self._app.layout = self._layout.build(options)

    def _register_rq_callbacks(self) -> None:

        @self._app.callback(
            Output("rq1-chart", "figure"),
            Output("rq2-chart", "figure"),
            Output("rq3-chart", "figure"),
            Output("rq4-chart", "figure"),
            Output("rq5-chart", "figure"),
            Output("rq1-finding", "children"),
            Output("rq2-finding", "children"),
            Output("rq3-finding", "children"),
            Output("rq4-finding", "children"),
            Output("rq5-finding", "children"),
            Input("rq1-chart", "id"),    # dummy trigger on load
        )
        def populate_rq_charts(_):
            return (self._rq1.build_chart(),
                self._rq2.build_chart(),
                self._rq3.build_chart(),
                self._rq4.build_chart(),
                self._rq5.build_chart(),
                self._rq1.get_key_finding(),
                self._rq2.get_key_finding(),
                self._rq3.get_key_finding(),
                self._rq4.get_key_finding(),
                self._rq5.get_key_finding(),)

    def run(self, host: str = "0.0.0.0", port: int = 8050, debug: bool = False) -> None:
        self.logger.info("Loading filter options...")
        options = FilterDataProvider().get_all_options()

        self._setup_layout(options)
        self._register_rq_callbacks()

        # wire filter callbacks from filter_callbacks.py
        filter_mgr = FilterManager(self._app, options)
        filter_mgr.register_all()

        self.logger.info(f"Dashboard ready at http://localhost:{port}")
        self._app.run(host=host, port=port, debug=debug)


# run: python dashboard/rq_panels.py
if __name__ == "__main__":
    app = RQDashboardApp()
    app.run(debug=True)
