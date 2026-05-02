
import os
import sys
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st


st.set_page_config(
    page_title="Cybersecurity Risk Analytics | Group E",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


ANALYSIS_DIR = os.path.join(os.path.dirname(__file__), "..", "analysis", "output")
ANALYSIS_DIR = os.path.normpath(ANALYSIS_DIR)

# colour palette 
C = {
    "primary": "#1B3A6B", "red": "#C0392B", "orange":"#E67E22",
    "green": "#27AE60", "teal":"#16A085",
    "purple": "#7D3C98", "critical": "#C0392B", "high": "#E67E22",
    "medium": "#F1C40F", "low": "#27AE60",
    "grey": "#7F8C8D",
}

PLOTLY_TEMPLATE = "plotly_white"


st.markdown("""
<style>
    /* font */
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'IBM Plex Sans', sans-serif;
    }

    /* header bar. Light green for now */
    .main-header {
        background: linear-gradient(135deg, #E6E6FA 0%, #D8B4F8 100%);
        padding: 20px 32px;
        border-radius: 12px;
        margin-bottom: 24px;
        border-left: 5px solid #E74C3C;
    }
    .main-header h1 {
        color: black;
        font-size: 32px;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .main-header p {
        color: #94A3B8;
        font-size: 13px;
        margin: 4px 0 0 0;
    }

    /* KPI tile */
    .kpi-box {
        background: white;
        border-radius: 10px;
        padding: 18px 20px;
        border-left: 4px solid #1B3A6B;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    .kpi-label {
        font-size: 11px;
        font-weight: 600;
        color: #7F8C8D;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-bottom: 6px;
    }
    .kpi-value {
        font-size: 32px;
        font-weight: 700;
        color: #1B3A6B;
        font-family: 'IBM Plex Mono', monospace;
        line-height: 1;
    }
    .kpi-sub {
        font-size: 11px;
        color: #95A5A6;
        margin-top: 4px;
    }

    /* section header */
    .section-header {
        background: #F8F9FA;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 20px 0 12px 0;
        border-left: 4px solid #1B3A6B;
    }
    .section-header h3 {
        margin: 0;
        font-size: 16px;
        font-weight: 600;
        color: #1B3A6B;
    }
    .section-header p {
        margin: 4px 0 0 0;
        font-size: 12px;
        color: #7F8C8D;
    }

    /* finding card */
    .finding-card {
        background: #EBF5FB;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 8px;
        border-left: 3px solid #2E86C1;
        font-size: 13px;
        color: #1B2631;
        line-height: 1.5;
    }

    /* sidebar: Grey color and Black text */
    [data-testid="stSidebar"] {
        background: #E6E6FA 0%, #D8B4F8 100%;
    }
    [data-testid="stSidebar"] * {
        color: black !important;
    }

    /* hide streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: visible;}
    [data-testid="stToolbar"] {visibility: hidden;}

    /* plotly chart border */
    .js-plotly-plot {
        border-radius: 10px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


# CSV loader

@st.cache_data(ttl=300)
def load_csv(filename: str) -> pd.DataFrame:
    """Load a CSV from analysis/output/. Returns empty df if not found."""
    path = os.path.join(ANALYSIS_DIR, filename)
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        df = pd.read_csv(path, low_memory=False)
        return df
    except Exception:
        return pd.DataFrame()


def fmt_number(n) -> str:
    """Format large numbers with K/M/B suffix."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "N/A"
    if n >= 1_000_000_000:
        return f"{n/1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return f"{n:,.0f}"

# Dashboard showing "Unkwn" for all other industries, fixing issue with fun
def rename_unknown(df: pd.DataFrame, col: str = "industry") -> pd.DataFrame:
    # privacy rights clearinghouse uses Unknown/Bsr codes that look ugly on charts
    if col not in df.columns:
        return df
    df = df.copy()
    df[col] = df[col].replace({
        "Unknown": "All Others",
        "Unkn":    "All Others",
        "unknown": "All Others",
        "Bsr":     "Business / Services",
    })
    return df



df_a1=load_csv("a1_industry_impact.csv")
df_a2 = load_csv("a2_yearly_threat_landscape.csv")
df_a3=load_csv("a3_attack_severity_patterns.csv")
df_a4=load_csv("a4_most_exploited_vendors.csv")
df_a5=load_csv("a5_time_to_weaponisation.csv")

df_breach_types = load_csv("extra_breach_types.csv")
df_cve_monthly = load_csv("extra_cve_monthly_volume.csv")
df_industry_enr=load_csv("extra_industry_summary.csv")
df_top_products= load_csv("extra_top_products.csv")
df_weapon_stats = load_csv("extra_weaponisation_summary.csv")

df_a1 = rename_unknown(df_a1)
df_breach_types = rename_unknown(df_breach_types, col="breach_type")



with st.sidebar:
    st.markdown("### Cybersecurity\nRisk Analytics")
    st.markdown("---")
    st.markdown("**Group E · NCI MS Data Analytics**")
    st.markdown("Nilesh · Shivakshi · Teena")
    st.markdown("---")

    st.markdown("#### Filters")

    # year filter - from a2 data
    yr_min, yr_max = 2010, 2024
    if not df_a2.empty and "year" in df_a2.columns:
        yr_min = int(df_a2["year"].min())
        yr_max = int(df_a2["year"].max())

    year_range = st.slider(
        "Year Range", min_value=yr_min,
        max_value=yr_max, value=(max(yr_min, 2015), yr_max),
        step=1,
    )


    industries = []
    if not df_a1.empty and "industry" in df_a1.columns:
        industries = sorted(df_a1["industry"].dropna().unique().tolist())

    selected_industries = st.multiselect(
        "Industry",
        options=industries,
        default=[],
        placeholder="All industries",
    )

    # severity filter
    min_severity = st.slider(
        "Min CVSS Severity", min_value=0.0,
        max_value=10.0, value=0.0,  step=0.5, )

    st.markdown("---")
    st.markdown("**Data Sources**")
    st.markdown("- NVD CVE API")
    st.markdown("- CISA KEV Catalog")
    st.markdown("- Privacy Rights Clearinghouse")
    st.markdown("---")
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()


def filter_by_year(df, col="year"):
    if df.empty or col not in df.columns:
        return df
    df[col] = pd.to_numeric(df[col], errors="coerce")
    return df[df[col].between(year_range[0], year_range[1])]

def filter_by_industry(df, col="industry"):
    if df.empty or not selected_industries or col not in df.columns:
        return df
    return df[df[col].isin(selected_industries)]

df_a1_f = filter_by_industry(df_a1)
df_a2_f = filter_by_year(df_a2)



st.markdown("""
<div class="main-header">
    <h1>🔐 Cybersecurity Risk Analytics Dashboard</h1>
    <p><!-- Group E &nbsp;·&nbsp; MS Data Analytics &nbsp;·&nbsp; National College of Ireland &nbsp;·&nbsp; -->
    Sources: NIST NVD &nbsp;|&nbsp; CISA KEV &nbsp;|&nbsp; Privacy Rights Clearinghouse</p>
</div>
""", unsafe_allow_html=True)



kpi1, kpi2, kpi3, kpi4 = st.columns(4)

total_cves = df_a3["total_cves"].sum() if not df_a3.empty and "total_cves" in df_a3.columns else 0
kpi1.markdown(f"""
<div class="kpi-box" style="border-left-color: #1B3A6B;">
    <div class="kpi-label">Total CVEs (NVD)</div>
    <div class="kpi-value" style="color:#1B3A6B;">{fmt_number(total_cves)}</div>
    <div class="kpi-sub">All disclosed vulnerabilities</div>
</div>
""", unsafe_allow_html=True)


total_exploited = df_a3["exploited_cves"].sum() if not df_a3.empty and "exploited_cves" in df_a3.columns else 0
kpi2.markdown(f"""
<div class="kpi-box" style="border-left-color: #C0392B;">
    <div class="kpi-label">Exploited (CISA KEV)</div>
    <div class="kpi-value" style="color:#C0392B;">{fmt_number(total_exploited)}</div>
    <div class="kpi-sub">Confirmed active exploitation</div>
</div>
""", unsafe_allow_html=True)


total_breaches = df_a1["breach_count"].sum() if not df_a1.empty and "breach_count" in df_a1.columns else 0
kpi3.markdown(f"""
<div class="kpi-box" style="border-left-color: #E67E22;">
    <div class="kpi-label">Data Breaches</div>
    <div class="kpi-value" style="color:#E67E22;">{fmt_number(total_breaches)}</div>
    <div class="kpi-sub">Breach incidents across all sectors</div>
</div>
""", unsafe_allow_html=True)


total_records = df_a1["total_records_exposed"].sum() if not df_a1.empty and "total_records_exposed" in df_a1.columns else 0
kpi4.markdown(f"""
<div class="kpi-box" style="border-left-color: #27AE60;">
    <div class="kpi-label">Records Exposed</div>
    <div class="kpi-value" style="color:#27AE60;">{fmt_number(total_records)}</div>
    <div class="kpi-sub">All years incl. Yahoo 3B, LinkedIn 700M</div>
</div>
""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# 
# 

st.markdown("""
<div class="section-header">
    <h3>A1 : Industry Impact Analysis</h3>
    <p>Which sectors experience the most breaches and the highest volume of exposed records?</p>
</div>
""", unsafe_allow_html=True)

if df_a1_f.empty:
    st.warning("a1_industry_impact.csv not found. Run sql_analysis.py first.")
else:
    col_left, col_right = st.columns(2)

    with col_left:
        
        df_plot = df_a1_f.sort_values("breach_count", ascending=True)
        colour_map = {
        "Healthcare":"#C39BD3", "All Others": "#A9DFBF",
            "Financial Services": "#85C1E9", "Education": "#7FB3D3",
        "Government/Military":"#5D8AA8", "Business/Other": "#82E0AA",
        "Business/Services": "#82E0AA", "Non-Profit": "#A3C4BC",
        }
        bar_colours = [colour_map.get(ind, "#AED6F1") for ind in df_plot["industry"]]
        fig = go.Figure(go.Bar(
            x=df_plot["breach_count"],
            y=df_plot["industry"],
            orientation="h",  marker=dict(color=bar_colours),
            text=df_plot["breach_count"].apply(lambda x: f"{int(x):,}"),
            textposition="outside", hovertemplate="<b>%{y}</b><br>Breaches: %{x:,}<extra></extra>",
        ))
        fig.update_layout(
            title="Breach Count by Industry Sector",
            xaxis_title="Number of Breaches",  yaxis_title="", template=PLOTLY_TEMPLATE,
            height=380,  margin=dict(l=10, r=60, t=45, b=10),
            font=dict(family="IBM Plex Sans"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
       
        df_plot2 = df_a1_f[df_a1_f["total_records_exposed"] > 0].copy()
        df_plot2["records_fmt"] = df_plot2["total_records_exposed"].apply(
                lambda x: f"{x/1e9:.1f}B" if x >= 1e9 else f"{x/1e6:.1f}M" if x >= 1e6 else f"{x/1e3:.0f}K"
            )
        if not df_plot2.empty:
            fig2 = px.treemap(
                df_plot2, path=["industry"],values="total_records_exposed",
                color="breach_count", color_continuous_scale="Purples",
                title="Records Exposed by Sector",
                custom_data=["records_fmt"],
            )
            fig2.update_layout(
                template=PLOTLY_TEMPLATE, height=380, margin=dict(l=10, r=10, t=45, b=10),
                font=dict(family="IBM Plex Sans"),
            )
            fig2.update_traces(
                hovertemplate="<b>%{label}</b><br>Records: %{customdata[0]}<extra></extra>",
                texttemplate="%{label}<br>%{customdata[0]}",
            )
            st.plotly_chart(fig2, use_container_width=True)

   
    if not df_a1_f.empty and "breach_count" in df_a1_f.columns:
        top_sector = df_a1_f.loc[df_a1_f["breach_count"].idxmax(), "industry"]
        top_count  = df_a1_f["breach_count"].max()
        top_records = df_a1_f.loc[df_a1_f["total_records_exposed"].idxmax(), "industry"]
        st.markdown(f"""
        <div class="finding-card">
        <strong>Key Finding:</strong> <em>{top_sector}</em> has the highest breach count
        ({int(top_count):,} incidents). <em>{top_records}</em> has the highest total records exposed,
        suggesting larger average breach sizes in that sector.
        </div>
        """, unsafe_allow_html=True)

    
    if not df_breach_types.empty and "breach_type" in df_breach_types.columns:
        with st.expander("Breach Type Breakdown"):
            df_bt = df_breach_types.copy()
            df_bt["breach_type"] = df_bt["breach_type"].replace({
                "Unknown": "All Others", "UNKN": "All Others"
            })
            df_bt = df_bt.sort_values("incidents", ascending=False)

            pastel = ["#C39BD3","#A9DFBF","#AED6F1","#F9E79F","#A3C4BC","#D5DBDB","#FAD7A0"]
            fig_bt = go.Figure(go.Bar(
                x=df_bt["breach_type"],  y=df_bt["incidents"],
                marker=dict(color=pastel[:len(df_bt)]),
                text=df_bt["incidents"].apply(lambda x: f"{int(x):,}"),
                textposition="outside", hovertemplate="<b>%{x}</b><br>Incidents: %{y:,}<extra></extra>",
            ))
            st.plotly_chart(fig_bt, use_container_width=True)



st.markdown("""
<div class="section-header">
    <h3>A2: Yearly Threat Landscape</h3>
    <p>How have CVE publication volume and breach frequency changed year on year?</p>
</div>
""", unsafe_allow_html=True)

if df_a2_f.empty:
    st.warning("a2_yearly_threat_landscape.csv not found. Run sql_analysis.py first.")
else:
    df_a2_f = df_a2_f.sort_values("year")

    col_l, col_r = st.columns(2)

    with col_l:
        
        fig_cve = go.Figure()
        fig_cve.add_trace(go.Scatter(
            x=df_a2_f["year"], y=df_a2_f["critical_count"],
            name="Critical (9-10)", mode="lines",
            stackgroup="one", line=dict(color=C["critical"]),
            hovertemplate="%{y:,} Critical CVEs<extra></extra>",
        ))
        fig_cve.add_trace(go.Scatter(
            x=df_a2_f["year"], y=df_a2_f["high_count"],
            name="High (7-8.9)", mode="lines",
            stackgroup="one", line=dict(color=C["high"]),
            hovertemplate="%{y:,} High CVEs<extra></extra>",
        ))
        other = df_a2_f["total_cves"] - df_a2_f["critical_count"] - df_a2_f["high_count"]
        fig_cve.add_trace(go.Scatter(
            x=df_a2_f["year"], y=other.clip(lower=0),
            name="Medium / Low", mode="lines",
            stackgroup="one", line=dict(color="#AEB6BF"),
            hovertemplate="%{y:,} other CVEs<extra></extra>",
        ))
        fig_cve.update_layout(
            title="CVE Publication Volume by Year & Severity",
            xaxis_title="Year",
            yaxis_title="CVE Count",
            template=PLOTLY_TEMPLATE,
            height=360,
            hovermode="x unified",
            legend=dict(orientation="h", y=-0.2),
            font=dict(family="IBM Plex Sans"),
        )
        st.plotly_chart(fig_cve, use_container_width=True)

    with col_r:
       
        fig_dual = make_subplots(specs=[[{"secondary_y": True}]])
        fig_dual.add_trace(go.Bar(
            x=df_a2_f["year"],
            y=df_a2_f["total_cves"],
            name="Total CVEs",
            marker_color="#AEB6BF",
            opacity=0.7,
        ), secondary_y=False)
        fig_dual.add_trace(go.Scatter(
            x=df_a2_f["year"],
            y=df_a2_f["total_breaches"],
            name="Data Breaches",
            mode="lines+markers",
            line=dict(color=C["red"], width=3),
            marker=dict(size=7),
        ), secondary_y=True)
        fig_dual.update_layout(
            title="CVE Volume vs Breach Frequency",
            template=PLOTLY_TEMPLATE,
            height=360,
            hovermode="x unified",
            legend=dict(orientation="h", y=-0.2),
            font=dict(family="IBM Plex Sans"),
        )
        fig_dual.update_yaxes(title_text="CVE Count", secondary_y=False)
        fig_dual.update_yaxes(title_text="Breaches", secondary_y=True)
        st.plotly_chart(fig_dual, use_container_width=True)

    if "total_cves" in df_a2_f.columns:
        peak_cve_yr = df_a2_f.loc[df_a2_f["total_cves"].idxmax(), "year"]
        peak_cve_n  = df_a2_f["total_cves"].max()
        peak_br_yr  = df_a2_f.loc[df_a2_f["total_breaches"].idxmax(), "year"]
        st.markdown(f"""
        <div class="finding-card">
        <strong>Key Finding:</strong> CVE disclosures peaked in <em>{int(peak_cve_yr)}</em>
        with {int(peak_cve_n):,} new vulnerabilities published. Data breach incidents peaked in
        <em>{int(peak_br_yr)}</em>, suggesting a lag between vulnerability disclosure and downstream
        organisational impact.
        </div>
        """, unsafe_allow_html=True)

    
    if not df_cve_monthly.empty:
        with st.expander("Monthly CVE Publication Trend"):
            df_cve_monthly["month"] = (
                pd.to_datetime(df_cve_monthly["month"], errors="coerce", utc=True)
                .dt.tz_localize(None))
            fig_mo = go.Figure()
            fig_mo.add_trace(go.Scatter(
                x=df_cve_monthly["month"], y=df_cve_monthly["cve_count"],
                mode="lines", name="All CVEs", line=dict(color="#AEB6BF"), fill="tozeroy",
                fillcolor="rgba(174,182,191,0.15)",
            ))
            fig_mo.add_trace(go.Scatter(
                x=df_cve_monthly["month"], y=df_cve_monthly["critical_count"],
                mode="lines", name="Critical", line=dict(color=C["critical"], width=2),
            ))
            fig_mo.update_layout(
                title="Monthly CVE Volume (2010–present)",
                xaxis_title="Month", yaxis_title="Count",
                template=PLOTLY_TEMPLATE, height=300,
                hovermode="x unified",
                legend=dict(orientation="h", y=-0.25),
                font=dict(family="IBM Plex Sans"),
            )
            st.plotly_chart(fig_mo, use_container_width=True)





st.markdown("""
<div class="section-header">
    <h3> A3: Attack Severity Patterns</h3>
    <p>Do attackers preferentially target high-severity CVEs, or is exploitation spread evenly?</p>
</div>
""", unsafe_allow_html=True)

if df_a3.empty:
    st.warning("a3_attack_severity_patterns.csv not found. Run sql_analysis.py first.")
else:
    band_order= ["Critical (9-10)", "High (7-8.9)", "Medium (4-6.9)", "Low (0.1-3.9)", "No Score"]
    band_colours=[C["critical"], C["high"], C["medium"], C["low"], C["grey"]]

    df_a3["severity_band"] = pd.Categorical(
        df_a3["severity_band"], categories=band_order, ordered=True
    )
    df_a3 = df_a3.sort_values("severity_band")

    col_l, = st.columns(1)

    with col_l:
        
        fig_sev = go.Figure()
        fig_sev.add_trace(go.Bar(
            name="Total CVEs",
            x=df_a3["severity_band"],
            y=df_a3["total_cves"],
            marker_color="#566573",
            hovertemplate="%{x}<br>Total: %{y:,}<extra></extra>",
        ))
        fig_sev.add_trace(go.Bar(
            name="Exploited CVEs",
            x=df_a3["severity_band"],
            y=df_a3["exploited_cves"],
            marker_color="#BFC9CA",
            hovertemplate="%{x}<br>Exploited: %{y:,}<extra></extra>",
        ))
        
        fig_sev.update_layout(
            title="Total vs Exploited CVEs by Severity Band",
            xaxis_title="Severity Band",
            yaxis_title="Count",
            barmode="group",
            template=PLOTLY_TEMPLATE,
            height=360,
            legend=dict(orientation="h", y=-0.2),
            font=dict(family="IBM Plex Sans"),
        ) 
        st.plotly_chart(fig_sev, use_container_width=True)

    #TODO: Not needed this wizard for now. Visit this later
    # with col_r:
    #     # exploitation rate as a simple bar: easier to read than funnel
    #     if "exploitation_rate_pct" in df_a3.columns:
    #         rate_colours = [C["critical"], C["high"], C["medium"], C["low"], C["grey"]]
    #         fig_rate = go.Figure(go.Bar(
    #             x=df_a3["severity_band"].astype(str),
    #             y=df_a3["exploitation_rate_pct"], marker=dict(color=rate_colours[:len(df_a3)]),
    #             text=df_a3["exploitation_rate_pct"].apply(lambda x: f"{x:.1f}%"),
    #             textposition="outside",   hovertemplate="%{x}<br>Rate: %{y:.2f}%<extra></extra>",
    #         ))
            
    #         fig_rate.update_layout(
    #             title="Exploitation Rate (%) by Severity Band",
    #             xaxis_title="Severity Band",  yaxis_title="Rate (%)",
    #             template=PLOTLY_TEMPLATE,
    #             height=360, font=dict(family="IBM Plex Sans"),
    #         )
    #         st.plotly_chart(fig_rate, use_container_width=True)

    if "exploitation_rate_pct" in df_a3.columns and not df_a3.empty:
        top_band = df_a3.loc[df_a3["exploitation_rate_pct"].idxmax(), "severity_band"]
        top_rate = df_a3["exploitation_rate_pct"].max()
        st.markdown(f"""
        <div class="finding-card">
        <strong>Key Finding:</strong> <em>{top_band}</em> CVEs have the highest exploitation rate
        at <em>{top_rate:.2f}%</em>. This confirms that attackers systematically prioritise the most
        severe vulnerabilities: patching Critical CVEs within days of disclosure is essential.
        </div>
        """, unsafe_allow_html=True)



st.markdown("""
<div class="section-header">
    <h3>A4: Most Exploited Vendors</h3>
    <p>Which software vendors appear most frequently in confirmed real-world exploitation events?</p>
</div>
""", unsafe_allow_html=True)

if df_a4.empty:
    st.warning("a4_most_exploited_vendors.csv not found. Run sql_analysis.py first.")
else:
    col_l, col_r = st.columns(2)

    with col_l:
        top20 = df_a4.nlargest(15, "exploited_cves").copy()
        top20["avg_cvss_score"] = pd.to_numeric(top20["avg_cvss_score"], errors="coerce").fillna(0)
        fig_v = go.Figure(go.Bar(
            x=top20["exploited_cves"],
            y=top20["vendor"], orientation="h",
            marker=dict(
                color=top20["avg_cvss_score"],
                colorscale=[[0, "#D5D8DC"], [1, "#2C3E50"]],
                cmin=0, cmax=10,
                showscale=True,   colorbar=dict(title="Avg CVSS", thickness=12),
            ),
            text=top20["exploited_cves"].apply(lambda x: f"{int(x):,}"),
            textposition="outside",
            hovertemplate="<b>%{y}</b><br>Exploited CVEs: %{x:,}<br>Avg CVSS: %{marker.color:.1f}<extra></extra>",
        ))
        fig_v.update_layout(
            title="Top 15 Vendors: Exploited CVE Count<br><sup>(colour = avg CVSS severity)</sup>",
            xaxis_title="Exploited CVE Count", yaxis_title="", template=PLOTLY_TEMPLATE,
            height=420, margin=dict(l=10, r=80, t=60, b=10),
            yaxis={"categoryorder": "total ascending"}, font=dict(family="IBM Plex Sans"),
        )
        st.plotly_chart(fig_v, use_container_width=True)

    with col_r:
        # scatter: exploited cves vs avg cvss, bubble = products affected
        if all(c in df_a4.columns for c in ["exploited_cves", "avg_cvss_score", "products_affected"]):
            fig_sc = px.scatter(
                df_a4.head(20),
                x="avg_cvss_score", y="exploited_cves",
                size="products_affected", color="years_active", color_continuous_scale="Oranges",
                text="vendor",
                hover_data={
                    "vendor": True,  "exploited_cves": ":,",
                    "avg_cvss_score": ":.2f",  "products_affected": True,
                },
                labels={
                    "avg_cvss_score": "Average CVSS Score",  "exploited_cves":  "Exploited CVEs",
                    "years_active": "Years Active",
                },
                title="Vendor Risk Landscape<br><sup>(size = products affected, colour = years active)</sup>",
            )
            fig_sc.update_traces(
                textposition="top center", textfont=dict(size=9),
                marker=dict(sizemin=6),
            )
            fig_sc.add_vline(x=7.0, line_dash="dot", line_color="#7F8C8D", opacity=0.6)
            fig_sc.update_layout(
                template=PLOTLY_TEMPLATE,
                height=420,
                font=dict(family="IBM Plex Sans"),
            )
            st.plotly_chart(fig_sc, use_container_width=True)

   
    if not df_top_products.empty:
        with st.expander("Top Exploited Products"):
            show_cols = ["vendor", "product", "exploited_count", "avg_cvss", "first_seen", "last_seen"]
            show_cols = [c for c in show_cols if c in df_top_products.columns]
            st.dataframe(
                df_top_products[show_cols].head(20).reset_index(drop=True),
                use_container_width=True,
                height=300,
            )

    if not df_a4.empty and "exploited_cves" in df_a4.columns:
        top_v  = df_a4.iloc[0]["vendor"]
        top_n  = df_a4.iloc[0]["exploited_cves"]
        top_cv = df_a4.iloc[0].get("avg_cvss_score", "N/A")
        st.markdown(f"""
        <div class="finding-card">
        <strong>Key Finding:</strong> <em>{top_v}</em> leads with {int(top_n):,} confirmed exploited CVEs
        (avg CVSS: {top_cv}). Organisations running {top_v} products should treat their patch cycle
        as a top security priority given the persistent exploitation history.
        </div>
        """, unsafe_allow_html=True)


st.markdown("""
<div class="section-header">
    <h3>A5: Time to Weaponisation</h3>
    <p>How quickly after public CVE disclosure do attackers weaponise vulnerabilities in real attacks?</p>
</div>
""", unsafe_allow_html=True)

if df_a5.empty:
    st.warning("a5_time_to_weaponisation.csv not found. Run sql_analysis.py first.")
else:
    df_a5["days_to_exploit"] = pd.to_numeric(df_a5["days_to_exploit"], errors="coerce")
    df_a5_valid = df_a5[df_a5["days_to_exploit"] >= 0].copy()

    bracket_order = [
        "Within a week", "Within a month",
        "1-3 months", "3-12 months", "Over a year"
    ]
    bracket_colours = {
        "Within a week": C["critical"],
        "Within a month": C["high"],
        "1-3 months": C["medium"],
        "3-12 months": C["low"],
        "Over a year": C["primary"],
    }

    col_l, col_r = st.columns(2)

    with col_l:
        
        if "time_bracket" in df_a5_valid.columns and not df_a5_valid.empty:
            fig_box = go.Figure()
            for bracket in bracket_order:
                subset = df_a5_valid[df_a5_valid["time_bracket"] == bracket]["days_to_exploit"]
                if subset.empty:
                    continue
                fig_box.add_trace(go.Box(
                    y=subset,
                    name=bracket,
                    marker_color=bracket_colours.get(bracket, C["grey"]),
                    boxpoints="outliers",
                    line=dict(width=1.5),
                ))
            median_days = df_a5_valid["days_to_exploit"].median()
            fig_box.add_hline(
                y=median_days,
                line_dash="dash",
                line_color="black",
                annotation_text=f"Median = {median_days:.0f} days",
                annotation_position="top right",
            )
            fig_box.update_layout(
                title="Days to Weaponisation Distribution",
                yaxis_title="Days from CVE Disclosure",
                template=PLOTLY_TEMPLATE,
                height=400,
                showlegend=False,
                font=dict(family="IBM Plex Sans"),
            )
            st.plotly_chart(fig_box, use_container_width=True)

    with col_r:
        
        if "time_bracket" in df_a5_valid.columns:
            bracket_counts = df_a5_valid["time_bracket"].value_counts().reset_index()
            bracket_counts.columns = ["bracket", "count"]
            bracket_counts["bracket"] = pd.Categorical(
                bracket_counts["bracket"], categories=bracket_order, ordered=True
            )
            bracket_counts = bracket_counts.sort_values("bracket")

            fig_pie = go.Figure(go.Pie(
                labels=bracket_counts["bracket"].astype(str),
                values=bracket_counts["count"],
                marker=dict(colors=[
                    bracket_colours.get(b, C["grey"])
                    for b in bracket_counts["bracket"].astype(str)
                ]),
                hole=0.45,
                textinfo="label+percent",
                hovertemplate="%{label}<br>%{value:,} CVEs (%{percent})<extra></extra>",
            ))
            fig_pie.update_layout(
                title="CVEs by Time-to-Weaponisation Window",
                template=PLOTLY_TEMPLATE,
                height=400,
                font=dict(family="IBM Plex Sans"),
                showlegend=False,
            )
            st.plotly_chart(fig_pie, use_container_width=True)

    
    if not df_weapon_stats.empty:
        s = df_weapon_stats.iloc[0]
        w1, w2, w3, w4 = st.columns(4)
        w1.metric("Median Days", f"{int(s.get('median_days', 0)):,}")
        w2.metric("Avg Days", f"{int(s.get('avg_days', 0)):,}")
        w3.metric("Fastest", f"{int(s.get('fastest_days', 0)):,} days")
        w4.metric("Within 30d", f"{s.get('pct_within_30', 0):.1f}%")

        st.markdown(f"""
        <div class="finding-card">
        <strong>Key Finding:</strong> The median time from CVE public disclosure to confirmed
        exploitation is <em>{int(s.get('median_days', 0)):,} days</em>.
        {s.get('pct_within_30', 0):.1f}% of exploited CVEs are weaponised within 30 days,
        underscoring that patch windows are critically short once a vulnerability is made public.
        </div>
        """, unsafe_allow_html=True)


st.markdown("---")
st.markdown("""
<p style='text-align:center; font-size:12px; color:#95A5A6;'>
    Cybersecurity Incident and Vulnerability Risk Analytics &nbsp;·&nbsp;
</p>
""", unsafe_allow_html=True)
