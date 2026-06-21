"""Network Bouncer — Streamlit security dashboard (Dev 4).

Run with:
    streamlit run dashboard/app.py

Upload a network-traffic CSV (UNSW-NB15 schema) and the app runs the full
Dev 1 -> Dev 2 -> Dev 3 pipeline, then presents an interactive SOC-style
dashboard: overview metrics, executive threat summary, filterable host tables,
visualisations and downloadable reports.
"""

from __future__ import annotations

import os
import sys

import pandas as pd
import streamlit as st

# Allow `streamlit run dashboard/app.py` from the project root to import `src`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard import charts  # noqa: E402
from dashboard.exports import (  # noqa: E402
    build_executive_summary,
    build_reports,
    flatten_for_export,
    summary_to_json,
    summary_to_txt,
)
from dashboard.pipeline_runner import (  # noqa: E402
    DEFAULT_SENSITIVITY,
    SENSITIVITY_PRESETS,
    AnalysisResult,
    run_from_bytes,
    run_full_pipeline,
)

# --------------------------------------------------------------------------- #
# Page configuration & styling
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="Network Bouncer — Port-Scan Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

_CSS = """
<style>
    .main .block-container { padding-top: 2rem; }
    /* Theme-agnostic metric cards. A translucent neutral tint + border reads
       well on BOTH light and dark backgrounds, so the dashboard follows the
       viewer's Streamlit/browser theme instead of forcing dark (which looked
       broken in light mode). */
    div[data-testid="stMetric"] {
        background: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-radius: 10px;
        padding: 14px 16px;
    }
    div[data-testid="stMetricValue"] { font-size: 1.7rem; }
    /* Title/body inherit the active theme's text colour (no hard-coded white). */
    .nb-title { font-size: 2.1rem; font-weight: 800; margin-bottom: 0; }
    .nb-sub { color: #7a8694; margin-top: 0; }   /* mid-grey: legible on light & dark */
    /* Severity accents stay readable on either background. */
    .nb-crit { color: #d7263d; font-weight: 700; }
    .nb-high { color: #e8590c; font-weight: 700; }
</style>
"""
st.markdown(_CSS, unsafe_allow_html=True)

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "None"]
DISPLAY_COLUMNS = [
    "srcip", "classification", "severity_level", "severity_score",
    "top_protocol", "total_connections", "unique_destinations",
    "unique_dst_ports", "unique_protocols", "rule_hits", "n_anomaly_indicators",
]


# --------------------------------------------------------------------------- #
# Cached pipeline runners
# --------------------------------------------------------------------------- #
@st.cache_data(show_spinner=False)
def _cached_run_upload(file_bytes: bytes, is_raw: bool, sensitivity: str) -> AnalysisResult:
    return run_from_bytes(file_bytes, is_raw=is_raw, sensitivity=sensitivity)


@st.cache_data(show_spinner=False)
def _cached_run_demo(sensitivity: str) -> AnalysisResult:
    return run_full_pipeline(_demo_dataframe(), sensitivity=sensitivity)


def _demo_dataframe() -> pd.DataFrame:
    """A population of 25 benign hosts + 3 scanners for instant demoing."""
    rows = []
    for h in range(25):
        ip = f"10.10.0.{h}"
        svc, port = ("https", 443) if h % 2 == 0 else ("dns", 53)
        for c in range(8):
            rows.append((ip, "10.20.0.5", 30000 + c, port, "tcp", svc, "FIN", 0))
    for d in range(25):           # block scanner
        for p in range(25):
            rows.append(("175.45.176.2", f"172.16.0.{d}", 40000 + p, 2000 + p, "ospf", "-", "INT", 1))
    for d in range(60):           # horizontal scanner
        rows.append(("59.166.0.5", f"149.171.126.{d}", 41000 + d, 80, "tcp", "-", "INT", 1))
    for p in range(50):           # vertical scanner
        rows.append(("175.45.176.1", "149.171.126.10", 50000 + p, 1000 + p, "tcp", "-", "REQ", 1))
    cols = ["srcip", "dstip", "sport", "dsport", "proto", "service", "state", "label"]
    return pd.DataFrame(rows, columns=cols)


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
def render_sidebar() -> dict:
    st.sidebar.markdown("## 🛡️ Network Bouncer")
    st.sidebar.caption("Port-scan detection for data-center traffic")
    st.sidebar.divider()

    uploaded = st.sidebar.file_uploader("Upload network traffic CSV", type=["csv"])
    is_raw = st.sidebar.checkbox(
        "Headerless raw UNSW-NB15 file", value=False,
        help="Tick if this is a raw UNSW-NB15_1..4.csv (no header row).",
    )
    sensitivity = st.sidebar.select_slider(
        "Detection sensitivity",
        options=list(SENSITIVITY_PRESETS.keys()),
        value=DEFAULT_SENSITIVITY,
    )
    st.sidebar.divider()
    use_demo = st.sidebar.button("▶ Load demo dataset", use_container_width=True)
    st.sidebar.caption(
        "Two formats auto-detected:\n\n"
        "• **Host capture** (srcip, dstip, sport, dsport, proto) → per-host "
        "port-scan detection.\n\n"
        "• **UNSW-NB15 feature set** (proto, state, service, ct_*…) → "
        "flow-level detection."
    )
    st.sidebar.divider()
    st.sidebar.caption(
        "🌗 **Light / Dark mode:** top-right **⋮** menu → **Settings** → "
        "**Theme**. The dashboard adapts to either."
    )
    return {"uploaded": uploaded, "is_raw": is_raw, "sensitivity": sensitivity, "use_demo": use_demo}


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #
def render_header() -> None:
    st.markdown('<p class="nb-title">🛡️ Network Bouncer</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="nb-sub">Detecting suspicious port scanning in data-center traffic</p>',
        unsafe_allow_html=True,
    )


def render_landing() -> None:
    st.info("⬅️ Upload a CSV in the sidebar, or click **Load demo dataset** to explore.")
    c1, c2, c3 = st.columns(3)
    c1.markdown("#### 1 · Upload\nDrop in a network-traffic CSV (UNSW-NB15 schema).")
    c2.markdown("#### 2 · Analyse\nThe full detection + scoring pipeline runs automatically.")
    c3.markdown("#### 3 · Investigate\nReview suspicious hosts, evidence and severity, then export.")


def render_overview(result: AnalysisResult) -> None:
    e = result.enriched
    total_hosts = len(e)
    n_susp = int(e["is_suspicious"].sum()) if "is_suspicious" in e else 0
    n_crit = int((e["severity_level"] == "Critical").sum()) if "severity_level" in e else 0
    n_high = int((e["severity_level"] == "High").sum()) if "severity_level" in e else 0
    rate = (n_susp / total_hosts * 100) if total_hosts else 0.0

    st.subheader("Overview")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Flows analysed", f"{result.quality.get('final_dataset_size', 0):,}",
              delta=f"-{result.quality.get('total_rows_removed', 0):,} dirty", delta_color="off")
    c2.metric("Hosts analysed", f"{total_hosts:,}")
    c3.metric("Suspicious hosts", f"{n_susp:,}")
    c4.metric("High severity", f"{n_high:,}")
    c5.metric("Critical severity", f"{n_crit:,}")
    c6.metric("Detection rate", f"{rate:.1f}%")


def render_threat_summary(result: AnalysisResult) -> None:
    e = result.enriched
    st.subheader("Threat Summary")
    if e.empty:
        st.success("No hosts to analyse.")
        return

    n_susp = int(e["is_suspicious"].sum())
    n_crit = int((e["severity_level"] == "Critical").sum())
    n_high = int((e["severity_level"] == "High").sum())

    if n_susp == 0:
        st.success(
            f"✅ No suspicious scanning behaviour detected across {len(e):,} hosts. "
            "All hosts classified **Normal**."
        )
        return

    top = e.sort_values("severity_score", ascending=False).iloc[0]
    banner = (
        f"🚨 **{n_susp} suspicious host(s)** detected — "
        f"<span class='nb-crit'>{n_crit} Critical</span>, "
        f"<span class='nb-high'>{n_high} High</span>."
    )
    st.markdown(banner, unsafe_allow_html=True)
    st.markdown(
        f"**Top threat:** `{top['srcip']}` "
        f"(severity **{top['severity_level']}**, score {top['severity_score']}/100) — "
        f"{top['classification']}."
    )
    reasons = top.get("reasons", [])
    if isinstance(reasons, list) and reasons:
        with st.expander("Why is the top host flagged?", expanded=True):
            for r in reasons:
                st.markdown(f"- {r}")
            anomalies = top.get("anomaly_indicators", [])
            if isinstance(anomalies, list) and anomalies:
                st.markdown("**Statistical outliers:**")
                for a in anomalies:
                    st.markdown(f"- {a}")


def _apply_filters(e: pd.DataFrame) -> pd.DataFrame:
    """Render filter widgets and return the filtered frame."""
    with st.expander("🔎 Filters", expanded=True):
        c1, c2, c3 = st.columns(3)
        sev = c1.multiselect("Severity", SEVERITY_LEVELS,
                             default=[s for s in SEVERITY_LEVELS if s != "None"])
        status = c2.multiselect("Detection status",
                                ["Suspicious", "Normal"], default=["Suspicious", "Normal"])
        protos = sorted(e["top_protocol"].dropna().unique()) if "top_protocol" in e else []
        proto_sel = c3.multiselect("Protocol", protos, default=protos)

        c4, c5 = st.columns([2, 1])
        host_q = c4.text_input("Host contains", "")
        min_score = c5.slider("Min severity score", 0, 100, 0)

    out = e.copy()
    if "severity_level" in out:
        out = out[out["severity_level"].isin(sev)]
    if status and "classification" in out:
        susp_wanted = "Suspicious" in status
        norm_wanted = "Normal" in status
        mask = pd.Series(False, index=out.index)
        if susp_wanted:
            mask |= out["is_suspicious"] == True   # noqa: E712
        if norm_wanted:
            mask |= out["is_suspicious"] == False  # noqa: E712
        out = out[mask]
    if proto_sel and "top_protocol" in out:
        out = out[out["top_protocol"].isin(proto_sel)]
    if host_q:
        out = out[out["srcip"].astype(str).str.contains(host_q, case=False, na=False)]
    if "severity_score" in out:
        out = out[out["severity_score"] >= min_score]
    return out


def render_hosts_tab(result: AnalysisResult) -> None:
    e = result.enriched
    if e.empty:
        st.warning("No hosts available.")
        return

    filtered = _apply_filters(e)
    st.caption(f"Showing **{len(filtered)}** of {len(e)} hosts.")

    cols = [c for c in DISPLAY_COLUMNS if c in filtered.columns]
    st.dataframe(
        filtered[cols],
        use_container_width=True, hide_index=True,
        column_config={
            "srcip": "Source Host",
            "severity_score": st.column_config.ProgressColumn(
                "Severity", min_value=0, max_value=100, format="%d"),
        },
    )

    # Per-host investigation panel.
    st.markdown("##### 🔬 Host investigation")
    if filtered.empty:
        st.info("No hosts match the current filters.")
        return
    host = st.selectbox("Select a host", filtered["srcip"].tolist())
    row = filtered[filtered["srcip"] == host].iloc[0]
    _render_host_detail(row)


def _render_host_detail(row: pd.Series) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Severity", row.get("severity_level", "-"))
    c2.metric("Score", f"{row.get('severity_score', 0)}/100")
    c3.metric("Connections", f"{int(row.get('total_connections', 0)):,}")
    c4.metric("Unique ports", f"{int(row.get('unique_dst_ports', 0)):,}")

    left, right = st.columns(2)
    with left:
        st.markdown("**Detection reasons (rule-based):**")
        reasons = row.get("reasons", [])
        if isinstance(reasons, list) and reasons:
            for r in reasons:
                st.markdown(f"- {r}")
        else:
            st.caption("None — no rules fired.")
    with right:
        st.markdown("**Statistical indicators:**")
        anomalies = row.get("anomaly_indicators", [])
        if isinstance(anomalies, list) and anomalies:
            for a in anomalies:
                st.markdown(f"- {a}")
        else:
            st.caption("None — not a statistical outlier.")

    expl = row.get("severity_explanation", [])
    if isinstance(expl, list) and expl:
        st.markdown("**Severity rationale:**")
        for x in expl:
            st.markdown(f"- {x}")


def render_charts_tab(result: AnalysisResult) -> None:
    e, profile = result.enriched, result.profile
    c1, c2 = st.columns(2)
    c1.plotly_chart(charts.severity_distribution(e), use_container_width=True)
    c2.plotly_chart(charts.suspicious_vs_normal(e), use_container_width=True)

    st.plotly_chart(charts.top_suspicious_hosts(e), use_container_width=True)

    c3, c4 = st.columns(2)
    c3.plotly_chart(charts.detection_reason_breakdown(e), use_container_width=True)
    c4.plotly_chart(charts.protocol_distribution(profile), use_container_width=True)

    st.plotly_chart(charts.anomaly_scatter(e), use_container_width=True)
    st.plotly_chart(charts.connection_distribution(e), use_container_width=True)


def _render_executive_summary(result: AnalysisResult) -> None:
    """Headline one-page summary + JSON/TXT downloads (both modes)."""
    summary = build_executive_summary(result)
    st.markdown("##### 📋 Executive summary")
    txt = summary_to_txt(summary).decode("utf-8")
    st.code(txt, language="text")
    c1, c2 = st.columns(2)
    c1.download_button("⬇ Summary (TXT)", summary_to_txt(summary),
                       "executive_summary.txt", "text/plain", use_container_width=True)
    c2.download_button("⬇ Summary (JSON)", summary_to_json(summary),
                       "executive_summary.json", "application/json", use_container_width=True)
    st.divider()


def render_export_tab(result: AnalysisResult) -> None:
    st.subheader("Export reports")
    _render_executive_summary(result)
    st.caption("Download analyst-ready CSVs of the analysis.")
    reports = build_reports(result.enriched)

    c1, c2, c3, c4 = st.columns(4)
    c1.download_button("⬇ Detection results", reports["detection_results"],
                       "detection_results.csv", "text/csv", use_container_width=True)
    c2.download_button("⬇ Suspicious hosts", reports["suspicious_report"],
                       "suspicious_report.csv", "text/csv", use_container_width=True)
    c3.download_button("⬇ Severity report", reports["severity_report"],
                       "severity_report.csv", "text/csv", use_container_width=True)
    c4.download_button("⬇ Investigation dataset", reports["investigation_dataset"],
                       "investigation_dataset.csv", "text/csv", use_container_width=True)

    st.markdown("##### Data quality")
    st.json(result.quality)


# --------------------------------------------------------------------------- #
# Flow-mode sections (UNSW-NB15 feature sets — no host identity)
# --------------------------------------------------------------------------- #
FLOW_DISPLAY_COLUMNS = [
    "proto", "service", "state", "sbytes", "dbytes", "ct_dst_src_ltm",
    "flow_classification", "flow_severity", "flow_score", "flow_reason",
    "attack_cat", "label",
]


def render_flow_overview(result: AnalysisResult) -> None:
    f = result.flow_df
    total = len(f)
    n_susp = int(f["flow_is_suspicious"].sum()) if "flow_is_suspicious" in f else 0
    n_high = int((f["flow_severity"] == "High").sum()) if "flow_severity" in f else 0
    n_med = int((f["flow_severity"] == "Medium").sum()) if "flow_severity" in f else 0
    rate = (n_susp / total * 100) if total else 0.0
    # Best available validation F1 (recon target preferred, else any-attack).
    m = result.flow_metrics or {}
    val = m.get("reconnaissance") or m.get("any_attack") or {}

    st.subheader("Overview")
    st.caption("Flow-level detection — this file has no host identity, so each "
               "network **flow** is scored individually.")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Flows analysed", f"{total:,}")
    c2.metric("Suspicious flows", f"{n_susp:,}")
    c3.metric("High severity", f"{n_high:,}")
    c4.metric("Medium severity", f"{n_med:,}")
    c5.metric("Flag rate", f"{rate:.1f}%")
    c6.metric("Validation F1", f"{val.get('f1', 0):.2f}" if val else "—",
              help="F1 vs ground-truth labels in the file, when present.")


def render_flow_threat_summary(result: AnalysisResult) -> None:
    f = result.flow_df
    st.subheader("Threat Summary")
    if f.empty:
        st.success("No flows to analyse.")
        return
    n_susp = int(f["flow_is_suspicious"].sum())
    if n_susp == 0:
        st.success(f"✅ No suspicious flows detected across {len(f):,} flows.")
    else:
        n_high = int((f["flow_severity"] == "High").sum())
        st.markdown(
            f"🚨 **{n_susp:,} suspicious flow(s)** detected out of {len(f):,} — "
            f"<span class='nb-high'>{n_high:,} High severity</span>. "
            "Flagged flows show the probe fingerprint: unknown service, tiny "
            "payload, low connection reuse and/or an incomplete connection state.",
            unsafe_allow_html=True,
        )

    # Ground-truth validation, if the file carried labels.
    if result.flow_metrics:
        st.markdown("**Ground-truth validation** (rules vs the file's own labels):")
        rows = []
        for target, mm in result.flow_metrics.items():
            rows.append({
                "Target": target, "Precision": mm["precision"], "Recall": mm["recall"],
                "F1": mm["f1"], "TP": mm["tp"], "FP": mm["fp"],
                "FN": mm["fn"], "TN": mm["tn"],
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        st.caption("Note: flow-level detection is inherently weaker than host-based "
                   "detection — without source IPs we cannot aggregate "
                   "“one machine → many destinations/ports”, the literal port-scan "
                   "signal. Upload a raw UNSW-NB15_1..4.csv for strong per-host detection.")


def _apply_flow_filters(f: pd.DataFrame) -> pd.DataFrame:
    with st.expander("🔎 Filters", expanded=True):
        c1, c2, c3 = st.columns(3)
        sev = c1.multiselect("Severity", ["High", "Medium", "Low", "None"],
                             default=["High", "Medium", "Low"])
        status = c2.multiselect("Detection status", ["Suspicious", "Normal"],
                                default=["Suspicious"])
        protos = sorted(f["proto"].dropna().astype(str).unique()) if "proto" in f else []
        proto_sel = c3.multiselect("Protocol", protos, default=protos)

    out = f.copy()
    if "flow_severity" in out:
        out = out[out["flow_severity"].isin(sev)]
    if status and "flow_is_suspicious" in out:
        mask = pd.Series(False, index=out.index)
        if "Suspicious" in status:
            mask |= out["flow_is_suspicious"] == True   # noqa: E712
        if "Normal" in status:
            mask |= out["flow_is_suspicious"] == False  # noqa: E712
        out = out[mask]
    if proto_sel and "proto" in out:
        out = out[out["proto"].astype(str).isin(proto_sel)]
    return out


def render_flow_table_tab(result: AnalysisResult) -> None:
    f = result.flow_df
    if f.empty:
        st.warning("No flows available.")
        return
    filtered = _apply_flow_filters(f)
    st.caption(f"Showing **{len(filtered):,}** of {len(f):,} flows.")
    cols = [c for c in FLOW_DISPLAY_COLUMNS if c in filtered.columns]
    st.dataframe(
        filtered[cols].head(1000), use_container_width=True, hide_index=True,
        column_config={
            "flow_classification": "Classification",
            "flow_severity": "Severity",
            "flow_score": st.column_config.ProgressColumn(
                "Indicators", min_value=0, max_value=4, format="%d"),
            "flow_reason": "Why flagged",
            "attack_cat": "Actual (ground truth)",
        },
    )
    if len(filtered) > 1000:
        st.caption("Showing first 1,000 rows. Use filters to narrow, or export the full set.")


def render_flow_charts_tab(result: AnalysisResult) -> None:
    f, profile = result.flow_df, result.profile
    c1, c2 = st.columns(2)
    c1.plotly_chart(charts.flow_severity_distribution(f), use_container_width=True)
    c2.plotly_chart(charts.flow_classification_donut(f), use_container_width=True)
    st.plotly_chart(charts.flow_reason_breakdown(f), use_container_width=True)
    c3, c4 = st.columns(2)
    c3.plotly_chart(charts.protocol_distribution(profile), use_container_width=True)
    c4.plotly_chart(charts.attack_category_distribution(profile), use_container_width=True)


def render_flow_export_tab(result: AnalysisResult) -> None:
    f = result.flow_df
    st.subheader("Export reports")
    _render_executive_summary(result)
    st.caption("Download analyst-ready CSVs of the flow-level analysis.")
    cols = [c for c in FLOW_DISPLAY_COLUMNS if c in f.columns]
    flagged = f[f["flow_is_suspicious"]] if "flow_is_suspicious" in f else f
    c1, c2 = st.columns(2)
    c1.download_button(
        "⬇ Flagged flows", flagged[cols].to_csv(index=False).encode("utf-8"),
        "flagged_flows.csv", "text/csv", use_container_width=True)
    c2.download_button(
        "⬇ All scored flows", f[cols].to_csv(index=False).encode("utf-8"),
        "all_flows_scored.csv", "text/csv", use_container_width=True)
    st.markdown("##### Dataset profile")
    st.json(result.profile)


def render_flow_mode(result: AnalysisResult) -> None:
    """Render the full flow-mode dashboard (feature-set files)."""
    render_flow_overview(result)
    render_flow_threat_summary(result)
    st.divider()
    tab_flows, tab_charts, tab_export = st.tabs(
        ["🌊 Suspicious Flows", "📊 Visualisations", "📤 Export"]
    )
    with tab_flows:
        render_flow_table_tab(result)
    with tab_charts:
        render_flow_charts_tab(result)
    with tab_export:
        render_flow_export_tab(result)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    render_header()
    controls = render_sidebar()

    result: AnalysisResult | None = None
    if controls["use_demo"]:
        with st.spinner("Running pipeline on demo dataset..."):
            result = _cached_run_demo(controls["sensitivity"])
    elif controls["uploaded"] is not None:
        with st.spinner("Running detection pipeline..."):
            result = _cached_run_upload(
                controls["uploaded"].getvalue(),
                controls["is_raw"],
                controls["sensitivity"],
            )

    if result is None:
        render_landing()
        return

    if not result.ok:
        st.error(f"Could not process file: {result.error}")
        if "srcip" in (result.error or ""):
            st.info("If this is a raw, headerless UNSW-NB15 file, tick "
                    "**Headerless raw UNSW-NB15 file** in the sidebar.")
        for w in result.warnings:
            st.warning(w)
        return

    # Schema notes are informational (e.g. extra UNSW-NB15 columns ignored).
    # Tuck them inside a collapsed expander so they never read as an error.
    if result.warnings:
        with st.expander(f"ℹ️ {len(result.warnings)} schema note(s)", expanded=False):
            for w in result.warnings:
                st.caption(w)

    # Route to the right dashboard based on the auto-detected file format.
    if result.mode == "flow":
        st.info("ℹ️ This file has no source/destination host columns "
                "(UNSW-NB15 feature set). Showing **flow-level** detection.")
        render_flow_mode(result)
        return

    render_overview(result)
    render_threat_summary(result)
    st.divider()

    tab_hosts, tab_charts, tab_export = st.tabs(
        ["🖥️ Suspicious Hosts", "📊 Visualisations", "📤 Export"]
    )
    with tab_hosts:
        render_hosts_tab(result)
    with tab_charts:
        render_charts_tab(result)
    with tab_export:
        render_export_tab(result)


if __name__ == "__main__":
    main()
