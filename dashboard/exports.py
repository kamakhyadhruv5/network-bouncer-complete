"""Report-export helpers for the dashboard (Dev 4).

Turns the enriched detection table into clean, analyst-ready CSV reports. List
and dict columns (rule reasons, anomaly indicators, z-scores) are flattened to
readable strings so the CSVs open cleanly in Excel.

Also builds a one-page **executive summary** (JSON / TXT) — the headline
numbers a SOC lead or judge wants without opening a spreadsheet.
"""

from __future__ import annotations

import json
from datetime import datetime

import pandas as pd

# Columns that hold Python lists/dicts and must be flattened for CSV.
_LIST_COLUMNS = (
    "triggered_rules",
    "scan_categories",
    "reasons",
    "anomaly_indicators",
    "severity_explanation",
)
_DICT_COLUMNS = ("feature_zscores",)


def flatten_for_export(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with list/dict columns flattened to readable strings."""
    out = df.copy()
    for col in _LIST_COLUMNS:
        if col in out.columns:
            out[col] = out[col].apply(
                lambda v: " | ".join(map(str, v)) if isinstance(v, list) else ("" if v is None else v)
            )
    for col in _DICT_COLUMNS:
        if col in out.columns:
            out[col] = out[col].apply(
                lambda v: "; ".join(f"{k}={val}" for k, val in v.items())
                if isinstance(v, dict) else ("" if v is None else v)
            )
    return out


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Encode a DataFrame as UTF-8 CSV bytes for st.download_button."""
    return flatten_for_export(df).to_csv(index=False).encode("utf-8")


def build_reports(enriched: pd.DataFrame) -> dict[str, bytes]:
    """Build the four downloadable reports as name -> CSV bytes.

    Returns
    -------
    dict
        ``detection_results``     — every host, full detail.
        ``suspicious_report``     — only rule-flagged hosts.
        ``severity_report``       — severity-focused summary.
        ``investigation_dataset`` — full enriched dataset for further analysis.
    """
    if enriched is None or enriched.empty:
        empty = pd.DataFrame()
        return {k: to_csv_bytes(empty) for k in
                ("detection_results", "suspicious_report", "severity_report", "investigation_dataset")}

    suspicious = enriched[enriched.get("is_suspicious", False) == True]  # noqa: E712

    severity_cols = [c for c in (
        "srcip", "classification", "severity_level", "severity_score",
        "suspicion_score", "outlier_score", "n_anomaly_indicators",
        "severity_explanation",
    ) if c in enriched.columns]

    return {
        "detection_results": to_csv_bytes(enriched),
        "suspicious_report": to_csv_bytes(suspicious),
        "severity_report": to_csv_bytes(enriched[severity_cols]),
        "investigation_dataset": to_csv_bytes(enriched),
    }


# --------------------------------------------------------------------------- #
# Executive summary (one-page headline report)
# --------------------------------------------------------------------------- #
def _severity_breakdown(series: pd.Series, order: list[str]) -> dict[str, int]:
    counts = series.value_counts()
    return {lvl: int(counts.get(lvl, 0)) for lvl in order}


def build_executive_summary(result, *, generated_at: datetime | None = None) -> dict:
    """Build the headline summary dict from a pipeline ``AnalysisResult``.

    Works for both analysis modes:

    * **host** — total flows, total hosts, suspicious hosts, top-threat host.
    * **flow** — total flows, suspicious flows, top-threat flow, plus
      ground-truth validation metrics (hosts are N/A: the file has no identity).

    The shape is stable so it serialises cleanly to JSON or a TXT report.
    """
    ts = (generated_at or datetime.now()).replace(microsecond=0)
    base = {
        "report": "Network Bouncer — Executive Summary",
        "generated_at": ts.isoformat(sep=" "),
        "mode": getattr(result, "mode", "host"),
    }

    if getattr(result, "mode", "host") == "flow":
        f = result.flow_df
        total = len(f)
        flagged = int(getattr(result, "flagged_flows", 0))
        rate = round(flagged / total * 100, 1) if total else 0.0
        top = _top_flow_threat(f)
        base.update({
            "total_flows": total,
            "total_hosts": None,                 # no host identity in this dataset
            "suspicious_hosts": None,
            "suspicious_flows": flagged,
            "detection_rate_pct": rate,
            # Breakdown over FLAGGED flows only, so it sums to suspicious_flows
            # (below-threshold flows carry a residual "Low"/"None" tag that would
            # otherwise dwarf the real detections).
            "severity_breakdown": _severity_breakdown(
                f.loc[f.get("flow_is_suspicious", False) == True, "flow_severity"]  # noqa: E712
                if "flow_severity" in f.columns else pd.Series(dtype=str),
                ["High", "Medium", "Low"]),
            "top_threat": top,
            "validation": result.flow_metrics or None,
        })
        return base

    # Host mode.
    e = result.enriched
    total_hosts = len(e)
    n_susp = int(e["is_suspicious"].sum()) if "is_suspicious" in e else 0
    total_flows = int((result.quality or {}).get("final_dataset_size", getattr(result, "raw_rows", 0)))
    rate = round(n_susp / total_hosts * 100, 1) if total_hosts else 0.0
    base.update({
        "total_flows": total_flows,
        "total_hosts": total_hosts,
        "suspicious_hosts": n_susp,
        "suspicious_flows": None,
        "detection_rate_pct": rate,
        "severity_breakdown": _severity_breakdown(
            e.get("severity_level", pd.Series(dtype=str)),
            ["Critical", "High", "Medium", "Low", "None"]),
        "top_threat": _top_host_threat(e),
    })
    return base


def _top_host_threat(e: pd.DataFrame) -> dict | None:
    if e is None or e.empty or "severity_score" not in e.columns:
        return None
    row = e.sort_values("severity_score", ascending=False).iloc[0]
    if float(row.get("severity_score", 0)) <= 0:
        return None
    return {
        "source_ip": str(row.get("srcip", "?")),
        "severity_level": str(row.get("severity_level", "-")),
        "severity_score": float(row.get("severity_score", 0)),
        "classification": str(row.get("classification", "-")),
        "total_connections": int(row.get("total_connections", 0)),
        "unique_destinations": int(row.get("unique_destinations", 0)),
        "unique_dst_ports": int(row.get("unique_dst_ports", 0)),
    }


def _top_flow_threat(f: pd.DataFrame) -> dict | None:
    if f is None or f.empty or "flow_score" not in f.columns:
        return None
    flagged = f[f.get("flow_is_suspicious", False) == True]  # noqa: E712
    if flagged.empty:
        return None
    row = flagged.sort_values("flow_score", ascending=False).iloc[0]
    return {
        "proto": str(row.get("proto", "?")),
        "service": str(row.get("service", "?")),
        "state": str(row.get("state", "?")),
        "severity_level": str(row.get("flow_severity", "-")),
        "indicator_count": int(row.get("flow_score", 0)),
        "reason": str(row.get("flow_reason", "")),
        "ground_truth": str(row.get("attack_cat", "n/a")),
    }


def summary_to_json(summary: dict) -> bytes:
    """Serialise the executive summary as pretty JSON bytes."""
    return json.dumps(summary, indent=2).encode("utf-8")


def summary_to_txt(summary: dict) -> bytes:
    """Render the executive summary as a plain-text report."""
    is_flow = summary.get("mode") == "flow"
    L: list[str] = []
    bar = "=" * 60
    L.append(bar)
    L.append("  NETWORK BOUNCER - EXECUTIVE SUMMARY")
    L.append(bar)
    L.append(f"Generated      : {summary['generated_at']}")
    L.append(f"Analysis mode  : {'Flow-level detection' if is_flow else 'Host-based port-scan detection'}")
    L.append("-" * 60)
    L.append(f"Total flows analysed : {summary.get('total_flows', 0):,}")

    if is_flow:
        L.append("Total hosts          : n/a (flow-level dataset - no host identity)")
        L.append(f"Suspicious flows     : {summary.get('suspicious_flows', 0):,} "
                 f"({summary.get('detection_rate_pct', 0)}% flag rate)")
    else:
        L.append(f"Total hosts          : {summary.get('total_hosts', 0):,}")
        L.append(f"Suspicious hosts     : {summary.get('suspicious_hosts', 0):,} "
                 f"({summary.get('detection_rate_pct', 0)}% detection rate)")

    sev = summary.get("severity_breakdown", {})
    if sev:
        L.append("Severity breakdown   : " + "  ".join(f"{k}={v}" for k, v in sev.items()))

    top = summary.get("top_threat")
    L.append("")
    if top and is_flow:
        L.append("TOP THREAT (flow)")
        L.append(f"  proto/service/state : {top['proto']} / {top['service']} / {top['state']}")
        L.append(f"  Severity            : {top['severity_level']} ({top['indicator_count']} indicators)")
        L.append(f"  Why flagged         : {top['reason']}")
        L.append(f"  Ground-truth label  : {top['ground_truth']}")
    elif top:
        L.append("TOP THREAT (host)")
        L.append(f"  Source IP           : {top['source_ip']}")
        L.append(f"  Severity            : {top['severity_level']} (score {top['severity_score']:.0f}/100)")
        L.append(f"  Classification      : {top['classification']}")
        L.append(f"  Connections         : {top['total_connections']:,}")
        L.append(f"  Unique destinations : {top['unique_destinations']:,}")
        L.append(f"  Unique ports        : {top['unique_dst_ports']:,}")
    else:
        L.append("TOP THREAT           : none - no suspicious activity detected")

    val = summary.get("validation")
    if val:
        L.append("")
        L.append("GROUND-TRUTH VALIDATION")
        for target, m in val.items():
            L.append(f"  {target:14s}: precision={m['precision']}  "
                     f"recall={m['recall']}  f1={m['f1']}")

    L.append(bar)
    return ("\n".join(L) + "\n").encode("utf-8")
