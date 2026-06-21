"""Tests for the executive-summary export (dashboard/exports.py)."""

from __future__ import annotations

import json
from datetime import datetime

import pandas as pd

from dashboard.exports import (
    build_executive_summary,
    summary_to_json,
    summary_to_txt,
)
from dashboard.pipeline_runner import AnalysisResult

FIXED_TS = datetime(2026, 6, 21, 12, 0, 0)


def _host_result() -> AnalysisResult:
    enriched = pd.DataFrame([
        {"srcip": "10.0.0.9", "is_suspicious": True, "severity_level": "High",
         "severity_score": 54.0, "classification": "Suspicious (Backdoor/Analysis)",
         "total_connections": 80, "unique_destinations": 40, "unique_dst_ports": 40},
        {"srcip": "10.0.0.1", "is_suspicious": False, "severity_level": "None",
         "severity_score": 0.0, "classification": "Normal",
         "total_connections": 8, "unique_destinations": 1, "unique_dst_ports": 1},
    ])
    return AnalysisResult(ok=True, mode="host", raw_rows=88,
                          quality={"final_dataset_size": 88}, enriched=enriched)


def _flow_result() -> AnalysisResult:
    flow = pd.DataFrame([
        {"proto": "udp", "service": "-", "state": "INT", "flow_is_suspicious": True,
         "flow_severity": "High", "flow_score": 4, "flow_reason": "tiny payload",
         "attack_cat": "Reconnaissance"},
        {"proto": "tcp", "service": "dns", "state": "FIN", "flow_is_suspicious": False,
         "flow_severity": "Low", "flow_score": 1, "flow_reason": "", "attack_cat": "Normal"},
    ])
    metrics = {"reconnaissance": {"precision": 0.5, "recall": 0.8, "f1": 0.62,
                                  "tp": 4, "fp": 4, "fn": 1, "tn": 10, "n_truth": 5}}
    return AnalysisResult(ok=True, mode="flow", raw_rows=2, flow_df=flow,
                          flagged_flows=1, flow_metrics=metrics)


def test_host_summary_fields():
    s = build_executive_summary(_host_result(), generated_at=FIXED_TS)
    assert s["mode"] == "host"
    assert s["total_flows"] == 88
    assert s["total_hosts"] == 2
    assert s["suspicious_hosts"] == 1
    assert s["detection_rate_pct"] == 50.0
    assert s["top_threat"]["source_ip"] == "10.0.0.9"
    assert s["generated_at"] == "2026-06-21 12:00:00"


def test_flow_summary_fields():
    s = build_executive_summary(_flow_result(), generated_at=FIXED_TS)
    assert s["mode"] == "flow"
    assert s["total_hosts"] is None          # no host identity in this dataset
    assert s["suspicious_flows"] == 1
    # Breakdown is restricted to flagged flows and sums to the suspicious count.
    assert sum(s["severity_breakdown"].values()) == s["suspicious_flows"]
    assert s["top_threat"]["ground_truth"] == "Reconnaissance"
    assert s["validation"]["reconnaissance"]["f1"] == 0.62


def test_summary_serialisers():
    s = build_executive_summary(_host_result(), generated_at=FIXED_TS)
    # JSON round-trips.
    assert json.loads(summary_to_json(s))["total_hosts"] == 2
    # TXT carries the headline numbers.
    txt = summary_to_txt(s).decode("utf-8")
    assert "EXECUTIVE SUMMARY" in txt
    assert "Total hosts" in txt
    assert "10.0.0.9" in txt


def test_no_threat_when_clean():
    clean = AnalysisResult(ok=True, mode="host", raw_rows=10,
                           quality={"final_dataset_size": 10},
                           enriched=pd.DataFrame([
                               {"srcip": "10.0.0.1", "is_suspicious": False,
                                "severity_level": "None", "severity_score": 0.0,
                                "classification": "Normal", "total_connections": 5,
                                "unique_destinations": 1, "unique_dst_ports": 1}]))
    s = build_executive_summary(clean, generated_at=FIXED_TS)
    assert s["top_threat"] is None
    assert "none - no suspicious activity" in summary_to_txt(s).decode("utf-8")
