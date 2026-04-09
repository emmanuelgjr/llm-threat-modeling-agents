"""Tests for trend tracking (history.jsonl) and Mermaid diagram generation."""

import json
from pathlib import Path

from main import run_pipeline
from utils.history import append_history, history_trend_svg, load_history
from utils.mermaid import scenario_mermaid


SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


# ---- History ---------------------------------------------------------------

def test_history_appends_entries(tmp_path):
    results = run_pipeline([SCENARIO])
    path = tmp_path / "hist.jsonl"
    e1 = append_history(results, str(path), label="run-1")
    e2 = append_history(results, str(path), label="run-2")
    assert e1["label"] == "run-1"
    assert e2["label"] == "run-2"
    loaded = load_history(str(path))
    assert len(loaded) == 2
    for entry in loaded:
        assert {"timestamp", "scenarios", "total_risks", "avg_score", "max_score", "severities"} <= entry.keys()
        assert entry["scenarios"] == 1
        assert entry["max_score"] >= 1


def test_history_trend_svg_renders():
    history = [
        {"timestamp": "2025-01-01T00:00:00+00:00", "avg_score": 5.0, "max_score": 12},
        {"timestamp": "2025-02-01T00:00:00+00:00", "avg_score": 8.5, "max_score": 20},
        {"timestamp": "2025-03-01T00:00:00+00:00", "avg_score": 9.2, "max_score": 25},
    ]
    svg = history_trend_svg(history)
    assert svg.startswith("<svg")
    assert "polyline" in svg
    assert "avg score" in svg
    assert "max score" in svg


def test_history_handles_empty(tmp_path):
    assert load_history(str(tmp_path / "missing.jsonl")) == []
    assert history_trend_svg([]) == ""


# ---- Mermaid ---------------------------------------------------------------

def test_mermaid_scenario_diagram_has_expected_pieces():
    results = run_pipeline([SCENARIO])
    diagram = scenario_mermaid(results[0])
    assert diagram.startswith("```mermaid")
    assert "flowchart LR" in diagram
    assert SCENARIO["name"] in diagram
    # At least one threat node and at least one severity class assignment.
    assert "T_" in diagram and "L_" in diagram and "class T_" in diagram
    assert diagram.endswith("```")


def test_mermaid_empty_when_no_risks():
    fake = {"scenario": {"name": "x"}, "risks": []}
    assert scenario_mermaid(fake) == ""
