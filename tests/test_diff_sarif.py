"""Tests for the diff engine and SARIF exporter."""

import copy
import json
import subprocess
import sys
from pathlib import Path

from main import run_pipeline
from utils.diff import diff_results, format_diff_text
from utils.sarif import write_sarif


SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


# ---- Diff ------------------------------------------------------------------

def test_diff_identical_results_is_empty():
    results = run_pipeline([SCENARIO])
    diff = diff_results(results, copy.deepcopy(results))
    assert diff["summary"] == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "regressions": 0,
        "improvements": 0,
    }


def test_diff_detects_added_removed_and_changed():
    baseline = run_pipeline([SCENARIO])
    current = copy.deepcopy(baseline)
    # Remove one risk -> "resolved"
    removed_risk = current[0]["risks"].pop()
    # Add a new risk -> "added"
    current[0]["risks"].append(
        {
            "threat": "Synthetic New Threat",
            "layer": "Agent",
            "likelihood": 3,
            "impact": 4,
            "risk_score": 12,
            "severity": "High",
            "description": "synthetic",
        }
    )
    # Worsen another risk
    current[0]["risks"][0] = {
        **current[0]["risks"][0],
        "severity": "Critical",
        "risk_score": 25,
    }
    diff = diff_results(baseline, current)
    assert diff["summary"]["added"] == 1
    assert diff["summary"]["removed"] == 1
    assert diff["summary"]["regressions"] >= 1
    assert removed_risk["threat"] in [r["threat"] for r in diff["removed"]]
    text = format_diff_text(diff)
    assert "Diff summary" in text


# ---- SARIF -----------------------------------------------------------------

def test_sarif_structure(tmp_path):
    results = run_pipeline([SCENARIO])
    out = tmp_path / "results.sarif"
    write_sarif(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "llm-threat-modeling-agents"
    assert run["tool"]["driver"]["rules"]
    assert run["results"], "expected at least one SARIF result"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in {"error", "warning", "note"}


# ---- CLI fail-on-diff ------------------------------------------------------

def test_cli_fail_on_diff_exits_3(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    baseline_path = tmp_path / "baseline.json"
    out_path = tmp_path / "current.json"

    # First run -> baseline
    subprocess.run(
        [sys.executable, "main.py", "--quiet", "--output", str(baseline_path)],
        cwd=repo,
        check=True,
        env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
    )
    # Hand-edit baseline so the next run shows new risks (drop one risk per scenario)
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    for item in data:
        if item["risks"]:
            item["risks"].pop(0)
    baseline_path.write_text(json.dumps(data), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--quiet",
            "--output",
            str(out_path),
            "--diff",
            str(baseline_path),
            "--fail-on-diff",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert proc.returncode == 3, proc.stderr
