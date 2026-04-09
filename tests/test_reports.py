"""Tests for report exporters and CI gate logic."""

import json
import subprocess
import sys
from pathlib import Path

from main import run_pipeline
from utils.report import scenario_score, scenario_severity, write_html, write_markdown


SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


def test_markdown_and_html_reports(tmp_path):
    results = run_pipeline([SCENARIO])
    md = tmp_path / "report.md"
    htmlp = tmp_path / "report.html"
    write_markdown(results, str(md))
    write_html(results, str(htmlp))

    md_text = md.read_text(encoding="utf-8")
    assert "# LLM Threat Modeling Report" in md_text
    assert SCENARIO["name"] in md_text
    assert "| Threat |" in md_text

    html_text = htmlp.read_text(encoding="utf-8")
    assert "<html" in html_text
    assert SCENARIO["name"] in html_text
    assert "badge" in html_text


def test_scenario_aggregates():
    results = run_pipeline([SCENARIO])
    assert 1 <= scenario_score(results[0]) <= 25
    assert scenario_severity(results[0]) in {"Low", "Medium", "High", "Critical"}


def test_fail_on_critical_exit_code(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--quiet",
            "--output",
            str(tmp_path / "out.json"),
            "--fail-on",
            "critical",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
    )
    # The bundled sample inputs do produce Critical risks, so the gate should fail.
    assert proc.returncode == 2, proc.stderr


def test_fail_on_none_exit_code(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "main.py", "--quiet", "--output", str(tmp_path / "out.json")],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert len(data) == 10
