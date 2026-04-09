"""Smoke and unit tests for the threat-modeling pipeline."""

from agents.compass_agent import CompassAgent
from agents.cve_agent import CVEAgent
from agents.maestro_agent import MaestroAgent
from agents.recommendation_agent import RecommendationAgent
from agents.risk_analyzer import RiskAnalyzer
from main import run_pipeline


SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


def test_maestro_maps_layers():
    out = MaestroAgent().analyze(SCENARIO)
    assert out["layers"], "expected at least one MAESTRO layer"
    assert all(1 <= l["likelihood"] <= 5 for l in out["layers"])
    assert any(l["matched_indicators"] for l in out["layers"])


def test_compass_finds_threats():
    out = CompassAgent().assess(SCENARIO)
    threat_names = [t["threat"] for t in out["threats"]]
    assert "Tool Misuse" in threat_names


def test_risk_scoring_bounds():
    maestro = MaestroAgent().analyze(SCENARIO)
    compass = CompassAgent().assess(SCENARIO)
    risks = RiskAnalyzer().evaluate(maestro, compass, SCENARIO)
    assert risks
    for r in risks:
        assert 1 <= r["likelihood"] <= 5
        assert 1 <= r["impact"] <= 5
        assert 1 <= r["risk_score"] <= 25
        assert r["severity"] in {"Low", "Medium", "High", "Critical"}
    # Sorted descending
    scores = [r["risk_score"] for r in risks]
    assert scores == sorted(scores, reverse=True)


def test_cve_and_recommendations_align():
    maestro = MaestroAgent().analyze(SCENARIO)
    compass = CompassAgent().assess(SCENARIO)
    risks = RiskAnalyzer().evaluate(maestro, compass, SCENARIO)
    cves = CVEAgent().match_cves(risks)
    recs = RecommendationAgent().generate(risks, cves)
    assert len(cves) == len(risks) == len(recs)
    for cve in cves:
        assert isinstance(cve["cwes"], list)
    for rec in recs:
        assert rec["recommendation"]


def test_run_pipeline_end_to_end():
    results = run_pipeline([SCENARIO])
    assert len(results) == 1
    item = results[0]
    assert {"scenario", "maestro", "compass", "risks", "cves", "recommendations"} <= item.keys()
