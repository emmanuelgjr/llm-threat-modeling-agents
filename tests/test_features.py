"""Tests for schema validation, NVD client (mocked), and traceability matrix."""

import json
import pytest

from agents.cve_agent import CVEAgent
from main import run_pipeline
from utils.matrix import build_traceability_matrix
from utils.schema import SchemaError, validate_inputs


SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


# ---- Schema validation -----------------------------------------------------

def test_schema_accepts_valid():
    validate_inputs({"scenarios": [SCENARIO]})


def test_schema_rejects_missing_field():
    with pytest.raises(SchemaError, match="missing required field 'description'"):
        validate_inputs({"scenarios": [{"name": "x", "environment": "y"}]})


def test_schema_rejects_empty_scenarios():
    with pytest.raises(SchemaError, match="non-empty array"):
        validate_inputs({"scenarios": []})


def test_schema_rejects_duplicate_names():
    with pytest.raises(SchemaError, match="Duplicate scenario name"):
        validate_inputs({"scenarios": [SCENARIO, SCENARIO]})


def test_schema_rejects_bad_agents_involved():
    bad = {**SCENARIO, "agents_involved": "not-a-list"}
    with pytest.raises(SchemaError, match="agents_involved"):
        validate_inputs({"scenarios": [bad]})


# ---- Traceability matrix ---------------------------------------------------

def test_traceability_matrix_structure():
    results = run_pipeline([SCENARIO])
    matrix = build_traceability_matrix(results)
    assert matrix
    row = matrix[0]
    assert {"threat", "layers", "scenarios", "count", "max_score", "max_severity"} <= row.keys()
    # Sorted by max_score descending
    scores = [r["max_score"] for r in matrix]
    assert scores == sorted(scores, reverse=True)


# ---- NVD CVE agent (mocked) ------------------------------------------------

class FakeNVD:
    def __init__(self):
        self.calls = []

    def fetch_for_cwes(self, cwes):
        self.calls.append(tuple(cwes))
        return [{"id": "CVE-2099-0001", "summary": "fake", "cvss": 9.8, "severity": "CRITICAL"}]


def test_cve_agent_uses_injected_nvd_client():
    fake = FakeNVD()
    agent = CVEAgent(nvd_enabled=True, nvd_client=fake)
    risks = [{"threat": "Tool Misuse", "description": "x", "severity": "High"}]
    matches = agent.match_cves(risks)
    assert matches[0]["cves"][0]["id"] == "CVE-2099-0001"
    assert fake.calls, "NVD client should have been called"


def test_cve_agent_disabled_by_default():
    agent = CVEAgent()
    risks = [{"threat": "Tool Misuse", "description": "x", "severity": "High"}]
    assert agent.match_cves(risks)[0]["cves"] == []
