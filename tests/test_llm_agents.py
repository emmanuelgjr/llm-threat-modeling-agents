"""Tests for the optional LLM-backed agents (no real API calls)."""

import json
import sys
from types import SimpleNamespace

import pytest

from agents.llm_agents import LLMCompassAgent, LLMMaestroAgent


SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


def test_llm_maestro_falls_back_when_disabled(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = LLMMaestroAgent()
    assert agent.enabled is False
    out = agent.analyze(SCENARIO)
    # Falls back to keyword agent — no 'source' field, layers populated.
    assert out["layers"]
    assert out.get("source") != "llm"


def test_llm_compass_falls_back_when_disabled(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    agent = LLMCompassAgent()
    out = agent.assess(SCENARIO)
    assert out["threats"]
    assert out.get("source") != "llm"


class _FakeMessages:
    def __init__(self, payload):
        self._payload = payload

    def create(self, model, max_tokens, system, messages):
        return SimpleNamespace(content=[SimpleNamespace(text=self._payload)])


class _FakeAnthropic:
    def __init__(self, payload):
        self.messages = _FakeMessages(payload)


def test_llm_maestro_uses_fake_client():
    payload = json.dumps(
        {
            "summary": "test",
            "layers": [
                {"layer": "Tools", "likelihood": 5, "matched_indicators": ["tool"], "reason": "tool calls"},
                {"layer": "Resources", "likelihood": 4, "matched_indicators": ["customer data"], "reason": "PII"},
                {"layer": "BogusLayer", "likelihood": 3},
            ],
        }
    )
    agent = LLMMaestroAgent()
    agent._client = _FakeAnthropic(payload)
    agent.enabled = True
    out = agent.analyze(SCENARIO)
    assert out["source"] == "llm"
    layers = [l["layer"] for l in out["layers"]]
    assert "Tools" in layers and "Resources" in layers
    assert "BogusLayer" not in layers  # invalid layers dropped
    assert out["layers"][0]["likelihood"] == 5  # sorted desc


def test_llm_compass_uses_fake_client():
    payload = json.dumps(
        {
            "summary": "test",
            "threats": [
                {"threat": "Tool Misuse", "likelihood": 5, "matched_indicators": ["tool"]},
                {"threat": "Identity Spoofing & Impersonation", "likelihood": 4},
                {"threat": "Not A Real Threat", "likelihood": 5},
            ],
        }
    )
    agent = LLMCompassAgent()
    agent._client = _FakeAnthropic(payload)
    agent.enabled = True
    out = agent.assess(SCENARIO)
    assert out["source"] == "llm"
    names = [t["threat"] for t in out["threats"]]
    assert "Tool Misuse" in names
    assert "Not A Real Threat" not in names


def test_llm_maestro_falls_back_on_api_error():
    class Boom:
        class messages:
            @staticmethod
            def create(**_):
                raise RuntimeError("network down")

    agent = LLMMaestroAgent()
    agent._client = Boom
    agent.enabled = True
    out = agent.analyze(SCENARIO)
    # Should silently fall back, returning a valid keyword analysis.
    assert out["layers"]
    assert out.get("source") != "llm"
