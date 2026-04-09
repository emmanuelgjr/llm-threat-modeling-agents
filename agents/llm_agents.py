"""Optional LLM-backed MAESTRO and COMPASS agents.

These wrap the keyword-based agents and ask an Anthropic Claude model to
produce a structured JSON analysis of the scenario. Behaviour is graceful:

- If the ``anthropic`` package isn't installed, the LLM agents fall back to
  the keyword agents transparently.
- If ``ANTHROPIC_API_KEY`` is missing, they fall back too.
- If the API call fails for any reason, they fall back and log a warning.

The downstream pipeline (RiskAnalyzer, CVEAgent, RecommendationAgent) only
ever sees the canonical output schema, so the LLM agents are a drop-in.
"""

from __future__ import annotations

import json
import logging
import os
import re

from agents.compass_agent import CompassAgent
from agents.maestro_agent import MaestroAgent
from utils.compass_threats import COMPASS_THREATS
from utils.maestro_layers import MAESTRO_LAYERS

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 1500


def _try_import_anthropic():
    try:
        import anthropic  # type: ignore

        return anthropic
    except ImportError:
        return None


def _extract_json(text: str):
    """Pull the first JSON object out of a model response."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in model response")
    return json.loads(match.group(0))


class _LLMBase:
    """Shared client wiring for the LLM-backed agents."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        self.model = model
        self._anthropic = _try_import_anthropic()
        api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if self._anthropic and api_key:
            self._client = self._anthropic.Anthropic(api_key=api_key)
            self.enabled = True
        else:
            self._client = None
            self.enabled = False
            if not self._anthropic:
                logger.info("anthropic package not installed; using keyword fallback.")
            elif not api_key:
                logger.info("ANTHROPIC_API_KEY not set; using keyword fallback.")

    def _call(self, system: str, user: str) -> str:
        message = self._client.messages.create(
            model=self.model,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # SDK returns a list of content blocks; concatenate text blocks.
        return "".join(getattr(block, "text", "") for block in message.content)


class LLMMaestroAgent(_LLMBase):
    """LLM-backed MAESTRO layer mapping."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        super().__init__(model=model, api_key=api_key)
        self._fallback = MaestroAgent()

    def analyze(self, scenario):
        if not self.enabled:
            return self._fallback.analyze(scenario)
        try:
            payload = self._call(
                system=(
                    "You are a security architect performing MAESTRO threat-layer "
                    "analysis on an LLM/GenAI system. Reply with strict JSON only."
                ),
                user=self._prompt(scenario),
            )
            data = _extract_json(payload)
            layers = self._normalise_layers(data.get("layers", []))
            return {
                "scenario": scenario.get("name", "unnamed"),
                "summary": data.get("summary")
                or f"LLM mapped scenario '{scenario.get('name', 'unnamed')}' to {len(layers)} MAESTRO layers.",
                "layers": layers,
                "maestro_layers": [l["layer"] for l in layers],
                "source": "llm",
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLMMaestroAgent failed (%s); falling back.", exc)
            return self._fallback.analyze(scenario)

    @staticmethod
    def _prompt(scenario):
        return (
            f"Scenario name: {scenario.get('name', '')}\n"
            f"Description: {scenario.get('description', '')}\n"
            f"Environment: {scenario.get('environment', '')}\n\n"
            f"Valid MAESTRO layers: {list(MAESTRO_LAYERS.keys())}\n\n"
            "Return JSON of the form:\n"
            "{\n"
            '  "summary": "<one sentence>",\n'
            '  "layers": [\n'
            '    {"layer": "Memory", "likelihood": 1-5, "matched_indicators": ["..."], "reason": "..."}\n'
            "  ]\n"
            "}\n"
            "Include every layer that is at least minimally relevant. Likelihood is 1-5."
        )

    @staticmethod
    def _normalise_layers(raw):
        out = []
        for entry in raw:
            name = entry.get("layer")
            if name not in MAESTRO_LAYERS:
                continue
            likelihood = max(1, min(5, int(entry.get("likelihood", 1))))
            out.append(
                {
                    "layer": name,
                    "description": MAESTRO_LAYERS[name]["description"],
                    "likelihood": likelihood,
                    "matched_indicators": entry.get("matched_indicators") or [],
                    "reason": entry.get("reason", ""),
                }
            )
        out.sort(key=lambda l: l["likelihood"], reverse=True)
        return out


class LLMCompassAgent(_LLMBase):
    """LLM-backed COMPASS threat assessment."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        super().__init__(model=model, api_key=api_key)
        self._fallback = CompassAgent()

    def assess(self, scenario):
        if not self.enabled:
            return self._fallback.assess(scenario)
        try:
            payload = self._call(
                system=(
                    "You are a security architect applying the OWASP COMPASS GenAI "
                    "threat taxonomy. Reply with strict JSON only."
                ),
                user=self._prompt(scenario),
            )
            data = _extract_json(payload)
            threats = self._normalise_threats(data.get("threats", []))
            return {
                "scenario": scenario.get("name", "unnamed"),
                "summary": data.get("summary")
                or f"LLM identified {len(threats)} COMPASS threats for '{scenario.get('name', 'unnamed')}'.",
                "threats": threats,
                "compass_threats": [t["threat"] for t in threats],
                "source": "llm",
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLMCompassAgent failed (%s); falling back.", exc)
            return self._fallback.assess(scenario)

    @staticmethod
    def _prompt(scenario):
        return (
            f"Scenario name: {scenario.get('name', '')}\n"
            f"Description: {scenario.get('description', '')}\n"
            f"Environment: {scenario.get('environment', '')}\n\n"
            f"Valid COMPASS threats: {list(COMPASS_THREATS.keys())}\n\n"
            "Return JSON of the form:\n"
            "{\n"
            '  "summary": "<one sentence>",\n'
            '  "threats": [\n'
            '    {"threat": "Tool Misuse", "likelihood": 1-5, "matched_indicators": ["..."], "reason": "..."}\n'
            "  ]\n"
            "}\n"
            "Only include threats that genuinely apply. Likelihood is 1-5."
        )

    @staticmethod
    def _normalise_threats(raw):
        out = []
        for entry in raw:
            name = entry.get("threat")
            meta = COMPASS_THREATS.get(name)
            if not meta:
                continue
            likelihood = max(1, min(5, int(entry.get("likelihood", 1))))
            out.append(
                {
                    "threat": name,
                    "likelihood": likelihood,
                    "impact": meta["impact"],
                    "maestro_layers": meta["maestro_layers"],
                    "matched_indicators": entry.get("matched_indicators") or [],
                    "reason": entry.get("reason", ""),
                }
            )
        out.sort(key=lambda t: t["likelihood"] * t["impact"], reverse=True)
        return out
