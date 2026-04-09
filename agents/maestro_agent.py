"""MAESTRO layer analyser.

Maps a free-text scenario onto the MAESTRO layers using keyword indicators
declared in ``utils.maestro_layers``. Each matched layer gets a likelihood
score (1-5) based on how strongly the scenario hits that layer's keywords.
"""

from utils.maestro_layers import MAESTRO_LAYERS


class MaestroAgent:
    def __init__(self, layers=None):
        self.layers = layers or MAESTRO_LAYERS

    def analyze(self, scenario):
        text = self._scenario_text(scenario).lower()
        layer_hits = []
        for name, meta in self.layers.items():
            hits = [kw for kw in meta["indicators"] if kw in text]
            # Every layer is at least minimally relevant for an LLM agent system,
            # so floor likelihood at 1 instead of dropping the layer entirely.
            likelihood = min(5, 1 + len(hits))
            layer_hits.append(
                {
                    "layer": name,
                    "description": meta["description"],
                    "likelihood": likelihood,
                    "matched_indicators": hits,
                }
            )

        layer_hits.sort(key=lambda l: l["likelihood"], reverse=True)
        return {
            "scenario": scenario.get("name", "unnamed"),
            "summary": f"Mapped scenario '{scenario.get('name', 'unnamed')}' to {len(layer_hits)} MAESTRO layers.",
            "layers": layer_hits,
            "maestro_layers": [l["layer"] for l in layer_hits],  # backwards compat
        }

    @staticmethod
    def _scenario_text(scenario):
        parts = [
            scenario.get("name", ""),
            scenario.get("description", ""),
            scenario.get("environment", ""),
        ]
        agents = scenario.get("agents_involved") or []
        if isinstance(agents, list):
            parts.extend(agents)
        return " ".join(str(p) for p in parts if p)
