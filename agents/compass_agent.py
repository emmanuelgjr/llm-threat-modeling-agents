"""OWASP COMPASS threat assessment.

Matches scenario keywords against the COMPASS threat metadata in
``utils.compass_threats`` and emits a likelihood score per matched threat.
"""

from utils.compass_threats import COMPASS_THREATS


class CompassAgent:
    def __init__(self, threats=None):
        self.threats = threats or COMPASS_THREATS

    def assess(self, scenario):
        text = self._scenario_text(scenario).lower()
        matched = []
        for name, meta in self.threats.items():
            hits = [kw for kw in meta["indicators"] if kw in text]
            if not hits:
                continue
            likelihood = min(5, 1 + len(hits))
            matched.append(
                {
                    "threat": name,
                    "likelihood": likelihood,
                    "impact": meta["impact"],
                    "maestro_layers": meta["maestro_layers"],
                    "matched_indicators": hits,
                }
            )

        # Always surface at least the top generic threats so reports aren't empty.
        if not matched:
            for fallback in ("Intent Breaking & Goal Manipulation", "Tool Misuse"):
                meta = self.threats[fallback]
                matched.append(
                    {
                        "threat": fallback,
                        "likelihood": 2,
                        "impact": meta["impact"],
                        "maestro_layers": meta["maestro_layers"],
                        "matched_indicators": [],
                    }
                )

        matched.sort(key=lambda t: t["likelihood"] * t["impact"], reverse=True)
        return {
            "scenario": scenario.get("name", "unnamed"),
            "summary": f"Identified {len(matched)} COMPASS threats for '{scenario.get('name', 'unnamed')}'.",
            "threats": matched,
            "compass_threats": [t["threat"] for t in matched],  # backwards compat
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
