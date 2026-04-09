"""Risk scoring across MAESTRO layers and COMPASS threats.

Risk score is computed as ``likelihood * impact`` (1-25) and bucketed into
Low / Medium / High / Critical severities. Each risk is keyed by the COMPASS
threat so downstream agents (CVE matching, recommendations) can join cleanly.
"""

from utils.compass_threats import COMPASS_THREATS
from utils.scoring import get_environment_boost


def _severity(score):
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


class RiskAnalyzer:
    def __init__(self, scenario_risk_boost=None):
        # Built-in defaults are merged with any boosts loaded from plugin files
        # via utils.scoring. Constructor overrides win.
        defaults = {
            "healthcare": 1,
            "banking": 1,
            "financial": 1,
            "soc": 1,
            "legal": 1,
        }
        defaults.update(get_environment_boost())
        if scenario_risk_boost:
            defaults.update(scenario_risk_boost)
        self.scenario_risk_boost = defaults

    def evaluate(self, maestro_output, compass_output, scenario=None):
        risks = []
        layer_likelihood = {l["layer"]: l["likelihood"] for l in maestro_output.get("layers", [])}
        env = (scenario or {}).get("environment", "").lower()
        boost = max(
            (v for k, v in self.scenario_risk_boost.items() if k in env),
            default=0,
        )

        for threat in compass_output.get("threats", []):
            name = threat["threat"]
            meta = COMPASS_THREATS.get(name, {})
            # Likelihood = COMPASS keyword likelihood reinforced by the strongest
            # related MAESTRO layer hit.
            related_layer_likelihoods = [
                layer_likelihood.get(layer, 1) for layer in threat.get("maestro_layers", [])
            ]
            base_likelihood = max([threat["likelihood"], *related_layer_likelihoods, 1])
            likelihood = min(5, base_likelihood + boost)
            impact = threat.get("impact", meta.get("impact", 3))
            score = likelihood * impact
            risks.append(
                {
                    "threat": name,
                    "layer": ", ".join(threat.get("maestro_layers", [])) or "Agent",
                    "likelihood": likelihood,
                    "impact": impact,
                    "risk_score": score,
                    "severity": _severity(score),
                    "description": f"{name}: matched indicators {threat.get('matched_indicators') or 'n/a'}",
                }
            )

        risks.sort(key=lambda r: r["risk_score"], reverse=True)
        return risks
