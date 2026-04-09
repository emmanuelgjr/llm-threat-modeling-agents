"""Per-threat remediation recommendations.

Pulls the canonical mitigation from ``utils.compass_threats`` and tags it
with the risk's severity so reports can be sorted by urgency.
"""

from utils.compass_threats import COMPASS_THREATS


class RecommendationAgent:
    def __init__(self, mitigations=None):
        self.mitigations = mitigations or {
            name: meta.get("mitigation", "") for name, meta in COMPASS_THREATS.items()
        }

    def generate(self, risks, cve_matches=None):
        cve_by_threat = {m["threat"]: m for m in (cve_matches or [])}
        recommendations = []
        for risk in risks:
            threat = risk["threat"]
            mitigation = self.mitigations.get(
                threat, "Apply defence-in-depth and review against MAESTRO/COMPASS guidance."
            )
            cve_match = cve_by_threat.get(threat, {})
            recommendations.append(
                {
                    "threat": threat,
                    "severity": risk["severity"],
                    "risk_score": risk["risk_score"],
                    "recommendation": mitigation,
                    "cwes": cve_match.get("cwes", []),
                }
            )
        return recommendations
