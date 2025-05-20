class RecommendationAgent:
    """
    Generates mitigation and remediation recommendations for identified risks.
    """
    def __init__(self):
        pass

    def generate(self, risks, cve_matches):
        """
        Generate recommendations for each risk/CVE.
        """
        recommendations = []
        for risk, cve in zip(risks, cve_matches):
            recommendations.append({
                "risk": risk["description"],
                "recommendation": f"Mitigate {risk['description']} by following best practices. See {cve['cve']}."
            })
        return recommendations
