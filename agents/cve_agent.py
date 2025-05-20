class CVEAgent:
    """
    Matches risks to known CVEs/CWEs (proof of concept).
    """
    def __init__(self):
        pass

    def match_cves(self, risks):
        """
        Mockup: Match risk items to sample CVEs/CWEs.
        """
        matches = []
        for risk in risks:
            # Demo: Attach a fake CVE to each risk
            matches.append({
                "risk": risk["description"],
                "cve": "CVE-2024-XXXX",
                "cwe": "CWE-123"
            })
        return matches
