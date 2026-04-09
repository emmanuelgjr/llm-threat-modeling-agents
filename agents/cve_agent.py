"""Map identified risks to CWE weakness identifiers and (optionally) CVEs.

By default the agent only emits CWE IDs declared per COMPASS threat in
``utils.compass_threats`` — no fabricated CVEs. Pass ``nvd_enabled=True`` (or
inject a custom client) to populate real CVE entries from the NVD 2.0 API.
"""

from utils.compass_threats import COMPASS_THREATS
from utils.nvd import NVDClient


class CVEAgent:
    def __init__(self, cwe_index=None, nvd_enabled: bool = False, nvd_client=None):
        self.cwe_index = cwe_index or {
            name: meta.get("cwes", []) for name, meta in COMPASS_THREATS.items()
        }
        self.nvd_enabled = nvd_enabled
        self._nvd = nvd_client if nvd_client is not None else (NVDClient() if nvd_enabled else None)

    def match_cves(self, risks):
        matches = []
        for risk in risks:
            cwes = self.cwe_index.get(risk["threat"], [])
            matches.append(
                {
                    "threat": risk["threat"],
                    "risk": risk["description"],
                    "severity": risk["severity"],
                    "cwes": cwes,
                    "cves": self.lookup_cves(risk["threat"], cwes),
                }
            )
        return matches

    def lookup_cves(self, threat, cwes):
        """Return CVE entries for the given CWEs.

        When NVD lookups are disabled, returns an empty list (no fake IDs).
        """
        if not self._nvd or not cwes:
            return []
        return self._nvd.fetch_for_cwes(cwes)
