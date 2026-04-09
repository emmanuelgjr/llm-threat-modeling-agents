"""SARIF 2.1.0 exporter.

Each risk becomes a SARIF ``result`` so the report can be uploaded to GitHub
code scanning (and other SARIF-aware tools). Rules correspond to COMPASS
threats; scenarios are encoded as artifact URIs.
"""

import json
import os

from utils.compass_threats import COMPASS_THREATS

TOOL_NAME = "llm-threat-modeling-agents"
TOOL_VERSION = "0.3.0"
INFORMATION_URI = "https://github.com/emmanuelgjr/llm-threat-modeling-agents"


SEVERITY_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


def _rules():
    rules = []
    for name, meta in COMPASS_THREATS.items():
        rules.append(
            {
                "id": _rule_id(name),
                "name": name.replace(" ", ""),
                "shortDescription": {"text": name},
                "fullDescription": {
                    "text": f"OWASP COMPASS threat: {name}. MAESTRO layers: {', '.join(meta['maestro_layers'])}."
                },
                "helpUri": INFORMATION_URI,
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "cwes": meta.get("cwes", []),
                    "maestroLayers": meta.get("maestro_layers", []),
                    "mitigation": meta.get("mitigation", ""),
                },
            }
        )
    return rules


def _rule_id(threat_name):
    return "COMPASS." + "".join(ch for ch in threat_name.title() if ch.isalnum())


def _scenario_uri(scenario_name):
    safe = scenario_name.lower().replace(" ", "-")
    return f"scenarios/{safe}.json"


def write_sarif(results, path):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    artifacts = []
    artifact_indices = {}
    sarif_results = []

    for item in results:
        scenario = item["scenario"]["name"]
        if scenario not in artifact_indices:
            artifact_indices[scenario] = len(artifacts)
            artifacts.append({"location": {"uri": _scenario_uri(scenario)}})

        for risk in item.get("risks", []):
            sarif_results.append(
                {
                    "ruleId": _rule_id(risk["threat"]),
                    "level": SEVERITY_TO_LEVEL.get(risk["severity"], "warning"),
                    "message": {
                        "text": (
                            f"{risk['threat']} in scenario '{scenario}' "
                            f"(likelihood {risk['likelihood']}, impact {risk['impact']}, "
                            f"score {risk['risk_score']}, severity {risk['severity']})."
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": _scenario_uri(scenario),
                                    "index": artifact_indices[scenario],
                                }
                            }
                        }
                    ],
                    "properties": {
                        "severity": risk["severity"],
                        "score": risk["risk_score"],
                        "likelihood": risk["likelihood"],
                        "impact": risk["impact"],
                        "maestroLayers": risk.get("layer", ""),
                    },
                }
            )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": INFORMATION_URI,
                        "rules": _rules(),
                    }
                },
                "artifacts": artifacts,
                "results": sarif_results,
            }
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
