"""Threat → MAESTRO traceability matrix.

Aggregates risks across all analysed scenarios and shows, for each COMPASS
threat, which MAESTRO layers it touches and how often it appeared.
"""

from collections import defaultdict


def build_traceability_matrix(results):
    rows = {}
    for item in results:
        for risk in item.get("risks", []):
            threat = risk["threat"]
            row = rows.setdefault(
                threat,
                {
                    "threat": threat,
                    "layers": set(),
                    "scenarios": set(),
                    "max_score": 0,
                    "max_severity": "Low",
                    "count": 0,
                },
            )
            for layer in (risk.get("layer") or "").split(","):
                layer = layer.strip()
                if layer:
                    row["layers"].add(layer)
            row["scenarios"].add(item["scenario"]["name"])
            row["count"] += 1
            if risk["risk_score"] > row["max_score"]:
                row["max_score"] = risk["risk_score"]
                row["max_severity"] = risk["severity"]

    out = []
    for row in rows.values():
        out.append(
            {
                "threat": row["threat"],
                "layers": sorted(row["layers"]),
                "scenarios": sorted(row["scenarios"]),
                "count": row["count"],
                "max_score": row["max_score"],
                "max_severity": row["max_severity"],
            }
        )
    out.sort(key=lambda r: (-r["max_score"], -r["count"], r["threat"]))
    return out
