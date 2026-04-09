"""Flat CSV risk register export.

One row per (scenario, threat) so the file drops straight into a spreadsheet
or BI tool. Mirrors the fields produced by the pipeline.
"""

from __future__ import annotations

import csv
import os

CSV_HEADERS = [
    "scenario",
    "environment",
    "threat",
    "maestro_layers",
    "likelihood",
    "impact",
    "risk_score",
    "severity",
    "cwes",
    "recommendation",
]


def write_csv(results, path: str) -> int:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    rows = 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        for item in results:
            scenario = item["scenario"]
            recs_by_threat = {r["threat"]: r for r in item.get("recommendations", [])}
            for risk in item.get("risks", []):
                rec = recs_by_threat.get(risk["threat"], {})
                writer.writerow(
                    [
                        scenario.get("name", ""),
                        scenario.get("environment", ""),
                        risk["threat"],
                        risk.get("layer", ""),
                        risk["likelihood"],
                        risk["impact"],
                        risk["risk_score"],
                        risk["severity"],
                        ";".join(rec.get("cwes", [])),
                        rec.get("recommendation", ""),
                    ]
                )
                rows += 1
    return rows
