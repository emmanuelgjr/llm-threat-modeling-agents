"""Generate Mermaid flowcharts for the Markdown report.

GitHub renders ```mermaid``` fenced blocks natively, so the diagrams appear
inline in any GitHub-rendered Markdown report without extra tooling.

For each scenario we draw a flowchart:

    Scenario --> MAESTRO Layer --> COMPASS Threat (color-coded by severity)

Threat nodes carry their severity in the label so the chart conveys risk
at a glance even in plain text.
"""

from __future__ import annotations

import re

SEVERITY_CLASS = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}

CLASS_DEFS = (
    "    classDef critical fill:#b00020,stroke:#600,color:#fff;\n"
    "    classDef high fill:#d35400,stroke:#732d00,color:#fff;\n"
    "    classDef medium fill:#c9a227,stroke:#7a6116,color:#222;\n"
    "    classDef low fill:#2e7d32,stroke:#1b4d1f,color:#fff;\n"
    "    classDef scenario fill:#263238,stroke:#000,color:#fff;\n"
    "    classDef layer fill:#eceff1,stroke:#90a4ae,color:#222;\n"
)


def _safe_id(text: str, prefix: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")
    return f"{prefix}_{cleaned}"[:60]


def scenario_mermaid(item: dict) -> str:
    scenario = item["scenario"]
    risks = item.get("risks", [])
    if not risks:
        return ""

    scenario_id = _safe_id(scenario["name"], "S")
    lines = ["```mermaid", "flowchart LR", CLASS_DEFS.rstrip()]
    lines.append(f'    {scenario_id}["{scenario["name"]}"]:::scenario')

    layer_ids: dict[str, str] = {}
    threat_ids: dict[str, str] = {}
    severity_classes: dict[str, str] = {}

    for risk in risks:
        threat = risk["threat"]
        threat_node = threat_ids.setdefault(threat, _safe_id(threat, "T"))
        severity_classes[threat_node] = SEVERITY_CLASS.get(risk["severity"], "medium")
        label = f"{threat}<br/>{risk['severity']} ({risk['risk_score']})"
        lines.append(f'    {threat_node}["{label}"]')

        for layer in (risk.get("layer") or "").split(","):
            layer = layer.strip()
            if not layer:
                continue
            layer_node = layer_ids.setdefault(layer, _safe_id(layer, "L"))
            lines.append(f'    {layer_node}(["{layer}"]):::layer')
            lines.append(f"    {scenario_id} --> {layer_node}")
            lines.append(f"    {layer_node} --> {threat_node}")

    for node_id, cls in severity_classes.items():
        lines.append(f"    class {node_id} {cls};")

    lines.append("```")
    # De-duplicate consecutive identical lines (edges/nodes can repeat).
    seen = set()
    deduped = []
    for line in lines:
        key = line.strip()
        if key.startswith(("flowchart", "classDef", "```", "class ")) or key not in seen:
            deduped.append(line)
            seen.add(key)
    return "\n".join(deduped)
