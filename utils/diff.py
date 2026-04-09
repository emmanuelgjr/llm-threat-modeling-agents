"""Diff two threat-modeling result files.

A risk is identified by ``(scenario_name, threat)``. The diff reports new
risks, resolved risks, and risks whose severity changed between runs — the
building blocks for tracking risk over time in CI.
"""

import json
from collections import OrderedDict


SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _index(results):
    """Index results as { (scenario, threat): risk_dict }."""
    out = OrderedDict()
    for item in results:
        scenario = item["scenario"]["name"]
        for risk in item.get("risks", []):
            out[(scenario, risk["threat"])] = risk
    return out


def load_results(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def diff_results(baseline, current):
    base_idx = _index(baseline)
    curr_idx = _index(current)

    added = []
    removed = []
    changed = []
    unchanged = 0

    for key, risk in curr_idx.items():
        if key not in base_idx:
            added.append({"scenario": key[0], "threat": key[1], "risk": risk})
        else:
            old = base_idx[key]
            old_sev = old.get("severity")
            new_sev = risk.get("severity")
            if old_sev != new_sev:
                direction = (
                    "worse"
                    if SEVERITY_RANK.get(new_sev, 0) > SEVERITY_RANK.get(old_sev, 0)
                    else "better"
                )
                changed.append(
                    {
                        "scenario": key[0],
                        "threat": key[1],
                        "from": old_sev,
                        "to": new_sev,
                        "from_score": old.get("risk_score"),
                        "to_score": risk.get("risk_score"),
                        "direction": direction,
                    }
                )
            else:
                unchanged += 1

    for key, risk in base_idx.items():
        if key not in curr_idx:
            removed.append({"scenario": key[0], "threat": key[1], "risk": risk})

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "regressions": sum(1 for c in changed if c["direction"] == "worse"),
            "improvements": sum(1 for c in changed if c["direction"] == "better"),
        },
    }


def format_diff_text(diff):
    lines = []
    s = diff["summary"]
    lines.append(
        f"Diff summary: +{s['added']} new  -{s['removed']} resolved  "
        f"~{s['changed']} changed  ({s['regressions']} worse, {s['improvements']} better)"
    )
    if diff["added"]:
        lines.append("\nNew risks:")
        for a in diff["added"]:
            r = a["risk"]
            lines.append(f"  + [{r['severity']}] {a['scenario']} :: {a['threat']} (score {r['risk_score']})")
    if diff["removed"]:
        lines.append("\nResolved risks:")
        for r_ in diff["removed"]:
            r = r_["risk"]
            lines.append(f"  - [{r['severity']}] {r_['scenario']} :: {r_['threat']}")
    if diff["changed"]:
        lines.append("\nSeverity changes:")
        for c in diff["changed"]:
            arrow = "->"
            tag = "WORSE" if c["direction"] == "worse" else "better"
            lines.append(
                f"  ~ [{tag}] {c['scenario']} :: {c['threat']}  "
                f"{c['from']} ({c['from_score']}) {arrow} {c['to']} ({c['to_score']})"
            )
    return "\n".join(lines)
