"""Markdown and HTML report generation."""

import html
import os
from collections import Counter

from utils.matrix import build_traceability_matrix
from utils.mermaid import scenario_mermaid


SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
SEVERITY_BADGE = {
    "Critical": "#b00020",
    "High": "#d35400",
    "Medium": "#c9a227",
    "Low": "#2e7d32",
}
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")


def _severity_bar_svg(severities):
    width = 520
    bar_h = 28
    gap = 8
    label_w = 90
    max_count = max((severities.get(s, 0) for s in SEVERITY_ORDER), default=0) or 1
    bar_max = width - label_w - 60
    height = (bar_h + gap) * len(SEVERITY_ORDER) + 20
    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' role='img' aria-label='Severity breakdown'>",
        "<style>text{font:13px -apple-system,Segoe UI,Arial,sans-serif;fill:#222}</style>",
    ]
    for i, sev in enumerate(SEVERITY_ORDER):
        count = severities.get(sev, 0)
        y = 10 + i * (bar_h + gap)
        bar_w = int((count / max_count) * bar_max) if count else 0
        parts.append(f"<text x='0' y='{y + bar_h - 9}'>{sev}</text>")
        parts.append(
            f"<rect x='{label_w}' y='{y}' width='{bar_w}' height='{bar_h}' "
            f"fill='{SEVERITY_BADGE[sev]}' rx='4'/>"
        )
        parts.append(f"<text x='{label_w + bar_w + 8}' y='{y + bar_h - 9}'>{count}</text>")
    parts.append("</svg>")
    return "".join(parts)


def _scenario_score_svg(results):
    if not results:
        return ""
    width = 720
    row_h = 22
    gap = 6
    label_w = 240
    bar_max = width - label_w - 70
    height = (row_h + gap) * len(results) + 20
    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' role='img' aria-label='Scenario scores'>",
        "<style>text{font:12px -apple-system,Segoe UI,Arial,sans-serif;fill:#222}</style>",
    ]
    ranked = sorted(results, key=lambda r: scenario_score(r), reverse=True)
    for i, item in enumerate(ranked):
        score = scenario_score(item)
        sev = scenario_severity(item)
        name = item["scenario"]["name"]
        if len(name) > 34:
            name = name[:33] + "\u2026"
        y = 10 + i * (row_h + gap)
        bar_w = int((score / 25) * bar_max)
        parts.append(f"<text x='0' y='{y + row_h - 7}'>{html.escape(name)}</text>")
        parts.append(
            f"<rect x='{label_w}' y='{y}' width='{bar_w}' height='{row_h}' "
            f"fill='{SEVERITY_BADGE[sev]}' rx='3'/>"
        )
        parts.append(f"<text x='{label_w + bar_w + 8}' y='{y + row_h - 7}'>{score}/25</text>")
    parts.append("</svg>")
    return "".join(parts)


def _aggregate(results):
    total_risks = sum(len(r["risks"]) for r in results)
    severities = Counter(risk["severity"] for r in results for risk in r["risks"])
    top_threats = Counter(risk["threat"] for r in results for risk in r["risks"]).most_common(5)
    avg = (
        sum(risk["risk_score"] for r in results for risk in r["risks"]) / total_risks
        if total_risks
        else 0
    )
    return {
        "scenarios": len(results),
        "total_risks": total_risks,
        "severities": severities,
        "top_threats": top_threats,
        "avg_score": avg,
    }


def scenario_score(item):
    """Single 0-25 score for a scenario: max risk score across its risks."""
    risks = item.get("risks", [])
    return max((r["risk_score"] for r in risks), default=0)


def scenario_severity(item):
    risks = item.get("risks", [])
    if not risks:
        return "Low"
    return max((r["severity"] for r in risks), key=lambda s: SEVERITY_RANK[s])


def _ensure_dir(path):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def write_markdown(results, path):
    _ensure_dir(path)
    agg = _aggregate(results)
    lines = []
    lines.append("# LLM Threat Modeling Report\n")
    lines.append("## Run summary\n")
    lines.append(f"- Scenarios analysed: **{agg['scenarios']}**")
    lines.append(f"- Total risks: **{agg['total_risks']}**")
    lines.append(f"- Average risk score: **{agg['avg_score']:.1f} / 25**")
    lines.append("- Severity breakdown:")
    for sev in ("Critical", "High", "Medium", "Low"):
        if agg["severities"].get(sev):
            lines.append(f"  - {sev}: {agg['severities'][sev]}")
    if agg["top_threats"]:
        lines.append("- Top threats:")
        for name, count in agg["top_threats"]:
            lines.append(f"  - {name} ({count})")
    lines.append("")

    matrix = build_traceability_matrix(results)
    if matrix:
        lines.append("## Traceability matrix (Threat → MAESTRO layers)\n")
        lines.append("| Threat | MAESTRO Layers | Scenarios | Count | Max Score | Severity |")
        lines.append("|---|---|---|---|---|---|")
        for row in matrix:
            lines.append(
                f"| {row['threat']} | {', '.join(row['layers'])} | "
                f"{len(row['scenarios'])} | {row['count']} | {row['max_score']} | {row['max_severity']} |"
            )
        lines.append("")

    for idx, item in enumerate(results, 1):
        scenario = item["scenario"]
        lines.append(f"## {idx}. {scenario['name']}")
        lines.append(f"**Environment:** {scenario.get('environment', 'n/a')}  ")
        lines.append(
            f"**Scenario severity:** {scenario_severity(item)} "
            f"(max score {scenario_score(item)} / 25)"
        )
        if scenario.get("description"):
            lines.append(f"\n{scenario['description']}\n")

        diagram = scenario_mermaid(item)
        if diagram:
            lines.append("\n### Threat flow\n")
            lines.append(diagram)

        risks = item.get("risks", [])
        if risks:
            lines.append("\n### Risks\n")
            lines.append("| Threat | MAESTRO Layer(s) | L | I | Score | Severity |")
            lines.append("|---|---|---|---|---|---|")
            for r in risks:
                lines.append(
                    f"| {r['threat']} | {r['layer']} | {r['likelihood']} | "
                    f"{r['impact']} | {r['risk_score']} | {r['severity']} |"
                )

        cves = item.get("cves", [])
        cve_rows = [(c["threat"], c.get("cves", [])) for c in cves if c.get("cves")]
        if cve_rows:
            lines.append("\n### CVEs (NVD)\n")
            lines.append("| Threat | CVE | CVSS | Severity | Summary |")
            lines.append("|---|---|---|---|---|")
            for threat, cve_list in cve_rows:
                for cve in cve_list:
                    summary = (cve.get("summary") or "").replace("|", "\\|")
                    lines.append(
                        f"| {threat} | {cve['id']} | {cve.get('cvss') or '-'} | "
                        f"{cve.get('severity') or '-'} | {summary} |"
                    )

        recs = item.get("recommendations", [])
        if recs:
            lines.append("\n### Recommendations\n")
            lines.append("| Threat | Severity | CWEs | Recommendation |")
            lines.append("|---|---|---|---|")
            for rec in recs:
                cwes = ", ".join(rec.get("cwes", [])) or "-"
                lines.append(
                    f"| {rec['threat']} | {rec['severity']} | {cwes} | {rec['recommendation']} |"
                )
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_html(results, path, history=None):
    _ensure_dir(path)
    agg = _aggregate(results)
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>LLM Threat Modeling Report</title>",
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#222}",
        "h1{border-bottom:2px solid #444;padding-bottom:.3rem}",
        "h2{margin-top:2.5rem;border-bottom:1px solid #ccc;padding-bottom:.2rem}",
        "table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}",
        "th,td{border:1px solid #ddd;padding:.45rem .6rem;text-align:left;vertical-align:top;font-size:.9rem}",
        "th{background:#f4f4f4}",
        ".badge{display:inline-block;padding:.15rem .55rem;border-radius:.7rem;color:#fff;font-size:.8rem;font-weight:600}",
        ".meta{color:#555;font-size:.9rem}",
        "</style></head><body>",
        "<h1>LLM Threat Modeling Report</h1>",
        "<h2>Run summary</h2><ul>",
        f"<li>Scenarios analysed: <b>{agg['scenarios']}</b></li>",
        f"<li>Total risks: <b>{agg['total_risks']}</b></li>",
        f"<li>Average risk score: <b>{agg['avg_score']:.1f} / 25</b></li>",
        "</ul><p><b>Severity breakdown:</b> ",
    ]
    for sev in ("Critical", "High", "Medium", "Low"):
        if agg["severities"].get(sev):
            parts.append(
                f"<span class='badge' style='background:{SEVERITY_BADGE[sev]}'>"
                f"{sev}: {agg['severities'][sev]}</span> "
            )
    parts.append("</p>")
    parts.append("<h3>Severity breakdown</h3>")
    parts.append(_severity_bar_svg(agg["severities"]))
    parts.append("<h3>Scenario risk scores</h3>")
    parts.append(_scenario_score_svg(results))
    if history:
        from utils.history import history_trend_svg

        parts.append("<h3>Risk trend over time</h3>")
        parts.append(history_trend_svg(history))
    if agg["top_threats"]:
        parts.append("<p><b>Top threats:</b><ul>")
        for name, count in agg["top_threats"]:
            parts.append(f"<li>{html.escape(name)} ({count})</li>")
        parts.append("</ul></p>")

    matrix = build_traceability_matrix(results)
    if matrix:
        parts.append("<h2>Traceability matrix (Threat &rarr; MAESTRO layers)</h2>")
        parts.append("<table><tr><th>Threat</th><th>MAESTRO Layers</th><th>Scenarios</th><th>Count</th><th>Max Score</th><th>Severity</th></tr>")
        for row in matrix:
            parts.append(
                f"<tr><td>{html.escape(row['threat'])}</td>"
                f"<td>{html.escape(', '.join(row['layers']))}</td>"
                f"<td>{len(row['scenarios'])}</td><td>{row['count']}</td><td>{row['max_score']}</td>"
                f"<td><span class='badge' style='background:{SEVERITY_BADGE[row['max_severity']]}'>"
                f"{row['max_severity']}</span></td></tr>"
            )
        parts.append("</table>")

    for idx, item in enumerate(results, 1):
        scenario = item["scenario"]
        sev = scenario_severity(item)
        parts.append(f"<h2>{idx}. {html.escape(scenario['name'])}</h2>")
        parts.append(
            f"<p class='meta'>Environment: {html.escape(str(scenario.get('environment', 'n/a')))} &middot; "
            f"Severity: <span class='badge' style='background:{SEVERITY_BADGE[sev]}'>{sev}</span> "
            f"(max score {scenario_score(item)} / 25)</p>"
        )
        if scenario.get("description"):
            parts.append(f"<p>{html.escape(scenario['description'])}</p>")

        risks = item.get("risks", [])
        if risks:
            parts.append("<h3>Risks</h3><table><tr><th>Threat</th><th>MAESTRO Layer(s)</th><th>L</th><th>I</th><th>Score</th><th>Severity</th></tr>")
            for r in risks:
                parts.append(
                    f"<tr><td>{html.escape(r['threat'])}</td><td>{html.escape(r['layer'])}</td>"
                    f"<td>{r['likelihood']}</td><td>{r['impact']}</td><td>{r['risk_score']}</td>"
                    f"<td><span class='badge' style='background:{SEVERITY_BADGE[r['severity']]}'>"
                    f"{r['severity']}</span></td></tr>"
                )
            parts.append("</table>")

        cves = item.get("cves", [])
        cve_rows = [(c["threat"], c.get("cves", [])) for c in cves if c.get("cves")]
        if cve_rows:
            parts.append("<h3>CVEs (NVD)</h3><table><tr><th>Threat</th><th>CVE</th><th>CVSS</th><th>Severity</th><th>Summary</th></tr>")
            for threat, cve_list in cve_rows:
                for cve in cve_list:
                    parts.append(
                        f"<tr><td>{html.escape(threat)}</td>"
                        f"<td>{html.escape(cve['id'])}</td>"
                        f"<td>{cve.get('cvss') or '-'}</td>"
                        f"<td>{html.escape(str(cve.get('severity') or '-'))}</td>"
                        f"<td>{html.escape(cve.get('summary') or '')}</td></tr>"
                    )
            parts.append("</table>")

        recs = item.get("recommendations", [])
        if recs:
            parts.append("<h3>Recommendations</h3><table><tr><th>Threat</th><th>Severity</th><th>CWEs</th><th>Recommendation</th></tr>")
            for rec in recs:
                cwes = html.escape(", ".join(rec.get("cwes", [])) or "-")
                parts.append(
                    f"<tr><td>{html.escape(rec['threat'])}</td>"
                    f"<td><span class='badge' style='background:{SEVERITY_BADGE[rec['severity']]}'>"
                    f"{rec['severity']}</span></td><td>{cwes}</td>"
                    f"<td>{html.escape(rec['recommendation'])}</td></tr>"
                )
            parts.append("</table>")

    parts.append("</body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(parts))
