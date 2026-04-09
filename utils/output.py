"""Output helpers: JSON persistence, terminal rendering and run summaries."""

import json
import os
from collections import Counter

from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLOR = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High": Fore.RED,
    "Medium": Fore.YELLOW,
    "Low": Fore.GREEN,
}


def save_results(results, path):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def _color_sev(sev):
    return f"{SEVERITY_COLOR.get(sev, '')}{sev}{Style.RESET_ALL}"


def print_results(results):
    for idx, item in enumerate(results, 1):
        scenario = item["scenario"]
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Scenario {idx}: {scenario['name']}")
        print(f"{Fore.YELLOW}Description: {scenario.get('description', '')}")
        print(f"{Fore.YELLOW}Environment: {scenario.get('environment', 'n/a')}")

        layers = item.get("maestro", {}).get("layers", [])
        if layers:
            print(f"\n{Fore.GREEN}MAESTRO Layers:")
            print(
                tabulate(
                    [[l["layer"], l["likelihood"], ", ".join(l["matched_indicators"]) or "-"] for l in layers],
                    headers=["Layer", "Likelihood", "Matched Indicators"],
                    tablefmt="fancy_grid",
                )
            )

        risks = item.get("risks", [])
        print(f"\n{Fore.MAGENTA}Risks:")
        if risks:
            print(
                tabulate(
                    [
                        [
                            r["threat"],
                            r["layer"],
                            r["likelihood"],
                            r["impact"],
                            r["risk_score"],
                            _color_sev(r["severity"]),
                        ]
                        for r in risks
                    ],
                    headers=["Threat", "MAESTRO Layer(s)", "L", "I", "Score", "Severity"],
                    tablefmt="fancy_grid",
                )
            )
        else:
            print("(No risks found)")

        cves = item.get("cves", [])
        print(f"\n{Fore.BLUE}CWE / CVE Matches:")
        if cves:
            print(
                tabulate(
                    [[c["threat"], ", ".join(c["cwes"]) or "-", ", ".join(c["cves"]) or "-"] for c in cves],
                    headers=["Threat", "CWEs", "CVEs"],
                    tablefmt="fancy_grid",
                )
            )
        else:
            print("(No CWE/CVE matches)")

        recs = item.get("recommendations", [])
        print(f"\n{Fore.GREEN}Recommendations:")
        if recs:
            print(
                tabulate(
                    [[r["threat"], _color_sev(r["severity"]), r["recommendation"]] for r in recs],
                    headers=["Threat", "Severity", "Recommendation"],
                    tablefmt="fancy_grid",
                    maxcolwidths=[None, None, 70],
                )
            )
        else:
            print("(No recommendations)")

        print("\n" + "=" * 70)


def print_summary(results):
    from utils.matrix import build_traceability_matrix
    from utils.report import scenario_score, scenario_severity

    total_scenarios = len(results)
    total_risks = sum(len(r["risks"]) for r in results)
    severities = Counter(risk["severity"] for r in results for risk in r["risks"])
    top_threats = Counter(risk["threat"] for r in results for risk in r["risks"]).most_common(5)
    avg_score = (
        sum(risk["risk_score"] for r in results for risk in r["risks"]) / total_risks
        if total_risks
        else 0
    )

    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Run Summary ===")
    print(f"Scenarios analysed : {total_scenarios}")
    print(f"Total risks        : {total_risks}")
    print(f"Average risk score : {avg_score:.1f} / 25")
    print("Severity breakdown :")
    for sev in ("Critical", "High", "Medium", "Low"):
        if severities.get(sev):
            print(f"  {_color_sev(sev):<20} {severities[sev]}")
    if top_threats:
        print("Top threats        :")
        for name, count in top_threats:
            print(f"  - {name} ({count})")

    ranked = sorted(results, key=scenario_score, reverse=True)
    print("\nScenario ranking (by max risk score):")
    print(
        tabulate(
            [
                [i, r["scenario"]["name"], scenario_score(r), _color_sev(scenario_severity(r)), len(r["risks"])]
                for i, r in enumerate(ranked, 1)
            ],
            headers=["#", "Scenario", "Max Score", "Severity", "Risks"],
            tablefmt="grid",
        )
    )

    matrix = build_traceability_matrix(results)
    if matrix:
        print("\nTraceability matrix (Threat -> MAESTRO layers):")
        print(
            tabulate(
                [
                    [
                        row["threat"],
                        ", ".join(row["layers"]),
                        len(row["scenarios"]),
                        row["count"],
                        row["max_score"],
                        _color_sev(row["max_severity"]),
                    ]
                    for row in matrix
                ],
                headers=["Threat", "MAESTRO Layers", "Scenarios", "Count", "Max", "Severity"],
                tablefmt="grid",
            )
        )
