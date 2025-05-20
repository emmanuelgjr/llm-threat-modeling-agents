import json
import os
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

def save_results(results, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(results, f, indent=2)

def print_results(results):
    for idx, item in enumerate(results, 1):
        print(f"{Fore.CYAN}{Style.BRIGHT}Scenario {idx}: {item['scenario']['name']}")
        print(f"{Fore.YELLOW}Description: {item['scenario'].get('description', '')}")
        print(f"{Fore.GREEN}MAESTRO Output: {item.get('maestro', {})}")
        print(f"{Fore.GREEN}COMPASS Output: {item.get('compass', {})}")

        # Print Risks Table
        print(f"{Fore.MAGENTA}\nRisks:")
        risk_table = [
            [risk.get("layer", ""), risk.get("risk_score", ""), risk.get("description", "")]
            for risk in item.get("risks", [])
        ]
        if risk_table:
            print(tabulate(risk_table, headers=["Layer", "Risk Score", "Description"], tablefmt="fancy_grid"))
        else:
            print("(No risks found)")

        # Print CVEs Table
        print(f"{Fore.BLUE}\nCVE Matches:")
        cve_table = [
            [cve.get("risk", ""), cve.get("cve", ""), cve.get("cwe", "")]
            for cve in item.get("cves", [])
        ]
        if cve_table:
            print(tabulate(cve_table, headers=["Risk", "CVE", "CWE"], tablefmt="fancy_grid"))
        else:
            print("(No CVEs found)")

        # Print Recommendations Table
        print(f"{Fore.GREEN}\nRecommendations:")
        rec_table = [
            [rec.get("risk", ""), rec.get("recommendation", "")]
            for rec in item.get("recommendations", [])
        ]
        if rec_table:
            print(tabulate(rec_table, headers=["Risk", "Recommendation"], tablefmt="fancy_grid"))
        else:
            print("(No recommendations found)")

        print("\n" + "="*60 + "\n")
