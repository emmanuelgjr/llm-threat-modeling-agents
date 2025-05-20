from agents.maestro_agent import MaestroAgent
from agents.compass_agent import CompassAgent
from agents.risk_analyzer import RiskAnalyzer
from agents.cve_agent import CVEAgent
from agents.recommendation_agent import RecommendationAgent
from utils.output import save_results, print_results
import json

def load_inputs(path):
    with open(path, "r") as f:
        return json.load(f)

def main():
    # Load input data
    inputs = load_inputs("data/sample_inputs.json")
    
    # Initialize agents
    maestro = MaestroAgent()
    compass = CompassAgent()
    risk_analyzer = RiskAnalyzer()
    cve_agent = CVEAgent()
    recommender = RecommendationAgent()

    # Process each scenario/input
    results = []
    for scenario in inputs["scenarios"]:
        # Orchestrate threat modeling
        maestro_output = maestro.analyze(scenario)
        compass_output = compass.assess(scenario)
        risks = risk_analyzer.evaluate(maestro_output, compass_output)
        cve_matches = cve_agent.match_cves(risks)
        recommendations = recommender.generate(risks, cve_matches)

        results.append({
            "scenario": scenario,
            "maestro": maestro_output,
            "compass": compass_output,
            "risks": risks,
            "cves": cve_matches,
            "recommendations": recommendations,
        })

    # Save results to JSON file
    save_results(results, "output/results.json")
    # Print results in terminal (color + tables)
    print_results(results)
    print("Threat modeling complete. Results saved to output/results.json")

if __name__ == "__main__":
    main()
