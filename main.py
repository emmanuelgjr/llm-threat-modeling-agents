"""Entry point for the LLM threat modeling pipeline.

Usage:
    python main.py [--input data/sample_inputs.json] [--output output/results.json] [--quiet]
"""

import argparse
import json
import logging
import sys

from agents.compass_agent import CompassAgent
from agents.cve_agent import CVEAgent
from agents.llm_agents import LLMCompassAgent, LLMMaestroAgent
from agents.maestro_agent import MaestroAgent
from agents.recommendation_agent import RecommendationAgent
from agents.risk_analyzer import RiskAnalyzer
from utils.cache import clear_cache, compute_cache_key, read_cache, write_cache
from utils.explain import explain
from utils.config import find_config, load_defaults
from utils.csv_export import write_csv
from utils.diff import diff_results, format_diff_text, load_results
from utils.history import append_history, history_trend_svg, load_history
from utils.init_project import init_project
from utils.output import print_results, print_summary, save_results
from utils.plugins import PluginError, load_plugins
from utils.report import write_html, write_markdown
from utils.sarif import write_sarif
from utils.schema import SchemaError, validate_inputs
from utils.scoring import load_scoring_plugins
from utils.webhook import notify as webhook_notify

logger = logging.getLogger("threat_modeling")


def load_inputs(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error("Input file not found: %s", path)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
        sys.exit(1)

    try:
        validate_inputs(data)
    except SchemaError as exc:
        logger.error("Invalid input file %s: %s", path, exc)
        sys.exit(1)
    return data


def run_pipeline(scenarios, nvd_enabled: bool = False, llm_enabled: bool = False, llm_model: str | None = None):
    if llm_enabled:
        maestro = LLMMaestroAgent(model=llm_model) if llm_model else LLMMaestroAgent()
        compass = LLMCompassAgent(model=llm_model) if llm_model else LLMCompassAgent()
    else:
        maestro = MaestroAgent()
        compass = CompassAgent()
    risk_analyzer = RiskAnalyzer()
    cve_agent = CVEAgent(nvd_enabled=nvd_enabled)
    recommender = RecommendationAgent()

    results = []
    for scenario in scenarios:
        logger.info("Analysing scenario: %s", scenario.get("name", "<unnamed>"))
        maestro_output = maestro.analyze(scenario)
        compass_output = compass.assess(scenario)
        risks = risk_analyzer.evaluate(maestro_output, compass_output, scenario)
        cve_matches = cve_agent.match_cves(risks)
        recommendations = recommender.generate(risks, cve_matches)
        results.append(
            {
                "scenario": scenario,
                "maestro": maestro_output,
                "compass": compass_output,
                "risks": risks,
                "cves": cve_matches,
                "recommendations": recommendations,
            }
        )
    return results


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="LLM Threat Modeling Agents pipeline")
    parser.add_argument("--init", metavar="DIR", help="Scaffold a new project in DIR and exit")
    parser.add_argument("--explain", metavar="NAME", help="Print COMPASS threat / MAESTRO layer reference and exit")
    parser.add_argument("--clear-cache", action="store_true", help="Delete all cached runs and exit")
    parser.add_argument(
        "--cache-ttl",
        type=float,
        default=None,
        help="Maximum age in seconds for cached runs (default: no expiry)",
    )
    parser.add_argument("--config", help="Path to a threat-model.toml config (default: auto-discover)")
    parser.add_argument("--csv", help="Optional path for a flat CSV risk register")
    parser.add_argument("--pdf", help="Optional path for a PDF report (requires the [pdf] extra)")
    parser.add_argument("--cache", action="store_true", help="Skip the pipeline when input + plugins are unchanged")
    parser.add_argument("--no-cache-write", action="store_true", help="Compute results but don't update the cache")
    parser.add_argument("--webhook", help="POST a summary to this webhook URL when --webhook-on is met")
    parser.add_argument(
        "--webhook-on",
        choices=["Critical", "High", "Medium", "Low"],
        default="Critical",
        help="Severity threshold for the webhook notifier",
    )
    parser.add_argument("--input", default="data/sample_inputs.json", help="Path to scenarios JSON")
    parser.add_argument("--output", default="output/results.json", help="Path for the results JSON")
    parser.add_argument("--nvd", action="store_true", help="Enrich CVE matches via the live NVD 2.0 API (cached)")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use Anthropic Claude for MAESTRO and COMPASS analysis (falls back to keywords if unavailable)",
    )
    parser.add_argument("--llm-model", help="Override the Claude model id (default: claude-sonnet-4-6)")
    parser.add_argument(
        "--plugins",
        action="append",
        default=[],
        help="Path to a plugin JSON file or directory; may be passed multiple times",
    )
    parser.add_argument("--markdown", help="Optional path to also write a Markdown report")
    parser.add_argument("--html", help="Optional path to also write an HTML report")
    parser.add_argument("--sarif", help="Optional path to also write a SARIF 2.1.0 report")
    parser.add_argument(
        "--history",
        help="Append this run's summary to a JSONL trend file (e.g. output/history.jsonl)",
    )
    parser.add_argument(
        "--history-label",
        help="Optional label (commit sha, branch name, ...) attached to the history entry",
    )
    parser.add_argument("--diff", help="Compare against a previous results JSON and report changes")
    parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="When --diff is set, exit non-zero if any new risks or severity regressions are found",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress per-scenario terminal output")
    parser.add_argument(
        "--fail-on",
        choices=["none", "critical", "high"],
        default="none",
        help="Exit non-zero if any risk reaches this severity (CI gate)",
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")

    # Apply defaults from threat-model.toml before parsing.
    pre_args, _ = parser.parse_known_args(argv)
    config_path = pre_args.config or find_config()
    if config_path:
        defaults = load_defaults(config_path)
        if defaults:
            # Map string keys with hyphens to argparse dest names.
            normalised = {k.replace("-", "_"): v for k, v in defaults.items()}
            parser.set_defaults(**normalised)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.explain:
        print(explain(args.explain))
        return

    if args.clear_cache:
        n = clear_cache()
        print(f"Cleared {n} cached run(s).")
        return

    if args.init:
        created = init_project(args.init)
        print(f"Initialised project in {args.init}")
        for path in created:
            print(f"  + {path}")
        if not created:
            print("  (nothing to do — files already exist)")
        return

    if args.plugins:
        try:
            added = load_plugins(args.plugins)
            logger.info(
                "Plugins loaded: %d layers, %d threats",
                len(added["maestro_layers"]),
                len(added["compass_threats"]),
            )
        except PluginError as exc:
            logger.error("Plugin error: %s", exc)
            sys.exit(1)
        load_scoring_plugins(args.plugins)

    inputs = load_inputs(args.input)

    cache_key = None
    results = None
    if args.cache:
        cache_key = compute_cache_key(args.input, args.plugins)
        cached = read_cache(cache_key, max_age_seconds=args.cache_ttl)
        if cached is not None:
            logger.info("Cache hit: %s — skipping pipeline", cache_key[:12])
            results = cached

    if results is None:
        results = run_pipeline(
            inputs["scenarios"],
            nvd_enabled=args.nvd,
            llm_enabled=args.llm,
            llm_model=args.llm_model,
        )
        if args.cache and not args.no_cache_write and cache_key:
            write_cache(cache_key, results)
    save_results(results, args.output)
    if args.markdown:
        write_markdown(results, args.markdown)
    if args.html:
        history_for_chart = load_history(args.history) if args.history else None
        write_html(results, args.html, history=history_for_chart)
    if args.sarif:
        write_sarif(results, args.sarif)
    if args.csv:
        rows = write_csv(results, args.csv)
        logger.info("CSV report: %s (%d rows)", args.csv, rows)
    if args.pdf:
        try:
            from utils.pdf import PDFUnavailableError, write_pdf

            write_pdf(results, args.pdf)
            logger.info("PDF report: %s", args.pdf)
        except PDFUnavailableError as exc:
            logger.error("%s", exc)
    if args.history:
        entry = append_history(results, args.history, label=args.history_label)
        logger.info(
            "History updated: %s -> avg %.2f / max %d",
            args.history,
            entry["avg_score"],
            entry["max_score"],
        )

    if not args.quiet:
        print_results(results)
    print_summary(results)
    print(f"\nThreat modeling complete. Results saved to {args.output}")
    if args.markdown:
        print(f"Markdown report: {args.markdown}")
    if args.html:
        print(f"HTML report: {args.html}")
    if args.sarif:
        print(f"SARIF report: {args.sarif}")

    diff = None
    if args.diff:
        try:
            baseline = load_results(args.diff)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Could not load baseline %s: %s", args.diff, exc)
            sys.exit(1)
        diff = diff_results(baseline, results)
        print("\n" + format_diff_text(diff))

    if args.fail_on != "none":
        threshold = {"critical": {"Critical"}, "high": {"Critical", "High"}}[args.fail_on]
        offending = [
            risk
            for item in results
            for risk in item["risks"]
            if risk["severity"] in threshold
        ]
        if offending:
            logger.error(
                "Failing: %d risk(s) at severity '%s' or above.",
                len(offending),
                args.fail_on,
            )
            sys.exit(2)

    if args.webhook:
        sent = webhook_notify(results, args.webhook, threshold=args.webhook_on)
        if sent:
            logger.info("Webhook notified at threshold %s", args.webhook_on)

    if args.fail_on_diff and diff is not None:
        if diff["summary"]["added"] or diff["summary"]["regressions"]:
            logger.error(
                "Failing: %d new risk(s), %d severity regression(s) vs baseline.",
                diff["summary"]["added"],
                diff["summary"]["regressions"],
            )
            sys.exit(3)


if __name__ == "__main__":
    main()
