![MIT License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
[![Open Issues](https://img.shields.io/github/issues/emmanuelgjr/llm-threat-modeling-agents.svg)](https://github.com/emmanuelgjr/llm-threat-modeling-agents/issues)

# LLM Threat Modeling Agents

> Multi-agent threat modeling framework for LLM / GenAI systems, grounded in the **MAESTRO** layered framework and the **OWASP COMPASS** GenAI threat taxonomy. Produces scored risks, CWE mappings and remediation recommendations from a plain-English scenario description.

## What it does

Given a JSON scenario like:

```json
{
  "name": "Customer Service GenAI Bot",
  "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
  "environment": "SaaS, Cloud"
}
```

The pipeline runs five cooperating agents:

| # | Agent | Responsibility |
|---|-------|----------------|
| 1 | `MaestroAgent` | Maps the scenario onto the seven MAESTRO layers (Memory, Agent, Environment, System, Tools, Resources, Objectives) using keyword indicators. |
| 2 | `CompassAgent` | Identifies which of the 16 OWASP COMPASS threats apply, with a per-threat likelihood. |
| 3 | `RiskAnalyzer` | Scores each threat as `likelihood × impact` (1-25) and assigns a Low/Medium/High/Critical severity, boosted for regulated environments (healthcare, banking, SOC, legal). |
| 4 | `CVEAgent` | Attaches the CWE weakness IDs declared per threat. Pluggable `lookup_cves` hook for live NVD integration. |
| 5 | `RecommendationAgent` | Emits the canonical mitigation for each threat, tagged with severity and CWEs. |

Results are written to `output/results.json` and rendered as colour-coded tables plus a run summary (severity breakdown and top threats).

## Quickstart

```bash
git clone https://github.com/emmanuelgjr/llm-threat-modeling-agents.git
cd llm-threat-modeling-agents
python -m venv venv
# Windows
.\venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# Install as a package (preferred)
pip install -e .                # core
pip install -e ".[llm]"         # + Anthropic SDK for LLM-backed agents
pip install -e ".[dev]"         # + pytest

# Run via the installed console script...
threat-model
# ...or directly
python main.py
```

### CLI options

```bash
python main.py --input data/sample_inputs.json \
               --output output/results.json \
               --markdown output/report.md \
               --html output/report.html \
               --log-level INFO
python main.py --quiet                  # only print the run summary
python main.py --fail-on critical       # CI gate: exit 2 if any Critical risk
python main.py --fail-on high           # CI gate: exit 2 on High or Critical
python main.py --nvd                    # enrich CWEs with live CVEs from NVD (cached)
python main.py --sarif output/results.sarif    # SARIF 2.1.0 for GitHub code scanning
python main.py --diff output/baseline.json     # compare against a previous run
python main.py --diff baseline.json --fail-on-diff   # exit 3 on new risks / regressions
python main.py --llm                                 # use Claude for MAESTRO + COMPASS analysis
python main.py --llm --llm-model claude-opus-4-6     # override the model
python main.py --plugins data/plugins                # load custom threats/layers
python main.py --history output/history.jsonl --history-label "$(git rev-parse --short HEAD)"
python main.py --csv output/risks.csv                # flat risk register
python main.py --pdf output/report.pdf               # requires the [pdf] extra
python main.py --cache                               # skip pipeline if input unchanged
python main.py --webhook https://hooks.slack.com/... --webhook-on Critical
threat-model --init my-project                       # scaffold a fresh project
```

### Project layout & subcommands

- **`threat-model --init DIR`** scaffolds a new project (`data/sample_inputs.json`, `data/plugins/example.json`, `threat-model.toml`).
- **`threat-model.toml`** can pin defaults so CI invocations stay short:
  ```toml
  [defaults]
  input = "data/sample_inputs.json"
  output = "output/results.json"
  markdown = "output/report.md"
  html = "output/report.html"
  sarif = "output/results.sarif"
  history = "output/history.jsonl"
  plugins = ["data/plugins"]
  fail_on = "high"
  ```
- **`--cache`** hashes the input + plugin files and reuses the previous run when nothing has changed (cache lives in `.cache/runs/`).

### Extra outputs

- `--csv PATH` writes a flat risk register (one row per `(scenario, threat)`) — drop straight into a spreadsheet.
- `--pdf PATH` writes a PDF rendered from the HTML report. Requires the optional extra: `pip install -e ".[pdf]"`.
- `--webhook URL [--webhook-on Critical|High|Medium|Low]` posts a JSON summary to a Slack-compatible webhook when the threshold is met.

### Custom scoring plugins

In addition to threats and layers, plugin files may declare environment-based likelihood boosts that feed `RiskAnalyzer`:

```json
{
  "scoring": {
    "environment_boost": {
      "iot": 1,
      "industrial": 2,
      "production": 1
    }
  }
}
```

Boosts are merged with the built-in defaults (healthcare/banking/SOC/legal) and applied to any scenario whose `environment` string matches the key.

### Web UI

A tiny FastAPI app lets you upload a scenarios JSON and view the rendered HTML report in a browser:

```bash
pip install -e ".[web]"
uvicorn web.app:app --reload
```

### MCP server

The pipeline is exposed as Model Context Protocol tools so other LLM agents (Claude Desktop, Claude Code, custom MCP clients) can call it directly:

```bash
pip install -e ".[mcp]"
threat-model-mcp        # stdio transport
```

Tools: `analyze_scenario` (single scenario) and `analyze_scenarios` (batch).

### Trend tracking

Pass `--history PATH` (typically `output/history.jsonl`) and the run summary — scenarios, total risks, average and max score, severity counts and per-scenario max — is appended as one JSON line. The file is append-only and safe to commit; CI runs can attach a `--history-label` (commit SHA, branch, build number).

When both `--history` and `--html` are set, the HTML report embeds an inline-SVG line chart of average and max risk score across every recorded run, so you can see your threat posture trend at a glance.

### Mermaid diagrams in Markdown

Each scenario in the Markdown report now includes a `mermaid` flowchart of `Scenario → MAESTRO Layer → Threat`, with threat nodes colour-coded by severity. GitHub renders these natively, so the diagrams appear inline in any rendered Markdown report.

### Custom threats and layers (plugins)

Drop a JSON file in any directory and pass it (or its parent) to `--plugins`. Plugins can extend the MAESTRO layer set, add COMPASS threats, or both — the new entries flow through risk scoring, CVE mapping, recommendations, reports, SARIF and diff with no code changes. See `data/plugins/example_network_layer.json` for the format. Pass `--plugins` multiple times to layer them.

### NVD API key & concurrency

Set `NVD_API_KEY` to lift the public NVD rate limit (5 → 50 req / 30s) and unlock concurrent CWE fetching:

```bash
export NVD_API_KEY=your-key
threat-model --nvd
```

Without a key the client falls back to single-threaded polite mode. Responses are cached in `.cache/nvd/` either way.

### HTML charts

The HTML report now includes inline-SVG charts (no JS dependencies) for the run-wide severity breakdown and per-scenario risk scores, in addition to the existing tables and traceability matrix.

### LLM-backed analysis (optional)

Install the optional extra and set your API key:

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-ant-...
threat-model --llm
```

When `--llm` is set the pipeline calls Claude (default `claude-sonnet-4-6`) to map each scenario onto MAESTRO layers and COMPASS threats. The output schema is identical to the keyword agents, so risk scoring, CVE mapping, recommendations and reports work unchanged. If the `anthropic` package isn't installed, `ANTHROPIC_API_KEY` is missing, or the API call fails, the agents **transparently fall back** to the keyword analysis — `--llm` is always safe to pass in CI.

### SARIF export & GitHub code scanning

`--sarif PATH` writes a SARIF 2.1.0 file. The bundled CI workflow uploads it via `github/codeql-action/upload-sarif`, so every threat appears in your repository's **Security → Code scanning** tab. Each COMPASS threat is registered as a SARIF rule with its CWEs, MAESTRO layers and canonical mitigation; severities map to `error` (Critical/High), `warning` (Medium) and `note` (Low).

### Diff mode (CI regression gate)

`--diff PATH` compares the current run against a saved baseline `results.json`. The output lists:

- **New risks** introduced since the baseline
- **Resolved risks** (present in baseline, gone now)
- **Severity changes** (worse / better) per risk

Combine with `--fail-on-diff` to exit `3` whenever a CI run introduces new risks or worsens existing ones — perfect for blocking PRs that regress your threat posture.

### Live CVE enrichment (NVD)

Pass `--nvd` to query the public [NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities) for real CVEs that match each threat's CWE list. Responses are cached under `.cache/nvd/` so re-runs are instant. Rate limiting is built in; for heavy use you may want to add an NVD API key.

### Input validation

Scenario files are validated before the pipeline runs (`utils/schema.py`). Missing fields, wrong types, empty `scenarios` arrays and duplicate scenario names produce a clear error and exit code `1` — no half-completed runs.

### Traceability matrix

Every run prints (and writes into both reports) a **Threat → MAESTRO layers** traceability matrix that aggregates risks across all analysed scenarios: which threats hit which layers, in how many scenarios, with the maximum observed score and severity.

### Reports

- `--markdown PATH` writes a share-ready Markdown report (run summary, per-scenario risks and recommendations).
- `--html PATH` writes a standalone HTML report with severity badges.
- The terminal summary now ranks scenarios by their **max risk score** so you can see the riskiest systems at a glance.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The repo ships with a `.pre-commit-config.yaml` (ruff + ruff-format + standard hygiene hooks); install with `pip install -e ".[dev]"` and `pre-commit install`.

### Continuous integration

A GitHub Actions workflow (`.github/workflows/ci.yml`) runs `pytest` on Python 3.9–3.12 and smoke-runs the pipeline, uploading the generated JSON / Markdown / HTML reports as build artifacts.

## Project layout

```
llm-threat-modeling-agents/
├── main.py                 # CLI entry point + pipeline orchestrator
├── agents/
│   ├── maestro_agent.py    # MAESTRO layer mapping
│   ├── compass_agent.py    # COMPASS threat assessment
│   ├── risk_analyzer.py    # likelihood × impact scoring
│   ├── cve_agent.py        # CWE / CVE mapping
│   └── recommendation_agent.py
├── utils/
│   ├── maestro_layers.py   # layer metadata + indicators
│   ├── compass_threats.py  # threat metadata, CWEs, mitigations
│   └── output.py           # JSON + colour table rendering, summary
├── data/sample_inputs.json # 10 example scenarios
├── tests/test_pipeline.py  # pytest smoke + unit tests
└── output/results.json     # latest run results
```

## Extending

- **Add a scenario** — append an entry to `data/sample_inputs.json` (or pass `--input` to your own file).
- **Add a threat** — add an entry to `COMPASS_THREATS` in `utils/compass_threats.py`. The new threat will automatically flow through risk scoring, CWE mapping and recommendations.
- **Plug a real CVE feed** — subclass `CVEAgent` and override `lookup_cves(threat, cwes)` to call NVD or your internal vulnerability database.
- **Swap to LLM-driven analysis** — replace the keyword matching in `MaestroAgent` / `CompassAgent` with calls to an LLM SDK. The downstream pipeline only needs the same output schema.

## Tests

```bash
pytest -v
```

The tests cover MAESTRO mapping, COMPASS detection, risk scoring bounds, CVE/recommendation alignment, and an end-to-end pipeline run.

## Frameworks

- **MAESTRO** — Multi-layer threat modelling for autonomous agents.
- **OWASP COMPASS** — Comprehensive Pattern Library for GenAI Security.

## License

MIT — see [LICENSE](LICENSE).
