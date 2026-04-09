# Architecture

The pipeline is a deterministic chain of small agents joined by a stable schema.

```mermaid
flowchart LR
    Input[Scenario JSON] --> Maestro[MaestroAgent]
    Input --> Compass[CompassAgent]
    Maestro --> Risk[RiskAnalyzer]
    Compass --> Risk
    Risk --> CVE[CVEAgent]
    Risk --> Recs[RecommendationAgent]
    CVE --> Out[Reports / SARIF / CSV / PDF / Diff / History]
    Recs --> Out
```

Every agent emits the same canonical schema, so you can swap any of them out (e.g. the LLM-backed agents in `agents/llm_agents.py`) without touching the downstream code.

## Layers

- **`agents/`** — keyword and LLM-backed analysers
- **`utils/`** — exporters (Markdown, HTML, SARIF, CSV, PDF), schema, plugins, cache, history, diff, scoring, webhook, MCP
- **`main.py`** — CLI entry point and pipeline orchestrator
- **`web/`** — optional FastAPI app
- **`mcp_server.py`** — optional MCP server
