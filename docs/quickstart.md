# Quickstart

## Install

```bash
git clone https://github.com/emmanuelgjr/llm-threat-modeling-agents.git
cd llm-threat-modeling-agents
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

Optional extras:

| Extra   | Adds                                |
|---------|-------------------------------------|
| `llm`   | Anthropic SDK for LLM-backed agents |
| `pdf`   | WeasyPrint for PDF export           |
| `web`   | FastAPI/Uvicorn web UI              |
| `mcp`   | Model Context Protocol server       |
| `docs`  | MkDocs Material for this site       |

## Run

```bash
threat-model                                # default config
threat-model --markdown out/report.md --html out/report.html --sarif out/results.sarif
threat-model --history out/history.jsonl --history-label "$(git rev-parse --short HEAD)"
threat-model --diff out/baseline.json --fail-on-diff
```

## Get help on a threat

```bash
threat-model --explain "Tool Misuse"
threat-model --explain "Memory"
```
