# Reports & integrations

| Output           | Flag                          | Notes                                              |
|------------------|-------------------------------|----------------------------------------------------|
| JSON results     | `--output`                    | Always written                                     |
| Markdown report  | `--markdown`                  | Includes Mermaid diagrams, traceability matrix     |
| HTML report      | `--html`                      | Inline SVG charts; embeds trend chart with history |
| SARIF 2.1.0      | `--sarif`                     | For GitHub code scanning                           |
| CSV risk register| `--csv`                       | One row per (scenario, threat)                     |
| PDF              | `--pdf`                       | Requires `[pdf]` extra                             |
| Trend log        | `--history` + `--history-label` | Append-only JSONL                                |
| Diff vs baseline | `--diff` + `--fail-on-diff`   | Exit 3 on regressions                              |
| Slack webhook    | `--webhook` + `--webhook-on`  | Posts on threshold                                 |
| MCP server       | `threat-model-mcp`            | stdio transport                                    |
| Web UI           | `uvicorn web.app:app`         | Upload-and-view                                    |

The HTML report ships with no external CSS or JavaScript dependencies.
