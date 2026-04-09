"""Model Context Protocol (MCP) server wrapper.

Exposes the threat-modeling pipeline as MCP tools so other LLM agents
(Claude Desktop, Claude Code, custom MCP clients) can call it directly.

Run with::

    pip install -e ".[mcp]"
    python -m mcp_server   # stdio transport

Two tools are exposed:

- ``analyze_scenario`` — analyse a single scenario, returns the structured
  result (risks, CVEs, recommendations) as JSON.
- ``analyze_scenarios`` — analyse a list of scenarios, returns the run
  summary plus per-scenario top risks.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "MCP server requires the mcp package. Install with: pip install -e \".[mcp]\""
    ) from exc

from main import run_pipeline
from utils.schema import SchemaError, validate_inputs

server = Server("llm-threat-modeling-agents")


def _run(scenarios: list[dict]) -> list[dict]:
    validate_inputs({"scenarios": scenarios})
    return run_pipeline(scenarios)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="analyze_scenario",
            description="Run MAESTRO + COMPASS threat modeling on one LLM/GenAI system scenario.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "environment": {"type": "string"},
                },
                "required": ["name", "description", "environment"],
            },
        ),
        Tool(
            name="analyze_scenarios",
            description="Run threat modeling on a batch of scenarios; returns per-scenario summaries.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scenarios": {
                        "type": "array",
                        "items": {"type": "object"},
                    }
                },
                "required": ["scenarios"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "analyze_scenario":
            results = _run([arguments])
            payload = results[0]
        elif name == "analyze_scenarios":
            results = _run(arguments.get("scenarios", []))
            payload = {
                "scenarios": [
                    {
                        "name": item["scenario"]["name"],
                        "max_score": max((r["risk_score"] for r in item["risks"]), default=0),
                        "top_risks": [
                            {"threat": r["threat"], "severity": r["severity"], "score": r["risk_score"]}
                            for r in item["risks"][:3]
                        ],
                    }
                    for item in results
                ]
            }
        else:
            raise ValueError(f"Unknown tool: {name}")
    except SchemaError as exc:
        return [TextContent(type="text", text=f"SchemaError: {exc}")]
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]


async def _amain() -> None:  # pragma: no cover
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:  # pragma: no cover
    asyncio.run(_amain())


if __name__ == "__main__":  # pragma: no cover
    main()
