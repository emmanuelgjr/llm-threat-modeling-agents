"""``threat-model --init DIR`` scaffolder.

Creates a minimal project layout (sample scenarios, plugin folder, config
file) so users can run ``threat-model`` immediately in a fresh directory.
"""

from __future__ import annotations

import json
import os
import textwrap

SAMPLE_SCENARIOS = {
    "scenarios": [
        {
            "name": "My GenAI Assistant",
            "description": "An LLM-powered assistant with tool calls and access to customer data.",
            "environment": "SaaS, Cloud",
        }
    ]
}

SAMPLE_PLUGIN = {
    "maestro_layers": {
        "Network": {
            "description": "Network ingress/egress around the agent system.",
            "indicators": ["network", "firewall", "ingress", "egress"],
        }
    },
    "scoring": {
        "environment_boost": {"production": 1}
    },
}

SAMPLE_CONFIG = textwrap.dedent(
    """\
    # threat-model.toml — project defaults for the LLM Threat Modeling pipeline.
    [defaults]
    input = "data/sample_inputs.json"
    output = "output/results.json"
    markdown = "output/report.md"
    html = "output/report.html"
    sarif = "output/results.sarif"
    history = "output/history.jsonl"
    plugins = ["data/plugins"]
    fail_on = "high"
    """
)


def init_project(target_dir: str) -> list[str]:
    """Scaffold a fresh project; returns the list of files created."""
    created = []
    os.makedirs(os.path.join(target_dir, "data", "plugins"), exist_ok=True)
    os.makedirs(os.path.join(target_dir, "output"), exist_ok=True)

    files = {
        os.path.join(target_dir, "data", "sample_inputs.json"): json.dumps(SAMPLE_SCENARIOS, indent=2),
        os.path.join(target_dir, "data", "plugins", "example.json"): json.dumps(SAMPLE_PLUGIN, indent=2),
        os.path.join(target_dir, "threat-model.toml"): SAMPLE_CONFIG,
    }
    for path, content in files.items():
        if os.path.exists(path):
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        created.append(path)
    return created
