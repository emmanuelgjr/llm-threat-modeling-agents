# LLM Threat Modeling Agents

A multi-agent threat-modeling pipeline for LLM and GenAI systems, grounded in the **MAESTRO** layered framework and the **OWASP COMPASS** GenAI threat taxonomy.

Given a plain-English scenario, the pipeline produces:

- MAESTRO layer mapping with per-layer likelihood
- COMPASS threats with `likelihood × impact` risk scores
- CWE / CVE matches (live NVD lookup optional)
- Prioritised mitigation recommendations
- JSON, Markdown (with Mermaid diagrams), HTML (with SVG charts), CSV, PDF and SARIF reports
- Trend tracking, run cache, diff vs baseline, CI gates

## Why

Threat modeling LLM systems by hand is slow and inconsistent. This project gives you a **deterministic, framework-grounded baseline** that you can extend with plugins, drop into CI, or call from another LLM agent via MCP.

## Get started

```bash
pip install -e .
threat-model --init my-project
cd my-project
threat-model
```

See [Quickstart](quickstart.md) for the full tour.
