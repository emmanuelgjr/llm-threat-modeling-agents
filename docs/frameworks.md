# Frameworks

## MAESTRO

Seven layers covering an LLM agent's surface area:

- **Memory** — vector stores, RAG, conversation history, caches
- **Agent** — the planner / executor / model itself
- **Environment** — cloud, on-prem, edge, network boundaries
- **System** — OS, orchestration, inter-component plumbing
- **Tools** — plugins, function calls, browser, code execution
- **Resources** — data, secrets, credentials, files
- **Objectives** — goals, instructions, policy constraints

## OWASP COMPASS

Sixteen GenAI-specific threat categories shipped in `utils/compass_threats.py`. Use `threat-model --explain "<Threat Name>"` to see indicators, CWEs, MAESTRO layers and the canonical mitigation for any of them.
