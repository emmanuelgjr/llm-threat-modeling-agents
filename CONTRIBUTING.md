# Contributing

Thanks for your interest in improving **LLM Threat Modeling Agents**! This project is small, deterministic and easy to hack on — most contributions can land in a single focused PR.

## Quick start

```bash
git clone https://github.com/emmanuelgjr/llm-threat-modeling-agents.git
cd llm-threat-modeling-agents
python -m venv venv
source venv/bin/activate          # Windows: .\venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
pytest
```

## Ways to contribute

- **New scenarios** — append entries to `data/sample_inputs.json` (validated by `utils/schema.py`).
- **New threats / layers** — drop a JSON plugin in `data/plugins/` or extend `utils/compass_threats.py` / `utils/maestro_layers.py` directly. See `data/plugins/example_network_layer.json` for the format.
- **New agent backends** — wrap the keyword agents (see `agents/llm_agents.py` for the Anthropic example). Always provide a graceful fallback.
- **Output formats** — add a writer to `utils/` and wire it through `main.py`. SARIF and Markdown are good templates.
- **Bug fixes & refactors** — please include a regression test.

## Style & checks

- `ruff` + `ruff format` are configured in `pyproject.toml` (line length 110).
- `pre-commit` runs ruff, trailing whitespace, JSON/YAML validation and large-file checks on every commit.
- Tests live under `tests/` and use plain `pytest`. Aim to keep the suite fast (currently <1s).

## Pull requests

1. Branch off `main`.
2. Add tests for new behaviour and snapshot-update where appropriate (`tests/test_snapshot.py`).
3. Run `pytest` and `pre-commit run --all-files`.
4. Open a PR using the template; reference the issue you're closing.

## Reporting issues

Use the bug report or feature request templates under `.github/ISSUE_TEMPLATE/`. Include the command you ran, the version (`pip show llm-threat-modeling-agents`), and (if relevant) a minimal scenario JSON that reproduces the problem.

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
