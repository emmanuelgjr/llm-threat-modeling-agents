![MIT License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
[![Open Issues](https://img.shields.io/github/issues/emmanuelgjr/llm-threat-modeling-agents.svg)](https://github.com/emmanuelgjr/llm-threat-modeling-agents/issues)

# LLM Threat Modeling Agents

> Multi-agent LLM threat modeling framework using MAESTRO and OWASP COMPASS, with modular agents for security risk analysis, CVE mapping, and remediation recommendations.

## Features

- Modular agent pipeline (MAESTRO, COMPASS, Risk, CVE, Remediation)
- Readable, tabulated, and color-coded output
- Easily extensible: add new scenarios, agents, or real LLM/AI integrations
- Save results to JSON for reporting or post-processing
- Demo-ready for workshops and real-world proof-of-concept

## Quickstart

```bash
git clone https://github.com/emmanuelgjr/llm-threat-modeling-agents.git
cd llm-threat-modeling-agents
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python main.py
