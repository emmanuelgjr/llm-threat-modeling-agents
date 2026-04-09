"""MAESTRO framework layer definitions and metadata.

Each layer carries a description and keyword indicators used by the
MaestroAgent to map free-text scenarios onto the framework.
"""

MAESTRO_LAYERS = {
    "Memory": {
        "description": "Persistent and short-term memory used by the agent (vector stores, conversation history, caches).",
        "indicators": ["memory", "vector", "embedding", "history", "context", "rag", "retrieval", "cache"],
    },
    "Agent": {
        "description": "The reasoning/decision core of the LLM agent itself (planner, executor, model).",
        "indicators": ["agent", "llm", "model", "chatbot", "assistant", "planner", "reasoning", "autonomous"],
    },
    "Environment": {
        "description": "Hosting and runtime environment (cloud, on-prem, edge, network boundaries).",
        "indicators": ["cloud", "on-prem", "edge", "saas", "hybrid", "kubernetes", "container", "network"],
    },
    "System": {
        "description": "Operating system, orchestration layer, and inter-component plumbing.",
        "indicators": ["system", "os", "orchestration", "pipeline", "service", "api", "microservice"],
    },
    "Tools": {
        "description": "External tools, plugins and function-calls the agent can invoke.",
        "indicators": ["tool", "plugin", "function call", "api call", "browser", "code execution", "shell"],
    },
    "Resources": {
        "description": "Data, secrets, credentials, files and external resources accessed by the agent.",
        "indicators": ["data", "database", "file", "document", "credential", "secret", "pii", "phi", "customer"],
    },
    "Objectives": {
        "description": "The agent's goals, instructions and policy constraints.",
        "indicators": ["goal", "objective", "instruction", "policy", "task", "decision", "approve", "classify"],
    },
}


def get_layers():
    """Return the list of MAESTRO layer names (backwards compatible)."""
    return list(MAESTRO_LAYERS.keys())


def get_layer_metadata(layer):
    return MAESTRO_LAYERS.get(layer, {})
