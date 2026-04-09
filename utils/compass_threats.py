"""OWASP COMPASS threat taxonomy with CWE mappings, severity and mitigations.

This metadata is consumed by CompassAgent, CVEAgent and RecommendationAgent
so the pipeline produces scenario-aware, framework-grounded output instead
of hardcoded placeholders.
"""

COMPASS_THREATS = {
    "Memory Poisoning": {
        "indicators": ["memory", "vector", "rag", "retrieval", "embedding", "history", "context"],
        "maestro_layers": ["Memory", "Resources"],
        "impact": 4,
        "cwes": ["CWE-20", "CWE-345", "CWE-502"],
        "mitigation": "Validate and sign all content written to long-term memory; isolate untrusted retrieval sources; monitor for drift in embeddings.",
    },
    "Tool Misuse": {
        "indicators": ["tool", "plugin", "function call", "api", "browser", "shell", "code execution"],
        "maestro_layers": ["Tools", "System"],
        "impact": 5,
        "cwes": ["CWE-77", "CWE-78", "CWE-829"],
        "mitigation": "Apply least-privilege scopes to every tool, require human approval for high-impact actions, and log all invocations.",
    },
    "Privilege Compromise": {
        "indicators": ["admin", "credential", "secret", "token", "role", "permission", "access"],
        "maestro_layers": ["System", "Resources"],
        "impact": 5,
        "cwes": ["CWE-269", "CWE-285", "CWE-732"],
        "mitigation": "Enforce least privilege, rotate credentials, and never grant the agent standing admin rights.",
    },
    "Resource Overload": {
        "indicators": ["real-time", "high volume", "stream", "throughput", "scale", "iot"],
        "maestro_layers": ["Environment", "System"],
        "impact": 3,
        "cwes": ["CWE-400", "CWE-770"],
        "mitigation": "Rate-limit inputs, set token/cost budgets per request, and add circuit breakers on downstream tools.",
    },
    "Cascading Hallucination Attacks": {
        "indicators": ["multi-agent", "chain", "pipeline", "downstream", "summarize", "decision"],
        "maestro_layers": ["Agent", "Memory"],
        "impact": 4,
        "cwes": ["CWE-20", "CWE-754"],
        "mitigation": "Add ground-truth verification between agent hops; require citations for factual claims; cap chain depth.",
    },
    "Intent Breaking & Goal Manipulation": {
        "indicators": ["goal", "objective", "instruction", "prompt", "policy", "user input"],
        "maestro_layers": ["Objectives", "Agent"],
        "impact": 4,
        "cwes": ["CWE-77", "CWE-94"],
        "mitigation": "Separate trusted system prompts from untrusted input; use prompt-injection detectors; pin objectives in immutable context.",
    },
    "Misaligned & Deceptive Behaviors": {
        "indicators": ["autonomous", "decision", "recommend", "approve", "screen", "evaluate"],
        "maestro_layers": ["Agent", "Objectives"],
        "impact": 4,
        "cwes": ["CWE-840", "CWE-754"],
        "mitigation": "Red-team for deceptive alignment; require explainability for high-stakes decisions; sample outputs for human review.",
    },
    "Repudiation & Untraceability": {
        "indicators": ["audit", "log", "compliance", "regulated", "legal", "financial", "healthcare"],
        "maestro_layers": ["System", "Environment"],
        "impact": 3,
        "cwes": ["CWE-778", "CWE-117"],
        "mitigation": "Log every agent decision with tamper-evident storage; correlate user, prompt, tool call and outcome.",
    },
    "Identity Spoofing & Impersonation": {
        "indicators": ["user", "customer", "identity", "authentication", "chatbot", "assistant"],
        "maestro_layers": ["Agent", "System"],
        "impact": 4,
        "cwes": ["CWE-287", "CWE-290"],
        "mitigation": "Authenticate users out-of-band before sensitive actions; never let the agent self-assert identity.",
    },
    "Overwhelming Human in the Loop": {
        "indicators": ["high volume", "real-time", "alerts", "triage", "incident", "soc"],
        "maestro_layers": ["Objectives", "Environment"],
        "impact": 3,
        "cwes": ["CWE-1248"],
        "mitigation": "Pre-filter and cluster alerts before human review; design for graceful degradation under load.",
    },
    "Unexpected RCE and Code Attacks": {
        "indicators": ["code execution", "shell", "interpreter", "eval", "sandbox", "container"],
        "maestro_layers": ["Tools", "System"],
        "impact": 5,
        "cwes": ["CWE-94", "CWE-95", "CWE-78"],
        "mitigation": "Run any code in a hardened, network-isolated sandbox with strict resource and syscall limits.",
    },
    "Agent Communication Poisoning": {
        "indicators": ["multi-agent", "communication", "message", "broker", "queue"],
        "maestro_layers": ["Agent", "System"],
        "impact": 4,
        "cwes": ["CWE-345", "CWE-20"],
        "mitigation": "Sign and validate inter-agent messages; treat peer agents as untrusted by default.",
    },
    "Rogue Agents in Multi-Agent Systems": {
        "indicators": ["multi-agent", "autonomous", "swarm", "agents involved"],
        "maestro_layers": ["Agent", "Objectives"],
        "impact": 5,
        "cwes": ["CWE-693", "CWE-840"],
        "mitigation": "Use a supervisor/policy agent that can revoke peers; monitor for behavioral anomalies.",
    },
    "Human Attacks on Multi-Agent Systems": {
        "indicators": ["user input", "customer", "public", "chatbot", "external"],
        "maestro_layers": ["Environment", "Agent"],
        "impact": 4,
        "cwes": ["CWE-77", "CWE-20"],
        "mitigation": "Treat all human-supplied content as untrusted; apply input filters at every boundary.",
    },
    "Human Manipulation": {
        "indicators": ["recommend", "advise", "persuade", "decision", "human"],
        "maestro_layers": ["Objectives", "Agent"],
        "impact": 3,
        "cwes": ["CWE-1021"],
        "mitigation": "Disclose AI involvement; constrain persuasive language; provide source-grounded explanations.",
    },
    "Model Inversion and Data Reconstruction Attacks": {
        "indicators": ["pii", "phi", "sensitive", "customer data", "training", "fine-tune"],
        "maestro_layers": ["Resources", "Memory"],
        "impact": 4,
        "cwes": ["CWE-200", "CWE-359"],
        "mitigation": "Apply differential privacy on training data; strip PII pre-ingest; rate-limit inference and detect probing.",
    },
}


def get_threats():
    """Return the list of COMPASS threat names (backwards compatible)."""
    return list(COMPASS_THREATS.keys())


def get_threat_metadata(threat):
    return COMPASS_THREATS.get(threat, {})
