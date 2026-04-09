"""Lightweight scenario input validator (no external deps)."""


class SchemaError(ValueError):
    pass


REQUIRED_FIELDS = {"name": str, "description": str, "environment": str}
OPTIONAL_FIELDS = {
    "risk_level": str,
    "agents_involved": list,
}


def validate_inputs(data) -> None:
    if not isinstance(data, dict):
        raise SchemaError("Top-level JSON must be an object with a 'scenarios' array.")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise SchemaError("'scenarios' must be a non-empty array.")

    seen_names = set()
    for idx, scenario in enumerate(scenarios):
        prefix = f"scenarios[{idx}]"
        if not isinstance(scenario, dict):
            raise SchemaError(f"{prefix} must be an object.")

        for field, ftype in REQUIRED_FIELDS.items():
            if field not in scenario:
                raise SchemaError(f"{prefix} missing required field '{field}'.")
            if not isinstance(scenario[field], ftype):
                raise SchemaError(
                    f"{prefix}.{field} must be {ftype.__name__}, got {type(scenario[field]).__name__}."
                )
            if ftype is str and not scenario[field].strip():
                raise SchemaError(f"{prefix}.{field} must be a non-empty string.")

        for field, ftype in OPTIONAL_FIELDS.items():
            if field in scenario and not isinstance(scenario[field], ftype):
                raise SchemaError(
                    f"{prefix}.{field} must be {ftype.__name__} if present."
                )
        if "agents_involved" in scenario:
            for j, agent in enumerate(scenario["agents_involved"]):
                if not isinstance(agent, str):
                    raise SchemaError(f"{prefix}.agents_involved[{j}] must be a string.")

        name = scenario["name"]
        if name in seen_names:
            raise SchemaError(f"Duplicate scenario name: '{name}'.")
        seen_names.add(name)
