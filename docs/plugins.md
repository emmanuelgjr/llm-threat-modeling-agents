# Plugins

Drop a JSON file in `data/plugins/` (or pass `--plugins PATH` repeatedly) to extend the framework without touching the source.

```json
{
  "maestro_layers": {
    "Network": {
      "description": "Network ingress/egress around the agent.",
      "indicators": ["network", "firewall", "ingress"]
    }
  },
  "compass_threats": {
    "Lateral Movement via Agent Network Path": {
      "indicators": ["lateral", "service mesh"],
      "maestro_layers": ["Network", "System"],
      "impact": 5,
      "cwes": ["CWE-668"],
      "mitigation": "Segment the agent's network reach; require mTLS."
    }
  },
  "scoring": {
    "environment_boost": {
      "production": 1,
      "iot": 2
    }
  }
}
```

Sections are optional — the smallest valid plugin is a new threat name with indicators.
