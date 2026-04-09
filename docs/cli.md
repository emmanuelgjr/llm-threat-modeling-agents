# CLI reference

```text
threat-model [--input PATH] [--output PATH]
             [--markdown PATH] [--html PATH] [--sarif PATH] [--csv PATH] [--pdf PATH]
             [--history PATH] [--history-label LABEL]
             [--diff PATH] [--fail-on-diff]
             [--fail-on {none,critical,high}]
             [--plugins PATH]...
             [--llm] [--llm-model MODEL]
             [--nvd]
             [--cache] [--no-cache-write] [--cache-ttl SECONDS] [--clear-cache]
             [--webhook URL] [--webhook-on {Critical,High,Medium,Low}]
             [--config PATH] [--init DIR] [--explain NAME]
             [--quiet] [--log-level LEVEL]
```

All flags can be defaulted in `threat-model.toml`:

```toml
[defaults]
input = "data/sample_inputs.json"
output = "output/results.json"
markdown = "output/report.md"
html = "output/report.html"
sarif = "output/results.sarif"
history = "output/history.jsonl"
plugins = ["data/plugins"]
fail_on = "high"
```

Exit codes: `0` ok, `1` input/plugin error, `2` `--fail-on` threshold met, `3` `--fail-on-diff` regression.
