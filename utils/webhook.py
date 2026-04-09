"""Slack-compatible webhook notifier.

Sends a JSON summary of the run to a webhook URL when the configured
severity threshold is met. Works with Slack incoming webhooks (uses ``text``
field) and with any service that accepts arbitrary JSON.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _build_payload(results, threshold: str) -> dict:
    threshold_rank = SEVERITY_RANK[threshold]
    severities = Counter(risk["severity"] for r in results for risk in r["risks"])
    matching = [
        (item["scenario"]["name"], risk)
        for item in results
        for risk in item["risks"]
        if SEVERITY_RANK[risk["severity"]] >= threshold_rank
    ]
    lines = [f"*LLM Threat Modeling*: {len(matching)} risk(s) at {threshold} or above."]
    for scenario, risk in matching[:10]:
        lines.append(f"- [{risk['severity']}] {scenario} :: {risk['threat']} (score {risk['risk_score']})")
    if len(matching) > 10:
        lines.append(f"...and {len(matching) - 10} more.")
    return {
        "text": "\n".join(lines),
        "summary": {
            "scenarios": len(results),
            "matching_risks": len(matching),
            "severities": dict(severities),
            "threshold": threshold,
        },
    }


def notify(results, url: str, threshold: str = "Critical", timeout: float = 10.0) -> bool:
    """Post a summary to ``url`` if any risk meets ``threshold``.

    Returns ``True`` when a notification was sent (or attempted), ``False``
    when the threshold wasn't met and nothing was posted.
    """
    threshold = threshold.capitalize()
    if threshold not in SEVERITY_RANK:
        raise ValueError(f"Unknown severity threshold: {threshold}")
    payload = _build_payload(results, threshold)
    if payload["summary"]["matching_risks"] == 0:
        return False
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            resp.read()
        return True
    except URLError as exc:
        logger.warning("Webhook notify failed: %s", exc)
        return False
