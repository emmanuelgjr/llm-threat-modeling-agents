"""Trend tracking: append per-run summaries to a JSONL history file.

Each line is a self-contained snapshot of one pipeline run. Old entries are
never rewritten, so the file is safe to commit and to read incrementally.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone


def _summarise(results) -> dict:
    total_risks = sum(len(r["risks"]) for r in results)
    severities = Counter(risk["severity"] for r in results for risk in r["risks"])
    avg_score = (
        sum(risk["risk_score"] for r in results for risk in r["risks"]) / total_risks
        if total_risks
        else 0.0
    )
    max_score = max((risk["risk_score"] for r in results for risk in r["risks"]), default=0)
    per_scenario = []
    for item in results:
        risks = item.get("risks", [])
        per_scenario.append(
            {
                "name": item["scenario"]["name"],
                "max_score": max((r["risk_score"] for r in risks), default=0),
                "risks": len(risks),
            }
        )
    return {
        "scenarios": len(results),
        "total_risks": total_risks,
        "avg_score": round(avg_score, 2),
        "max_score": max_score,
        "severities": dict(severities),
        "per_scenario": per_scenario,
    }


def append_history(results, path: str, label: str | None = None) -> dict:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "label": label or "",
        **_summarise(results),
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def load_history(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    out: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def history_trend_svg(history: list[dict], width: int = 720, height: int = 220) -> str:
    """Render an inline SVG line chart of avg_score and max_score over time."""
    if not history:
        return ""
    pad_l, pad_r, pad_t, pad_b = 50, 20, 20, 35
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(history)
    max_y = 25  # risk scores are bounded 0..25

    def x(i):
        return pad_l + (i * plot_w / max(1, n - 1)) if n > 1 else pad_l + plot_w / 2

    def y(v):
        return pad_t + plot_h - (v / max_y) * plot_h

    def points(key):
        return " ".join(f"{x(i):.1f},{y(h[key]):.1f}" for i, h in enumerate(history))

    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' role='img' aria-label='Risk score history'>",
        "<style>text{font:11px -apple-system,Segoe UI,Arial,sans-serif;fill:#333}</style>",
        f"<rect x='{pad_l}' y='{pad_t}' width='{plot_w}' height='{plot_h}' fill='#fafafa' stroke='#ccc'/>",
    ]
    # y-axis ticks at 0, 5, 10, 15, 20, 25
    for tick in (0, 5, 10, 15, 20, 25):
        ty = y(tick)
        parts.append(
            f"<line x1='{pad_l}' y1='{ty:.1f}' x2='{pad_l + plot_w}' y2='{ty:.1f}' stroke='#eee'/>"
        )
        parts.append(f"<text x='{pad_l - 8}' y='{ty + 3:.1f}' text-anchor='end'>{tick}</text>")
    # lines
    parts.append(
        f"<polyline fill='none' stroke='#1976d2' stroke-width='2' points='{points('avg_score')}'/>"
    )
    parts.append(
        f"<polyline fill='none' stroke='#b00020' stroke-width='2' points='{points('max_score')}'/>"
    )
    # x-axis labels (first, middle, last)
    label_indices = sorted({0, n // 2, n - 1})
    for i in label_indices:
        ts = history[i]["timestamp"][:10]
        parts.append(f"<text x='{x(i):.1f}' y='{height - 12}' text-anchor='middle'>{ts}</text>")
    # legend
    parts.append(
        f"<rect x='{pad_l}' y='{pad_t - 14}' width='12' height='3' fill='#1976d2'/>"
        f"<text x='{pad_l + 16}' y='{pad_t - 10}'>avg score</text>"
        f"<rect x='{pad_l + 90}' y='{pad_t - 14}' width='12' height='3' fill='#b00020'/>"
        f"<text x='{pad_l + 106}' y='{pad_t - 10}'>max score</text>"
    )
    parts.append("</svg>")
    return "".join(parts)
