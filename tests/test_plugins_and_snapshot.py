"""Plugin loader tests + deterministic pipeline snapshot."""

import copy
import json
from pathlib import Path

import pytest

from main import run_pipeline
from utils.compass_threats import COMPASS_THREATS
from utils.maestro_layers import MAESTRO_LAYERS
from utils.plugins import PluginError, load_plugins


SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


@pytest.fixture
def restore_registries():
    layers = copy.deepcopy(MAESTRO_LAYERS)
    threats = copy.deepcopy(COMPASS_THREATS)
    yield
    MAESTRO_LAYERS.clear()
    MAESTRO_LAYERS.update(layers)
    COMPASS_THREATS.clear()
    COMPASS_THREATS.update(threats)


# ---- Plugin loader ---------------------------------------------------------

def test_plugin_adds_layer_and_threat(tmp_path, restore_registries):
    plugin = {
        "maestro_layers": {
            "Network": {"description": "test", "indicators": ["network"]},
        },
        "compass_threats": {
            "Lateral Movement": {
                "indicators": ["lateral", "internal api"],
                "maestro_layers": ["Network"],
                "impact": 5,
                "cwes": ["CWE-668"],
                "mitigation": "segment",
            }
        },
    }
    p = tmp_path / "plug.json"
    p.write_text(json.dumps(plugin), encoding="utf-8")
    added = load_plugins([str(p)])
    assert "Network" in added["maestro_layers"]
    assert "Lateral Movement" in added["compass_threats"]
    assert "Network" in MAESTRO_LAYERS
    assert COMPASS_THREATS["Lateral Movement"]["impact"] == 5


def test_plugin_directory_discovery(tmp_path, restore_registries):
    (tmp_path / "_skip.json").write_text("{}", encoding="utf-8")
    (tmp_path / "good.json").write_text(
        json.dumps({"maestro_layers": {"Edge": {"indicators": ["edge"]}}}),
        encoding="utf-8",
    )
    added = load_plugins([str(tmp_path)])
    assert "Edge" in added["maestro_layers"]


def test_plugin_rejects_unknown_layer_reference(tmp_path, restore_registries):
    p = tmp_path / "bad.json"
    p.write_text(
        json.dumps(
            {
                "compass_threats": {
                    "X": {
                        "indicators": ["x"],
                        "maestro_layers": ["NopeLayer"],
                        "impact": 3,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PluginError, match="unknown MAESTRO layers"):
        load_plugins([str(p)])


def test_plugin_threat_flows_through_pipeline(restore_registries):
    plugin_path = Path(__file__).resolve().parents[1] / "data" / "plugins" / "example_network_layer.json"
    load_plugins([str(plugin_path)])
    scenario = {
        "name": "Internal Service Mesh Agent",
        "description": "Agent traverses internal api boundaries via service mesh and lateral calls.",
        "environment": "Private Cloud",
    }
    results = run_pipeline([scenario])
    threats = [r["threat"] for r in results[0]["risks"]]
    assert "Lateral Movement via Agent Network Path" in threats


# ---- Snapshot --------------------------------------------------------------

SNAPSHOT_SCENARIO = {
    "name": "Snapshot Bot",
    "description": "A chatbot agent that uses tool calls and accesses customer data.",
    "environment": "SaaS, Cloud",
}


def _snapshot(results):
    """Reduce a results list to a stable comparable shape."""
    snap = []
    for item in results:
        snap.append(
            {
                "scenario": item["scenario"]["name"],
                "risks": [
                    {
                        "threat": r["threat"],
                        "likelihood": r["likelihood"],
                        "impact": r["impact"],
                        "risk_score": r["risk_score"],
                        "severity": r["severity"],
                    }
                    for r in item["risks"]
                ],
            }
        )
    return snap


SNAPSHOT_PATH = Path(__file__).parent / "snapshots" / "snapshot_bot.json"


def test_pipeline_snapshot_matches():
    results = run_pipeline([SNAPSHOT_SCENARIO])
    actual = _snapshot(results)
    if not SNAPSHOT_PATH.exists():
        SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT_PATH.write_text(json.dumps(actual, indent=2), encoding="utf-8")
        pytest.skip("snapshot created on first run")
    expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert actual == expected, (
        "Pipeline output drifted from snapshot. If intentional, delete "
        f"{SNAPSHOT_PATH} and re-run."
    )
