"""Tiny FastAPI web UI: upload a scenario JSON, view the HTML report.

Optional. Install with::

    pip install -e ".[web]"
    uvicorn web.app:app --reload

The pipeline runs in-process, so this is suitable for local demos and
internal tools — not as a public service.
"""

from __future__ import annotations

import io
import json
import tempfile

try:
    from fastapi import FastAPI, File, HTTPException, UploadFile
    from fastapi.responses import HTMLResponse, PlainTextResponse
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Web UI requires FastAPI. Install with: pip install -e \".[web]\""
    ) from exc

from main import run_pipeline
from utils.report import write_html
from utils.schema import SchemaError, validate_inputs

app = FastAPI(title="LLM Threat Modeling Agents", version="0.4.0")


INDEX_HTML = """<!doctype html>
<html><head><meta charset='utf-8'><title>LLM Threat Modeling</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:720px;margin:3rem auto;padding:0 1rem}
h1{margin-bottom:.3rem}
form{padding:1.5rem;border:1px solid #ddd;border-radius:8px;background:#fafafa}
button{padding:.6rem 1.2rem;background:#1976d2;color:#fff;border:0;border-radius:4px;cursor:pointer}
code{background:#eee;padding:.1rem .3rem;border-radius:3px}
</style></head><body>
<h1>LLM Threat Modeling</h1>
<p>Upload a scenarios JSON file (same shape as <code>data/sample_inputs.json</code>) and get the HTML report.</p>
<form action='/analyze' method='post' enctype='multipart/form-data'>
  <input type='file' name='file' accept='application/json' required>
  <button type='submit'>Analyse</button>
</form>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


@app.get("/health", response_class=PlainTextResponse)
def health() -> str:
    return "ok"


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(file: UploadFile = File(...)) -> HTMLResponse:
    raw = await file.read()
    try:
        data = json.loads(raw.decode("utf-8"))
        validate_inputs(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc
    except SchemaError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    results = run_pipeline(data["scenarios"])
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
        html_path = tmp.name
    write_html(results, html_path)
    with open(html_path, "r", encoding="utf-8") as f:
        body = f.read()
    return HTMLResponse(body)
