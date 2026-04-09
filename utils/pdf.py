"""Optional PDF export, built on top of the HTML report.

Uses WeasyPrint when available; otherwise raises a helpful error so the CLI
can show a graceful message. The HTML writer is the single source of truth
for layout, so PDFs always match the on-screen report.
"""

from __future__ import annotations

import os
import tempfile

from utils.report import write_html


class PDFUnavailableError(RuntimeError):
    """Raised when WeasyPrint isn't installed."""


def _import_weasyprint():
    try:
        from weasyprint import HTML  # type: ignore

        return HTML
    except ImportError as exc:  # pragma: no cover - exercised via fallback test
        raise PDFUnavailableError(
            "PDF export requires WeasyPrint. Install with: pip install -e \".[pdf]\""
        ) from exc


def write_pdf(results, path: str, history=None) -> None:
    HTML = _import_weasyprint()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
        html_path = tmp.name
    try:
        write_html(results, html_path, history=history)
        HTML(filename=html_path).write_pdf(path)
    finally:
        try:
            os.unlink(html_path)
        except OSError:
            pass
