"""Lightweight NVD CVE lookup with on-disk caching, API key + concurrency.

Stdlib only. Without an API key, NVD rate-limits to ~5 requests / 30s; with
an API key (``NVD_API_KEY`` env var or constructor arg) the limit jumps to
50 / 30s, so we also fetch CWEs concurrently in that mode.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE = os.path.join(".cache", "nvd")
USER_AGENT = "llm-threat-modeling-agents/0.3 (+https://github.com/emmanuelgjr/llm-threat-modeling-agents)"


class NVDClient:
    def __init__(
        self,
        cache_dir: str = DEFAULT_CACHE,
        max_per_cwe: int = 5,
        timeout: float = 10.0,
        api_key: str | None = None,
        max_workers: int | None = None,
    ):
        self.cache_dir = cache_dir
        self.max_per_cwe = max_per_cwe
        self.timeout = timeout
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        # NVD: 5 req / 30s without key, 50 req / 30s with key.
        self._sleep = 0.15 if self.api_key else 0.7
        # Concurrency only meaningfully helps with an API key.
        self.max_workers = max_workers or (8 if self.api_key else 1)
        self._lock = threading.Lock()
        os.makedirs(self.cache_dir, exist_ok=True)

    def _cache_path(self, cwe: str) -> str:
        return os.path.join(self.cache_dir, f"{cwe.replace('/', '_')}.json")

    def fetch_for_cwe(self, cwe: str) -> list[dict]:
        cached = self._read_cache(cwe)
        if cached is not None:
            return cached

        params = {"cweId": cwe, "resultsPerPage": str(self.max_per_cwe)}
        url = f"{NVD_ENDPOINT}?{urlencode(params)}"
        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("NVD lookup failed for %s: %s", cwe, exc)
            self._write_cache(cwe, [])
            return []

        items = []
        for vuln in payload.get("vulnerabilities", [])[: self.max_per_cwe]:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions") or []
            desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = None
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    data = metrics[key][0].get("cvssData", {})
                    score = data.get("baseScore")
                    severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                    break
            items.append(
                {
                    "id": cve_id,
                    "summary": (desc[:240] + "...") if len(desc) > 240 else desc,
                    "cvss": score,
                    "severity": severity,
                }
            )
        self._write_cache(cwe, items)
        with self._lock:
            time.sleep(self._sleep)
        return items

    def fetch_for_cwes(self, cwes: list[str]) -> list[dict]:
        if not cwes:
            return []
        seen = set()
        out: list[dict] = []
        if self.max_workers <= 1 or len(cwes) <= 1:
            results_iter = (self.fetch_for_cwe(c) for c in cwes)
        else:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self.fetch_for_cwe, c): c for c in cwes}
                results_iter = (f.result() for f in as_completed(futures))
        for items in results_iter:
            for item in items:
                if item["id"] in seen:
                    continue
                seen.add(item["id"])
                out.append(item)
        return out

    def _read_cache(self, cwe: str):
        path = self._cache_path(cwe)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def _write_cache(self, cwe: str, data):
        try:
            with open(self._cache_path(cwe), "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError as exc:
            logger.warning("Could not write NVD cache for %s: %s", cwe, exc)
