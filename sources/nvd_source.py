from __future__ import annotations

import time
from typing import Any, Callable

from clients.http_client import HttpClient
from config import PipelineConfig
from models import NvdEnrichment


class NvdSource:
    name = "nvd"

    def __init__(
        self,
        http: HttpClient,
        config: PipelineConfig,
        logger: Callable[[str], None] | None = None,
    ):
        self._http = http
        self._config = config
        self._logger = logger
        self._max_rate_limit_retries = 5
        self._last_nvd_request_at = 0.0

    def fetch_by_cve_id(self, cve_id: str) -> tuple[NvdEnrichment | None, str | None]:
        last_error = ""
        for attempt in range(self._max_rate_limit_retries + 1):
            self._throttle_nvd_requests()
            status, payload, error = self._http.try_get_json(
                self._config.nvd_api_base,
                params={"cveId": cve_id},
                headers=self._config.nvd_headers,
            )

            if status == 429 and self._is_retryable_rate_limit(payload):
                wait_seconds = self._compute_rate_limit_wait_seconds(payload=payload, attempt=attempt)
                last_error = error or f"NVD rate-limited for {cve_id}"

                if attempt >= self._max_rate_limit_retries:
                    return (
                        None,
                        (f"NVD rate limit persisted for {cve_id} after {self._max_rate_limit_retries} retries. " f"Last error: {last_error}"),
                    )

                self._log(
                    (f"Rate limited by NVD for {cve_id} (attempt {attempt + 1}/" f"{self._max_rate_limit_retries + 1}); retrying in {wait_seconds}s")
                )
                time.sleep(wait_seconds)
                continue

            if status >= 400 or not isinstance(payload, dict):
                return None, error or f"NVD request failed for {cve_id}"

            vulnerabilities = payload.get("vulnerabilities", []) or []
            if not vulnerabilities:
                return None, f"No NVD entry found for {cve_id}"

            cve = (vulnerabilities[0] or {}).get("cve", {})
            metrics = cve.get("metrics", {}) or {}

            score = None
            vector = ""
            severity = ""

            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, []) or []
                if not metric_list:
                    continue
                metric = metric_list[0] or {}
                cvss_data = metric.get("cvssData", {}) or {}
                score = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString", "")
                severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or metric.get("severity", "")
                break

            weaknesses: list[str] = []
            for weakness in cve.get("weaknesses", []) or []:
                for desc in weakness.get("description", []) or []:
                    value = desc.get("value") if isinstance(desc, dict) else ""
                    if value:
                        weaknesses.append(value)

            cpes = self._extract_cpes(cve.get("configurations", []) or [])

            return (
                NvdEnrichment(
                    cvss_score=score,
                    cvss_vector=vector,
                    severity=severity,
                    weaknesses=sorted(set(weaknesses)),
                    cpes=sorted(set(cpes)),
                ),
                None,
            )

        return None, f"NVD request failed for {cve_id}: unknown retry state"

    def _throttle_nvd_requests(self) -> None:
        min_interval = self._config.nvd_min_request_interval_seconds
        if min_interval <= 0:
            self._last_nvd_request_at = time.monotonic()
            return

        now = time.monotonic()
        elapsed = now - self._last_nvd_request_at
        if elapsed < min_interval:
            wait_seconds = min_interval - elapsed
            self._log(f"Throttling NVD request for {wait_seconds:.2f}s")
            time.sleep(wait_seconds)

        self._last_nvd_request_at = time.monotonic()

    def _is_retryable_rate_limit(self, payload: Any) -> bool:
        if isinstance(payload, dict):
            if payload.get("retryable") is False:
                return False
            if payload.get("error_code") == 1015:
                return True
            if payload.get("status") == 429:
                return True
        return True

    def _compute_rate_limit_wait_seconds(self, payload: Any, attempt: int) -> int:
        default_wait = min(30 * (2**attempt), 300)
        if not isinstance(payload, dict):
            return default_wait

        raw_retry_after = payload.get("retry_after")
        if isinstance(raw_retry_after, (int, float)):
            return max(1, int(raw_retry_after))
        if isinstance(raw_retry_after, str) and raw_retry_after.isdigit():
            return max(1, int(raw_retry_after))
        return default_wait

    def _log(self, message: str) -> None:
        if self._logger:
            self._logger(f"[nvd] {message}")

    def _extract_cpes(self, configurations: list[dict[str, Any]]) -> list[str]:
        cpes: list[str] = []

        def walk_nodes(nodes: list[dict[str, Any]]) -> None:
            for node in nodes:
                for match in node.get("cpeMatch", []) or []:
                    criteria = match.get("criteria") if isinstance(match, dict) else ""
                    if criteria:
                        cpes.append(criteria)
                nested = node.get("nodes", []) or []
                if nested:
                    walk_nodes(nested)

        for config in configurations:
            walk_nodes(config.get("nodes", []) or [])

        return cpes
