from __future__ import annotations

from clients.http_client import HttpClient
from config import PipelineConfig, SourceMode
from models import CveRecord
from sources.cve_utils import extract_raw_cve_records, normalize_cve_record


class CveServicesSource:
    name = "cve-services"

    def __init__(self, http: HttpClient, config: PipelineConfig):
        self._http = http
        self._config = config

    def search(self, version: str, limit: int) -> tuple[list[CveRecord], list[str]]:
        warnings: list[str] = []

        if not self._config.has_cve_credentials:
            if self._config.cve_mode != SourceMode.AUTHENTICATED:
                return [], warnings

            missing: list[str] = []
            if not self._config.cve_api_user:
                missing.append("CVE_API_USER")
            if not self._config.cve_api_org:
                missing.append("CVE_API_ORG")
            if not self._config.cve_api_key:
                missing.append("CVE_API_KEY")

            missing_text = ", ".join(missing) if missing else "CVE_API_USER/CVE_API_ORG/CVE_API_KEY"
            warnings.append(
                "Missing CVE Services credentials; authenticated search skipped. "
                f"Required env vars: {missing_text}. "
                "Note: NVD_API_KEY is only used for NVD enrichment."
            )
            return [], warnings

        headers = self._config.cve_auth_headers
        endpoint = f"{self._config.cve_api_base}/cve"

        parts = [segment for segment in version.split(".") if segment]
        seeds = [version]
        if len(parts) >= 3:
            seeds.append(".".join(parts[:3]))
        if len(parts) >= 2:
            seeds.append(".".join(parts[:2]))

        query_terms: list[str] = []
        for seed in seeds:
            query_terms.extend([f'"{seed}" chrome', f'"{seed}" chromium', seed])

        deduped_query_terms: list[str] = []
        seen_terms: set[str] = set()
        for term in query_terms:
            lowered = term.lower()
            if lowered not in seen_terms:
                seen_terms.add(lowered)
                deduped_query_terms.append(term)

        collected: dict[str, CveRecord] = {}

        for term in deduped_query_terms:
            params = {"keywordSearch": term}
            status, payload, error = self._http.try_get_json(endpoint, params=params, headers=headers)

            if status in (401, 403):
                warnings.append("Authenticated CVE search denied by CVE Services. Verify CVE credentials and permissions.")
                return [], warnings

            if status >= 400 or payload is None:
                warnings.append(f"CVE Services search failed for '{term}': {error}")
                continue

            raw_records = extract_raw_cve_records(payload)
            for raw in raw_records:
                normalized = normalize_cve_record(raw, source=self.name)
                if normalized and normalized.cve_id not in collected:
                    collected[normalized.cve_id] = normalized
                if len(collected) >= limit:
                    return list(collected.values())[:limit], warnings

        return list(collected.values())[:limit], warnings

    def get_record(self, cve_id: str) -> tuple[CveRecord | None, str | None]:
        headers = self._config.cve_auth_headers if self._config.has_cve_credentials else None
        endpoint = f"{self._config.cve_api_base}/cve/{cve_id}"
        status, payload, error = self._http.try_get_json(endpoint, headers=headers)

        if status >= 400 or payload is None:
            return None, error or f"Unable to fetch {cve_id}"

        raw_records = extract_raw_cve_records(payload)
        if not raw_records and isinstance(payload, dict):
            raw_records = [payload]

        for raw in raw_records:
            normalized = normalize_cve_record(raw, source=self.name)
            if normalized and normalized.cve_id.upper() == cve_id.upper():
                return normalized, None

        return None, f"No usable CVE payload found for {cve_id}"
