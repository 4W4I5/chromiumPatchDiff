from __future__ import annotations

from urllib.parse import quote_plus

from clients.http_client import HttpClient
from config import PipelineConfig
from models import CveRecord
from sources.cve_services_source import CveServicesSource
from sources.cve_utils import find_cve_ids, normalize_cve_record


class CvePublicSource:
    name = "cve-public"
    search_endpoint = "https://www.cve.org/restapiv1/search"

    def __init__(self, http: HttpClient, config: PipelineConfig):
        self._http = http
        self._config = config
        self._record_fetcher = CveServicesSource(http, config)

    def search(self, version: str, limit: int) -> tuple[list[CveRecord], list[str]]:
        warnings: list[str] = []
        records, api_warnings = self._search_rest_api(version, limit)
        warnings.extend(api_warnings)
        if records:
            return records[:limit], warnings

        cve_ids: list[str] = []
        seen: set[str] = set()

        queries = self._build_queries(version)

        for query in queries:
            search_url = self._config.cve_public_search_url_template.format(query=quote_plus(query))
            status, text, error = self._http.try_get_text(search_url)
            if status >= 400:
                warnings.append(f"cve.org search request failed for '{query}': {error}")
                continue

            for cve_id in find_cve_ids(text):
                if cve_id not in seen:
                    seen.add(cve_id)
                    cve_ids.append(cve_id)
                    if len(cve_ids) >= limit:
                        break
            if len(cve_ids) >= limit:
                break

        records: list[CveRecord] = []
        for cve_id in cve_ids[:limit]:
            record, error = self._record_fetcher.get_record(cve_id)
            if record is not None:
                record.source = self.name
                records.append(record)
                continue

            warnings.append(f"Failed to fetch full record for {cve_id}: {error}")
            records.append(CveRecord(cve_id=cve_id, source=self.name, title=cve_id))

        if not records:
            warnings.append("No CVE IDs found in public cve.org results for this version.")

        return records, warnings

    def _search_rest_api(self, version: str, limit: int) -> tuple[list[CveRecord], list[str]]:
        warnings: list[str] = []
        records: list[CveRecord] = []
        seen: set[str] = set()

        queries = self._build_queries(version)

        for query in queries:
            payload = {
                "query": query,
                "from": 0,
                "size": int(limit),
                "sort": {"property": "cveId", "order": "desc"},
            }
            status, response_payload, error = self._http.try_post_json(
                self.search_endpoint,
                json_body=payload,
            )

            if status >= 400 or not isinstance(response_payload, dict):
                warnings.append(f"Public cve.org search failed for '{query}': {error}")
                continue

            metadata = response_payload.get("searchMetadata", {})
            if isinstance(metadata, dict) and metadata.get("searchStatus") not in ("ok", None):
                warnings.append(f"Public cve.org search returned non-ok status for '{query}'.")
                continue

            for item in response_payload.get("data", []) or []:
                if not isinstance(item, dict):
                    continue
                raw = item.get("_source", {}) or {}
                cve_id = item.get("_id")
                if isinstance(cve_id, str) and cve_id and "cveMetadata" not in raw:
                    raw = {"cveMetadata": {"cveId": cve_id}, **raw}

                normalized = normalize_cve_record(raw, source=self.name)
                if normalized and normalized.cve_id not in seen:
                    seen.add(normalized.cve_id)
                    records.append(normalized)

                if len(records) >= limit:
                    return records[:limit], warnings

            if records:
                return records[:limit], warnings

        return records, warnings

    def _build_queries(self, version: str) -> list[str]:
        parts = [segment for segment in version.split(".") if segment]
        seeds = [version]
        if len(parts) >= 3:
            seeds.append(".".join(parts[:3]))
        if len(parts) >= 2:
            seeds.append(".".join(parts[:2]))

        queries: list[str] = []
        for seed in seeds:
            queries.append(f'"{seed}" chrome')
            queries.append(f'"{seed}" chromium')
            queries.append(seed)

        unique: list[str] = []
        seen: set[str] = set()
        for query in queries:
            lowered = query.lower()
            if lowered not in seen:
                seen.add(lowered)
                unique.append(query)
        return unique
