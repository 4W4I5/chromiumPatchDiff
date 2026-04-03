from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from clients.http_client import HttpClient
from config import PipelineConfig
from models import CveRecord
from sources.chromium_source import ChromiumMirrorSource
from sources.cve_local_source import CveLocalListSource
from sources.cve_public_source import CvePublicSource
from sources.cve_services_source import CveServicesSource
from sources.cve_utils import normalize_cve_record
from sources.nvd_source import NvdSource


class CveEnrichmentService:
    def __init__(self, config: PipelineConfig):
        self._config = config

    def get_cve_snapshot(self, cve_id: str, *, include_nvd: bool = True) -> tuple[dict[str, Any] | None, list[str], list[str]]:
        record, warnings, provenance = self.get_enriched_record(cve_id, include_nvd=include_nvd)
        if record is None:
            return None, warnings, provenance
        return record.to_dict(include_raw=False), warnings, provenance

    def get_enriched_record(
        self,
        cve_id: str,
        *,
        include_nvd: bool = True,
        context_version: str = "",
    ) -> tuple[CveRecord | None, list[str], list[str]]:
        record, warnings, provenance = self.fetch_cve_record(cve_id)
        if record is None:
            return None, warnings, provenance

        blended_record, context_warnings, context_provenance = self.blend_context(record, context_version=context_version)
        warnings.extend(context_warnings)
        provenance.extend(context_provenance)

        committed_record, evidence_warnings, evidence_provenance = self.attach_evidence(blended_record, include_nvd=include_nvd)
        warnings.extend(evidence_warnings)
        provenance.extend(evidence_provenance)

        return committed_record, self._dedupe(warnings), self._dedupe(provenance)

    def blend_context(self, record: CveRecord, *, context_version: str = "") -> tuple[CveRecord, list[str], list[str]]:
        blended_record, warnings, provenance = self._blend_public_local_context(record=record, context_version=context_version)
        return blended_record, self._dedupe(warnings), self._dedupe(provenance)

    def attach_evidence(self, record: CveRecord, *, include_nvd: bool = True) -> tuple[CveRecord, list[str], list[str]]:
        warnings: list[str] = []
        provenance: list[str] = []

        committed_record, commit_warnings = self._attach_commit_evidence(record)
        warnings.extend(commit_warnings)
        if commit_warnings:
            provenance.append("chromium-github-mirror")

        if include_nvd:
            nvd_warnings = self._attach_nvd(committed_record)
            warnings.extend(nvd_warnings)
            provenance.append("nvd")

        return committed_record, self._dedupe(warnings), self._dedupe(provenance)

    def fetch_cve_record(self, cve_id: str) -> tuple[CveRecord | None, list[str], list[str]]:
        normalized_cve_id = str(cve_id or "").strip().upper()
        warnings: list[str] = []
        provenance: list[str] = []

        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized_cve_id):
            return None, [f"Invalid CVE ID format: {cve_id}"], provenance

        http = HttpClient(self._config)
        services_source = CveServicesSource(http, self._config)
        local_source = CveLocalListSource(self._config)
        public_source = CvePublicSource(http, self._config)

        record, error = services_source.get_record(normalized_cve_id)
        if record is not None:
            provenance.append(services_source.name)
            return record, warnings, provenance

        if error:
            warnings.append(f"[{services_source.name}] {error}")

        local_candidate = self._find_local_record_by_cve_id(local_source=local_source, cve_id=normalized_cve_id)
        if local_candidate is not None:
            provenance.append(local_source.name)
            return local_candidate, warnings, provenance

        warnings.append(
            f"[{local_source.name}] Direct CVE-ID lookup did not find {normalized_cve_id} in local cvelist path."
        )

        public_records, public_warnings = public_source.search(normalized_cve_id, limit=50)
        warnings.extend([f"[{public_source.name}] {item}" for item in public_warnings])
        for candidate in public_records:
            if candidate.cve_id.upper() == normalized_cve_id:
                provenance.append(public_source.name)
                return candidate, warnings, provenance

        warnings.append(f"No CVE record found for {normalized_cve_id} in services/public/local sources.")
        return None, warnings, provenance

    def fetch_cve_record_fast(self, cve_id: str) -> tuple[CveRecord | None, list[str], list[str]]:
        """
        Fast-path record lookup for interactive analysis jobs.

        This intentionally avoids broad public CVE searches to keep compare workflows responsive.
        Full context enrichment is deferred to DOCX export.
        """
        normalized_cve_id = str(cve_id or "").strip().upper()
        warnings: list[str] = []
        provenance: list[str] = []

        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized_cve_id):
            return None, [f"Invalid CVE ID format: {cve_id}"], provenance

        local_source = CveLocalListSource(self._config)
        local_candidate = self._find_local_record_by_cve_id(local_source=local_source, cve_id=normalized_cve_id)
        if local_candidate is not None:
            provenance.append(local_source.name)
            return local_candidate, warnings, provenance

        warnings.append(
            f"[{local_source.name}] Direct CVE-ID lookup did not find {normalized_cve_id} in local cvelist path."
        )

        http = HttpClient(self._config)
        services_source = CveServicesSource(http, self._config)

        record, error = services_source.get_record(normalized_cve_id)
        if record is not None:
            provenance.append(services_source.name)
            return record, warnings, provenance

        if error:
            warnings.append(f"[{services_source.name}] {error}")

        warnings.append(
            (
                f"Fast CVE lookup did not find {normalized_cve_id} in services/local sources. "
                "Broad public enrichment is deferred until DOCX export."
            )
        )
        return None, warnings, provenance

    def extract_patched_candidates(self, record: CveRecord) -> list[str]:
        candidates: list[str] = []

        for affected in record.affected_versions:
            value = str(affected or "").strip()
            if value.startswith("<="):
                candidates.append(value[2:])
                continue
            if value.startswith("<"):
                candidates.append(value[1:])

        raw = record.raw if isinstance(record.raw, dict) else {}
        containers = raw.get("containers", {}) if isinstance(raw.get("containers"), dict) else {}
        cna = containers.get("cna", {}) if isinstance(containers.get("cna"), dict) else {}
        affected = cna.get("affected", []) if isinstance(cna.get("affected"), list) else []

        for item in affected:
            if not isinstance(item, dict):
                continue
            versions = item.get("versions", []) if isinstance(item.get("versions"), list) else []
            for version_info in versions:
                if not isinstance(version_info, dict):
                    continue
                for key in ("lessThan", "lessThanOrEqual", "version"):
                    version_value = str(version_info.get(key, "") or "").strip()
                    if version_value:
                        candidates.append(version_value)

        blob = "\n".join(
            [
                record.title,
                record.description,
                "\n".join(record.references),
            ]
        )
        candidates.extend(re.findall(r"\d+\.\d+\.\d+\.\d+", blob))

        unique: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            matched = re.search(r"\d+\.\d+\.\d+\.\d+", candidate)
            if not matched:
                continue
            version = matched.group(0)
            if version not in seen:
                seen.add(version)
                unique.append(version)

        unique.sort(key=self._version_sort_key, reverse=True)
        return unique

    def _blend_public_local_context(self, record: CveRecord, context_version: str) -> tuple[CveRecord, list[str], list[str]]:
        warnings: list[str] = []
        provenance: list[str] = []
        merged = record

        http = HttpClient(self._config)
        public_source = CvePublicSource(http, self._config)
        local_source = CveLocalListSource(self._config)

        version_context = context_version.strip()

        local_candidate = self._find_local_record_by_cve_id(local_source=local_source, cve_id=record.cve_id)
        if local_candidate is not None:
            merged = self._merge_record(merged, local_candidate)
            provenance.append(local_source.name)

        if version_context:
            local_records, local_warnings = local_source.search(version_context, limit=120)
            warnings.extend([f"[{local_source.name}] {item}" for item in local_warnings])
            for candidate in local_records:
                if candidate.cve_id.upper() == record.cve_id.upper():
                    merged = self._merge_record(merged, candidate)
                    provenance.append(local_source.name)
                    break

            public_records, public_warnings = public_source.search(version_context, limit=120)
            warnings.extend([f"[{public_source.name}] {item}" for item in public_warnings])
            for candidate in public_records:
                if candidate.cve_id.upper() == record.cve_id.upper():
                    merged = self._merge_record(merged, candidate)
                    provenance.append(public_source.name)
                    break
        else:
            warnings.append(
                "Skipped broad public/local search without version context to avoid full-dataset scans; "
                "version-context enrichment will run after patched version resolution."
            )

        return merged, warnings, provenance

    def _attach_commit_evidence(self, record: CveRecord) -> tuple[CveRecord, list[str]]:
        warnings: list[str] = []

        http = HttpClient(self._config)
        chromium_source = ChromiumMirrorSource(http, self._config)
        commits, commit_warnings = chromium_source.search_commits_for_cve(
            cve_id=record.cve_id,
            references=record.references,
            description=record.description,
            max_results=12,
        )
        warnings.extend([f"[{chromium_source.name}] {item}" for item in commit_warnings])
        record.commits = commits
        return record, warnings

    def _attach_nvd(self, record: CveRecord) -> list[str]:
        warnings: list[str] = []
        http = HttpClient(self._config)
        nvd_source = NvdSource(http, self._config)
        nvd_data, error = nvd_source.fetch_by_cve_id(record.cve_id)

        if error:
            warnings.append(f"[{nvd_source.name}] {error}")

        record.nvd = nvd_data
        return warnings

    def _merge_record(self, primary: CveRecord, candidate: CveRecord) -> CveRecord:
        merged = CveRecord.from_dict(primary.to_dict(include_raw=True))

        if candidate.title and len(candidate.title) > len(merged.title):
            merged.title = candidate.title

        if candidate.description and len(candidate.description) > len(merged.description):
            merged.description = candidate.description

        if not merged.published and candidate.published:
            merged.published = candidate.published

        if not merged.updated and candidate.updated:
            merged.updated = candidate.updated

        refs = list(merged.references)
        for reference in candidate.references:
            if reference not in refs:
                refs.append(reference)
        merged.references = refs

        affected = list(merged.affected_versions)
        for item in candidate.affected_versions:
            if item not in affected:
                affected.append(item)
        merged.affected_versions = affected

        if not merged.raw and candidate.raw:
            merged.raw = candidate.raw

        return merged

    def _find_local_record_by_cve_id(self, local_source: CveLocalListSource, cve_id: str) -> CveRecord | None:
        normalized = str(cve_id or "").strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized):
            return None

        resolve_root = getattr(local_source, "_resolve_root_path", None)
        map_relative = getattr(local_source, "_cve_id_to_relative_path", None)
        if not callable(resolve_root) or not callable(map_relative):
            return None

        root = resolve_root()
        if root is None:
            return None

        relative = map_relative(normalized)
        if relative is None:
            return None

        candidate_path = Path(root) / relative
        if not candidate_path.exists() or not candidate_path.is_file():
            return None

        try:
            payload = json.loads(candidate_path.read_text(encoding="utf-8"))
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None

        normalized_record = normalize_cve_record(payload, source=local_source.name)
        return normalized_record

    def _version_sort_key(self, version: str) -> tuple[int, int, int, int]:
        try:
            parts = [int(item) for item in version.split(".") if item.strip()]
        except ValueError:
            return (0, 0, 0, 0)

        while len(parts) < 4:
            parts.append(0)
        return tuple(parts[:4])

    def _dedupe(self, items: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in items:
            normalized = str(item or "").strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                deduped.append(normalized)
        return deduped
