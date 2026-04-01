from __future__ import annotations

import sys
from datetime import datetime, timezone

from colorama import Fore, Style
from colorama import init as colorama_init

from chrome import Chrome
from clients.http_client import HttpClient
from config import PipelineConfig, SourceMode
from models import CveRecord
from pipeline.enriched_cve_cache import EnrichedCveDiskCache
from sources.chromium_source import ChromiumMirrorSource
from sources.cve_local_source import CveLocalListSource
from sources.cve_public_source import CvePublicSource
from sources.cve_services_source import CveServicesSource
from sources.nvd_source import NvdSource


class EnrichmentOrchestrator:
    def __init__(self, config: PipelineConfig, verbose: bool = False):
        colorama_init(autoreset=True)
        self._config = config
        self._verbose = verbose
        self._http = HttpClient(config)
        self._public_source = CvePublicSource(self._http, config)
        self._services_source = CveServicesSource(self._http, config)
        self._local_source = CveLocalListSource(config)
        self._chromium_source = ChromiumMirrorSource(self._http, config, logger=self._log if verbose else None)
        self._nvd_source = NvdSource(self._http, config, logger=self._log if verbose else None)
        self._enriched_cache = EnrichedCveDiskCache(
            cache_file=config.enriched_cache_file,
            enabled=config.cache_enabled,
            ttl_seconds=config.enriched_cache_ttl_seconds,
        )

    def run(
        self,
        chrome_version: str,
        limit: int = 25,
        include_nvd: bool = True,
        base_version: str | None = None,
    ) -> dict:
        chrome = Chrome(chrome_version)
        canonical_version = chrome.getVersion()
        canonical_base_version = Chrome(base_version).getVersion() if base_version else ""

        self._log(
            f"Starting pipeline: target={canonical_version}, base={canonical_base_version or 'none'}, "
            f"mode={self._config.cve_mode.value}, limit={limit}, include_nvd={include_nvd}"
        )

        warnings: list[str] = []
        raw_candidates: list[CveRecord] = []
        selected_source = ""
        compare_commits = []

        if canonical_base_version:
            self._log(f"Fetching compare commits from GitHub range {canonical_base_version}...{canonical_version}")
            compare_commits, compare_warnings = self._chromium_source.get_compare_commits(
                base_version=canonical_base_version,
                head_version=canonical_version,
            )
            warnings.extend([f"[{self._chromium_source.name}] {warning}" for warning in compare_warnings])
            self._log(f"Compare commit fetch complete: commits={len(compare_commits)}, warnings={len(compare_warnings)}")

        ordered_sources = self._ordered_cve_sources()
        online_sources = [source for source in ordered_sources if source.name != self._local_source.name]
        local_sources = [source for source in ordered_sources if source.name == self._local_source.name]

        for source in online_sources:
            self._log(f"Querying CVE source: {source.name}")
            records, source_warnings = source.search(canonical_version, limit)
            warnings.extend([f"[{source.name}] {warning}" for warning in source_warnings])
            self._log(f"CVE source result: {source.name}, records={len(records)}, warnings={len(source_warnings)}")
            if records:
                raw_candidates = records
                selected_source = source.name
                break

        if not raw_candidates:
            for source in local_sources:
                self._log(f"Querying CVE source: {source.name}")
                records, source_warnings = source.search(canonical_version, limit)
                warnings.extend([f"[{source.name}] {warning}" for warning in source_warnings])
                self._log(f"CVE source result: {source.name}, records={len(records)}, warnings={len(source_warnings)}")
                if records:
                    raw_candidates = records
                    selected_source = source.name
                    break

        self._log(f"Selected CVE source: {selected_source or 'none'}, candidate records={len(raw_candidates)}")

        enriched: list[CveRecord] = []
        for index, record in enumerate(raw_candidates, start=1):
            self._log(f"Processing CVE {index}/{len(raw_candidates)}: {record.cve_id}")

            if not self._is_chromium_related(record):
                self._log(f"Skipping non-Chromium-related CVE: {record.cve_id}")
                continue

            reason, confidence = self._version_match(record, canonical_version, chrome)
            if confidence <= 0:
                self._log(f"Skipping CVE due to version mismatch: {record.cve_id}")
                continue

            record.match_reason = reason
            record.match_confidence = confidence
            self._log(f"Version match accepted: {record.cve_id}, reason={reason}, confidence={confidence:.2f}")

            cached = self._enriched_cache.get(
                record.cve_id,
                base_version=canonical_base_version,
                include_nvd=include_nvd,
                current_updated=record.updated,
            )
            if cached is not None:
                cached.match_reason = reason
                cached.match_confidence = confidence
                cached.source = record.source
                self._log(f"Cache hit for {record.cve_id}; using enriched record from disk")
                enriched.append(cached)
                continue

            commits, commit_warnings = self._chromium_source.search_commits_for_cve(
                record.cve_id,
                references=record.references,
                description=record.description,
                candidate_commits=compare_commits if compare_commits else None,
            )
            warnings.extend([f"[{self._chromium_source.name}] {warning}" for warning in commit_warnings])
            record.commits = commits
            self._log(f"Commit enrichment complete: {record.cve_id}, commits={len(commits)}, warnings={len(commit_warnings)}")

            if include_nvd:
                self._log(f"Fetching NVD enrichment: {record.cve_id}")
                nvd_data, nvd_error = self._nvd_source.fetch_by_cve_id(record.cve_id)
                if nvd_error:
                    warnings.append(f"[{self._nvd_source.name}] {nvd_error}")
                    self._log(f"NVD enrichment warning for {record.cve_id}: {nvd_error}")
                record.nvd = nvd_data
                self._log(f"NVD enrichment complete: {record.cve_id}, has_data={nvd_data is not None}")

            enriched.append(record)
            self._enriched_cache.set(
                record,
                base_version=canonical_base_version,
                include_nvd=include_nvd,
            )

        enriched.sort(key=lambda record: record.match_confidence, reverse=True)

        warnings = self._prune_expected_warnings(warnings, selected_source)

        self._log(
            f"Pipeline finished: matched={len(enriched)}, warnings={len(self._dedupe(warnings))}, " f"selected_source={selected_source or 'none'}"
        )

        return {
            "input_version": canonical_version,
            "compare_base_version": canonical_base_version,
            "compare_commit_count": len(compare_commits),
            "source_mode": self._config.cve_mode.value,
            "selected_cve_source": selected_source,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "candidate_count": len(raw_candidates),
            "matched_count": len(enriched),
            "cves": [record.to_dict(include_raw=False) for record in enriched],
            "warnings": self._dedupe(warnings),
        }

    def _log(self, message: str) -> None:
        if not self._verbose:
            return

        now = datetime.now(timezone.utc).isoformat()
        lower = message.lower()
        message_color = Fore.CYAN
        if "warning" in lower or "rate limit" in lower or "retry" in lower or "skip" in lower:
            message_color = Fore.YELLOW
        elif "error" in lower or "failed" in lower:
            message_color = Fore.RED
        elif "finished" in lower or "complete" in lower or "accepted" in lower:
            message_color = Fore.GREEN

        print(
            f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} " f"{Style.DIM}{now}{Style.RESET_ALL} " f"{message_color}{message}{Style.RESET_ALL}",
            file=sys.stderr,
        )

    def _ordered_cve_sources(self) -> list:
        if self._config.cve_mode == SourceMode.AUTHENTICATED:
            return [self._services_source, self._public_source, self._local_source]
        if self._config.cve_mode == SourceMode.PUBLIC:
            return [self._public_source, self._local_source]

        if self._config.has_cve_credentials:
            return [self._services_source, self._public_source, self._local_source]
        return [self._public_source, self._local_source]

    def _prune_expected_warnings(self, warnings: list[str], selected_source: str) -> list[str]:
        pruned: list[str] = []
        for warning in warnings:
            if selected_source and selected_source != self._public_source.name:
                if warning.startswith("[cve-public] No CVE IDs found in public cve.org results for this version."):
                    continue

            if self._config.cve_mode != SourceMode.AUTHENTICATED:
                if warning.startswith("[cve-services] Missing CVE Services credentials; authenticated search skipped."):
                    continue

            pruned.append(warning)
        return pruned

    def _is_chromium_related(self, record: CveRecord) -> bool:
        blob = " ".join(
            [
                record.title,
                record.description,
                " ".join(record.references),
            ]
        ).lower()

        indicators = ("chrome", "chromium", "blink", "v8", "google")
        return any(indicator in blob for indicator in indicators)

    def _version_match(self, record: CveRecord, full_version: str, chrome: Chrome) -> tuple[str, float]:
        structured_specs = self._extract_structured_affected_specs(record)
        if structured_specs:
            if self._matches_structured_affected(full_version, structured_specs):
                return "affected_version_range", 0.95
            return "no_match", 0.0

        major_minor_build = f"{chrome.getMajorVersion()}.{chrome.getMinorVersion()}.{chrome.getBuildNumber()}"
        major_minor = f"{chrome.getMajorVersion()}.{chrome.getMinorVersion()}"

        blob = " ".join(
            [
                record.title,
                record.description,
                " ".join(record.affected_versions),
                " ".join(record.references),
            ]
        ).lower()

        if full_version.lower() in blob:
            return "exact_version", 1.0

        if major_minor_build in blob:
            return "same_major_minor_build", 0.85

        if major_minor in blob:
            return "same_major_minor", 0.65

        # Keep lower-confidence Chromium CVEs that do not include explicit version strings.
        if self._is_chromium_related(record):
            return "chromium_related_no_explicit_version", 0.35

        return "no_match", 0.0

    def _extract_structured_affected_specs(self, record: CveRecord) -> list[dict[str, str]]:
        raw = record.raw if isinstance(record.raw, dict) else {}
        containers = raw.get("containers", {}) if isinstance(raw.get("containers"), dict) else {}
        cna = containers.get("cna", {}) if isinstance(containers.get("cna"), dict) else {}
        affected = cna.get("affected", []) if isinstance(cna.get("affected"), list) else []

        specs: list[dict[str, str]] = []
        for item in affected:
            if not isinstance(item, dict):
                continue
            versions = item.get("versions", [])
            if not isinstance(versions, list):
                continue

            for version_entry in versions:
                if not isinstance(version_entry, dict):
                    continue
                specs.append(
                    {
                        "version": str(version_entry.get("version", "") or "").strip(),
                        "status": str(version_entry.get("status", "") or "").strip().lower(),
                        "less_than": str(version_entry.get("lessThan", "") or "").strip(),
                        "less_than_or_equal": str(version_entry.get("lessThanOrEqual", "") or "").strip(),
                    }
                )

        return specs

    def _matches_structured_affected(self, target_version: str, specs: list[dict[str, str]]) -> bool:
        for spec in specs:
            status = spec.get("status", "")
            if status and status != "affected":
                continue

            if self._is_target_in_spec(target_version, spec):
                return True

        return False

    def _is_target_in_spec(self, target_version: str, spec: dict[str, str]) -> bool:
        floor = spec.get("version", "")
        less_than = spec.get("less_than", "")
        less_than_or_equal = spec.get("less_than_or_equal", "")

        # Wildcard/unbounded lower bound values commonly used in CVE records.
        if floor.lower() in {"", "*", "n/a", "unspecified", "all", "0"}:
            floor = ""

        # Many cvelist entries encode "prior to X" as version=X plus lessThan=X.
        # Treat this as having no explicit lower bound.
        if floor and less_than and self._compare_versions(floor, less_than) == 0:
            floor = ""

        floor_cmp = self._compare_versions(target_version, floor) if floor else 0
        lt_cmp = self._compare_versions(target_version, less_than) if less_than else 0
        lte_cmp = self._compare_versions(target_version, less_than_or_equal) if less_than_or_equal else 0

        if floor and floor_cmp < 0:
            return False
        if less_than and lt_cmp >= 0:
            return False
        if less_than_or_equal and lte_cmp > 0:
            return False

        # If only a concrete floor/version exists, treat it as exact-or-prefix match.
        if floor and not less_than and not less_than_or_equal:
            if target_version == floor:
                return True
            if target_version.startswith(f"{floor}."):
                return True
            return False

        return True

    def _compare_versions(self, left: str, right: str) -> int:
        if not left or not right:
            return 0

        left_parts = self._normalize_version_parts(left)
        right_parts = self._normalize_version_parts(right)
        max_len = max(len(left_parts), len(right_parts))

        left_parts.extend([0] * (max_len - len(left_parts)))
        right_parts.extend([0] * (max_len - len(right_parts)))

        for l_item, r_item in zip(left_parts, right_parts):
            if l_item < r_item:
                return -1
            if l_item > r_item:
                return 1
        return 0

    def _normalize_version_parts(self, value: str) -> list[int]:
        parts: list[int] = []
        for chunk in value.split("."):
            digits = "".join(ch for ch in chunk if ch.isdigit())
            if digits:
                parts.append(int(digits))
            else:
                parts.append(0)
        return parts

    def _dedupe(self, entries: list[str]) -> list[str]:
        unique: list[str] = []
        seen: set[str] = set()
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                unique.append(entry)
        return unique
