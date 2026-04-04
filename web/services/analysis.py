from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timezone
import re
from typing import Any, Callable

from chrome import Chrome
from clients.http_client import HttpClient
from config import CompareComponent, PipelineConfig, resolve_component_repo
from models import CveRecord
from pipeline.orchestrator import EnrichmentOrchestrator
from sources.chrome_releases_source import ChromeReleasesSource
from sources.component_ref_resolver import ChromiumComponentRefResolver
from sources.chromium_source import ChromiumMirrorSource
from sources.cve_utils import infer_focus_keywords
from web.schemas import AnalysisRequest, InputMode
from web.services.cve_enrichment import CveEnrichmentService
from web.services.version_catalog import VersionCatalogService


class AnalysisService:
    def __init__(
        self,
        config: PipelineConfig,
        version_catalog_service: VersionCatalogService,
        cve_enrichment_service: CveEnrichmentService,
    ):
        self._config = config
        self._version_catalog_service = version_catalog_service
        self._cve_enrichment_service = cve_enrichment_service

    def run_analysis(self, payload: AnalysisRequest, progress: Callable[[int, str], None]) -> dict[str, Any]:
        progress(5, "Validating input")

        if payload.input_mode == InputMode.CVE:
            return self._run_cve_analysis(payload, progress)

        return self._run_version_analysis(payload, progress)

    def _run_cve_analysis(self, payload: AnalysisRequest, progress: Callable[[int, str], None]) -> dict[str, Any]:
        normalized_cve_id = str(payload.cve_id or "").strip().upper()

        progress(12, f"Fetching base CVE record for {normalized_cve_id} (fast services/local path)")
        cve_record, cve_warnings, cve_provenance = self._cve_enrichment_service.fetch_cve_record_fast(normalized_cve_id)
        if cve_record is None:
            cve_record = CveRecord(
                cve_id=normalized_cve_id,
                source="deferred-cve-fetch",
                title="",
                description="",
            )

        progress(22, "Searching Chrome Releases Stable Desktop posts for CVE")
        release_source = ChromeReleasesSource(HttpClient(self._config), self._config)
        release_posts, release_warnings = release_source.search_stable_desktop_posts_for_cve(
            normalized_cve_id,
            max_results=40,
        )
        selected_log_range, selection_warnings = release_source.select_preferred_log_range(
            release_posts,
            version_hint=payload.version,
        )

        release_blog_payload = {
            "query_cve_id": normalized_cve_id,
            "post_count": len(release_posts),
            "posts": release_posts,
            "selected_log_range": selected_log_range,
        }

        patched_version = ""
        unpatched_version = ""
        patched_provenance: list[str] = []
        patched_warnings: list[str] = []
        predecessor_warnings: list[str] = []

        if isinstance(selected_log_range, dict):
            patched_from_log = self._version_catalog_service.normalize_version(str(selected_log_range.get("head_version", "")))
            unpatched_from_log = self._version_catalog_service.normalize_version(str(selected_log_range.get("base_version", "")))
            if patched_from_log and unpatched_from_log:
                patched_version = patched_from_log
                unpatched_version = unpatched_from_log
                patched_provenance.append(
                    "Patched/unpatched versions resolved from Chrome Releases Log range "
                    f"{unpatched_version}..{patched_version}."
                )
            else:
                patched_warnings.append(
                    "Chrome Releases Log range was found but did not expose a parseable base/head version; "
                    "falling back to CVE metadata inference."
                )

        if not patched_version:
            progress(30, "Resolving patched version from CVE metadata and release sources")
            patched_candidates = self._cve_enrichment_service.extract_patched_candidates(cve_record)
            if payload.version:
                patched_candidates.insert(0, payload.version)

            patched_version, patched_provenance_fallback, patched_warnings_fallback = self._version_catalog_service.resolve_patched_version(
                patched_candidates,
                published=cve_record.published,
                updated=cve_record.updated,
            )
            patched_provenance.extend(patched_provenance_fallback)
            patched_warnings.extend(patched_warnings_fallback)

            if not patched_version:
                raise ValueError(
                    "Could not resolve a patched Chromium version from CVE metadata. "
                    "Provide an explicit version input to continue."
                )

        progress(
            36,
            (
                "Deferring heavy CVE/NVD enrichment until DOCX export "
                f"(cve={normalized_cve_id}, patched={patched_version or 'unknown'}). "
                "Prioritizing code diff generation."
            ),
        )
        context_warnings: list[str] = []
        context_provenance: list[str] = []
        evidence_warnings: list[str] = []
        evidence_provenance: list[str] = []

        if not unpatched_version:
            progress(48, "Inferring latest unpatched predecessor")
            unpatched_version, predecessor_warnings = self._version_catalog_service.find_previous_version(patched_version)
            if not unpatched_version:
                raise ValueError(f"Unable to infer a predecessor version for patched version {patched_version}.")

        auto_keywords = infer_focus_keywords(cve_record.title, cve_record.description)
        manual_keywords = self._split_keywords(payload.keyword)
        effective_keywords = self._merge_keywords(auto_keywords, manual_keywords)
        evidence_tokens = self._build_security_evidence_tokens(
            cve_id=normalized_cve_id,
            references=cve_record.references,
            description=cve_record.description,
        )
        effective_components = self._resolve_effective_components(payload)

        progress(52, "Running filtered compare across selected components")
        compare_result, compare_warnings = self._run_component_compare(
            base_version=unpatched_version,
            head_version=patched_version,
            payload=payload,
            components=effective_components,
            keyword=payload.keyword,
            hard_keywords=manual_keywords,
            soft_keywords=auto_keywords,
            evidence_tokens=evidence_tokens,
            strict_commit_platform=False,
            strict_file_platform=False,
            soft_file_focus=True,
            min_commit_confidence=0.6,
            progress=progress,
            start_progress=52,
            end_progress=88,
        )

        progress(92, "Finalizing analysis output")
        warnings: list[str] = []
        warnings.extend(cve_warnings)
        warnings.extend(release_warnings)
        warnings.extend(selection_warnings)
        warnings.extend(context_warnings)
        warnings.extend(evidence_warnings)
        warnings.extend(patched_warnings)
        warnings.extend(predecessor_warnings)
        warnings.extend(compare_warnings)
        notes = ["Detailed CVE context and NVD enrichment deferred until DOCX export."]

        provenance: list[str] = []
        provenance.extend(cve_provenance)
        provenance.extend(context_provenance)
        provenance.extend(evidence_provenance)
        provenance.extend(patched_provenance)
        if release_posts:
            provenance.append("chrome-releases-googleblog")

        result = {
            "input_mode": payload.input_mode.value,
            "input": {
                "cve_id": normalized_cve_id,
                "version_hint": payload.version,
                "platform": payload.platform.value,
                "components": [component.value for component in effective_components],
                "path_prefixes": payload.path_prefixes,
                "file_extensions": payload.file_extensions,
                "keyword": payload.keyword,
                "include_nvd": payload.include_nvd,
            },
            "patched_version": patched_version,
            "unpatched_version": unpatched_version,
            "cve": cve_record.to_dict(include_raw=False),
            "release_blog": release_blog_payload,
            "enrichment_deferred": True,
            "enrichment_deferred_meta": {
                "mode": "cve",
                "cve_id": normalized_cve_id,
                "context_version": patched_version,
                "include_nvd": payload.include_nvd,
            },
            "effective_focus": {
                "minimal_mode": payload.minimal_mode,
                "code_scope": "changed-files-only",
                "components": [component.value for component in effective_components],
                "manual_keywords": manual_keywords,
                "auto_keywords": auto_keywords,
                "keywords": effective_keywords,
            },
            "compare": compare_result,
            "notes": notes,
            "warnings": self._dedupe(warnings),
            "provenance": self._dedupe(provenance),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        progress(100, "Completed")
        return result

    def _run_version_analysis(self, payload: AnalysisRequest, progress: Callable[[int, str], None]) -> dict[str, Any]:
        normalized_version = self._version_catalog_service.normalize_version(payload.version)

        if not normalized_version:
            raise ValueError("Version input is empty after normalization.")

        try:
            normalized_version = Chrome(normalized_version).getVersion()
        except ValueError as exc:
            raise ValueError(f"Invalid Chromium version: {exc}") from exc

        progress(16, "Inferring predecessor version from merged catalog")
        predecessor_version, predecessor_warnings = self._version_catalog_service.find_previous_version(normalized_version)
        if not predecessor_version:
            raise ValueError(f"Unable to infer predecessor for version {normalized_version}.")

        effective_components = self._resolve_effective_components(payload)
        manual_keywords = self._split_keywords(payload.keyword)

        progress(
            28,
            (
                "Deferring CVE/NVD enrichment until DOCX export "
                f"(version={normalized_version}, base={predecessor_version}). "
                "Prioritizing code diff generation."
            ),
        )
        enrichment_result: dict[str, Any] = {}

        progress(42, "Running filtered compare across selected components")
        compare_result, compare_warnings = self._run_component_compare(
            base_version=predecessor_version,
            head_version=normalized_version,
            payload=payload,
            components=effective_components,
            keyword=payload.keyword,
            hard_keywords=manual_keywords,
            soft_keywords=[],
            evidence_tokens=[],
            strict_commit_platform=True,
            strict_file_platform=True,
            soft_file_focus=False,
            min_commit_confidence=0.0,
            progress=progress,
            start_progress=42,
            end_progress=88,
        )

        primary_cve = None

        warnings: list[str] = []
        warnings.extend(predecessor_warnings)
        warnings.extend(compare_warnings)
        notes = ["Detailed CVE context and NVD enrichment deferred until DOCX export."]

        result = {
            "input_mode": payload.input_mode.value,
            "input": {
                "version": normalized_version,
                "platform": payload.platform.value,
                "components": [component.value for component in effective_components],
                "path_prefixes": payload.path_prefixes,
                "file_extensions": payload.file_extensions,
                "keyword": payload.keyword,
                "include_nvd": payload.include_nvd,
                "limit": payload.limit,
            },
            "patched_version": normalized_version,
            "unpatched_version": predecessor_version,
            "primary_cve": primary_cve,
            "enrichment": enrichment_result,
            "enrichment_deferred": True,
            "enrichment_deferred_meta": {
                "mode": "version",
                "version": normalized_version,
                "base_version": predecessor_version,
                "include_nvd": payload.include_nvd,
                "limit": payload.limit,
            },
            "effective_focus": {
                "minimal_mode": payload.minimal_mode,
                "code_scope": "changed-files-only",
                "components": [component.value for component in effective_components],
                "manual_keywords": manual_keywords,
                "auto_keywords": [],
                "keywords": manual_keywords,
            },
            "compare": compare_result,
            "notes": notes,
            "warnings": self._dedupe(warnings),
            "provenance": ["chromium-github-mirror", "chromiumdash"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        progress(100, "Completed")
        return result

    def enrich_result_for_docx(self, result: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(result, dict):
            return result

        if not bool(result.get("enrichment_deferred")):
            return result

        metadata = result.get("enrichment_deferred_meta", {}) if isinstance(result.get("enrichment_deferred_meta"), dict) else {}
        mode = str(metadata.get("mode") or result.get("input_mode") or "").strip().lower()

        if mode == InputMode.CVE.value:
            return self._enrich_cve_result_for_docx(result=result, metadata=metadata)
        if mode == InputMode.VERSION.value:
            return self._enrich_version_result_for_docx(result=result, metadata=metadata)

        return result

    def _enrich_cve_result_for_docx(self, *, result: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
        cve_id = str(
            metadata.get("cve_id")
            or ((result.get("input") or {}).get("cve_id") if isinstance(result.get("input"), dict) else "")
            or ((result.get("cve") or {}).get("cve_id") if isinstance(result.get("cve"), dict) else "")
            or ""
        ).strip().upper()
        include_nvd = bool(metadata.get("include_nvd", True))
        context_version = str(metadata.get("context_version") or result.get("patched_version") or "").strip()

        if not cve_id:
            warnings = [str(item) for item in (result.get("warnings") or []) if str(item).strip()]
            warnings.append("DOCX enrichment skipped: CVE ID missing from analysis payload.")
            result["warnings"] = self._dedupe(warnings)
            return result

        record, fetch_warnings, fetch_provenance = self._cve_enrichment_service.fetch_cve_record(cve_id)
        if record is None:
            warnings = [str(item) for item in (result.get("warnings") or []) if str(item).strip()]
            warnings.extend(fetch_warnings)
            warnings.append(f"DOCX enrichment skipped: could not fetch CVE record for {cve_id}.")
            result["warnings"] = self._dedupe(warnings)
            return result

        record, context_warnings, context_provenance = self._cve_enrichment_service.blend_context(record, context_version=context_version)
        record, evidence_warnings, evidence_provenance = self._cve_enrichment_service.attach_evidence(record, include_nvd=include_nvd)

        warnings = [str(item) for item in (result.get("warnings") or []) if str(item).strip()]
        warnings.extend(fetch_warnings)
        warnings.extend(context_warnings)
        warnings.extend(evidence_warnings)
        result["warnings"] = self._dedupe(warnings)

        provenance = [str(item) for item in (result.get("provenance") or []) if str(item).strip()]
        provenance.extend(fetch_provenance)
        provenance.extend(context_provenance)
        provenance.extend(evidence_provenance)
        result["provenance"] = self._dedupe(provenance)

        result["cve"] = record.to_dict(include_raw=False)
        result["enrichment_deferred"] = False
        result["docx_enriched_at"] = datetime.now(timezone.utc).isoformat()
        return result

    def _enrich_version_result_for_docx(self, *, result: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
        version = str(metadata.get("version") or result.get("patched_version") or "").strip()
        base_version = str(metadata.get("base_version") or result.get("unpatched_version") or "").strip()
        include_nvd = bool(metadata.get("include_nvd", True))

        try:
            limit = int(metadata.get("limit") or ((result.get("input") or {}).get("limit") if isinstance(result.get("input"), dict) else 25) or 25)
        except Exception:
            limit = 25
        limit = max(1, min(limit, 500))

        if not version or not base_version:
            warnings = [str(item) for item in (result.get("warnings") or []) if str(item).strip()]
            warnings.append("DOCX enrichment skipped: version compare range missing from analysis payload.")
            result["warnings"] = self._dedupe(warnings)
            return result

        orchestrator = EnrichmentOrchestrator(self._config, verbose=False)
        enrichment_result = orchestrator.run(
            chrome_version=version,
            limit=limit,
            include_nvd=include_nvd,
            base_version=base_version,
        )

        warnings = [str(item) for item in (result.get("warnings") or []) if str(item).strip()]
        warnings.extend([str(item) for item in (enrichment_result.get("warnings") or []) if str(item).strip()])
        result["warnings"] = self._dedupe(warnings)

        provenance = [str(item) for item in (result.get("provenance") or []) if str(item).strip()]
        provenance.extend(["cve-public", "cve-local", "cve-services"])
        if include_nvd:
            provenance.append("nvd")
        result["provenance"] = self._dedupe(provenance)

        cves = enrichment_result.get("cves", []) if isinstance(enrichment_result, dict) else []
        if not isinstance(cves, list):
            cves = []

        result["enrichment"] = enrichment_result
        result["primary_cve"] = cves[0] if cves else None
        result["enrichment_deferred"] = False
        result["docx_enriched_at"] = datetime.now(timezone.utc).isoformat()
        return result

    def _run_component_compare(
        self,
        *,
        base_version: str,
        head_version: str,
        payload: AnalysisRequest,
        components: list[CompareComponent] | None,
        keyword: str,
        hard_keywords: list[str],
        soft_keywords: list[str],
        evidence_tokens: list[str],
        strict_commit_platform: bool,
        strict_file_platform: bool,
        soft_file_focus: bool,
        min_commit_confidence: float,
        progress: Callable[[int, str], None],
        start_progress: int,
        end_progress: int,
    ) -> tuple[dict[str, Any], list[str]]:
        warnings: list[str] = []
        component_results: list[dict[str, Any]] = []
        selected_components = self._normalize_components(components or payload.components)

        if not selected_components:
            raise ValueError("At least one component must be selected for compare.")

        resolver = ChromiumComponentRefResolver(HttpClient(self._config), self._config)
        resolved_refs, resolution_warnings = resolver.resolve_component_refs(
            base_version=base_version,
            head_version=head_version,
            components=selected_components,
        )
        warnings.extend(resolution_warnings)

        progress_span = max(1, end_progress - start_progress)

        for index, component in enumerate(selected_components, start=1):
            repo = resolve_component_repo(component)
            resolved_ref = resolved_refs.get(component)

            if resolved_ref is None:
                component_warning = (
                    "Component compare skipped because base/head refs could not be resolved from Chromium DEPS."
                )
                warnings.append(f"[{component.value}] {component_warning}")
                component_results.append(
                    {
                        "component": component.value,
                        "status": "error",
                        "repo": repo,
                        "compare_url": "",
                        "commit_count": 0,
                        "file_count": 0,
                        "compare_meta": {
                            "total_commits": 0,
                            "ahead_by": 0,
                            "behind_by": 0,
                            "total_files": 0,
                            "truncated": False,
                        },
                        "filter_metrics": {
                            "total_files_from_api": 0,
                            "after_platform_filter": 0,
                            "after_path_prefix_filter": 0,
                            "after_extension_filter": 0,
                            "after_keyword_filter": 0,
                            "after_soft_focus_filter": 0,
                            "commit_confidence_fallback_applied": False,
                            "soft_file_focus_fallback_applied": False,
                        },
                        "resolved_refs": {
                            "base": "",
                            "head": "",
                            "strategy": "unresolved",
                        },
                        "warnings": [component_warning],
                        "commits": [],
                        "files": [],
                        "available_directories": [],
                        "directory_file_counts": [],
                    }
                )
                continue

            cfg = replace(self._config)
            cfg.github_repo = repo

            request_progress = start_progress + int((index - 1) * progress_span / len(selected_components))
            progress(request_progress, f"Comparing {component.value} ({index}/{len(selected_components)})")

            source = ChromiumMirrorSource(HttpClient(cfg), cfg)
            compare_payload, compare_warnings = source.get_compare_diff(
                base_version=resolved_ref.base_ref,
                head_version=resolved_ref.head_ref,
                platform=payload.platform,
                component=component,
                path_prefixes=payload.path_prefixes,
                file_extensions=payload.file_extensions,
                keyword=keyword,
                keywords=hard_keywords,
                soft_keywords=soft_keywords,
                evidence_tokens=evidence_tokens,
                strict_commit_platform=strict_commit_platform,
                strict_file_platform=strict_file_platform,
                soft_file_focus=soft_file_focus,
                min_commit_confidence=min_commit_confidence,
            )

            warnings.extend([f"[{component.value}] {item}" for item in compare_warnings])

            commits = [asdict(item) for item in compare_payload.get("commits", []) or []]
            files = [item for item in compare_payload.get("files", []) or [] if isinstance(item, dict)]
            component_directories, component_directory_counts = self._extract_directory_hierarchy(files)
            total_commits_api = int(compare_payload.get("total_commits", 0) or 0)
            total_files_api = int(compare_payload.get("total_files", 0) or 0)
            compare_status = str(compare_payload.get("status", "ok") or "ok")

            component_status = "changed"
            if compare_status == "error":
                component_status = "error"
            elif compare_status == "unchanged":
                component_status = "unchanged"
            elif total_files_api > 0 and not files:
                component_status = "filtered_out"
            elif total_commits_api > 0 and not commits and not files:
                component_status = "filtered_out"
            elif total_commits_api == 0 and total_files_api == 0 and not commits and not files:
                component_status = "unchanged"

            compare_url = ""
            if component_status not in {"unchanged", "error"}:
                compare_url = self._build_compare_url(repo, resolved_ref.base_ref, resolved_ref.head_ref)

            component_results.append(
                {
                    "component": component.value,
                    "status": component_status,
                    "repo": repo,
                    "compare_url": compare_url,
                    "commit_count": len(commits),
                    "file_count": len(files),
                    "compare_meta": {
                        "total_commits": total_commits_api,
                        "ahead_by": int(compare_payload.get("ahead_by", 0) or 0),
                        "behind_by": int(compare_payload.get("behind_by", 0) or 0),
                        "total_files": total_files_api,
                        "truncated": bool(compare_payload.get("truncated", False)),
                    },
                    "filter_metrics": compare_payload.get("filter_metrics", {}),
                    "resolved_refs": {
                        "base": resolved_ref.base_ref,
                        "head": resolved_ref.head_ref,
                        "strategy": resolved_ref.strategy,
                    },
                    "warnings": compare_warnings,
                    "commits": commits,
                    "files": files,
                    "available_directories": component_directories,
                    "directory_file_counts": component_directory_counts,
                }
            )

        total_commits = sum(item.get("commit_count", 0) for item in component_results)
        total_files = sum(item.get("file_count", 0) for item in component_results)
        aggregate_directory_counts: dict[str, int] = {}
        for component_result in component_results:
            for row in component_result.get("directory_file_counts", []) or []:
                if not isinstance(row, dict):
                    continue
                directory = str(row.get("directory", "") or "").strip()
                if not directory:
                    continue
                aggregate_directory_counts[directory] = aggregate_directory_counts.get(directory, 0) + int(
                    row.get("file_count", 0) or 0
                )

        available_directories = sorted(aggregate_directory_counts.keys(), key=self._directory_sort_key)
        directory_file_counts = [
            {"directory": item, "file_count": aggregate_directory_counts[item]} for item in available_directories
        ]

        return (
            {
                "base_version": base_version,
                "head_version": head_version,
                "platform": payload.platform.value,
                "components": component_results,
                "total_component_count": len(component_results),
                "total_commit_count": int(total_commits),
                "total_file_count": int(total_files),
                "available_directories": available_directories,
                "directory_file_counts": directory_file_counts,
                "filters": {
                    "path_prefixes": payload.path_prefixes,
                    "file_extensions": payload.file_extensions,
                    "keyword": keyword,
                    "hard_keywords": list(hard_keywords),
                    "soft_keywords": list(soft_keywords),
                    "evidence_tokens": list(evidence_tokens),
                    "strict_commit_platform": bool(strict_commit_platform),
                    "strict_file_platform": bool(strict_file_platform),
                    "soft_file_focus": bool(soft_file_focus),
                    "min_commit_confidence": float(min_commit_confidence),
                    "keywords": self._merge_keywords(hard_keywords, soft_keywords),
                },
            },
            warnings,
        )

    def _resolve_effective_components(self, payload: AnalysisRequest) -> list[CompareComponent]:
        if payload.minimal_mode:
            return [CompareComponent.CHROME]
        return self._normalize_components(payload.components)

    def _split_keywords(self, value: str) -> list[str]:
        raw = str(value or "").strip().lower()
        if not raw:
            return []

        items: list[str]
        if "," in raw:
            items = [item.strip() for item in raw.split(",") if item.strip()]
        else:
            items = [raw]
            words = [item.strip() for item in raw.split() if len(item.strip()) >= 3]
            if len(words) > 1:
                items.extend(words)

        return self._dedupe(items)

    def _merge_keywords(self, *groups: list[str]) -> list[str]:
        merged: list[str] = []
        for group in groups:
            merged.extend(group)
        return self._dedupe(merged)

    def _normalize_components(self, components: list[CompareComponent]) -> list[CompareComponent]:
        seen: set[str] = set()
        normalized: list[CompareComponent] = []
        for component in components:
            if component.value in seen:
                continue
            seen.add(component.value)
            normalized.append(component)
        return normalized

    def _build_compare_url(self, repo: str, base_version: str, head_version: str) -> str:
        repo_path = repo.strip("/") or "chromium/chromium"
        if not base_version or not head_version:
            return ""
        if str(base_version).strip() == str(head_version).strip():
            return ""
        return f"https://github.com/{repo_path}/compare/{base_version}...{head_version}"

    def _build_security_evidence_tokens(self, *, cve_id: str, references: list[str], description: str) -> list[str]:
        tokens = [str(cve_id or "").strip()]
        issue_ids: set[str] = set()

        for ref in references:
            for match in re.findall(r"issues\.chromium\.org/issues/(\d+)", str(ref or "")):
                issue_ids.add(match)
            for match in re.findall(r"crbug\.com/(\d+)", str(ref or "")):
                issue_ids.add(match)

        for match in re.findall(r"(?:crbug|bug)\s*[:#/]?\s*(\d{6,})", str(description or ""), flags=re.IGNORECASE):
            issue_ids.add(match)

        for issue_id in sorted(issue_ids):
            tokens.extend(
                [
                    issue_id,
                    f"issues.chromium.org/issues/{issue_id}",
                    f"crbug/{issue_id}",
                    f"bug:{issue_id}",
                ]
            )

        return self._dedupe(tokens)

    def _extract_directory_hierarchy(self, files: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, int]]]:
        directory_counts: dict[str, int] = {}

        for item in files:
            if not isinstance(item, dict):
                continue

            filename = str(item.get("filename", "") or "").strip().strip("/")
            if not filename or "/" not in filename:
                continue

            parts = [part for part in filename.split("/") if part]
            for depth in range(1, len(parts)):
                directory = "/".join(parts[:depth])
                directory_counts[directory] = directory_counts.get(directory, 0) + 1

        ordered_directories = sorted(directory_counts.keys(), key=self._directory_sort_key)
        rows = [{"directory": item, "file_count": int(directory_counts[item])} for item in ordered_directories]
        return ordered_directories, rows

    def _directory_sort_key(self, directory: str) -> tuple[int, str]:
        normalized = str(directory or "").strip().lower()
        return (normalized.count("/"), normalized)

    def _dedupe(self, items: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in items:
            normalized = str(item or "").strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                deduped.append(normalized)
        return deduped
