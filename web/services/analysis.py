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
    _SOFT_PATH_HINTS_BY_TOKEN: dict[str, list[str]] = {
        "compositing": [
            "cc/",
            "components/viz/",
            "ui/compositor/",
            "third_party/blink/renderer/platform/graphics/",
            "third_party/blink/renderer/core/paint/",
        ],
        "compositor": ["cc/", "components/viz/", "ui/compositor/"],
        "codec": [
            "media/",
            "third_party/blink/renderer/modules/webcodecs/",
            "third_party/blink/renderer/modules/media/",
            "gpu/command_buffer/",
        ],
        "codecs": [
            "media/",
            "third_party/blink/renderer/modules/webcodecs/",
            "third_party/blink/renderer/modules/media/",
            "gpu/command_buffer/",
        ],
        "encode": ["media/", "third_party/blink/renderer/modules/webcodecs/"],
        "decode": ["media/", "third_party/blink/renderer/modules/webcodecs/"],
        "webgl": ["third_party/blink/renderer/modules/webgl/", "gpu/", "third_party/angle/"],
        "angle": ["third_party/angle/", "gpu/", "third_party/blink/renderer/modules/webgl/"],
        "gpu": ["gpu/", "components/viz/", "third_party/angle/"],
        "skia": ["skia/", "cc/paint/"],
        "pdf": ["components/pdf/", "chrome/browser/pdf/", "pdf/", "third_party/pdfium/", "fpdfsdk/", "core/fpdf"],
        "pdfium": ["components/pdf/", "chrome/browser/pdf/", "pdf/", "third_party/pdfium/", "fpdfsdk/", "core/fpdf"],
        "webusb": ["third_party/blink/renderer/modules/webusb/", "services/device/usb/", "device/usb/"],
        "webmidi": ["third_party/blink/renderer/modules/webmidi/", "media/midi/", "services/device/midi/"],
        "navigation": ["content/browser/", "content/renderer/", "third_party/blink/renderer/core/frame/"],
        "webview": ["android_webview/", "android/"],
        "v8": ["src/compiler/", "src/objects/", "src/heap/", "v8/"],
        "dawn": ["third_party/dawn/", "gpu/", "third_party/blink/renderer/modules/webgpu/"],
        "css": ["third_party/blink/renderer/core/css/", "third_party/blink/renderer/core/style/"],
    }

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
        release_posts, release_warnings, release_cache_meta = release_source.search_stable_desktop_posts_for_cve(
            normalized_cve_id,
            max_results=40,
        )
        selected_log_range, selection_warnings = release_source.select_preferred_log_range(
            release_posts,
            version_hint=payload.version,
        )

        release_security_fixes = self._collect_release_security_fixes(release_posts)
        release_bug_map = self._build_release_bug_map(release_security_fixes)
        release_bug_ids_for_query = sorted(
            [bug_id for bug_id, mapped_cve in release_bug_map.items() if str(mapped_cve).strip().upper() == normalized_cve_id]
        )
        release_focus_keywords = self._infer_release_focus_keywords(
            security_fixes=release_security_fixes,
            cve_id=normalized_cve_id,
        )
        if release_posts and not release_bug_ids_for_query:
            release_warnings.append(
                f"Chrome Releases posts mention {normalized_cve_id}, but no bug IDs were mapped to this CVE from release security rows. "
                "Continuing with broader compare evidence."
            )

        release_blog_payload = {
            "query_cve_id": normalized_cve_id,
            "post_count": len(release_posts),
            "posts": release_posts,
            "selected_log_range": selected_log_range,
            "security_fix_count": len(release_security_fixes),
            "security_fixes": release_security_fixes,
            "query_cve_bug_ids": release_bug_ids_for_query,
            "cache": release_cache_meta,
        }

        patched_version = ""
        unpatched_version = ""
        patched_version_details: dict[str, Any] = {
            "stage": "patched",
            "selected_version": "",
            "confidence_tier": "UNKNOWN",
            "confidence_score": 0.0,
            "source": "",
            "strategy": "",
            "not_provable_reasons": [],
        }
        unpatched_version_details: dict[str, Any] = {
            "stage": "unpatched",
            "selected_version": "",
            "confidence_tier": "UNKNOWN",
            "confidence_score": 0.0,
            "source": "",
            "strategy": "",
            "not_provable_reasons": [],
        }
        patched_provenance: list[str] = []
        patched_warnings: list[str] = []
        predecessor_warnings: list[str] = []

        if isinstance(selected_log_range, dict):
            patched_from_log = self._version_catalog_service.normalize_version(str(selected_log_range.get("head_version", "")))
            unpatched_from_log = self._version_catalog_service.normalize_version(str(selected_log_range.get("base_version", "")))
            if patched_from_log and unpatched_from_log:
                patched_version = patched_from_log
                unpatched_version = unpatched_from_log
                patched_version_details.update(
                    {
                        "selected_version": patched_version,
                        "confidence_tier": "EXACT",
                        "confidence_score": 1.0,
                        "source": "chrome-releases-log-range",
                        "strategy": "selected-log-head-version",
                    }
                )
                unpatched_version_details.update(
                    {
                        "selected_version": unpatched_version,
                        "confidence_tier": "EXACT",
                        "confidence_score": 1.0,
                        "source": "chrome-releases-log-range",
                        "strategy": "selected-log-base-version",
                    }
                )
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

            (
                patched_version,
                patched_provenance_fallback,
                patched_warnings_fallback,
                patched_version_details,
            ) = self._version_catalog_service.resolve_patched_version(
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
            (
                unpatched_version,
                predecessor_warnings,
                unpatched_version_details,
            ) = self._version_catalog_service.find_previous_version(patched_version)
            if not unpatched_version:
                raise ValueError(f"Unable to infer a predecessor version for patched version {patched_version}.")

        auto_keywords = self._merge_keywords(
            infer_focus_keywords(cve_record.title, cve_record.description),
            release_focus_keywords,
        )
        manual_keywords = self._split_keywords(payload.keyword)
        effective_keywords = self._merge_keywords(auto_keywords, manual_keywords)
        soft_path_hints = self._infer_soft_path_hints(
            cve_title=cve_record.title,
            cve_description=cve_record.description,
            keywords=effective_keywords,
        )
        evidence_tokens = self._build_security_evidence_tokens(
            cve_id=normalized_cve_id,
            references=cve_record.references,
            description=cve_record.description,
            extra_issue_ids=release_bug_ids_for_query,
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
            release_bug_map=release_bug_map,
            target_cve_id=normalized_cve_id,
            query_cve_bug_ids=release_bug_ids_for_query,
            soft_path_hints=soft_path_hints,
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
            "patched_version_details": patched_version_details,
            "unpatched_version": unpatched_version,
            "unpatched_version_details": unpatched_version_details,
            "version_resolution": {
                "patched": patched_version_details,
                "unpatched": unpatched_version_details,
                "not_provable": [
                    *[
                        str(item)
                        for item in (patched_version_details.get("not_provable_reasons", []) if isinstance(patched_version_details, dict) else [])
                        if str(item).strip()
                    ],
                    *[
                        str(item)
                        for item in (unpatched_version_details.get("not_provable_reasons", []) if isinstance(unpatched_version_details, dict) else [])
                        if str(item).strip()
                    ],
                ],
            },
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
                "release_keywords": release_focus_keywords,
                "path_hints": soft_path_hints,
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
        predecessor_version, predecessor_warnings, predecessor_details = self._version_catalog_service.find_previous_version(normalized_version)
        if not predecessor_version:
            raise ValueError(f"Unable to infer predecessor for version {normalized_version}.")

        patched_version_details = {
            "stage": "patched",
            "selected_version": normalized_version,
            "confidence_tier": "EXACT",
            "confidence_score": 1.0,
            "source": "user-input-version",
            "strategy": "explicit-version-mode-input",
            "not_provable_reasons": [],
        }

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
            release_bug_map={},
            target_cve_id="",
            query_cve_bug_ids=[],
            soft_path_hints=[],
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
            "patched_version_details": patched_version_details,
            "unpatched_version": predecessor_version,
            "unpatched_version_details": predecessor_details,
            "version_resolution": {
                "patched": patched_version_details,
                "unpatched": predecessor_details,
                "not_provable": [
                    str(item)
                    for item in (predecessor_details.get("not_provable_reasons", []) if isinstance(predecessor_details, dict) else [])
                    if str(item).strip()
                ],
            },
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
                "path_hints": [],
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
        release_bug_map: dict[str, str] | None,
        target_cve_id: str,
        query_cve_bug_ids: list[str] | None,
        soft_path_hints: list[str],
        progress: Callable[[int, str], None],
        start_progress: int,
        end_progress: int,
    ) -> tuple[dict[str, Any], list[str]]:
        warnings: list[str] = []
        component_results: list[dict[str, Any]] = []
        selected_components = self._normalize_components(components or payload.components)
        normalized_release_bug_map = {
            str(bug_id).strip(): str(cve_id).strip().upper()
            for bug_id, cve_id in (release_bug_map or {}).items()
            if str(bug_id).strip() and str(cve_id).strip()
        }
        normalized_target_cve = str(target_cve_id or "").strip().upper()
        normalized_query_bug_ids = sorted(
            {
                re.sub(r"\D", "", str(item or "").strip())
                for item in (query_cve_bug_ids or [])
                if re.sub(r"\D", "", str(item or "").strip())
            }
        )

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

            component_strict_commit_platform = strict_commit_platform
            component_strict_file_platform = strict_file_platform
            if component == CompareComponent.PDFIUM:
                component_strict_commit_platform = False
                component_strict_file_platform = False

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
                soft_path_hints=soft_path_hints,
                strict_commit_platform=component_strict_commit_platform,
                strict_file_platform=component_strict_file_platform,
                soft_file_focus=soft_file_focus,
                min_commit_confidence=min_commit_confidence,
            )

            commits = [asdict(item) for item in compare_payload.get("commits", []) or []]
            strict_bug_scope_requested = bool(normalized_release_bug_map and normalized_target_cve and normalized_query_bug_ids)
            strict_bug_scope_active = strict_bug_scope_requested
            if normalized_release_bug_map and commits:
                self._annotate_release_bug_cve_mappings(commits, normalized_release_bug_map)

                if normalized_target_cve:
                    for commit in commits:
                        mapped_cves = [
                            str(item).strip().upper()
                            for item in (commit.get("mapped_release_cves", []) if isinstance(commit, dict) else [])
                            if str(item).strip()
                        ]
                        commit["matches_query_cve"] = normalized_target_cve in mapped_cves

                    if strict_bug_scope_requested:
                        query_mapped = [
                            commit
                            for commit in commits
                            if isinstance(commit, dict) and bool(commit.get("matches_query_cve", False))
                        ]
                        if query_mapped:
                            commits = query_mapped
                        else:
                            compare_warnings.append(
                                f"No commits in compare range were mapped to release bug IDs for {normalized_target_cve}; "
                                "falling back to full compare diff."
                            )
                            strict_bug_scope_active = False

            matched_bug_ids = sorted(
                {
                    str(bug_id)
                    for commit in commits
                    for bug_id in (commit.get("matched_release_bug_ids", []) if isinstance(commit, dict) else [])
                    if str(bug_id).strip()
                }
            )
            mapped_release_cves = sorted(
                {
                    str(cve_id)
                    for commit in commits
                    for cve_id in (commit.get("mapped_release_cves", []) if isinstance(commit, dict) else [])
                    if str(cve_id).strip()
                }
            )

            files = [item for item in compare_payload.get("files", []) or [] if isinstance(item, dict)]
            if strict_bug_scope_active:
                scoped_shas = [
                    str(commit.get("sha", "") or "").strip()
                    for commit in commits
                    if isinstance(commit, dict) and str(commit.get("sha", "") or "").strip()
                ]
                if scoped_shas:
                    scoped_files, scoped_file_warnings = source.get_files_for_commit_shas(
                        commit_shas=scoped_shas,
                        base_ref=resolved_ref.base_ref,
                        head_ref=resolved_ref.head_ref,
                        component=component,
                    )
                    compare_warnings.extend(scoped_file_warnings)
                    if scoped_files:
                        files = scoped_files
                    else:
                        compare_warnings.append(
                            "Mapped commit file lookup returned no files; falling back to full compare diff files."
                        )
                else:
                    compare_warnings.append(
                        "Mapped commit scope produced no commit SHAs; falling back to full compare diff files."
                    )

            warnings.extend([f"[{component.value}] {item}" for item in compare_warnings])

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
            payload_compare_url = str(compare_payload.get("compare_url", "") or "").strip()
            if payload_compare_url:
                compare_url = payload_compare_url
            elif component_status not in {"unchanged", "error"}:
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
                    "matched_release_bug_ids": matched_bug_ids,
                    "mapped_release_cves": mapped_release_cves,
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
                    "soft_path_hints": list(soft_path_hints),
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
        normalized_components = self._normalize_components(payload.components)
        if payload.minimal_mode and len(normalized_components) == 1 and normalized_components[0] == CompareComponent.CHROME:
            return [CompareComponent.CHROME]
        return normalized_components

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

    def _build_security_evidence_tokens(
        self,
        *,
        cve_id: str,
        references: list[str],
        description: str,
        extra_issue_ids: list[str] | None = None,
    ) -> list[str]:
        tokens = [str(cve_id or "").strip()]
        issue_ids: set[str] = set()

        for ref in references:
            for match in re.findall(r"issues\.chromium\.org/issues/(\d+)", str(ref or "")):
                issue_ids.add(match)
            for match in re.findall(r"crbug\.com/(\d+)", str(ref or "")):
                issue_ids.add(match)

        for match in re.findall(r"(?:crbug|bug)\s*[:#/]?\s*(\d{6,})", str(description or ""), flags=re.IGNORECASE):
            issue_ids.add(match)

        for item in extra_issue_ids or []:
            normalized = re.sub(r"\D", "", str(item or "").strip())
            if re.fullmatch(r"\d{6,}", normalized):
                issue_ids.add(normalized)

        for issue_id in sorted(issue_ids):
            tokens.extend(
                [
                    issue_id,
                    f"issues.chromium.org/issues/{issue_id}",
                    f"crbug.com/{issue_id}",
                    f"crbug/{issue_id}",
                    f"bug:{issue_id}",
                ]
            )

        return self._dedupe(tokens)

    def _infer_release_focus_keywords(self, *, security_fixes: list[dict[str, str]], cve_id: str) -> list[str]:
        target_cve = str(cve_id or "").strip().upper()
        if not target_cve:
            return []

        snippets: list[str] = []
        for item in security_fixes:
            if not isinstance(item, dict):
                continue
            mapped_cve = str(item.get("cve_id", "") or "").strip().upper()
            if mapped_cve != target_cve:
                continue

            title = str(item.get("title", "") or "").strip()
            severity = str(item.get("severity", "") or "").strip()
            if title:
                snippets.append(title)
                if severity:
                    snippets.append(f"{severity} {title}")

        if not snippets:
            return []

        return infer_focus_keywords(" ".join(snippets), "", limit=10)

    def _infer_soft_path_hints(self, *, cve_title: str, cve_description: str, keywords: list[str]) -> list[str]:
        corpus = "\n".join(
            [
                str(cve_title or ""),
                str(cve_description or ""),
                " ".join([str(item or "") for item in (keywords or [])]),
            ]
        ).lower()

        hints: list[str] = []
        for trigger, values in self._SOFT_PATH_HINTS_BY_TOKEN.items():
            if str(trigger).lower() in corpus:
                hints.extend(values)

        normalized_hints = [str(item or "").strip().lower().lstrip("/") for item in hints if str(item or "").strip()]
        return self._dedupe(normalized_hints)

    def _collect_release_security_fixes(self, posts: list[dict[str, Any]]) -> list[dict[str, str]]:
        collected: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        for post in posts:
            if not isinstance(post, dict):
                continue

            post_title = str(post.get("title", "") or "").strip()
            post_url = str(post.get("url", "") or "").strip()

            for item in post.get("security_fixes", []) or []:
                if not isinstance(item, dict):
                    continue

                bug_id = str(item.get("bug_id", "") or "").strip()
                cve_id = str(item.get("cve_id", "") or "").strip().upper()
                title = str(item.get("title", "") or "").strip()
                severity = str(item.get("severity", "") or "").strip().title()
                status_tag = str(item.get("status_tag", "") or "").strip().upper()

                if not bug_id or not cve_id:
                    continue

                dedupe_key = (bug_id, cve_id, title)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                collected.append(
                    {
                        "bug_id": bug_id,
                        "cve_id": cve_id,
                        "severity": severity,
                        "title": title,
                        "status_tag": status_tag,
                        "post_title": post_title,
                        "post_url": post_url,
                    }
                )

        return collected

    def _build_release_bug_map(self, security_fixes: list[dict[str, str]]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        conflicts: set[str] = set()

        for item in security_fixes:
            if not isinstance(item, dict):
                continue

            bug_id = str(item.get("bug_id", "") or "").strip()
            cve_id = str(item.get("cve_id", "") or "").strip().upper()
            if not bug_id or not cve_id:
                continue

            existing = mapping.get(bug_id)
            if existing is None:
                mapping[bug_id] = cve_id
                continue

            if existing != cve_id:
                conflicts.add(bug_id)

        for bug_id in conflicts:
            mapping.pop(bug_id, None)

        return mapping

    def _annotate_release_bug_cve_mappings(self, commits: list[dict[str, Any]], release_bug_map: dict[str, str]) -> None:
        bug_ids = set(str(key).strip() for key in release_bug_map.keys() if str(key).strip())
        if not bug_ids:
            return

        for commit in commits:
            if not isinstance(commit, dict):
                continue

            haystack = (
                f"{str(commit.get('title', '') or '')}\n"
                f"{str(commit.get('message', '') or '')}\n"
                f"{str(commit.get('url', '') or '')}"
            )
            numeric_tokens = set(re.findall(r"\d{6,}", haystack))
            matched_bug_ids = sorted(token for token in numeric_tokens if token in bug_ids)
            mapped_cves = sorted({release_bug_map[token] for token in matched_bug_ids if token in release_bug_map})

            commit["matched_release_bug_ids"] = matched_bug_ids
            commit["mapped_release_cves"] = mapped_cves

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
