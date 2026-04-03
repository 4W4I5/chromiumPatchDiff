from __future__ import annotations

import difflib
import re
import threading
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from clients.http_client import HttpClient
from exporters.docx_exporter import build_analysis_docx
from web.schemas import (
    AnalysisRequest,
    CveLookupResponse,
    DocxReportRequest,
    JobCreateResponse,
    JobStatusResponse,
    SourceFileContentRequest,
    SourceFileContentResponse,
    VersionsResponse,
)

router = APIRouter(prefix="/api", tags=["api"])


@router.post("/jobs", response_model=JobCreateResponse)
def create_analysis_job(payload: AnalysisRequest, request: Request) -> JobCreateResponse:
    job_store = request.app.state.job_store
    analysis_service = request.app.state.analysis_service
    record = job_store.create_job("Queued analysis job")

    def _update(progress_value: int, message: str) -> None:
        job_store.update(
            record.job_id,
            status="running",
            progress=max(0, min(100, int(progress_value))),
            message=message,
        )

    def _worker() -> None:
        try:
            _update(3, "Starting job")
            result = analysis_service.run_analysis(payload, _update)
            job_store.complete(record.job_id, result)
        except Exception as exc:
            job_store.fail(record.job_id, str(exc))

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()

    return JobCreateResponse(job_id=record.job_id, status=record.status)


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
def get_job(job_id: str, request: Request) -> JobStatusResponse:
    job_store = request.app.state.job_store
    record = job_store.get(job_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

    payload = job_store.to_dict(record)
    return JobStatusResponse(**payload)


@router.post("/jobs/{job_id}/files/content", response_model=SourceFileContentResponse)
def get_job_file_content(job_id: str, payload: SourceFileContentRequest, request: Request) -> SourceFileContentResponse:
    job_store = request.app.state.job_store
    config = request.app.state.config

    if not config.source_content_enabled:
        raise HTTPException(status_code=400, detail="Source-content retrieval is disabled by configuration.")

    record = job_store.get(job_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    if record.status != "completed" or not isinstance(record.result, dict):
        raise HTTPException(status_code=400, detail="Job has not completed successfully yet.")

    compare = record.result.get("compare", {}) if isinstance(record.result.get("compare"), dict) else {}
    resolved = _find_compare_file(compare, payload.file_key)
    if resolved is None:
        raise HTTPException(status_code=404, detail=f"Matched compare file not found for key: {payload.file_key}")

    component_item, file_item = resolved
    repo = str(component_item.get("repo", "") or "").strip()
    filename = str(file_item.get("filename", "") or "").strip()
    base_version = str(compare.get("base_version", "") or "").strip()
    head_version = str(compare.get("head_version", "") or "").strip()

    if not repo or not filename or not base_version or not head_version:
        raise HTTPException(status_code=400, detail="Compare payload is missing repo/path/version metadata for this file.")

    base_url = str(file_item.get("base_raw_url", "") or "").strip() or _build_raw_url(repo, base_version, filename)
    head_url = str(file_item.get("head_raw_url", "") or "").strip() or _build_raw_url(repo, head_version, filename)

    cache = request.app.state.source_content_cache
    http = HttpClient(config)
    warnings: list[str] = []

    base_content, base_warnings = _load_text_content(
        http=http,
        cache=cache,
        cache_key=f"source-content:{repo}:{base_version}:{filename}",
        url=base_url,
        max_bytes=config.source_content_max_bytes,
        ttl_seconds=config.source_content_cache_ttl_seconds,
    )
    head_content, head_warnings = _load_text_content(
        http=http,
        cache=cache,
        cache_key=f"source-content:{repo}:{head_version}:{filename}",
        url=head_url,
        max_bytes=config.source_content_max_bytes,
        ttl_seconds=config.source_content_cache_ttl_seconds,
    )

    warnings.extend(base_warnings)
    warnings.extend(head_warnings)

    if not base_content and not head_content:
        detail = warnings[0] if warnings else "Could not load source content for selected file."
        raise HTTPException(status_code=502, detail=detail)

    diff_lines = list(
        difflib.unified_diff(
            base_content.splitlines(),
            head_content.splitlines(),
            fromfile=f"{filename}@{base_version}",
            tofile=f"{filename}@{head_version}",
            n=3,
            lineterm="",
        )
    )
    if len(diff_lines) > payload.max_diff_lines:
        diff_lines = diff_lines[: payload.max_diff_lines]
        diff_lines.append("... diff preview truncated ...")

    return SourceFileContentResponse(
        file_key=payload.file_key,
        component=str(component_item.get("component", "") or ""),
        repo=repo,
        filename=filename,
        base_version=base_version,
        head_version=head_version,
        base_content=base_content,
        head_content=head_content,
        unified_diff_preview="\n".join(diff_lines),
        warnings=_dedupe(warnings),
    )


@router.get("/versions", response_model=VersionsResponse)
def list_versions(request: Request, limit: int = 0) -> VersionsResponse:
    version_catalog = request.app.state.version_catalog_service
    versions, warnings = version_catalog.list_versions(limit=limit if limit > 0 else None)
    return VersionsResponse(versions=versions, warnings=warnings)


@router.get("/cve/{cve_id}", response_model=CveLookupResponse)
def get_cve(cve_id: str, request: Request, include_nvd: bool = True) -> CveLookupResponse:
    cve_service = request.app.state.cve_enrichment_service
    record, warnings, provenance = cve_service.get_cve_snapshot(cve_id, include_nvd=include_nvd)

    return CveLookupResponse(
        cve_id=cve_id.upper(),
        found=record is not None,
        warnings=warnings,
        provenance=provenance,
        record=record,
    )


@router.post("/reports/docx")
def generate_docx(payload: DocxReportRequest, request: Request) -> Response:
    job_store = request.app.state.job_store
    analysis_service = request.app.state.analysis_service
    record = job_store.get(payload.job_id)

    if record is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {payload.job_id}")
    if record.status != "completed" or not isinstance(record.result, dict):
        raise HTTPException(status_code=400, detail="Job has not completed successfully yet.")

    result_payload = record.result
    try:
        result_payload = analysis_service.enrich_result_for_docx(result_payload)
    except Exception as exc:
        warnings = [str(item) for item in (result_payload.get("warnings") or []) if str(item).strip()]
        warnings.append(f"DOCX enrichment warning: {exc}")
        result_payload["warnings"] = _dedupe(warnings)

    record.result = result_payload
    docx_bytes = build_analysis_docx(result_payload)
    file_name = _sanitize_file_name(payload.file_name) or "chromium_patch_diff_report.docx"

    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": f'attachment; filename="{file_name}"',
        },
    )


def _sanitize_file_name(file_name: str) -> str:
    trimmed = str(file_name or "").strip()
    if not trimmed:
        return ""

    lowered = trimmed.lower()
    if not lowered.endswith(".docx"):
        trimmed = f"{trimmed}.docx"

    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", trimmed)
    return safe[:128]


def _find_compare_file(compare: dict[str, Any], file_key: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    target = str(file_key or "").strip()
    if not target:
        return None

    for component_item in compare.get("components", []) or []:
        if not isinstance(component_item, dict):
            continue
        for file_item in component_item.get("files", []) or []:
            if not isinstance(file_item, dict):
                continue
            if str(file_item.get("file_key", "") or "").strip() == target:
                return component_item, file_item

    return None


def _build_raw_url(repo: str, ref: str, filename: str) -> str:
    safe_repo = str(repo or "").strip().strip("/")
    safe_ref = quote(str(ref or "").strip(), safe="")
    safe_filename = quote(str(filename or "").strip().lstrip("/"), safe="/")
    if not safe_repo or not safe_ref or not safe_filename:
        return ""
    return f"https://raw.githubusercontent.com/{safe_repo}/{safe_ref}/{safe_filename}"


def _load_text_content(
    *,
    http: HttpClient,
    cache: Any,
    cache_key: str,
    url: str,
    max_bytes: int,
    ttl_seconds: int,
) -> tuple[str, list[str]]:
    warnings: list[str] = []

    if not url:
        return "", ["Source URL is empty for selected file."]

    cached = cache.get(cache_key) if cache is not None else None
    if isinstance(cached, str):
        return cached, warnings

    status, payload, headers, error = http.try_get_bytes(url, headers={"Accept": "text/plain, */*"})
    if status >= 400:
        return "", [f"Source fetch failed ({status}) for {url}: {error}"]

    content_type = str((headers or {}).get("Content-Type", "") or "").lower()
    if content_type and not any(marker in content_type for marker in ("text", "json", "javascript", "xml", "x-c", "x-c++")):
        return "", [f"Rejected non-text content type '{content_type}' for {url}."]

    size = len(payload)
    if size > max_bytes:
        return "", [f"Rejected source content larger than configured limit ({size} > {max_bytes} bytes) for {url}."]

    if _is_probably_binary(payload):
        return "", [f"Rejected probable binary content for {url}."]

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = payload.decode("utf-8", errors="replace")
        warnings.append(f"Source content required UTF-8 replacement decoding for {url}.")

    if cache is not None:
        cache.set(cache_key, text, ttl_seconds=ttl_seconds)

    return text, warnings


def _is_probably_binary(payload: bytes) -> bool:
    if not payload:
        return False
    if b"\x00" in payload:
        return True

    sample = payload[:2048]
    printable = sum(1 for value in sample if value in (9, 10, 13) or 32 <= value <= 126)
    ratio = printable / max(1, len(sample))
    return ratio < 0.70


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        normalized = str(item or "").strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped
