from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openpyxl import Workbook


def _parse_iso_utc(value: str) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None

    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _days_since(value: str, now_utc: datetime) -> int | str:
    parsed = _parse_iso_utc(value)
    if parsed is None:
        return ""
    return max(0, (now_utc - parsed).days)


def _as_joined_lines(items: list[Any]) -> str:
    return "\n".join(str(item) for item in items if str(item).strip())


def write_enrichment_xlsx(result: dict[str, Any], output_path: str) -> None:
    workbook = Workbook()
    now_utc = datetime.now(timezone.utc)
    cves = result.get("cves", []) or []

    cve_sheet = workbook.active
    cve_sheet.title = "CVEs"
    cve_sheet.append(
        [
            "cve_id",
            "source",
            "title",
            "description",
            "published",
            "updated",
            "match_reason",
            "match_confidence",
            "has_commit",
            "commit_count",
            "max_commit_confidence",
            "references_count",
            "affected_versions_count",
            "days_since_published",
            "nvd_cvss_score",
            "nvd_cvss_vector",
            "nvd_severity",
            "nvd_weaknesses",
            "nvd_cpes",
            "references",
            "affected_versions",
            "commits",
        ]
    )

    for cve in cves:
        commits = cve.get("commits", []) or []
        references = cve.get("references", []) or []
        affected_versions = cve.get("affected_versions", []) or []
        nvd = cve.get("nvd") or {}
        commit_confidences = [
            float(item.get("confidence", 0.0) or 0.0)
            for item in commits
            if isinstance(item, dict)
        ]

        cve_sheet.append(
            [
                cve.get("cve_id", ""),
                cve.get("source", ""),
                cve.get("title", ""),
                cve.get("description", ""),
                cve.get("published", ""),
                cve.get("updated", ""),
                cve.get("match_reason", ""),
                cve.get("match_confidence", 0),
                bool(commits),
                len(commits),
                max(commit_confidences) if commit_confidences else 0.0,
                len(references),
                len(affected_versions),
                _days_since(str(cve.get("published", "") or ""), now_utc),
                nvd.get("cvss_score", "") if isinstance(nvd, dict) else "",
                nvd.get("cvss_vector", "") if isinstance(nvd, dict) else "",
                nvd.get("severity", "") if isinstance(nvd, dict) else "",
                _as_joined_lines(nvd.get("weaknesses", []) if isinstance(nvd, dict) else []),
                _as_joined_lines(nvd.get("cpes", []) if isinstance(nvd, dict) else []),
                _as_joined_lines(references),
                _as_joined_lines(affected_versions),
                _as_joined_lines([
                    f"{item.get('sha', '')} | {item.get('title', '')}"
                    for item in commits
                    if isinstance(item, dict)
                ]),
            ]
        )

    commits_sheet = workbook.create_sheet(title="Commits")
    commits_sheet.append(["cve_id", "sha", "title", "url", "author", "date", "confidence", "source"])
    for cve in cves:
        cve_id = cve.get("cve_id", "")
        for commit in cve.get("commits", []) or []:
            if not isinstance(commit, dict):
                continue
            commits_sheet.append(
                [
                    cve_id,
                    commit.get("sha", ""),
                    commit.get("title", ""),
                    commit.get("url", ""),
                    commit.get("author", ""),
                    commit.get("date", ""),
                    commit.get("confidence", 0),
                    commit.get("source", ""),
                ]
            )

    references_sheet = workbook.create_sheet(title="References")
    references_sheet.append(["cve_id", "reference_url"])
    for cve in cves:
        cve_id = cve.get("cve_id", "")
        for reference in cve.get("references", []) or []:
            references_sheet.append([cve_id, reference])

    warnings_sheet = workbook.create_sheet(title="Warnings")
    warnings_sheet.append(["warning"])
    for warning in result.get("warnings", []) or []:
        warnings_sheet.append([warning])

    metadata_sheet = workbook.create_sheet(title="Metadata")
    metadata_sheet.append(["key", "value"])
    for key in (
        "input_version",
        "compare_base_version",
        "compare_commit_count",
        "source_mode",
        "selected_cve_source",
        "generated_at",
        "candidate_count",
        "matched_count",
    ):
        metadata_sheet.append([key, result.get(key, "")])

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)
