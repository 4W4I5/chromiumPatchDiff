from __future__ import annotations

from io import BytesIO
from typing import Any

from docx import Document
from docx.shared import Pt


def build_analysis_docx(result: dict[str, Any]) -> bytes:
    document = Document()
    document.add_heading("Chromium Patch Diff Analysis Report", level=0)
    document.add_paragraph(f"Generated at: {result.get('generated_at', '')}")

    _add_executive_summary(document, result)
    _add_cve_details(document, result)
    _add_release_blog_details(document, result)
    _add_commit_evidence(document, result)
    _add_filtered_diff_summary(document, result)
    _add_patch_appendix(document, result)
    _add_warnings_and_provenance(document, result)

    output = BytesIO()
    document.save(output)
    return output.getvalue()


def _add_executive_summary(document: Document, result: dict[str, Any]) -> None:
    document.add_heading("Executive Summary", level=1)

    input_payload = result.get("input", {}) if isinstance(result.get("input"), dict) else {}
    summary_rows = [
        ("Input mode", str(result.get("input_mode", ""))),
        ("CVE ID", str(input_payload.get("cve_id", ""))),
        ("Version input", str(input_payload.get("version", input_payload.get("version_hint", "")))),
        ("Patched version", str(result.get("patched_version", ""))),
        ("Unpatched version", str(result.get("unpatched_version", ""))),
        ("Platform", str(input_payload.get("platform", ""))),
        ("Components", ", ".join(input_payload.get("components", []) or [])),
    ]

    _add_key_value_table(document, summary_rows)


def _add_cve_details(document: Document, result: dict[str, Any]) -> None:
    cve_payload = result.get("cve")
    if not isinstance(cve_payload, dict):
        cve_payload = (result.get("primary_cve") if isinstance(result.get("primary_cve"), dict) else None)

    if not isinstance(cve_payload, dict):
        cves = (result.get("enrichment", {}) if isinstance(result.get("enrichment"), dict) else {}).get("cves", [])
        if isinstance(cves, list) and cves:
            cve_payload = cves[0] if isinstance(cves[0], dict) else None

    document.add_heading("CVE Enrichment Details", level=1)

    if not isinstance(cve_payload, dict):
        document.add_paragraph("No CVE detail payload was available for this run.")
        return

    detail_rows = [
        ("CVE ID", str(cve_payload.get("cve_id", ""))),
        ("Source", str(cve_payload.get("source", ""))),
        ("Published", str(cve_payload.get("published", ""))),
        ("Updated", str(cve_payload.get("updated", ""))),
        ("Match reason", str(cve_payload.get("match_reason", ""))),
        ("Match confidence", str(cve_payload.get("match_confidence", ""))),
        ("NVD severity", str((cve_payload.get("nvd") or {}).get("severity", ""))),
        ("NVD CVSS", str((cve_payload.get("nvd") or {}).get("cvss_score", ""))),
    ]
    _add_key_value_table(document, detail_rows)

    if cve_payload.get("title"):
        document.add_paragraph(f"Title: {cve_payload.get('title', '')}")

    if cve_payload.get("description"):
        document.add_paragraph("Description:")
        document.add_paragraph(str(cve_payload.get("description", "")))

    references = cve_payload.get("references", []) or []
    if references:
        document.add_paragraph("References:")
        for item in references:
            document.add_paragraph(str(item), style="List Bullet")

    affected_versions = cve_payload.get("affected_versions", []) or []
    if affected_versions:
        document.add_paragraph("Affected version hints:")
        for item in affected_versions:
            document.add_paragraph(str(item), style="List Bullet")

    weaknesses = (cve_payload.get("nvd") or {}).get("weaknesses", []) or []
    if weaknesses:
        document.add_paragraph("NVD weaknesses:")
        for item in weaknesses:
            document.add_paragraph(str(item), style="List Bullet")


def _add_release_blog_details(document: Document, result: dict[str, Any]) -> None:
    document.add_heading("Chrome Releases Blog Matches", level=1)

    release_blog = result.get("release_blog") if isinstance(result.get("release_blog"), dict) else {}
    posts = release_blog.get("posts", []) if isinstance(release_blog.get("posts"), list) else []
    selected = release_blog.get("selected_log_range") if isinstance(release_blog.get("selected_log_range"), dict) else {}

    selected_range = ""
    if isinstance(selected, dict):
        base_version = str(selected.get("base_version", ""))
        head_version = str(selected.get("head_version", ""))
        if base_version and head_version:
            selected_range = f"{base_version}..{head_version}"

    summary_rows = [
        ("Query CVE", str(release_blog.get("query_cve_id", ""))),
        ("Matched post count", str(len(posts))),
        ("Selected log range", selected_range or "(none)"),
        ("Selected post", str(selected.get("post_title", "") if isinstance(selected, dict) else "")),
    ]
    _add_key_value_table(document, summary_rows)

    if isinstance(selected, dict) and selected.get("log_url"):
        document.add_paragraph(f"Selected log URL: {selected.get('log_url', '')}")

    if not posts:
        document.add_paragraph("No Stable Desktop Chrome Releases post matched this CVE lookup.")
        return

    for post in posts:
        if not isinstance(post, dict):
            continue

        title = str(post.get("title", "")).strip() or "Chrome release post"
        document.add_heading(title, level=2)

        post_rows = [
            ("Post URL", str(post.get("url", ""))),
            ("Published", str(post.get("published", ""))),
            ("Updated", str(post.get("updated", ""))),
            ("Matched CVEs", ", ".join(post.get("matched_cves", []) or [])),
        ]
        _add_key_value_table(document, post_rows)

        log_links = post.get("log_links", []) or []
        if log_links:
            document.add_paragraph("Log links:")
            for item in log_links:
                if not isinstance(item, dict):
                    continue
                base = str(item.get("base_version", ""))
                head = str(item.get("head_version", ""))
                range_label = f"{base}..{head}" if base and head else "range-unparsed"
                document.add_paragraph(f"{range_label}: {item.get('url', '')}", style="List Bullet")


def _add_commit_evidence(document: Document, result: dict[str, Any]) -> None:
    document.add_heading("Commit Evidence", level=1)
    commits = _collect_commit_rows(result)

    if not commits:
        document.add_paragraph("No commit evidence was found for this analysis.")
        return

    table = document.add_table(rows=1, cols=5)
    header_cells = table.rows[0].cells
    header_cells[0].text = "Component"
    header_cells[1].text = "SHA"
    header_cells[2].text = "Title"
    header_cells[3].text = "URL"
    header_cells[4].text = "Confidence"

    for row in commits:
        cells = table.add_row().cells
        cells[0].text = row.get("component", "")
        cells[1].text = row.get("sha", "")
        cells[2].text = row.get("title", "")
        cells[3].text = row.get("url", "")
        cells[4].text = row.get("confidence", "")


def _add_filtered_diff_summary(document: Document, result: dict[str, Any]) -> None:
    document.add_heading("Filtered File Diff Summary", level=1)

    compare = result.get("compare", {}) if isinstance(result.get("compare"), dict) else {}
    filters = compare.get("filters", {}) if isinstance(compare.get("filters"), dict) else {}

    filter_rows = [
        ("Path prefixes", ", ".join(filters.get("path_prefixes", []) or []) or "(none)"),
        ("File extensions", ", ".join(filters.get("file_extensions", []) or []) or "(none)"),
        ("Keyword", str(filters.get("keyword", "") or "(none)")),
        ("Platform", str(compare.get("platform", ""))),
        ("Total components", str(compare.get("total_component_count", 0))),
        ("Total commits", str(compare.get("total_commit_count", 0))),
        ("Total files", str(compare.get("total_file_count", 0))),
        ("Directory filter options", str(len(compare.get("available_directories", []) or []))),
    ]
    _add_key_value_table(document, filter_rows)

    directory_counts = compare.get("directory_file_counts", []) or []
    if directory_counts:
        document.add_paragraph("Directory taxonomy from filtered files:")
        table = document.add_table(rows=1, cols=2)
        table.rows[0].cells[0].text = "Directory"
        table.rows[0].cells[1].text = "File count"
        for row_item in directory_counts:
            if not isinstance(row_item, dict):
                continue
            row = table.add_row().cells
            row[0].text = str(row_item.get("directory", ""))
            row[1].text = str(row_item.get("file_count", 0))

    components = compare.get("components", []) or []
    for component_result in components:
        if not isinstance(component_result, dict):
            continue

        component_name = str(component_result.get("component", "")).strip() or "unknown"
        document.add_heading(f"Component: {component_name}", level=2)

        component_rows = [
            ("Repo", str(component_result.get("repo", ""))),
            ("Compare URL", str(component_result.get("compare_url", ""))),
            ("Commit count", str(component_result.get("commit_count", 0))),
            ("File count", str(component_result.get("file_count", 0))),
            ("Truncated", str((component_result.get("compare_meta") or {}).get("truncated", False))),
        ]
        _add_key_value_table(document, component_rows)

        files = component_result.get("files", []) or []
        if files:
            table = document.add_table(rows=1, cols=5)
            table.rows[0].cells[0].text = "Filename"
            table.rows[0].cells[1].text = "Status"
            table.rows[0].cells[2].text = "Additions"
            table.rows[0].cells[3].text = "Deletions"
            table.rows[0].cells[4].text = "Changes"

            for file_item in files:
                if not isinstance(file_item, dict):
                    continue
                row = table.add_row().cells
                row[0].text = str(file_item.get("filename", ""))
                row[1].text = str(file_item.get("status", ""))
                row[2].text = str(file_item.get("additions", 0))
                row[3].text = str(file_item.get("deletions", 0))
                row[4].text = str(file_item.get("changes", 0))


def _add_patch_appendix(document: Document, result: dict[str, Any]) -> None:
    document.add_heading("Full Patch Text Appendix", level=1)

    compare = result.get("compare", {}) if isinstance(result.get("compare"), dict) else {}
    components = compare.get("components", []) or []

    has_patch = False
    for component_result in components:
        if not isinstance(component_result, dict):
            continue

        component_name = str(component_result.get("component", "")).strip() or "unknown"
        files = component_result.get("files", []) or []

        for file_item in files:
            if not isinstance(file_item, dict):
                continue

            patch_text = str(file_item.get("patch", "") or "")
            filename = str(file_item.get("filename", "") or "")
            if not patch_text:
                continue

            has_patch = True
            document.add_heading(f"{component_name}: {filename}", level=2)

            paragraph = document.add_paragraph()
            run = paragraph.add_run(patch_text)
            run.font.name = "Consolas"
            run.font.size = Pt(8)

    if not has_patch:
        document.add_paragraph("No textual patch data was returned by the compare sources for this analysis.")


def _add_warnings_and_provenance(document: Document, result: dict[str, Any]) -> None:
    document.add_heading("Warnings and Data Source Provenance", level=1)

    warnings = result.get("warnings", []) or []
    if warnings:
        document.add_paragraph("Warnings:")
        for item in warnings:
            document.add_paragraph(str(item), style="List Bullet")
    else:
        document.add_paragraph("Warnings: none")

    provenance = result.get("provenance", []) or []
    if provenance:
        document.add_paragraph("Provenance:")
        for item in provenance:
            document.add_paragraph(str(item), style="List Bullet")


def _collect_commit_rows(result: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    cve = result.get("cve") if isinstance(result.get("cve"), dict) else None
    if isinstance(cve, dict):
        for commit in cve.get("commits", []) or []:
            if not isinstance(commit, dict):
                continue
            rows.append(
                {
                    "component": "cve-linked",
                    "sha": str(commit.get("sha", "")),
                    "title": str(commit.get("title", "")),
                    "url": str(commit.get("url", "")),
                    "confidence": str(commit.get("confidence", "")),
                }
            )

    compare = result.get("compare", {}) if isinstance(result.get("compare"), dict) else {}
    for component_result in compare.get("components", []) or []:
        if not isinstance(component_result, dict):
            continue
        component_name = str(component_result.get("component", "")).strip() or "unknown"
        for commit in component_result.get("commits", []) or []:
            if not isinstance(commit, dict):
                continue
            rows.append(
                {
                    "component": component_name,
                    "sha": str(commit.get("sha", "")),
                    "title": str(commit.get("title", "")),
                    "url": str(commit.get("url", "")),
                    "confidence": str(commit.get("confidence", "")),
                }
            )

    return rows


def _add_key_value_table(document: Document, rows: list[tuple[str, str]]) -> None:
    table = document.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "Field"
    table.rows[0].cells[1].text = "Value"

    for key, value in rows:
        row = table.add_row().cells
        row[0].text = str(key)
        row[1].text = str(value)
