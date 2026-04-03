from __future__ import annotations

import re
from typing import Any

from models import CveRecord

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{2,}")

_FOCUS_ALIAS_MAP: dict[str, list[str]] = {
    "webcodecs": ["webcodecs", "codec"],
    "codec": ["codec", "codecs"],
    "webrtc": ["webrtc", "rtc"],
    "pdfium": ["pdfium", "pdf"],
    "skia": ["skia"],
    "v8": ["v8", "javascript"],
    "blink": ["blink", "renderer"],
    "media": ["media", "codec"],
    "gpu": ["gpu", "gl"],
}

_FOCUS_STOPWORDS = {
    "out",
    "bounds",
    "read",
    "write",
    "use",
    "after",
    "free",
    "in",
    "the",
    "and",
    "for",
    "via",
    "from",
    "memory",
    "issue",
    "vulnerability",
    "chrome",
    "chromium",
}


def find_cve_ids(text: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for match in CVE_ID_RE.findall(text):
        normalized = match.upper()
        if normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)
    return ordered


def _dig(payload: Any) -> list[Any]:
    stack = [payload]
    nodes: list[Any] = []
    while stack:
        item = stack.pop()
        nodes.append(item)
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return nodes


def _extract_cve_id(raw: dict[str, Any]) -> str:
    candidates = [
        raw.get("cveMetadata", {}).get("cveId", ""),
        raw.get("id", ""),
        raw.get("cve", {}).get("id", ""),
        raw.get("cve", {}).get("CVE_data_meta", {}).get("ID", ""),
    ]

    for candidate in candidates:
        if isinstance(candidate, str) and CVE_ID_RE.fullmatch(candidate.strip().upper()):
            return candidate.strip().upper()

    text = str(raw)
    found = find_cve_ids(text)
    return found[0] if found else ""


def extract_raw_cve_records(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []

    found: list[dict[str, Any]] = []

    if isinstance(payload, dict):
        for key in ("vulnerabilities", "items", "cveRecords", "records", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        found.append(item)

        if _extract_cve_id(payload):
            found.append(payload)

    for node in _dig(payload):
        if isinstance(node, dict) and _extract_cve_id(node):
            found.append(node)

    unique: dict[str, dict[str, Any]] = {}
    for record in found:
        cve_id = _extract_cve_id(record)
        if cve_id and cve_id not in unique:
            unique[cve_id] = record

    return list(unique.values())


def _extract_descriptions(raw: dict[str, Any]) -> list[str]:
    descriptions: list[str] = []

    cna = raw.get("containers", {}).get("cna", {})
    for item in cna.get("descriptions", []) or []:
        value = item.get("value", "") if isinstance(item, dict) else ""
        if value:
            descriptions.append(value.strip())

    adp_entries = raw.get("containers", {}).get("adp", []) or []
    for adp in adp_entries:
        for item in adp.get("descriptions", []) or []:
            value = item.get("value", "") if isinstance(item, dict) else ""
            if value:
                descriptions.append(value.strip())

    for item in raw.get("descriptions", []) or []:
        if isinstance(item, dict):
            value = item.get("value", "")
            if value:
                descriptions.append(value.strip())

    nvd_cve = raw.get("cve", {})
    for item in nvd_cve.get("descriptions", []) or []:
        if isinstance(item, dict):
            value = item.get("value", "")
            if value:
                descriptions.append(value.strip())

    if not descriptions:
        fallback = raw.get("description", "")
        if isinstance(fallback, str) and fallback.strip():
            descriptions.append(fallback.strip())

    return descriptions


def _extract_references(raw: dict[str, Any]) -> list[str]:
    refs: list[str] = []

    cna = raw.get("containers", {}).get("cna", {})
    for item in cna.get("references", []) or []:
        if isinstance(item, dict) and item.get("url"):
            refs.append(item["url"])

    adp_entries = raw.get("containers", {}).get("adp", []) or []
    for adp in adp_entries:
        for item in adp.get("references", []) or []:
            if isinstance(item, dict) and item.get("url"):
                refs.append(item["url"])

    for item in raw.get("references", []) or []:
        if isinstance(item, dict) and item.get("url"):
            refs.append(item["url"])

    nvd_cve = raw.get("cve", {})
    for item in nvd_cve.get("references", []) or []:
        if isinstance(item, dict) and item.get("url"):
            refs.append(item["url"])

    unique: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            unique.append(ref)
    return unique


def _extract_affected_versions(raw: dict[str, Any]) -> list[str]:
    versions: list[str] = []

    cna = raw.get("containers", {}).get("cna", {})
    for affected in cna.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        for version in affected.get("versions", []) or []:
            if not isinstance(version, dict):
                continue
            value = version.get("version", "")
            less_than = version.get("lessThan")
            less_equal = version.get("lessThanOrEqual")
            status = version.get("status")
            if value:
                versions.append(str(value))
            if less_than:
                versions.append(f"<{less_than}")
            if less_equal:
                versions.append(f"<={less_equal}")
            if status:
                versions.append(f"status:{status}")

    unique: list[str] = []
    seen: set[str] = set()
    for version in versions:
        if version not in seen:
            seen.add(version)
            unique.append(version)
    return unique


def normalize_cve_record(raw: dict[str, Any], source: str) -> CveRecord | None:
    cve_id = _extract_cve_id(raw)
    if not cve_id:
        return None

    descriptions = _extract_descriptions(raw)
    description = descriptions[0] if descriptions else ""

    cve_metadata = raw.get("cveMetadata", {}) if isinstance(raw.get("cveMetadata"), dict) else {}
    published = cve_metadata.get("datePublished") or raw.get("published") or raw.get("datePublished") or raw.get("cve", {}).get("published") or ""
    updated = cve_metadata.get("dateUpdated") or raw.get("updated") or raw.get("dateUpdated") or raw.get("cve", {}).get("lastModified") or ""

    title = raw.get("title", "")
    if not title:
        title = description[:120]

    return CveRecord(
        cve_id=cve_id,
        source=source,
        title=title,
        description=description,
        published=str(published) if published else "",
        updated=str(updated) if updated else "",
        references=_extract_references(raw),
        affected_versions=_extract_affected_versions(raw),
        raw=raw,
    )


def infer_focus_keywords(title: str, description: str, limit: int = 8) -> list[str]:
    combined = f"{str(title or '').strip()}\n{str(description or '').strip()}"
    lowered = combined.lower()

    collected: list[str] = []
    seen: set[str] = set()

    def _add(token: str) -> None:
        normalized = str(token or "").strip().lower()
        if not normalized:
            return
        if normalized in _FOCUS_STOPWORDS:
            return
        if normalized in seen:
            return
        seen.add(normalized)
        collected.append(normalized)

    for trigger, aliases in _FOCUS_ALIAS_MAP.items():
        if trigger in lowered:
            for alias in aliases:
                _add(alias)

    for token in _TOKEN_RE.findall(str(title or "")):
        _add(token)

    if not collected:
        for token in _TOKEN_RE.findall(str(description or "")):
            _add(token)
            if len(collected) >= limit:
                break

    return collected[:limit]
