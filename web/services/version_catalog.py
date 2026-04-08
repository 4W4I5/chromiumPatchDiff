from __future__ import annotations

import re
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from chrome import Chrome
from clients.http_client import HttpClient
from config import PipelineConfig, ReleaseChannel
from sources.chromium_source import ChromiumMirrorSource
from sources.chromiumdash_source import ChromiumDashSource


class VersionCatalogService:
    def __init__(self, config: PipelineConfig, cache_ttl_seconds: int = 1800):
        self._config = config
        self._cache_ttl_seconds = max(60, int(cache_ttl_seconds))
        self._cache_expires_at: datetime | None = None
        self._cached_versions: list[str] = []
        self._cached_releases: list[dict[str, Any]] = []
        self._cached_warnings: list[str] = []
        self._cached_source_versions: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def normalize_version(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""

        try:
            return Chrome(raw).getVersion()
        except ValueError:
            matched = re.search(r"\d+\.\d+\.\d+\.\d+", raw)
            return matched.group(0) if matched else raw

    def list_versions(self, limit: int | None = None) -> tuple[list[str], list[str]]:
        versions, _, warnings, _ = self.get_catalog()
        if limit is not None and limit > 0:
            return versions[:limit], warnings
        return versions, warnings

    def get_catalog(self, *, force_refresh: bool = False) -> tuple[list[str], list[dict[str, Any]], list[str], dict[str, set[str]]]:
        with self._lock:
            now = datetime.now(timezone.utc)
            if not force_refresh and self._cache_expires_at is not None and now < self._cache_expires_at:
                return (
                    list(self._cached_versions),
                    list(self._cached_releases),
                    list(self._cached_warnings),
                    {key: set(value) for key, value in self._cached_source_versions.items()},
                )

            http = HttpClient(self._config)
            dash_source = ChromiumDashSource(http, self._config)
            dash_versions, dash_releases, dash_warnings = dash_source.fetch_stable_extended_versions(platform="Windows")

            googlesource_versions, googlesource_warnings = self._fetch_versions_from_googlesource(http)

            github_config = replace(self._config)
            github_config.github_min_request_interval_seconds = min(
                max(0.0, float(github_config.github_min_request_interval_seconds)),
                0.8,
            )
            github_max_pages = 3 if not github_config.github_token else 8

            mirror_source = ChromiumMirrorSource(HttpClient(github_config), github_config)
            github_versions, github_warnings = mirror_source.list_version_tags(
                repo="chromium/chromium",
                release_channel=ReleaseChannel.STABLE,
                max_pages=github_max_pages,
                per_page=100,
            )

            merged_versions = set(dash_versions)
            merged_versions.update(googlesource_versions)
            merged_versions.update(github_versions)

            warnings: list[str] = []
            warnings.extend(dash_warnings)
            warnings.extend(googlesource_warnings)
            warnings.extend(github_warnings)

            sorted_versions = sorted(merged_versions, key=self._version_sort_key, reverse=True)
            source_versions = {
                "chromiumdash": set(dash_versions),
                "chromium_tags": set(googlesource_versions),
                "github_tags": set(github_versions),
            }

            self._cached_versions = list(sorted_versions)
            self._cached_releases = list(dash_releases)
            self._cached_warnings = list(dict.fromkeys(warnings))
            self._cached_source_versions = source_versions
            self._cache_expires_at = now + timedelta(seconds=self._cache_ttl_seconds)

            return (
                list(self._cached_versions),
                list(self._cached_releases),
                list(self._cached_warnings),
                {key: set(value) for key, value in self._cached_source_versions.items()},
            )

    def resolve_patched_version(
        self,
        candidates: list[str],
        *,
        published: str = "",
        updated: str = "",
    ) -> tuple[str, list[str], list[str], dict[str, Any]]:
        versions, releases, warnings, source_versions = self.get_catalog()
        provenance: list[str] = []
        local_warnings: list[str] = list(warnings)
        confidence_enabled = bool(self._config.enable_version_confidence_tiers)

        normalized_candidates = self._normalize_candidate_versions(candidates)
        details = self._build_resolution_details(
            stage="patched",
            candidates=normalized_candidates,
            catalog_versions=versions,
            source_versions=source_versions,
        )

        for candidate in normalized_candidates:
            if candidate in versions:
                provenance.append(f"Patched version resolved from CVE data and validated in merged catalog: {candidate}")
                details.update(
                    {
                        "selected_version": candidate,
                        "confidence_tier": "HIGH" if confidence_enabled else "LEGACY",
                        "confidence_score": 0.95,
                        "source": "merged-version-catalog",
                        "strategy": "candidate-present-in-merged-catalog",
                    }
                )
                return candidate, provenance, local_warnings, details

            if candidate in source_versions.get("chromium_tags", set()) or candidate in source_versions.get("github_tags", set()):
                provenance.append(
                    f"Patched version resolved from CVE data and confirmed by Chromium/GitHub tags even when absent in ChromiumDash: {candidate}"
                )
                local_warnings.append(
                    f"ChromiumDash stable/extended did not include patched candidate {candidate}; accepted from tag sources per fallback policy."
                )
                details.update(
                    {
                        "selected_version": candidate,
                        "confidence_tier": "MEDIUM" if confidence_enabled else "LEGACY",
                        "confidence_score": 0.75,
                        "source": "chromium-or-github-tags",
                        "strategy": "candidate-present-in-tag-sources",
                    }
                )
                return candidate, provenance, local_warnings, details

        if releases:
            dash_source = ChromiumDashSource(HttpClient(self._config), self._config)
            nearest = dash_source.choose_nearest_release_version(releases, published=published, updated=updated)
            if nearest:
                provenance.append(f"Patched version inferred from ChromiumDash release timeline: {nearest}")
                local_warnings.append(
                    "Patched version inferred heuristically from release dates because explicit CVE patched boundary could not be confirmed."
                )
                details.update(
                    {
                        "selected_version": nearest,
                        "confidence_tier": "LOW" if confidence_enabled else "LEGACY",
                        "confidence_score": 0.5,
                        "source": "chromiumdash-release-timeline",
                        "strategy": "nearest-release-by-date",
                    }
                )
                return nearest, provenance, local_warnings, details

        local_warnings.append("Unable to resolve patched Chromium version from CVE metadata or release sources.")
        details["not_provable_reasons"].append("No patched boundary candidate was verifiable from catalogs/tags/release timeline.")
        return "", provenance, local_warnings, details

    def find_previous_version(self, patched_version: str) -> tuple[str, list[str], dict[str, Any]]:
        normalized_patched = self.normalize_version(patched_version)
        versions, _, warnings, _ = self.get_catalog()
        confidence_enabled = bool(self._config.enable_version_confidence_tiers)
        details = {
            "stage": "unpatched",
            "input_version": normalized_patched,
            "selected_version": "",
            "confidence_tier": "UNKNOWN",
            "confidence_score": 0.0,
            "source": "merged-version-catalog",
            "strategy": "",
            "not_provable_reasons": [],
        }

        if not normalized_patched:
            details["not_provable_reasons"].append("Patched version is empty after normalization.")
            return "", ["Patched version is empty after normalization."], details

        lower_versions = [version for version in versions if self._compare_versions(version, normalized_patched) < 0]
        if not lower_versions:
            details["not_provable_reasons"].append(f"No version lower than patched version {normalized_patched} was found.")
            return "", warnings + [f"No version lower than patched version {normalized_patched} was found."], details

        patched_parts = normalized_patched.split(".")
        branch_build_prefix = ".".join(patched_parts[:3])
        branch_minor_prefix = ".".join(patched_parts[:2])

        same_build = [version for version in lower_versions if version.startswith(f"{branch_build_prefix}.")]
        if same_build:
            selected = max(same_build, key=self._version_sort_key)
            details.update(
                {
                    "selected_version": selected,
                    "confidence_tier": "MEDIUM" if confidence_enabled else "LEGACY",
                    "confidence_score": 0.65,
                    "strategy": "same-major-minor-build-predecessor",
                }
            )
            return selected, warnings, details

        same_branch = [version for version in lower_versions if version.startswith(f"{branch_minor_prefix}.")]
        if same_branch:
            selected = max(same_branch, key=self._version_sort_key)
            details.update(
                {
                    "selected_version": selected,
                    "confidence_tier": "LOW" if confidence_enabled else "LEGACY",
                    "confidence_score": 0.55,
                    "strategy": "same-major-minor-predecessor",
                }
            )
            return selected, warnings, details

        selected = max(lower_versions, key=self._version_sort_key)
        details.update(
            {
                "selected_version": selected,
                "confidence_tier": "LOW" if confidence_enabled else "LEGACY",
                "confidence_score": 0.45,
                "strategy": "global-highest-lower-version",
            }
        )
        return selected, warnings, details

    def _build_resolution_details(
        self,
        *,
        stage: str,
        candidates: list[str],
        catalog_versions: list[str],
        source_versions: dict[str, set[str]],
    ) -> dict[str, Any]:
        return {
            "stage": stage,
            "selected_version": "",
            "confidence_tier": "UNKNOWN",
            "confidence_score": 0.0,
            "source": "",
            "strategy": "",
            "candidates_considered": list(candidates),
            "catalog_status": {
                "merged_version_count": len(catalog_versions),
                "chromiumdash_version_count": len(source_versions.get("chromiumdash", set())),
                "chromium_tags_count": len(source_versions.get("chromium_tags", set())),
                "github_tags_count": len(source_versions.get("github_tags", set())),
            },
            "not_provable_reasons": [],
        }

    def _normalize_candidate_versions(self, candidates: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []

        for raw in candidates:
            candidate = self.normalize_version(raw)
            if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", candidate):
                continue
            if candidate not in seen:
                seen.add(candidate)
                normalized.append(candidate)

        normalized.sort(key=self._version_sort_key, reverse=True)
        return normalized

    def _fetch_versions_from_googlesource(self, http: HttpClient) -> tuple[list[str], list[str]]:
        warnings: list[str] = []
        versions: set[str] = set()
        url = "https://chromium.googlesource.com/chromium/src.git/+refs"
        headers = {
            "User-Agent": "chromiumPatchDiff-web/1.0 (+https://chromium.googlesource.com/chromium/src.git/+refs)",
            "Accept": "text/html,application/xhtml+xml",
        }

        status, payload, error = http.try_get_text(url, headers=headers)
        if status >= 400 or not payload:
            warnings.append(f"Chromium tags fetch failed from googlesource: {error}")
            return [], warnings

        version_pattern = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(payload, "html.parser")
            tags_column = None
            for column in soup.select("div.RefList.RefList--column"):
                heading = column.find("h3")
                if heading and heading.get_text(strip=True).lower() == "tags":
                    tags_column = column
                    break

            anchors = tags_column.select("li.RefList-item a") if tags_column is not None else []
            for anchor in anchors:
                candidate = anchor.get_text(strip=True)
                if version_pattern.fullmatch(candidate):
                    versions.add(candidate)

            if not versions:
                href_pattern = re.compile(r"/\+/refs/tags/(\d+\.\d+\.\d+\.\d+)$")
                for anchor in soup.select("a[href*='/+/refs/tags/']"):
                    candidate = anchor.get_text(strip=True)
                    if version_pattern.fullmatch(candidate):
                        versions.add(candidate)
                        continue

                    href = (anchor.get("href") or "").strip()
                    match = href_pattern.search(href)
                    if match:
                        versions.add(match.group(1))
        except ModuleNotFoundError:
            for candidate in re.findall(r"/\+/refs/tags/(\d+\.\d+\.\d+\.\d+)", payload):
                if version_pattern.fullmatch(candidate):
                    versions.add(candidate)

        return sorted(versions, key=self._version_sort_key, reverse=True), warnings

    def _compare_versions(self, left: str, right: str) -> int:
        left_parts = [int(item) for item in left.split(".")]
        right_parts = [int(item) for item in right.split(".")]

        max_len = max(len(left_parts), len(right_parts))
        left_parts.extend([0] * (max_len - len(left_parts)))
        right_parts.extend([0] * (max_len - len(right_parts)))

        for left_item, right_item in zip(left_parts, right_parts):
            if left_item < right_item:
                return -1
            if left_item > right_item:
                return 1
        return 0

    def _version_sort_key(self, version: str) -> tuple[int, int, int, int]:
        try:
            parts = [int(item) for item in version.split(".") if item.strip()]
        except ValueError:
            return (0, 0, 0, 0)

        while len(parts) < 4:
            parts.append(0)
        return tuple(parts[:4])
