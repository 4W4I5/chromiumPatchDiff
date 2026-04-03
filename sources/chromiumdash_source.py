from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from clients.http_client import HttpClient
from config import PipelineConfig


class ChromiumDashSource:
    name = "chromiumdash"

    def __init__(self, http: HttpClient, config: PipelineConfig):
        self._http = http
        self._config = config
        self._base_url = "https://chromiumdash.appspot.com"

    def fetch_releases(
        self,
        channel: str,
        platform: str = "Windows",
        *,
        per_page: int = 200,
        max_pages: int = 8,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        warnings: list[str] = []
        releases: list[dict[str, Any]] = []
        endpoint = f"{self._base_url}/fetch_releases"

        for page_idx in range(max_pages):
            offset = page_idx * per_page
            status, payload, error = self._http.try_get_json(
                endpoint,
                params={
                    "channel": channel,
                    "platform": platform,
                    "num": per_page,
                    "offset": offset,
                },
            )
            if status >= 400 or not isinstance(payload, list):
                warnings.append(f"ChromiumDash fetch failed for channel={channel}, platform={platform}: {error}")
                break

            if not payload:
                break

            for item in payload:
                if isinstance(item, dict):
                    releases.append(item)

            if len(payload) < per_page:
                break

        return releases, warnings

    def fetch_stable_extended_versions(
        self,
        *,
        platform: str = "Windows",
        per_page: int = 200,
        max_pages: int = 8,
    ) -> tuple[list[str], list[dict[str, Any]], list[str]]:
        warnings: list[str] = []
        releases: list[dict[str, Any]] = []

        for channel in ("Stable", "Extended"):
            channel_releases, channel_warnings = self.fetch_releases(
                channel=channel,
                platform=platform,
                per_page=per_page,
                max_pages=max_pages,
            )
            warnings.extend(channel_warnings)
            releases.extend(channel_releases)

        versions: set[str] = set()
        for item in releases:
            version = self._extract_version(item)
            if version:
                versions.add(version)

        sorted_versions = sorted(versions, key=self._version_sort_key, reverse=True)
        return sorted_versions, releases, warnings

    def choose_nearest_release_version(
        self,
        releases: list[dict[str, Any]],
        *,
        published: str = "",
        updated: str = "",
    ) -> str:
        target_time = self._parse_datetime(updated) or self._parse_datetime(published)
        if target_time is None:
            return ""

        best_version = ""
        best_delta_seconds: float | None = None

        for item in releases:
            release_version = self._extract_version(item)
            release_time = self._extract_release_datetime(item)
            if not release_version or release_time is None:
                continue

            delta = abs((release_time - target_time).total_seconds())
            if best_delta_seconds is None or delta < best_delta_seconds:
                best_delta_seconds = delta
                best_version = release_version

        return best_version

    def _extract_version(self, item: dict[str, Any]) -> str:
        candidates = [
            str(item.get("version", "") or "").strip(),
            str(item.get("milestone_version", "") or "").strip(),
            str(item.get("chromium_version", "") or "").strip(),
        ]

        for candidate in candidates:
            matched = re.search(r"\d+\.\d+\.\d+\.\d+", candidate)
            if matched:
                return matched.group(0)

        as_text = str(item)
        fallback = re.search(r"\d+\.\d+\.\d+\.\d+", as_text)
        if fallback:
            return fallback.group(0)
        return ""

    def _extract_release_datetime(self, item: dict[str, Any]) -> datetime | None:
        for key in (
            "time",
            "timestamp",
            "date",
            "publish_time",
            "release_date",
            "serving_start",
            "serving_start_time",
        ):
            parsed = self._parse_datetime(str(item.get(key, "") or ""))
            if parsed is not None:
                return parsed
        return None

    def _parse_datetime(self, value: str) -> datetime | None:
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

    def _version_sort_key(self, version: str) -> tuple[int, int, int, int]:
        try:
            parts = [int(item) for item in version.split(".") if item.strip()]
        except ValueError:
            return (0, 0, 0, 0)

        while len(parts) < 4:
            parts.append(0)
        return tuple(parts[:4])
