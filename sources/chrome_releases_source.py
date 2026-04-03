from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Any, Callable
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup

from clients.http_client import HttpClient
from config import PipelineConfig


class ChromeReleasesSource:
    name = "chrome-releases-googleblog"

    _FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default"
    _LOG_URL_HINT = "chromium.googlesource.com/chromium/src/+log/"
    _CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", flags=re.IGNORECASE)
    _VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+\.\d+")

    def __init__(
        self,
        http: HttpClient,
        config: PipelineConfig,
        logger: Callable[[str], None] | None = None,
    ):
        self._http = http
        self._config = config
        self._logger = logger

    def search_stable_desktop_posts_for_cve(
        self,
        cve_id: str,
        max_results: int = 25,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        normalized_cve_id = str(cve_id or "").strip().upper()
        warnings: list[str] = []

        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized_cve_id):
            return [], [f"Invalid CVE ID format for Chrome Releases lookup: {cve_id}"]

        params = {
            "alt": "json",
            "q": normalized_cve_id,
            "max-results": str(max(1, min(100, int(max_results or 25)))),
        }

        status, payload, error = self._http.try_get_json(self._FEED_URL, params=params)
        if status >= 400 or not isinstance(payload, dict):
            return [], [f"Chrome Releases feed lookup failed for {normalized_cve_id}: {error}"]

        feed = payload.get("feed", {}) if isinstance(payload.get("feed"), dict) else {}
        entries = feed.get("entry", [])
        if isinstance(entries, dict):
            entries = [entries]

        if not isinstance(entries, list) or not entries:
            warnings.append(f"Chrome Releases feed returned no entries for {normalized_cve_id}.")
            return [], warnings

        posts: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            parsed = self._parse_entry(entry)
            if not parsed:
                continue

            if not self._is_stable_desktop_post(parsed):
                continue

            cves = [item.upper() for item in parsed.get("matched_cves", [])]
            if normalized_cve_id not in cves:
                continue

            posts.append(parsed)

        posts.sort(key=lambda item: self._timestamp_sort_key(item.get("published", "")), reverse=True)

        if not posts:
            warnings.append(
                f"No Stable Desktop Chrome Releases posts were matched for {normalized_cve_id}; "
                "fallback resolver will be used."
            )

        return posts, warnings

    def select_preferred_log_range(
        self,
        posts: list[dict[str, Any]],
        *,
        version_hint: str = "",
    ) -> tuple[dict[str, Any] | None, list[str]]:
        warnings: list[str] = []
        candidates: list[dict[str, Any]] = []

        for post in posts:
            if not isinstance(post, dict):
                continue
            for link in post.get("log_links", []) or []:
                if not isinstance(link, dict):
                    continue

                base_version = self._extract_version(str(link.get("base_version", "") or ""))
                head_version = self._extract_version(str(link.get("head_version", "") or ""))
                if not base_version or not head_version:
                    continue

                candidates.append(
                    {
                        "post_title": str(post.get("title", "") or ""),
                        "post_url": str(post.get("url", "") or ""),
                        "published": str(post.get("published", "") or ""),
                        "updated": str(post.get("updated", "") or ""),
                        "log_url": str(link.get("url", "") or ""),
                        "base_version": base_version,
                        "head_version": head_version,
                    }
                )

        if not candidates:
            return None, ["No parseable Chromium version ranges were found in Chrome Releases Log links."]

        normalized_hint = self._extract_version(version_hint)
        if normalized_hint:
            exact_matches = [item for item in candidates if item.get("head_version") == normalized_hint]
            if exact_matches:
                selected = max(exact_matches, key=self._candidate_sort_key)
                return selected, warnings
            warnings.append(
                "Version hint did not match any Log head version in Chrome Releases posts; "
                "using latest matched range."
            )

        selected = max(candidates, key=self._candidate_sort_key)
        return selected, warnings

    def _parse_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        title = ""
        title_payload = entry.get("title")
        if isinstance(title_payload, dict):
            title = str(title_payload.get("$t", "") or "")

        content_html = ""
        content_payload = entry.get("content")
        if isinstance(content_payload, dict):
            content_html = str(content_payload.get("$t", "") or "")

        categories: list[str] = []
        raw_categories = entry.get("category", [])
        if isinstance(raw_categories, list):
            for item in raw_categories:
                if not isinstance(item, dict):
                    continue
                term = str(item.get("term", "") or "").strip()
                if term:
                    categories.append(term)

        url = ""
        raw_links = entry.get("link", [])
        if isinstance(raw_links, list):
            for item in raw_links:
                if not isinstance(item, dict):
                    continue
                if str(item.get("rel", "") or "") != "alternate":
                    continue
                href = str(item.get("href", "") or "").strip()
                if href:
                    url = href
                    break

        text_blob = f"{title}\n{self._html_to_text(content_html)}"
        matched_cves = sorted({match.upper() for match in self._CVE_PATTERN.findall(text_blob)})
        log_links = self._extract_log_links(content_html)

        return {
            "id": str((entry.get("id") or {}).get("$t", "") if isinstance(entry.get("id"), dict) else ""),
            "title": title,
            "url": url,
            "published": str((entry.get("published") or {}).get("$t", "") if isinstance(entry.get("published"), dict) else ""),
            "updated": str((entry.get("updated") or {}).get("$t", "") if isinstance(entry.get("updated"), dict) else ""),
            "categories": categories,
            "matched_cves": matched_cves,
            "log_links": log_links,
        }

    def _is_stable_desktop_post(self, post: dict[str, Any]) -> bool:
        categories = [str(item).strip().lower() for item in post.get("categories", []) if str(item).strip()]
        title = str(post.get("title", "") or "").strip().lower()

        has_stable = "stable updates" in categories
        has_desktop = "desktop update" in categories or "desktop" in title

        return has_stable and has_desktop

    def _extract_log_links(self, content_html: str) -> list[dict[str, str]]:
        links: list[dict[str, str]] = []
        seen_urls: set[str] = set()

        decoded_html = html.unescape(str(content_html or ""))
        soup = BeautifulSoup(decoded_html, "html.parser")

        for anchor in soup.select("a[href]"):
            href = html.unescape(str(anchor.get("href", "") or "").strip())
            if not href:
                continue
            if self._LOG_URL_HINT not in href.lower():
                continue

            if href in seen_urls:
                continue

            base_version, head_version = self._extract_versions_from_log_url(href)
            links.append(
                {
                    "label": str(anchor.get_text(" ", strip=True) or "Log"),
                    "url": href,
                    "base_version": base_version,
                    "head_version": head_version,
                }
            )
            seen_urls.add(href)

        for url in re.findall(r"https?://chromium\.googlesource\.com/chromium/src/\+log/[^\s\"'<>]+", decoded_html):
            normalized_url = html.unescape(str(url).strip())
            if not normalized_url or normalized_url in seen_urls:
                continue

            base_version, head_version = self._extract_versions_from_log_url(normalized_url)
            links.append(
                {
                    "label": "Log",
                    "url": normalized_url,
                    "base_version": base_version,
                    "head_version": head_version,
                }
            )
            seen_urls.add(normalized_url)

        return links

    def _extract_versions_from_log_url(self, url: str) -> tuple[str, str]:
        normalized_url = html.unescape(str(url or "").strip())
        if not normalized_url:
            return "", ""

        parsed = urlparse(normalized_url)
        path = unquote(parsed.path or "")
        match = re.search(r"/\+log/([^?#]+)", path)
        if not match:
            return "", ""

        range_blob = match.group(1).strip("/")
        if ".." not in range_blob:
            return "", ""

        base_raw, head_raw = range_blob.split("..", 1)
        base_version = self._extract_version(base_raw)
        head_version = self._extract_version(head_raw)
        return base_version, head_version

    def _extract_version(self, value: str) -> str:
        matched = self._VERSION_PATTERN.search(str(value or ""))
        return matched.group(0) if matched else ""

    def _candidate_sort_key(self, candidate: dict[str, Any]) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int], float]:
        head_version = str(candidate.get("head_version", "") or "")
        base_version = str(candidate.get("base_version", "") or "")
        published = str(candidate.get("published", "") or "")
        return (
            self._version_sort_key(head_version),
            self._version_sort_key(base_version),
            self._timestamp_sort_key(published),
        )

    def _html_to_text(self, content_html: str) -> str:
        decoded_html = html.unescape(str(content_html or ""))
        soup = BeautifulSoup(decoded_html, "html.parser")
        return soup.get_text("\n", strip=True)

    def _timestamp_sort_key(self, value: str) -> float:
        raw = str(value or "").strip()
        if not raw:
            return 0.0

        normalized = raw.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized).timestamp()
        except ValueError:
            return 0.0

    def _version_sort_key(self, version: str) -> tuple[int, int, int, int]:
        try:
            parts = [int(item) for item in str(version or "").split(".") if item.strip()]
        except ValueError:
            return (0, 0, 0, 0)

        while len(parts) < 4:
            parts.append(0)

        return tuple(parts[:4])
