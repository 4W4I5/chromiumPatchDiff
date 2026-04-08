from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup

from clients.cache_store import FileCacheStore
from clients.http_client import HttpClient
from config import PipelineConfig


class ChromeReleasesSource:
    name = "chrome-releases-googleblog"

    _FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default"
    _LOG_URL_HINT = "chromium.googlesource.com/chromium/src/+log/"
    _CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", flags=re.IGNORECASE)
    _VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+\.\d+")
    _SECURITY_FIX_CVE_LINE_PATTERN = re.compile(
        r"^(?:(?P<severity>Critical|High|Medium|Low)\s+)?"
        r"(?P<cve>CVE-\d{4}-\d{4,7})\s*:\s*(?P<title>.+?)\s*$",
        flags=re.IGNORECASE,
    )
    _SECURITY_FIX_BUG_LINK_PATTERN = re.compile(r"issues\.chromium\.org/issues/(?P<bug_id>\d{5,})", flags=re.IGNORECASE)
    _SECURITY_FIX_STATUS_TAG_PATTERN = re.compile(r"\[(?P<status>TBD|NA)\]\[", flags=re.IGNORECASE)

    def __init__(
        self,
        http: HttpClient,
        config: PipelineConfig,
        logger: Callable[[str], None] | None = None,
    ):
        self._http = http
        self._config = config
        self._logger = logger
        self._cache: FileCacheStore | None = None
        if self._config.cache_enabled and self._config.chrome_releases_cache_enabled:
            self._cache = FileCacheStore(
                self._config.chrome_releases_cache_file,
                enabled=True,
            )

    def search_stable_desktop_posts_for_cve(
        self,
        cve_id: str,
        max_results: int = 25,
    ) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
        normalized_cve_id = str(cve_id or "").strip().upper()
        normalized_max_results = max(1, min(100, int(max_results or 25)))
        warnings: list[str] = []
        cache_key = self._build_cache_key(normalized_cve_id, normalized_max_results)
        cache_metadata = {
            "enabled": self._cache is not None,
            "cache_key": cache_key if self._cache is not None else "",
            "cache_status": "disabled" if self._cache is None else "miss",
            "cached_at": "",
            "feed_updated_at": "",
            "upstream_checked_at": "",
            "used_stale_cache": False,
        }

        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized_cve_id):
            cache_metadata["cache_status"] = "bypass"
            return [], [f"Invalid CVE ID format for Chrome Releases lookup: {cve_id}"], cache_metadata

        cached_payload = self._load_cached_entry(cache_key)
        if cached_payload is not None:
            cache_metadata["cached_at"] = str(cached_payload.get("cached_at", "") or "")
            cache_metadata["feed_updated_at"] = str(cached_payload.get("feed_updated_at", "") or "")

            cached_at = self._parse_iso_datetime(str(cached_payload.get("cached_at", "") or ""))
            if cached_at is not None:
                age_seconds = (datetime.now(timezone.utc) - cached_at).total_seconds()
                if age_seconds <= float(self._config.chrome_releases_cache_soft_ttl_seconds):
                    cache_metadata["cache_status"] = "hit"
                    return (
                        self._coerce_cached_posts(cached_payload.get("posts", [])),
                        self._coerce_cached_warnings(cached_payload.get("warnings", [])),
                        cache_metadata,
                    )

        params = {
            "alt": "json",
            "q": normalized_cve_id,
            "max-results": str(normalized_max_results),
        }

        cache_metadata["upstream_checked_at"] = datetime.now(timezone.utc).isoformat()
        status, payload, error = self._http.try_get_json(self._FEED_URL, params=params)
        if status >= 400 or not isinstance(payload, dict):
            if (
                cached_payload is not None
                and self._config.chrome_releases_cache_fallback_on_rate_limit_or_unreachable
                and self._is_rate_limited_or_unreachable(status=status, payload=payload, error=error)
            ):
                cache_metadata["cache_status"] = "fallback_stale"
                cache_metadata["used_stale_cache"] = True
                fallback_warnings = self._coerce_cached_warnings(cached_payload.get("warnings", []))
                fallback_warnings.append(
                    (
                        f"Chrome Releases upstream lookup failed ({status}); using cached feed data "
                        f"for {normalized_cve_id}."
                    )
                )
                return (
                    self._coerce_cached_posts(cached_payload.get("posts", [])),
                    self._dedupe(fallback_warnings),
                    cache_metadata,
                )

            cache_metadata["cache_status"] = "upstream_error"
            return [], [f"Chrome Releases feed lookup failed for {normalized_cve_id}: {error}"], cache_metadata

        current_feed_updated_at = self._extract_feed_updated_at(payload)
        if cached_payload is not None:
            cached_feed_updated_at = str(cached_payload.get("feed_updated_at", "") or "")
            if cached_feed_updated_at and cached_feed_updated_at == current_feed_updated_at:
                refreshed_posts = self._coerce_cached_posts(cached_payload.get("posts", []))
                refreshed_warnings = self._coerce_cached_warnings(cached_payload.get("warnings", []))
                self._store_cached_entry(
                    cache_key=cache_key,
                    cve_id=normalized_cve_id,
                    max_results=normalized_max_results,
                    posts=refreshed_posts,
                    warnings=refreshed_warnings,
                    feed_updated_at=current_feed_updated_at,
                )

                cache_metadata["cache_status"] = "validated_unchanged"
                cache_metadata["feed_updated_at"] = current_feed_updated_at
                cache_metadata["cached_at"] = datetime.now(timezone.utc).isoformat()
                return refreshed_posts, refreshed_warnings, cache_metadata

        posts, warnings = self._extract_posts_from_payload(payload=payload, cve_id=normalized_cve_id)

        self._store_cached_entry(
            cache_key=cache_key,
            cve_id=normalized_cve_id,
            max_results=normalized_max_results,
            posts=posts,
            warnings=warnings,
            feed_updated_at=current_feed_updated_at,
        )

        cache_metadata["cache_status"] = "refresh" if cached_payload is not None else "miss"
        cache_metadata["feed_updated_at"] = current_feed_updated_at
        cache_metadata["cached_at"] = datetime.now(timezone.utc).isoformat()
        return posts, warnings, cache_metadata

    def _extract_posts_from_payload(self, *, payload: dict[str, Any], cve_id: str) -> tuple[list[dict[str, Any]], list[str]]:
        warnings: list[str] = []

        feed = payload.get("feed", {}) if isinstance(payload.get("feed"), dict) else {}
        entries = feed.get("entry", [])
        if isinstance(entries, dict):
            entries = [entries]

        if not isinstance(entries, list) or not entries:
            warnings.append(f"Chrome Releases feed returned no entries for {cve_id}.")
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
            if cve_id not in cves:
                continue

            posts.append(parsed)

        posts.sort(key=lambda item: self._timestamp_sort_key(item.get("published", "")), reverse=True)

        if not posts:
            warnings.append(
                f"No Stable Desktop Chrome Releases posts were matched for {cve_id}; "
                "fallback resolver will be used."
            )

        return posts, warnings

    def _build_cache_key(self, cve_id: str, max_results: int) -> str:
        return f"chrome-releases:{str(cve_id or '').strip().upper()}|max-results:{int(max_results)}"

    def _load_cached_entry(self, cache_key: str) -> dict[str, Any] | None:
        if self._cache is None:
            return None

        payload = self._cache.get(cache_key)
        if not isinstance(payload, dict):
            return None

        return payload

    def _store_cached_entry(
        self,
        *,
        cache_key: str,
        cve_id: str,
        max_results: int,
        posts: list[dict[str, Any]],
        warnings: list[str],
        feed_updated_at: str,
    ) -> None:
        if self._cache is None:
            return

        cache_payload = {
            "query_cve_id": str(cve_id or "").strip().upper(),
            "max_results": int(max_results),
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "feed_updated_at": str(feed_updated_at or ""),
            "posts": posts,
            "warnings": self._dedupe(warnings),
        }

        self._cache.set(
            cache_key,
            cache_payload,
            ttl_seconds=self._config.chrome_releases_cache_hard_ttl_seconds,
        )

    def _extract_feed_updated_at(self, payload: dict[str, Any]) -> str:
        feed = payload.get("feed", {}) if isinstance(payload.get("feed"), dict) else {}
        updated = feed.get("updated") if isinstance(feed.get("updated"), dict) else {}
        value = str(updated.get("$t", "") if isinstance(updated, dict) else "").strip()
        if value:
            return value

        entries = feed.get("entry", [])
        if isinstance(entries, dict):
            entries = [entries]

        if isinstance(entries, list):
            newest = ""
            newest_key = 0.0
            for item in entries:
                if not isinstance(item, dict):
                    continue
                updated_payload = item.get("updated") if isinstance(item.get("updated"), dict) else {}
                updated_value = str(updated_payload.get("$t", "") if isinstance(updated_payload, dict) else "").strip()
                if not updated_value:
                    continue
                sort_key = self._timestamp_sort_key(updated_value)
                if sort_key >= newest_key:
                    newest = updated_value
                    newest_key = sort_key
            return newest

        return ""

    def _parse_iso_datetime(self, value: str) -> datetime | None:
        raw = str(value or "").strip()
        if not raw:
            return None

        normalized = raw.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _coerce_cached_posts(self, payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    def _coerce_cached_warnings(self, payload: Any) -> list[str]:
        if not isinstance(payload, list):
            return []
        return [str(item) for item in payload if str(item or "").strip()]

    def _is_rate_limited_or_unreachable(self, *, status: int, payload: Any, error: str | None) -> bool:
        if status == 0:
            return True
        if status in (429, 502, 503, 504):
            return True

        message = ""
        if isinstance(payload, dict):
            message = str(payload.get("message", "") or "").lower()
        if not message:
            message = str(error or "").lower()

        if status == 403 and ("rate limit" in message or "abuse" in message):
            return True

        network_hints = ("timed out", "timeout", "connection", "temporarily unavailable", "dns")
        return any(hint in message for hint in network_hints)

    def _dedupe(self, items: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in items:
            normalized = str(item or "").strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                deduped.append(normalized)
        return deduped

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

        content_text = self._html_to_text(content_html)
        text_blob = f"{title}\n{content_text}"
        matched_cves = sorted({match.upper() for match in self._CVE_PATTERN.findall(text_blob)})
        log_links = self._extract_log_links(content_html)
        security_fixes = self._extract_security_fixes(content_html=content_html, content_text=content_text)
        matched_bug_ids = sorted({str(item.get("bug_id", "") or "") for item in security_fixes if str(item.get("bug_id", "") or "")})

        return {
            "id": str((entry.get("id") or {}).get("$t", "") if isinstance(entry.get("id"), dict) else ""),
            "title": title,
            "url": url,
            "published": str((entry.get("published") or {}).get("$t", "") if isinstance(entry.get("published"), dict) else ""),
            "updated": str((entry.get("updated") or {}).get("$t", "") if isinstance(entry.get("updated"), dict) else ""),
            "categories": categories,
            "matched_cves": matched_cves,
            "matched_bug_ids": matched_bug_ids,
            "security_fixes": security_fixes,
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

    def _extract_security_fixes(self, *, content_html: str, content_text: str) -> list[dict[str, str]]:
        fixes: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        decoded_html = html.unescape(str(content_html or ""))
        issue_ids = [match.group("bug_id") for match in self._SECURITY_FIX_BUG_LINK_PATTERN.finditer(decoded_html)]
        status_tags = [match.group("status").upper() for match in self._SECURITY_FIX_STATUS_TAG_PATTERN.finditer(decoded_html)]

        cve_rows: list[dict[str, str]] = []
        for raw_line in str(content_text or "").splitlines():
            line = str(raw_line or "").strip()
            if not line:
                continue

            match = self._SECURITY_FIX_CVE_LINE_PATTERN.match(line)
            if not match:
                continue

            cve_rows.append(
                {
                    "cve_id": str(match.group("cve") or "").strip().upper(),
                    "severity": str(match.group("severity") or "").strip().title(),
                    "title": re.sub(r"\s+", " ", str(match.group("title") or "").strip()),
                }
            )

        pair_count = min(len(issue_ids), len(cve_rows))
        for index in range(pair_count):
            bug_id = str(issue_ids[index] or "").strip()
            cve_id = str(cve_rows[index].get("cve_id", "") or "").strip().upper()
            severity = str(cve_rows[index].get("severity", "") or "").strip().title()
            title = str(cve_rows[index].get("title", "") or "").strip()
            row_tag = status_tags[index] if index < len(status_tags) else ""

            if not bug_id or not cve_id:
                continue

            dedupe_key = (bug_id, cve_id, title)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            fixes.append(
                {
                    "bug_id": bug_id,
                    "cve_id": cve_id,
                    "severity": severity,
                    "title": title,
                    "status_tag": row_tag,
                }
            )

        return fixes

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
