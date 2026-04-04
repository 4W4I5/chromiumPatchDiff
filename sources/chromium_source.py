from __future__ import annotations

import base64
import binascii
import json
import re
import time
from typing import Any, Callable
from urllib.parse import quote

from clients.http_client import HttpClient
from config import CompareComponent, ComparePlatform, PipelineConfig, ReleaseChannel
from models import CommitEvidence


class ChromiumMirrorSource:
    name = "chromium-github-mirror"
    _SECURITY_ID_RE = re.compile(
        r"(CVE-\d{4}-\d{4,7}|issues\.chromium\.org/issues/\d+|crbug(?:\.com|\s*[:/#]?\s*)\d{5,})",
        flags=re.IGNORECASE,
    )
    _AUTOROLLER_HINTS: tuple[str, ...] = (
        "autoroll",
        "chrome release autoroll",
        "rubber stamper",
        "roll chrome win",
        "pgo profile",
        "merge-approval-bypass",
    )

    _PLATFORM_PATH_RULES: dict[ComparePlatform, tuple[str, ...]] = {
        ComparePlatform.WINDOWS: ("win/", "windows/", "_win", "win32", "win64", "platform/win"),
        ComparePlatform.LINUX: ("linux/", "_linux", "platform/linux", "ozone/", "x11/", "wayland/"),
        ComparePlatform.MACOS: ("mac/", "macos/", "darwin/", "_mac", "platform/mac"),
        ComparePlatform.ANDROID: ("android/", "_android", "platform/android", "java/org/chromium/"),
    }
    _PLATFORM_MESSAGE_RULES: dict[ComparePlatform, tuple[str, ...]] = {
        ComparePlatform.WINDOWS: ("windows", "win32", "win64", " win "),
        ComparePlatform.LINUX: ("linux", "x11", "wayland", "ozone"),
        ComparePlatform.MACOS: ("mac", "macos", "darwin"),
        ComparePlatform.ANDROID: ("android", "play services", "chromium android"),
    }
    _PDFIUM_GOOGLESOURCE_BASE = "https://pdfium.googlesource.com/pdfium"

    def __init__(
        self,
        http: HttpClient,
        config: PipelineConfig,
        logger: Callable[[str], None] | None = None,
    ):
        self._http = http
        self._config = config
        self._logger = logger
        self._rate_limited_until = 0.0
        self._last_github_request_at = 0.0

    def search_commits_for_cve(
        self,
        cve_id: str,
        references: list[str] | None = None,
        description: str = "",
        candidate_commits: list[CommitEvidence] | None = None,
        max_results: int = 5,
    ) -> tuple[list[CommitEvidence], list[str]]:
        warnings: list[str] = []

        references = references or []
        commits: list[CommitEvidence] = []
        seen_sha: set[str] = set()

        for ref in self._extract_direct_commit_refs(references):
            if ref.sha in seen_sha:
                continue
            seen_sha.add(ref.sha)
            commits.append(ref)

        search_tokens = self._build_search_tokens(cve_id, references, description)
        if not self._config.github_token:
            search_tokens = search_tokens[:1]

        if self._is_in_rate_limit_cooldown():
            warnings.append(self._rate_limit_skip_warning())
            return commits[:max_results], warnings

        if candidate_commits:
            scoped_matches = self._match_candidate_commits(
                cve_id=cve_id,
                search_tokens=search_tokens,
                candidate_commits=candidate_commits,
                max_results=max_results,
            )
            for match in scoped_matches:
                if match.sha in seen_sha:
                    continue
                seen_sha.add(match.sha)
                commits.append(match)
                if len(commits) >= max_results:
                    return commits[:max_results], warnings

            if commits:
                return commits[:max_results], warnings

        endpoint = f"{self._config.github_api_base}/search/commits"
        for token in search_tokens:
            if self._is_in_rate_limit_cooldown():
                warnings.append(self._rate_limit_skip_warning())
                break

            query = f'"{token}" repo:{self._config.github_repo}'
            self._throttle_github_requests()
            status, payload, error = self._http.try_get_json(
                endpoint,
                params={"q": query, "per_page": max_results},
                headers=self._config.github_headers,
            )

            if status != 200 or not isinstance(payload, dict):
                if self._is_github_rate_limit_response(status=status, payload=payload, error=error):
                    self._enter_rate_limit_cooldown(status=status, payload=payload)
                    warnings.append(self._rate_limit_skip_warning())
                    break
                if status not in (0, 422):
                    warnings.append(f"GitHub commit search did not return results for token '{token}': {error}")
                continue

            for item in payload.get("items", []) or []:
                if not isinstance(item, dict):
                    continue

                sha = item.get("sha", "")
                if not sha or sha in seen_sha:
                    continue

                commit = item.get("commit", {}) or {}
                message = commit.get("message", "") or ""
                title = (message.splitlines() or [""])[0]
                confidence = 1.0 if cve_id.upper() in title.upper() else 0.75

                seen_sha.add(sha)
                commits.append(
                    CommitEvidence(
                        sha=sha,
                        url=item.get("html_url", item.get("url", "")),
                        title=title,
                        message=message,
                        author=((commit.get("author") or {}).get("name") or ""),
                        date=((commit.get("author") or {}).get("date") or ""),
                        confidence=confidence,
                        source=f"github:{self._config.github_repo}",
                    )
                )
                if len(commits) >= max_results:
                    return commits[:max_results], warnings

        if commits:
            return commits[:max_results], warnings

        warnings.append(f"No GitHub commit hits found for {cve_id} with current heuristics.")

        if self._is_in_rate_limit_cooldown():
            warnings.append("GitHub fallback commit lookup skipped due to active API cooldown.")
            return [], warnings

        if not self._config.github_token:
            warnings.append("GitHub fallback commit lookup skipped without GITHUB_TOKEN to reduce rate-limit risk.")
            return commits[:max_results], warnings

        fallback_endpoint = f"{self._config.github_api_base}/repos/{self._config.github_repo}/commits"
        self._throttle_github_requests()
        fallback_status, fallback_payload, fallback_error = self._http.try_get_json(
            fallback_endpoint,
            params={"sha": "main", "per_page": 100},
            headers=self._config.github_headers,
        )

        if fallback_status >= 400 or not isinstance(fallback_payload, list):
            if self._is_github_rate_limit_response(status=fallback_status, payload=fallback_payload, error=fallback_error):
                self._enter_rate_limit_cooldown(status=fallback_status, payload=fallback_payload)
                warnings.append(self._rate_limit_skip_warning())
            warnings.append(f"GitHub fallback commit lookup failed for {cve_id}: {fallback_error}")
            return [], warnings

        for item in fallback_payload:
            if not isinstance(item, dict):
                continue
            commit = item.get("commit", {}) or {}
            message = commit.get("message", "")
            if not any(token.upper() in message.upper() for token in search_tokens):
                continue

            title = (message.splitlines() or [""])[0]
            sha = item.get("sha", "")
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
            commits.append(
                CommitEvidence(
                    sha=sha,
                    url=item.get("html_url", ""),
                    title=title,
                    message=message,
                    author=((commit.get("author") or {}).get("name") or ""),
                    date=((commit.get("author") or {}).get("date") or ""),
                    confidence=0.7,
                    source=f"github:{self._config.github_repo}",
                )
            )
            if len(commits) >= max_results:
                break

        return commits[:max_results], warnings

    def _is_github_rate_limit_response(self, status: int, payload: Any, error: str | None) -> bool:
        if status not in (403, 429):
            return False

        message = ""
        if isinstance(payload, dict):
            message = str(payload.get("message", "")).lower()
        if not message and error:
            message = error.lower()

        return "rate limit" in message or "abuse" in message

    def _enter_rate_limit_cooldown(self, status: int, payload: Any) -> None:
        wait_seconds = 180
        if status == 429:
            wait_seconds = 240
        if isinstance(payload, dict):
            message = str(payload.get("message", "")).lower()
            if "abuse" in message:
                wait_seconds = 300

        self._rate_limited_until = time.time() + wait_seconds

    def _is_in_rate_limit_cooldown(self) -> bool:
        return time.time() < self._rate_limited_until

    def _rate_limit_skip_warning(self) -> str:
        return (
            "GitHub API is currently rate-limited/abuse-limited; skipping additional commit searches "
            "until cooldown expires. Set GITHUB_TOKEN to raise limits."
        )

    def get_compare_commits(
        self,
        base_version: str,
        head_version: str,
        max_results: int = 250,
    ) -> tuple[list[CommitEvidence], list[str]]:
        compare_result, warnings = self.get_compare_diff(
            base_version=base_version,
            head_version=head_version,
            platform=ComparePlatform.ALL,
            component=CompareComponent.CHROME,
            max_results=max_results,
        )
        commits = compare_result.get("commits", []) or []
        return [item for item in commits if isinstance(item, CommitEvidence)], warnings

    def get_compare_diff(
        self,
        base_version: str,
        head_version: str,
        platform: ComparePlatform = ComparePlatform.ALL,
        component: CompareComponent = CompareComponent.CHROME,
        path_prefixes: list[str] | None = None,
        file_extensions: list[str] | None = None,
        keyword: str = "",
        keywords: list[str] | None = None,
        soft_keywords: list[str] | None = None,
        evidence_tokens: list[str] | None = None,
        strict_commit_platform: bool = True,
        strict_file_platform: bool = True,
        soft_file_focus: bool = False,
        min_commit_confidence: float = 0.0,
        max_results: int = 250,
    ) -> tuple[dict[str, Any], list[str]]:
        warnings: list[str] = []

        normalized_base_ref = str(base_version or "").strip()
        normalized_head_ref = str(head_version or "").strip()
        if normalized_base_ref and normalized_head_ref and normalized_base_ref == normalized_head_ref:
            return {
                "status": "unchanged",
                "commits": [],
                "files": [],
                "base_ref": normalized_base_ref,
                "head_ref": normalized_head_ref,
                "compare_url": "",
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
                "total_commits": 0,
                "ahead_by": 0,
                "behind_by": 0,
                "total_files": 0,
                "truncated": False,
                "platform": platform.value,
                "component": component.value,
                "release_channel": "",
            }, warnings

        endpoint = (
            f"{self._config.github_api_base}/repos/{self._config.github_repo}"
            f"/compare/{normalized_base_ref}...{normalized_head_ref}"
        )
        self._throttle_github_requests()
        status, payload, error = self._http.try_get_json(
            endpoint,
            headers=self._config.github_headers,
        )

        if status >= 400 or not isinstance(payload, dict):
            if component == CompareComponent.PDFIUM:
                googlesource_payload, googlesource_error = self._get_pdfium_googlesource_compare_payload(
                    base_ref=normalized_base_ref,
                    head_ref=normalized_head_ref,
                )
                if isinstance(googlesource_payload, dict):
                    payload = googlesource_payload
                else:
                    warnings.append(
                        "GitHub compare failed for range "
                        f"{normalized_base_ref}...{normalized_head_ref}: {error}; "
                        f"pdfium.googlesource compare also failed: {googlesource_error or 'unknown error'}"
                    )
                    return {
                        "status": "error",
                        "commits": [],
                        "files": [],
                        "base_ref": normalized_base_ref,
                        "head_ref": normalized_head_ref,
                        "compare_url": "",
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
                        "total_commits": 0,
                        "ahead_by": 0,
                        "behind_by": 0,
                        "total_files": 0,
                        "truncated": False,
                        "platform": platform.value,
                        "component": component.value,
                        "release_channel": "",
                    }, warnings
            else:
                warnings.append(f"GitHub compare failed for range {normalized_base_ref}...{normalized_head_ref}: {error}")
                return {
                    "status": "error",
                    "commits": [],
                    "files": [],
                    "base_ref": normalized_base_ref,
                    "head_ref": normalized_head_ref,
                    "compare_url": "",
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
                    "total_commits": 0,
                    "ahead_by": 0,
                    "behind_by": 0,
                    "total_files": 0,
                    "truncated": False,
                    "platform": platform.value,
                    "component": component.value,
                    "release_channel": "",
                }, warnings

        normalized_prefixes = [item.strip().lower().lstrip("/") for item in (path_prefixes or []) if item.strip()]
        normalized_extensions = [self._normalize_extension(item) for item in (file_extensions or []) if item.strip()]
        normalized_hard_keywords = self._normalize_keywords(keyword=keyword, keywords=keywords)
        normalized_soft_keywords = self._normalize_keywords(keyword="", keywords=soft_keywords)
        normalized_evidence_tokens = self._normalize_evidence_tokens(evidence_tokens)
        try:
            min_commit_confidence = float(min_commit_confidence)
        except (TypeError, ValueError):
            min_commit_confidence = 0.0
        min_commit_confidence = max(0.0, min(min_commit_confidence, 1.0))

        def _collect_compare_commits() -> list[CommitEvidence]:
            items: list[CommitEvidence] = []
            for item in payload.get("commits", []) or []:
                if not isinstance(item, dict):
                    continue

                sha = item.get("sha", "")
                commit = item.get("commit", {}) or {}
                message = commit.get("message", "") or ""
                title = (message.splitlines() or [""])[0]
                combined = f"{title} {message}"

                platform_match = self._message_matches_platform(message, platform)
                if strict_commit_platform and platform != ComparePlatform.ALL and not platform_match:
                    continue

                hard_keyword_match = True
                if normalized_hard_keywords:
                    hard_keyword_match = self._matches_any_keyword(combined.lower(), normalized_hard_keywords)
                if not hard_keyword_match:
                    continue

                confidence = self._score_compare_commit(
                    title=title,
                    message=message,
                    platform_match=platform_match,
                    strict_commit_platform=strict_commit_platform,
                    normalized_soft_keywords=normalized_soft_keywords,
                    normalized_evidence_tokens=normalized_evidence_tokens,
                )

                items.append(
                    CommitEvidence(
                        sha=sha,
                        url=item.get("html_url", ""),
                        title=title,
                        message=message,
                        author=((commit.get("author") or {}).get("name") or ""),
                        date=((commit.get("author") or {}).get("date") or ""),
                        confidence=confidence,
                        source=f"github:{self._config.github_repo}:compare",
                    )
                )
            return items

        compare_commits = _collect_compare_commits()

        if compare_commits:
            compare_commits.sort(
                key=lambda item: (item.confidence, str(item.date or "")),
                reverse=True,
            )

            commit_confidence_fallback_applied = False
            if min_commit_confidence > 0:
                above_threshold = [
                    item for item in compare_commits if float(item.confidence or 0.0) >= min_commit_confidence
                ]
                if above_threshold:
                    compare_commits = above_threshold
                elif normalized_soft_keywords or normalized_evidence_tokens:
                    fallback_count = min(max_results, 40)
                    commit_confidence_fallback_applied = True
                    if len(compare_commits) > fallback_count:
                        compare_commits = compare_commits[:fallback_count]
            else:
                commit_confidence_fallback_applied = False

            if len(compare_commits) > max_results:
                warnings.append(f"Compare commit list truncated at {max_results} entries.")
                compare_commits = compare_commits[:max_results]
        else:
            commit_confidence_fallback_applied = False

        compare_files: list[dict[str, Any]] = []
        candidate_files: list[tuple[dict[str, Any], bool]] = []
        raw_files = payload.get("files", []) or []
        files_after_platform_filter = 0
        files_after_path_prefix_filter = 0
        files_after_extension_filter = 0
        files_after_keyword_filter = 0
        files_after_soft_focus_filter = 0
        soft_file_focus_fallback_applied = False
        for file_payload in raw_files:
            if not isinstance(file_payload, dict):
                continue

            filename = str(file_payload.get("filename", "") or "")
            patch = str(file_payload.get("patch", "") or "")
            lowered_filename = filename.lower().lstrip("/")

            path_matches_platform = self._path_matches_platform(lowered_filename, platform)
            if platform != ComparePlatform.ALL and strict_file_platform and not path_matches_platform:
                continue
            files_after_platform_filter += 1

            if normalized_prefixes:
                prefix_match = any(
                    lowered_filename.startswith(prefix.rstrip("/") + "/") or lowered_filename == prefix.rstrip("/") for prefix in normalized_prefixes
                )
                if not prefix_match:
                    continue
            files_after_path_prefix_filter += 1

            if normalized_extensions:
                suffix = ""
                if "." in lowered_filename:
                    suffix = "." + lowered_filename.rsplit(".", 1)[1]
                if suffix not in normalized_extensions:
                    continue
            files_after_extension_filter += 1

            file_haystack = f"{lowered_filename}\n{patch.lower()}"
            if normalized_hard_keywords and not self._matches_any_keyword(file_haystack, normalized_hard_keywords):
                continue
            files_after_keyword_filter += 1

            soft_focus_match = self._matches_any_keyword(file_haystack, normalized_soft_keywords) if normalized_soft_keywords else False
            evidence_match = self._matches_any_evidence_token(file_haystack, normalized_evidence_tokens)

            normalized_name = filename.strip().lstrip("/")
            base_raw_url = str(file_payload.get("base_raw_url", "") or "").strip()
            if not base_raw_url:
                base_raw_url = self._build_raw_url(self._config.github_repo, normalized_base_ref, normalized_name)

            head_raw_url = str(file_payload.get("raw_url", "") or "").strip()
            if not head_raw_url:
                head_raw_url = str(file_payload.get("head_raw_url", "") or "").strip()
            if not head_raw_url:
                head_raw_url = self._build_raw_url(self._config.github_repo, normalized_head_ref, normalized_name)

            candidate_files.append(
                (
                    {
                        "filename": filename,
                        "status": str(file_payload.get("status", "") or ""),
                        "additions": int(file_payload.get("additions", 0) or 0),
                        "deletions": int(file_payload.get("deletions", 0) or 0),
                        "changes": int(file_payload.get("changes", 0) or 0),
                        "blob_url": str(file_payload.get("blob_url", "") or ""),
                        "raw_url": head_raw_url,
                        "base_raw_url": base_raw_url,
                        "head_raw_url": head_raw_url,
                        "file_key": self._build_file_key(component, normalized_name),
                        "patch": patch,
                    },
                    soft_focus_match or evidence_match,
                )
            )

        if soft_file_focus and (normalized_soft_keywords or normalized_evidence_tokens):
            focused_files = [item for item, matches_focus in candidate_files if matches_focus]
            if focused_files:
                compare_files = focused_files
                files_after_soft_focus_filter = len(compare_files)
            else:
                compare_files = [item for item, _ in candidate_files]
                files_after_soft_focus_filter = 0
                if compare_files:
                    soft_file_focus_fallback_applied = True
        else:
            compare_files = [item for item, _ in candidate_files]
            files_after_soft_focus_filter = len(compare_files)

        total_commits = int(payload.get("total_commits", 0) or 0)
        if not compare_commits:
            if total_commits > 0:
                warnings.append(
                    "No commits matched active filters/signals "
                    f"(total_commits={total_commits}, strict_commit_platform={strict_commit_platform}, "
                    f"hard_keywords={len(normalized_hard_keywords)}, soft_keywords={len(normalized_soft_keywords)}, "
                    f"evidence_tokens={len(normalized_evidence_tokens)})."
                )
            else:
                warnings.append(
                    f"GitHub compare returned no commits for range {normalized_base_ref}...{normalized_head_ref}."
                )
        if platform != ComparePlatform.ALL and strict_file_platform and not compare_files:
            warnings.append(
                "No changed files matched platform filter "
                f"'{platform.value}' (total_files={len(raw_files)}, after_platform={files_after_platform_filter}, "
                f"after_path_prefix={files_after_path_prefix_filter}, after_extension={files_after_extension_filter}, "
                f"after_keyword={files_after_keyword_filter}, after_soft_focus={files_after_soft_focus_filter})."
            )

        return {
            "status": "ok",
            "commits": compare_commits,
            "files": compare_files,
            "base_ref": normalized_base_ref,
            "head_ref": normalized_head_ref,
            "compare_url": str(payload.get("compare_url", "") or ""),
            "filter_metrics": {
                "total_files_from_api": len(raw_files),
                "after_platform_filter": files_after_platform_filter,
                "after_path_prefix_filter": files_after_path_prefix_filter,
                "after_extension_filter": files_after_extension_filter,
                "after_keyword_filter": files_after_keyword_filter,
                "after_soft_focus_filter": files_after_soft_focus_filter,
                "commit_confidence_fallback_applied": bool(commit_confidence_fallback_applied),
                "soft_file_focus_fallback_applied": bool(soft_file_focus_fallback_applied),
            },
            "total_commits": int(payload.get("total_commits", 0) or 0),
            "ahead_by": int(payload.get("ahead_by", 0) or 0),
            "behind_by": int(payload.get("behind_by", 0) or 0),
            "total_files": len(raw_files),
            "truncated": bool(payload.get("files") and len(raw_files) >= 300),
            "platform": platform.value,
            "component": component.value,
            "keywords": normalized_hard_keywords,
            "soft_keywords": normalized_soft_keywords,
            "strict_commit_platform": bool(strict_commit_platform),
            "strict_file_platform": bool(strict_file_platform),
            "soft_file_focus": bool(soft_file_focus),
            "min_commit_confidence": min_commit_confidence,
            "release_channel": "",
        }, warnings

    def list_version_tags(
        self,
        repo: str,
        release_channel: ReleaseChannel = ReleaseChannel.STABLE,
        max_pages: int = 8,
        per_page: int = 100,
    ) -> tuple[list[str], list[str]]:
        warnings: list[str] = []
        normalized_repo = (repo or "").strip("/") or self._config.github_repo
        candidate_versions: set[str] = set()
        channel_keywords = {
            ReleaseChannel.STABLE: (),
            ReleaseChannel.BETA: ("beta",),
            ReleaseChannel.DEV: ("dev",),
            ReleaseChannel.CANARY: ("canary",),
        }

        endpoint = f"{self._config.github_api_base}/repos/{normalized_repo}/tags"
        for page in range(1, max_pages + 1):
            self._throttle_github_requests()
            status, payload, error = self._http.try_get_json(
                endpoint,
                params={"per_page": per_page, "page": page},
                headers=self._config.github_headers,
            )
            if status >= 400 or not isinstance(payload, list):
                warnings.append(f"GitHub tags fetch failed for {normalized_repo}: {error}")
                break

            if not payload:
                break

            for item in payload:
                if not isinstance(item, dict):
                    continue
                tag_name = str(item.get("name", "") or "")
                if not tag_name:
                    continue

                version_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", tag_name)
                if not version_match:
                    continue

                lowered_tag = tag_name.lower()
                required_keywords = channel_keywords.get(release_channel, ())
                if required_keywords and not any(keyword in lowered_tag for keyword in required_keywords):
                    continue

                candidate_versions.add(version_match.group(1))

        if not candidate_versions and release_channel != ReleaseChannel.STABLE:
            warnings.append(f"No tags matched release channel '{release_channel.value}' in {normalized_repo}; falling back to stable tag list.")
            return self.list_version_tags(
                repo=normalized_repo,
                release_channel=ReleaseChannel.STABLE,
                max_pages=max_pages,
                per_page=per_page,
            )

        sorted_versions = sorted(candidate_versions, key=self._version_sort_key, reverse=True)
        return sorted_versions, warnings

    def _throttle_github_requests(self) -> None:
        min_interval = self._config.github_min_request_interval_seconds
        if min_interval <= 0:
            self._last_github_request_at = time.monotonic()
            return

        now = time.monotonic()
        elapsed = now - self._last_github_request_at
        if elapsed < min_interval:
            wait_seconds = min_interval - elapsed
            self._log(f"Throttling GitHub request for {wait_seconds:.2f}s")
            time.sleep(wait_seconds)

        self._last_github_request_at = time.monotonic()

    def _log(self, message: str) -> None:
        if self._logger:
            self._logger(f"[{self.name}] {message}")

    def _build_search_tokens(self, cve_id: str, references: list[str], description: str) -> list[str]:
        tokens = [cve_id]

        issue_ids = self._extract_issue_ids(references, description)
        for issue_id in issue_ids:
            tokens.extend(
                [
                    issue_id,
                    f"crbug/{issue_id}",
                    f"bug:{issue_id}",
                ]
            )

        unique: list[str] = []
        seen: set[str] = set()
        for token in tokens:
            normalized = token.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(normalized)
        return unique

    def _extract_issue_ids(self, references: list[str], description: str) -> list[str]:
        issue_ids: set[str] = set()

        for ref in references:
            for match in re.findall(r"issues\.chromium\.org/issues/(\d+)", ref):
                issue_ids.add(match)
            for match in re.findall(r"crbug\.com/(\d+)", ref):
                issue_ids.add(match)

        for match in re.findall(r"(?:crbug|bug)\s*[:#/]?\s*(\d{6,})", description, flags=re.IGNORECASE):
            issue_ids.add(match)

        return sorted(issue_ids)

    def _extract_direct_commit_refs(self, references: list[str]) -> list[CommitEvidence]:
        commits: list[CommitEvidence] = []
        seen: set[str] = set()

        for ref in references:
            sha = ""
            commit_match = re.search(r"/commit/([0-9a-f]{7,40})", ref, flags=re.IGNORECASE)
            plus_match = re.search(r"/\+/([0-9a-f]{7,40})", ref, flags=re.IGNORECASE)
            if commit_match:
                sha = commit_match.group(1)
            elif plus_match:
                sha = plus_match.group(1)

            if sha and sha not in seen:
                seen.add(sha)
                commits.append(
                    CommitEvidence(
                        sha=sha,
                        url=ref,
                        title="Referenced upstream commit",
                        message="",
                        confidence=1.0,
                        source=f"github:{self._config.github_repo}",
                    )
                )

        return commits

    def _match_candidate_commits(
        self,
        cve_id: str,
        search_tokens: list[str],
        candidate_commits: list[CommitEvidence],
        max_results: int,
    ) -> list[CommitEvidence]:
        matches: list[CommitEvidence] = []
        seen: set[str] = set()

        for commit in candidate_commits:
            if commit.sha in seen:
                continue

            haystack = f"{commit.title} {commit.message} {commit.url}".upper()
            if not any(token.upper() in haystack for token in search_tokens):
                continue

            confidence = 0.75
            if cve_id.upper() in haystack:
                confidence = 1.0

            seen.add(commit.sha)
            matches.append(
                CommitEvidence(
                    sha=commit.sha,
                    url=commit.url,
                    title=commit.title,
                    message=commit.message,
                    author=commit.author,
                    date=commit.date,
                    confidence=confidence,
                    source=commit.source,
                )
            )

            if len(matches) >= max_results:
                break

        return matches

    def _path_matches_platform(self, lowered_path: str, platform: ComparePlatform) -> bool:
        if platform == ComparePlatform.ALL:
            return True

        rules = self._PLATFORM_PATH_RULES.get(platform, ())
        if not rules:
            return False

        return any(rule in lowered_path for rule in rules)

    def _message_matches_platform(self, message: str, platform: ComparePlatform) -> bool:
        if platform == ComparePlatform.ALL:
            return True

        lowered_message = f" {(message or '').lower()} "
        rules = self._PLATFORM_MESSAGE_RULES.get(platform, ())
        if not rules:
            return False

        return any(rule in lowered_message for rule in rules)

    def _normalize_extension(self, value: str) -> str:
        trimmed = value.strip().lower()
        if not trimmed:
            return ""
        if not trimmed.startswith("."):
            return f".{trimmed}"
        return trimmed

    def _normalize_keywords(self, keyword: str, keywords: list[str] | None) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for item in [keyword, *(keywords or [])]:
            token = str(item or "").strip().lower()
            if not token:
                continue
            if token in seen:
                continue
            seen.add(token)
            normalized.append(token)

        return normalized

    def _normalize_evidence_tokens(self, evidence_tokens: list[str] | None) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for item in evidence_tokens or []:
            token = str(item or "").strip()
            if not token:
                continue
            upper_token = token.upper()
            if upper_token in seen:
                continue
            seen.add(upper_token)
            normalized.append(upper_token)

        return normalized

    def _matches_any_evidence_token(self, haystack: str, tokens: list[str]) -> bool:
        if not tokens:
            return False
        upper_haystack = str(haystack or "").upper()
        return any(token in upper_haystack for token in tokens)

    def _matches_any_keyword(self, haystack: str, keywords: list[str]) -> bool:
        return any(token in haystack for token in keywords)

    def _score_compare_commit(
        self,
        *,
        title: str,
        message: str,
        platform_match: bool,
        strict_commit_platform: bool,
        normalized_soft_keywords: list[str],
        normalized_evidence_tokens: list[str],
    ) -> float:
        title_text = str(title or "")
        message_text = str(message or "")
        combined = f"{title_text}\n{message_text}"
        lowered_title = title_text.lower()
        lowered_message = message_text.lower()
        lowered_combined = combined.lower()

        has_security_identifier = bool(self._SECURITY_ID_RE.search(combined))
        if has_security_identifier:
            return 1.0

        if self._matches_any_evidence_token(combined, normalized_evidence_tokens):
            return 0.95

        score = 0.18
        if normalized_soft_keywords:
            title_hits = sum(1 for token in normalized_soft_keywords if token in lowered_title)
            message_hits = sum(1 for token in normalized_soft_keywords if token in lowered_message)
            if title_hits > 0 and message_hits > 0:
                score = 0.78
            elif title_hits > 0:
                score = 0.72
            elif message_hits > 0:
                score = 0.62

        if platform_match:
            score += 0.05
        elif not strict_commit_platform:
            score -= 0.05

        is_autoroller = any(hint in lowered_combined for hint in self._AUTOROLLER_HINTS)
        if is_autoroller:
            score = min(score, 0.12)

        return round(max(0.05, min(score, 1.0)), 3)

    def _parse_json_with_optional_xssi(self, text: str) -> Any:
        payload = str(text or "")
        stripped = payload.lstrip()
        if stripped.startswith(")]}'"):
            lines = stripped.splitlines()
            payload = "\n".join(lines[1:]) if len(lines) > 1 else ""
        return json.loads(payload)

    def _build_googlesource_file_url(self, ref: str, filename: str, *, raw: bool) -> str:
        safe_ref = quote(str(ref or "").strip(), safe="")
        safe_filename = quote(str(filename or "").strip().lstrip("/"), safe="/")
        if not safe_ref or not safe_filename:
            return ""

        suffix = "?format=TEXT" if raw else ""
        return f"{self._PDFIUM_GOOGLESOURCE_BASE}/+/{safe_ref}/{safe_filename}{suffix}"

    def _parse_unified_patch_sections(self, patch_text: str) -> list[dict[str, Any]]:
        sections: list[list[str]] = []
        current: list[str] = []

        for line in str(patch_text or "").splitlines():
            if line.startswith("diff --git "):
                if current:
                    sections.append(current)
                current = [line]
                continue
            if current:
                current.append(line)

        if current:
            sections.append(current)

        parsed: list[dict[str, Any]] = []
        for section_lines in sections:
            header = section_lines[0]
            match = re.match(r"diff --git a/(?P<old>.+?) b/(?P<new>.+)$", header)
            if not match:
                continue

            old_path = match.group("old")
            new_path = match.group("new")
            status = "modified"
            filename = new_path
            rename_to = ""

            for marker in section_lines[1:40]:
                if marker.startswith("new file mode "):
                    status = "added"
                elif marker.startswith("deleted file mode "):
                    status = "removed"
                    filename = old_path
                elif marker.startswith("rename from "):
                    status = "renamed"
                elif marker.startswith("rename to "):
                    status = "renamed"
                    rename_to = marker[len("rename to ") :].strip()

            if rename_to:
                filename = rename_to

            additions = sum(1 for line in section_lines if line.startswith("+") and not line.startswith("+++"))
            deletions = sum(1 for line in section_lines if line.startswith("-") and not line.startswith("---"))

            parsed.append(
                {
                    "filename": filename,
                    "status": status,
                    "additions": additions,
                    "deletions": deletions,
                    "changes": additions + deletions,
                    "patch": "\n".join(section_lines),
                }
            )

        return parsed

    def _merge_file_status(self, prior: str, current: str) -> str:
        normalized_prior = str(prior or "").strip().lower()
        normalized_current = str(current or "").strip().lower()
        if normalized_prior == normalized_current:
            return normalized_current or normalized_prior

        priority = {
            "removed": 4,
            "added": 3,
            "renamed": 2,
            "modified": 1,
        }
        prior_weight = priority.get(normalized_prior, 0)
        current_weight = priority.get(normalized_current, 0)
        return normalized_prior if prior_weight >= current_weight else normalized_current

    def _get_pdfium_googlesource_compare_payload(
        self,
        *,
        base_ref: str,
        head_ref: str,
    ) -> tuple[dict[str, Any] | None, str | None]:
        safe_base = quote(str(base_ref or "").strip(), safe="")
        safe_head = quote(str(head_ref or "").strip(), safe="")
        if not safe_base or not safe_head:
            return None, "Missing base/head refs for pdfium.googlesource compare."

        log_url = f"{self._PDFIUM_GOOGLESOURCE_BASE}/+log/{safe_base}..{safe_head}?format=JSON"
        status, log_text, error = self._http.try_get_text(log_url, headers={"Accept": "application/json, text/plain, */*"})
        if status >= 400 or not log_text:
            return None, f"log lookup failed: {error}"

        try:
            parsed_log = self._parse_json_with_optional_xssi(log_text)
        except (json.JSONDecodeError, ValueError) as exc:
            return None, f"Could not parse log payload: {exc}"

        if not isinstance(parsed_log, dict):
            return None, "Unexpected log payload shape from pdfium.googlesource."

        log_items = [item for item in (parsed_log.get("log") or []) if isinstance(item, dict)]
        commits_payload: list[dict[str, Any]] = []
        file_map: dict[str, dict[str, Any]] = {}

        for item in log_items:
            sha = str(item.get("commit", "") or "").strip()
            if not sha:
                continue

            message = str(item.get("message", "") or "")
            author = item.get("author") if isinstance(item.get("author"), dict) else {}
            author_name = str((author or {}).get("name", "") or "")
            author_time = str((author or {}).get("time", "") or "")

            commits_payload.append(
                {
                    "sha": sha,
                    "html_url": f"{self._PDFIUM_GOOGLESOURCE_BASE}/+/{sha}",
                    "commit": {
                        "message": message,
                        "author": {
                            "name": author_name,
                            "date": author_time,
                        },
                    },
                }
            )

            patch_url = f"{self._PDFIUM_GOOGLESOURCE_BASE}/+/{quote(sha, safe='')}^!?format=TEXT"
            patch_status, patch_b64, _patch_error = self._http.try_get_text(
                patch_url,
                headers={"Accept": "text/plain, */*"},
            )
            if patch_status >= 400 or not patch_b64:
                continue

            try:
                patch_bytes = base64.b64decode(patch_b64.encode("utf-8"), validate=False)
                patch_text = patch_bytes.decode("utf-8", errors="replace")
            except (binascii.Error, ValueError):
                continue

            for section in self._parse_unified_patch_sections(patch_text):
                filename = str(section.get("filename", "") or "").strip().lstrip("/")
                if not filename:
                    continue

                existing = file_map.get(filename)
                if existing is None:
                    file_map[filename] = {
                        "filename": filename,
                        "status": str(section.get("status", "modified") or "modified"),
                        "additions": int(section.get("additions", 0) or 0),
                        "deletions": int(section.get("deletions", 0) or 0),
                        "changes": int(section.get("changes", 0) or 0),
                        "blob_url": self._build_googlesource_file_url(head_ref, filename, raw=False),
                        "raw_url": self._build_googlesource_file_url(head_ref, filename, raw=True),
                        "head_raw_url": self._build_googlesource_file_url(head_ref, filename, raw=True),
                        "base_raw_url": self._build_googlesource_file_url(base_ref, filename, raw=True),
                        "patch": str(section.get("patch", "") or ""),
                    }
                    continue

                existing["status"] = self._merge_file_status(existing.get("status", "modified"), section.get("status", "modified"))
                existing["additions"] = int(existing.get("additions", 0) or 0) + int(section.get("additions", 0) or 0)
                existing["deletions"] = int(existing.get("deletions", 0) or 0) + int(section.get("deletions", 0) or 0)
                existing["changes"] = int(existing.get("changes", 0) or 0) + int(section.get("changes", 0) or 0)

                combined_patch = f"{existing.get('patch', '')}\n\n{str(section.get('patch', '') or '')}".strip()
                existing["patch"] = combined_patch[:20000]

        files_payload = list(file_map.values())
        return {
            "status": "ok",
            "commits": commits_payload,
            "files": files_payload,
            "base_ref": base_ref,
            "head_ref": head_ref,
            "compare_url": f"{self._PDFIUM_GOOGLESOURCE_BASE}/+log/{safe_base}..{safe_head}",
            "total_commits": len(commits_payload),
            "ahead_by": len(commits_payload),
            "behind_by": 0,
            "total_files": len(files_payload),
            "truncated": False,
        }, None

    def _build_raw_url(self, repo: str, ref: str, filename: str) -> str:
        safe_repo = str(repo or "").strip("/")
        safe_ref = quote(str(ref or "").strip(), safe="")
        safe_filename = quote(str(filename or "").strip().lstrip("/"), safe="/")
        if not safe_repo or not safe_ref or not safe_filename:
            return ""
        return f"https://raw.githubusercontent.com/{safe_repo}/{safe_ref}/{safe_filename}"

    def _build_file_key(self, component: CompareComponent, filename: str) -> str:
        return f"{component.value}:{str(filename or '').strip().lower()}"

    def _version_sort_key(self, version: str) -> tuple[int, int, int, int]:
        try:
            parts = [int(item) for item in version.split(".") if item.strip()]
        except ValueError:
            return (0, 0, 0, 0)

        while len(parts) < 4:
            parts.append(0)
        return tuple(parts[:4])
