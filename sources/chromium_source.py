from __future__ import annotations

import re
import time
from typing import Any, Callable

from clients.http_client import HttpClient
from config import PipelineConfig
from models import CommitEvidence


class ChromiumMirrorSource:
    name = "chromium-github-mirror"

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
            # Unauthenticated GitHub requests have very low limits; keep query volume very low.
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
                title = ((commit.get("message") or "").splitlines() or [""])[0]
                confidence = 1.0 if cve_id.upper() in title.upper() else 0.75

                seen_sha.add(sha)
                commits.append(
                    CommitEvidence(
                        sha=sha,
                        url=item.get("html_url", item.get("url", "")),
                        title=title,
                        author=((commit.get("author") or {}).get("name") or ""),
                        date=((commit.get("author") or {}).get("date") or ""),
                        confidence=confidence,
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

        # Fallback for stricter API limits: inspect latest commits and filter by CVE token.
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
                    author=((commit.get("author") or {}).get("name") or ""),
                    date=((commit.get("author") or {}).get("date") or ""),
                    confidence=0.7,
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
        warnings: list[str] = []

        endpoint = f"{self._config.github_api_base}/repos/{self._config.github_repo}" f"/compare/{base_version}...{head_version}"
        self._throttle_github_requests()
        status, payload, error = self._http.try_get_json(
            endpoint,
            headers=self._config.github_headers,
        )

        if status >= 400 or not isinstance(payload, dict):
            warnings.append(f"GitHub compare failed for range {base_version}...{head_version}: {error}")
            return [], warnings

        compare_commits: list[CommitEvidence] = []
        for item in payload.get("commits", []) or []:
            if not isinstance(item, dict):
                continue

            sha = item.get("sha", "")
            commit = item.get("commit", {}) or {}
            message = commit.get("message", "") or ""
            title = (message.splitlines() or [""])[0]

            compare_commits.append(
                CommitEvidence(
                    sha=sha,
                    url=item.get("html_url", ""),
                    title=title,
                    author=((commit.get("author") or {}).get("name") or ""),
                    date=((commit.get("author") or {}).get("date") or ""),
                    confidence=0.6,
                    source="github:chromium/chromium:compare",
                )
            )

            if len(compare_commits) >= max_results:
                break

        if not compare_commits:
            warnings.append(f"GitHub compare returned no commits for range {base_version}...{head_version}.")

        return compare_commits, warnings

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
                        confidence=1.0,
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

            haystack = f"{commit.title} {commit.url}".upper()
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
                    author=commit.author,
                    date=commit.date,
                    confidence=confidence,
                    source=commit.source,
                )
            )

            if len(matches) >= max_results:
                break

        return matches
