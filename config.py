from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class SourceMode(str, Enum):
    AUTO = "auto"
    AUTHENTICATED = "authenticated"
    PUBLIC = "public"


class CompareComponent(str, Enum):
    CHROME = "chrome"
    PDFIUM = "pdfium"
    SKIA = "skia"
    V8 = "v8"


class ComparePlatform(str, Enum):
    ALL = "all"
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"


class ReleaseChannel(str, Enum):
    STABLE = "stable"
    BETA = "beta"
    DEV = "dev"
    CANARY = "canary"


COMPONENT_REPO_MAP: dict[CompareComponent, str] = {
    CompareComponent.CHROME: "chromium/chromium",
    CompareComponent.PDFIUM: "chromium/pdfium",
    CompareComponent.SKIA: "google/skia",
    CompareComponent.V8: "v8/v8",
}


def resolve_component_repo(component: CompareComponent) -> str:
    return COMPONENT_REPO_MAP.get(component, COMPONENT_REPO_MAP[CompareComponent.CHROME])


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class PipelineConfig:
    cve_mode: SourceMode = SourceMode.AUTO
    cve_api_base: str = "https://cveawg.mitre.org/api"
    cve_public_search_url_template: str = "https://www.cve.org/CVERecord/SearchResults?query={query}"
    cve_api_user: str = ""
    cve_api_org: str = ""
    cve_api_key: str = ""

    github_api_base: str = "https://api.github.com"
    github_repo: str = "chromium/chromium"
    github_token: str = ""
    github_min_request_interval_seconds: float = 0.0

    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""
    nvd_min_request_interval_seconds: float = 0.0

    timeout_seconds: int = 20
    max_retries: int = 3
    retry_backoff_seconds: float = 0.6

    cache_enabled: bool = True
    enriched_cache_file: str = ".cache/enriched_cves.json"
    enriched_cache_ttl_seconds: int = 0

    local_cvelist_enabled: bool = True
    local_cvelist_path: str = ""
    local_cvelist_recent_years: int = 25

    source_content_enabled: bool = True
    source_content_cache_file: str = ".cache/source_contents.json"
    source_content_cache_ttl_seconds: int = 21600
    source_content_max_bytes: int = 350000

    chrome_releases_cache_enabled: bool = True
    chrome_releases_cache_file: str = ".cache/chrome_releases.json"
    chrome_releases_cache_soft_ttl_seconds: int = 21600
    chrome_releases_cache_hard_ttl_seconds: int = 604800
    chrome_releases_cache_fallback_on_rate_limit_or_unreachable: bool = True

    enable_version_confidence_tiers: bool = True

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        mode_value = os.getenv("CVE_SOURCE_MODE", SourceMode.AUTO.value).strip().lower()
        mode = SourceMode(mode_value) if mode_value in {m.value for m in SourceMode} else SourceMode.AUTO

        github_token = os.getenv("GITHUB_TOKEN", "").strip()
        nvd_api_key = os.getenv("NVD_API_KEY", "").strip()

        github_default_interval = "2.0" if github_token else "7.0"
        nvd_default_interval = "2.0" if nvd_api_key else "7.0"
        chrome_releases_soft_ttl_seconds = max(60, int(os.getenv("CHROME_RELEASES_CACHE_SOFT_TTL_SECONDS", "21600")))
        chrome_releases_hard_ttl_seconds = max(
            chrome_releases_soft_ttl_seconds,
            int(os.getenv("CHROME_RELEASES_CACHE_HARD_TTL_SECONDS", "604800")),
        )

        return cls(
            cve_mode=mode,
            cve_api_base=os.getenv("CVE_API_BASE", "https://cveawg.mitre.org/api").strip(),
            cve_public_search_url_template=os.getenv(
                "CVE_PUBLIC_SEARCH_URL_TEMPLATE",
                "https://www.cve.org/CVERecord/SearchResults?query={query}",
            ).strip(),
            cve_api_user=os.getenv("CVE_API_USER", "").strip(),
            cve_api_org=os.getenv("CVE_API_ORG", "").strip(),
            cve_api_key=os.getenv("CVE_API_KEY", "").strip(),
            github_api_base=os.getenv("GITHUB_API_BASE", "https://api.github.com").strip(),
            github_repo=os.getenv("GITHUB_REPO", "chromium/chromium").strip(),
            github_token=github_token,
            github_min_request_interval_seconds=max(
                0.0,
                float(os.getenv("GITHUB_MIN_REQUEST_INTERVAL_SECONDS", github_default_interval)),
            ),
            nvd_api_base=os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0").strip(),
            nvd_api_key=nvd_api_key,
            nvd_min_request_interval_seconds=max(
                0.0,
                float(os.getenv("NVD_MIN_REQUEST_INTERVAL_SECONDS", nvd_default_interval)),
            ),
            timeout_seconds=max(1, int(os.getenv("PIPELINE_TIMEOUT_SECONDS", "20"))),
            max_retries=max(0, int(os.getenv("PIPELINE_MAX_RETRIES", "3"))),
            retry_backoff_seconds=max(0.0, float(os.getenv("PIPELINE_RETRY_BACKOFF_SECONDS", "0.6"))),
            cache_enabled=_env_bool("PIPELINE_CACHE_ENABLED", True),
            enriched_cache_file=os.getenv("ENRICHED_CACHE_FILE", ".cache/enriched_cves.json").strip(),
            enriched_cache_ttl_seconds=max(0, int(os.getenv("ENRICHED_CACHE_TTL_SECONDS", "0"))),
            local_cvelist_enabled=_env_bool("LOCAL_CVELIST_ENABLED", True),
            local_cvelist_path=os.getenv("LOCAL_CVELIST_PATH", "").strip(),
            local_cvelist_recent_years=max(0, int(os.getenv("LOCAL_CVELIST_RECENT_YEARS", "25"))),
            source_content_enabled=_env_bool("SOURCE_CONTENT_ENABLED", True),
            source_content_cache_file=os.getenv("SOURCE_CONTENT_CACHE_FILE", ".cache/source_contents.json").strip(),
            source_content_cache_ttl_seconds=max(60, int(os.getenv("SOURCE_CONTENT_CACHE_TTL_SECONDS", "21600"))),
            source_content_max_bytes=max(10000, int(os.getenv("SOURCE_CONTENT_MAX_BYTES", "350000"))),
            chrome_releases_cache_enabled=_env_bool("CHROME_RELEASES_CACHE_ENABLED", True),
            chrome_releases_cache_file=os.getenv("CHROME_RELEASES_CACHE_FILE", ".cache/chrome_releases.json").strip(),
            chrome_releases_cache_soft_ttl_seconds=chrome_releases_soft_ttl_seconds,
            chrome_releases_cache_hard_ttl_seconds=chrome_releases_hard_ttl_seconds,
            chrome_releases_cache_fallback_on_rate_limit_or_unreachable=_env_bool(
                "CHROME_RELEASES_CACHE_FALLBACK_ON_RATE_LIMIT_OR_UNREACHABLE",
                True,
            ),
            enable_version_confidence_tiers=_env_bool("ENABLE_VERSION_CONFIDENCE_TIERS", True),
        )

    @property
    def has_cve_credentials(self) -> bool:
        return bool(self.cve_api_user and self.cve_api_org and self.cve_api_key)

    @property
    def cve_auth_headers(self) -> dict[str, str]:
        if not self.has_cve_credentials:
            return {}
        return {
            "CVE-API-USER": self.cve_api_user,
            "CVE-API-ORG": self.cve_api_org,
            "CVE-API-KEY": self.cve_api_key,
        }

    @property
    def github_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    @property
    def nvd_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        return headers
