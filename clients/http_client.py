from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import PipelineConfig


class HttpClient:
    def __init__(self, config: PipelineConfig):
        self._config = config
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "chromium-patch-diff/0.1",
                "Accept": "application/json, text/plain, */*",
            }
        )

        retry = Retry(
            total=config.max_retries,
            connect=config.max_retries,
            read=config.max_retries,
            status=config.max_retries,
            backoff_factor=config.retry_backoff_seconds,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def try_get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any | None, str | None]:
        try:
            response = self._session.get(
                url,
                params=params,
                headers=headers,
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException as exc:
            return 0, None, str(exc)

        try:
            payload = response.json()
        except ValueError:
            payload = None

        if response.ok:
            return response.status_code, payload, None

        detail = payload if isinstance(payload, dict) else response.text[:300]
        return response.status_code, payload, f"HTTP {response.status_code}: {detail}"

    def try_get_text(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, str | None]:
        try:
            response = self._session.get(
                url,
                params=params,
                headers=headers,
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException as exc:
            return 0, "", str(exc)

        if response.ok:
            return response.status_code, response.text, None

        return response.status_code, response.text, f"HTTP {response.status_code}: {response.text[:300]}"

    def try_post_json(
        self,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any | None, str | None]:
        try:
            response = self._session.post(
                url,
                json=json_body,
                params=params,
                headers=headers,
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException as exc:
            return 0, None, str(exc)

        try:
            payload = response.json()
        except ValueError:
            payload = None

        if response.ok:
            return response.status_code, payload, None

        detail = payload if isinstance(payload, dict) else response.text[:300]
        return response.status_code, payload, f"HTTP {response.status_code}: {detail}"
