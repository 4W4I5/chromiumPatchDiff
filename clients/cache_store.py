from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class FileCacheStore:
    def __init__(self, cache_file_path: str, enabled: bool = True):
        self._enabled = enabled
        self._cache_file = Path(cache_file_path)
        self._entries: dict[str, dict[str, Any]] = {}

        if not self._enabled:
            return

        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def get(self, key: str) -> Any | None:
        if not self._enabled:
            return None

        entry = self._entries.get(key)
        if not entry:
            return None

        expires_at = float(entry.get("expires_at", 0))
        if expires_at <= time.time():
            self._entries.pop(key, None)
            self._save()
            return None

        return entry.get("value")

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        if not self._enabled or ttl_seconds <= 0:
            return

        self._entries[key] = {
            "expires_at": time.time() + ttl_seconds,
            "value": value,
        }
        self._save()

    def _load(self) -> None:
        if not self._cache_file.exists():
            self._entries = {}
            return

        try:
            payload = json.loads(self._cache_file.read_text(encoding="utf-8"))
            entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
            self._entries = entries if isinstance(entries, dict) else {}
        except (OSError, json.JSONDecodeError):
            self._entries = {}

    def _save(self) -> None:
        payload = {"entries": self._entries}
        try:
            self._cache_file.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
        except OSError:
            # Cache persistence should never break request flow.
            return
