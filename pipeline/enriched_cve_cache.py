from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from models import CveRecord


class EnrichedCveDiskCache:
    def __init__(self, cache_file: str, enabled: bool = True, ttl_seconds: int = 0):
        self._enabled = enabled
        self._cache_file = Path(cache_file)
        self._ttl_seconds = max(0, int(ttl_seconds))
        self._entries: dict[str, dict[str, Any]] = {}

        if not self._enabled:
            return

        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def get(
        self,
        cve_id: str,
        *,
        base_version: str,
        include_nvd: bool,
        current_updated: str,
    ) -> CveRecord | None:
        if not self._enabled:
            return None

        key = self._make_key(cve_id, base_version)
        entry = self._entries.get(key)
        if not isinstance(entry, dict):
            return None

        if self._ttl_seconds > 0:
            stored_at = float(entry.get("stored_at", 0))
            if (time.time() - stored_at) > self._ttl_seconds:
                self._entries.pop(key, None)
                self._save()
                return None

        cached_updated = str(entry.get("updated", ""))
        if current_updated and cached_updated and current_updated != cached_updated:
            self._entries.pop(key, None)
            self._save()
            return None

        value = entry.get("value")
        if not isinstance(value, dict):
            return None

        record = CveRecord.from_dict(value)
        if include_nvd and record.nvd is None:
            return None

        return record

    def set(
        self,
        record: CveRecord,
        *,
        base_version: str,
        include_nvd: bool,
    ) -> None:
        if not self._enabled:
            return

        key = self._make_key(record.cve_id, base_version)
        self._entries[key] = {
            "stored_at": time.time(),
            "updated": record.updated,
            "includes_nvd": include_nvd and record.nvd is not None,
            "value": record.to_dict(include_raw=False),
        }
        self._save()

    def _make_key(self, cve_id: str, base_version: str) -> str:
        normalized_base = base_version or "none"
        return f"{cve_id.upper()}|base:{normalized_base}"

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
            return
