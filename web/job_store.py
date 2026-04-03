from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass
class JobRecord:
    job_id: str
    status: str
    progress: int
    message: str
    created_at: str
    updated_at: str
    error: str = ""
    result: dict[str, Any] | None = None


class JobStore:
    def __init__(self, ttl_seconds: int = 21600):
        self._ttl_seconds = max(300, int(ttl_seconds))
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()

    def create_job(self, message: str = "Queued") -> JobRecord:
        with self._lock:
            self._prune_expired_locked()
            now = self._now_iso()
            record = JobRecord(
                job_id=str(uuid.uuid4()),
                status="queued",
                progress=0,
                message=message,
                created_at=now,
                updated_at=now,
            )
            self._jobs[record.job_id] = record
            return record

    def update(self, job_id: str, *, status: str, progress: int, message: str) -> JobRecord | None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return None

            record.status = status
            record.progress = max(0, min(100, int(progress)))
            record.message = str(message or "").strip() or record.message
            record.updated_at = self._now_iso()
            return record

    def complete(self, job_id: str, result: dict[str, Any]) -> JobRecord | None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return None

            record.status = "completed"
            record.progress = 100
            record.message = "Completed"
            record.result = result
            record.error = ""
            record.updated_at = self._now_iso()
            return record

    def fail(self, job_id: str, error: str) -> JobRecord | None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return None

            record.status = "failed"
            record.progress = min(record.progress, 100)
            record.message = "Failed"
            record.error = str(error or "Unknown error")
            record.updated_at = self._now_iso()
            return record

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            self._prune_expired_locked()
            return self._jobs.get(job_id)

    def to_dict(self, record: JobRecord) -> dict[str, Any]:
        return asdict(record)

    def _prune_expired_locked(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._ttl_seconds)
        expired_ids: list[str] = []

        for job_id, record in self._jobs.items():
            updated = self._parse_iso(record.updated_at)
            if updated is None:
                continue
            if updated < cutoff:
                expired_ids.append(job_id)

        for job_id in expired_ids:
            self._jobs.pop(job_id, None)

    def _parse_iso(self, value: str) -> datetime | None:
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

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()
