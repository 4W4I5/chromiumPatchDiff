from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CommitEvidence:
    sha: str
    url: str
    title: str
    message: str = ""
    author: str = ""
    date: str = ""
    confidence: float = 0.0
    source: str = "github:chromium/chromium"

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CommitEvidence":
        return cls(
            sha=str(payload.get("sha", "")),
            url=str(payload.get("url", "")),
            title=str(payload.get("title", "")),
            message=str(payload.get("message", "")),
            author=str(payload.get("author", "")),
            date=str(payload.get("date", "")),
            confidence=float(payload.get("confidence", 0.0) or 0.0),
            source=str(payload.get("source", "github:chromium/chromium")),
        )


@dataclass
class NvdEnrichment:
    cvss_score: float | None = None
    cvss_vector: str = ""
    severity: str = ""
    weaknesses: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NvdEnrichment":
        return cls(
            cvss_score=payload.get("cvss_score"),
            cvss_vector=str(payload.get("cvss_vector", "")),
            severity=str(payload.get("severity", "")),
            weaknesses=list(payload.get("weaknesses", []) or []),
            cpes=list(payload.get("cpes", []) or []),
        )


@dataclass
class CveRecord:
    cve_id: str
    source: str
    title: str = ""
    description: str = ""
    published: str = ""
    updated: str = ""
    references: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)

    match_reason: str = ""
    match_confidence: float = 0.0

    commits: list[CommitEvidence] = field(default_factory=list)
    nvd: NvdEnrichment | None = None

    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_raw:
            data.pop("raw", None)
        return data

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CveRecord":
        commits_payload = payload.get("commits", []) or []
        nvd_payload = payload.get("nvd")

        return cls(
            cve_id=str(payload.get("cve_id", "")),
            source=str(payload.get("source", "")),
            title=str(payload.get("title", "")),
            description=str(payload.get("description", "")),
            published=str(payload.get("published", "")),
            updated=str(payload.get("updated", "")),
            references=list(payload.get("references", []) or []),
            affected_versions=list(payload.get("affected_versions", []) or []),
            match_reason=str(payload.get("match_reason", "")),
            match_confidence=float(payload.get("match_confidence", 0.0) or 0.0),
            commits=[CommitEvidence.from_dict(item) for item in commits_payload if isinstance(item, dict)],
            nvd=NvdEnrichment.from_dict(nvd_payload) if isinstance(nvd_payload, dict) else None,
            raw=dict(payload.get("raw", {}) or {}),
        )
