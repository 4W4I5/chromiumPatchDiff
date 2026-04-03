from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from config import CompareComponent, ComparePlatform


class InputMode(str, Enum):
    CVE = "cve"
    VERSION = "version"


class AnalysisRequest(BaseModel):
    input_mode: InputMode = InputMode.CVE
    cve_id: str = ""
    version: str = ""
    minimal_mode: bool = True
    platform: ComparePlatform = ComparePlatform.WINDOWS
    components: list[CompareComponent] = Field(
        default_factory=lambda: [
            CompareComponent.CHROME,
            CompareComponent.PDFIUM,
            CompareComponent.SKIA,
            CompareComponent.V8,
        ]
    )
    path_prefixes: list[str] = Field(default_factory=list)
    file_extensions: list[str] = Field(default_factory=list)
    keyword: str = ""
    include_nvd: bool = True
    limit: int = Field(default=25, ge=1, le=500)

    @field_validator("cve_id", "version", "keyword", mode="before")
    @classmethod
    def _normalize_scalar(cls, value: Any) -> str:
        return str(value or "").strip()

    @field_validator("path_prefixes", "file_extensions", mode="before")
    @classmethod
    def _normalize_lists(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",")]
            return [item for item in items if item]
        if isinstance(value, list):
            normalized = [str(item or "").strip() for item in value]
            return [item for item in normalized if item]
        return []

    @model_validator(mode="after")
    def _validate_mode_inputs(self) -> "AnalysisRequest":
        if self.input_mode == InputMode.CVE and not self.cve_id:
            raise ValueError("cve_id is required when input_mode='cve'.")
        if self.input_mode == InputMode.VERSION and not self.version:
            raise ValueError("version is required when input_mode='version'.")
        if not self.components:
            raise ValueError("components cannot be empty.")
        return self


class JobCreateResponse(BaseModel):
    job_id: str
    status: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    message: str
    created_at: str
    updated_at: str
    error: str = ""
    result: dict[str, Any] | None = None


class VersionsResponse(BaseModel):
    versions: list[str]
    warnings: list[str] = Field(default_factory=list)


class CveLookupResponse(BaseModel):
    cve_id: str
    found: bool
    warnings: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    record: dict[str, Any] | None = None


class DocxReportRequest(BaseModel):
    job_id: str
    file_name: str = "chromium_patch_diff_report.docx"

    @field_validator("job_id", "file_name", mode="before")
    @classmethod
    def _normalize_report_values(cls, value: Any) -> str:
        return str(value or "").strip()


class SourceFileContentRequest(BaseModel):
    file_key: str
    max_diff_lines: int = Field(default=1200, ge=100, le=4000)

    @field_validator("file_key", mode="before")
    @classmethod
    def _normalize_file_key(cls, value: Any) -> str:
        return str(value or "").strip()


class SourceFileContentResponse(BaseModel):
    file_key: str
    component: str
    repo: str
    filename: str
    base_version: str
    head_version: str
    base_content: str
    head_content: str
    unified_diff_preview: str
    warnings: list[str] = Field(default_factory=list)
