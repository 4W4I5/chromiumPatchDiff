from __future__ import annotations

import json
import re
from pathlib import Path

from config import PipelineConfig
from models import CveRecord
from sources.cve_utils import normalize_cve_record


class CveLocalListSource:
    name = "cve-local"

    def __init__(self, config: PipelineConfig):
        self._config = config
        self._repo_root = Path(__file__).resolve().parent.parent

    def search(self, version: str, limit: int) -> tuple[list[CveRecord], list[str]]:
        warnings: list[str] = []
        if not self._config.local_cvelist_enabled:
            warnings.append("Local cvelist source is disabled (LOCAL_CVELIST_ENABLED=false).")
            return [], warnings

        root = self._resolve_root_path()
        if root is None:
            warnings.append("Local cvelist folder not found. Set LOCAL_CVELIST_PATH to your extracted cvelistv5 root.")
            return [], warnings

        tokens = self._build_query_tokens(version)
        collected: dict[str, CveRecord] = {}
        parse_failures = 0

        # First pass: delta.json is tiny and often contains the latest updates.
        for candidate in self._candidate_paths_from_delta(root):
            record, failed = self._load_if_match(candidate, tokens)
            parse_failures += int(failed)
            if record is not None and record.cve_id not in collected:
                collected[record.cve_id] = record
                if len(collected) >= limit:
                    return list(collected.values())[:limit], warnings

        year_dirs = self._year_dirs(root)
        if self._config.local_cvelist_recent_years > 0:
            year_dirs = year_dirs[: self._config.local_cvelist_recent_years]

        for year_dir in year_dirs:
            for cve_file in sorted(year_dir.rglob("CVE-*.json"), reverse=True):
                record, failed = self._load_if_match(cve_file, tokens)
                parse_failures += int(failed)
                if record is not None and record.cve_id not in collected:
                    collected[record.cve_id] = record
                    if len(collected) >= limit:
                        break
            if len(collected) >= limit:
                break

        if not collected:
            warnings.append(f"No local cvelist matches found for version '{version}' in {root}.")

        if parse_failures:
            warnings.append(f"Local cvelist had {parse_failures} JSON files that could not be parsed.")

        return list(collected.values())[:limit], warnings

    def _resolve_root_path(self) -> Path | None:
        candidates: list[Path] = []

        configured = self._config.local_cvelist_path.strip()
        if configured:
            candidates.append(Path(configured))

        candidates.extend(
            [
                self._repo_root / "cve-list",
                self._repo_root / "cvelist",
                Path("C:/cve-list"),
                Path("C:/cvelist"),
                self._repo_root / "cves",
            ]
        )

        for candidate in candidates:
            if self._is_cvelist_root(candidate):
                return candidate

        return None

    def _is_cvelist_root(self, path: Path) -> bool:
        if not path.exists() or not path.is_dir():
            return False

        if (path / "delta.json").exists():
            return True

        return any(child.is_dir() and child.name.isdigit() and len(child.name) == 4 for child in path.iterdir())

    def _build_query_tokens(self, version: str) -> list[str]:
        parts = [segment for segment in version.split(".") if segment]
        tokens = [version]
        if len(parts) >= 3:
            tokens.append(".".join(parts[:3]))

        unique: list[str] = []
        seen: set[str] = set()
        for token in tokens:
            lowered = token.lower()
            if lowered not in seen:
                seen.add(lowered)
                unique.append(lowered)
        return unique

    def _candidate_paths_from_delta(self, root: Path) -> list[Path]:
        delta_path = root / "delta.json"
        if not delta_path.exists():
            return []

        try:
            payload = json.loads(delta_path.read_text(encoding="utf-8"))
        except Exception:
            return []

        candidates: list[Path] = []
        for key in ("new", "updated"):
            entries = payload.get(key, []) if isinstance(payload, dict) else []
            if not isinstance(entries, list):
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    continue

                github_link = str(entry.get("githubLink", "") or "")
                if "/cves/" in github_link:
                    relative = github_link.split("/cves/", 1)[1]
                    candidates.append(root.joinpath(*relative.split("/")))
                    continue

                cve_id = str(entry.get("cveId", "") or "").upper()
                relative = self._cve_id_to_relative_path(cve_id)
                if relative is not None:
                    candidates.append(root / relative)

        deduped: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate)
            if key not in seen:
                seen.add(key)
                deduped.append(candidate)

        return deduped

    def _cve_id_to_relative_path(self, cve_id: str) -> Path | None:
        match = re.fullmatch(r"CVE-(\d{4})-(\d{4,7})", cve_id, re.IGNORECASE)
        if not match:
            return None

        year = match.group(1)
        serial = int(match.group(2))
        bucket = f"{serial // 1000}xxx"
        return Path(year) / bucket / f"{cve_id.upper()}.json"

    def _year_dirs(self, root: Path) -> list[Path]:
        years = [child for child in root.iterdir() if child.is_dir() and child.name.isdigit() and len(child.name) == 4]
        return sorted(years, key=lambda item: item.name, reverse=True)

    def _load_if_match(self, path: Path, tokens: list[str]) -> tuple[CveRecord | None, bool]:
        if not path.exists() or not path.is_file():
            return None, False

        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            return None, True

        lowered = text.lower()
        if not any(token in lowered for token in tokens):
            return None, False

        try:
            payload = json.loads(text)
        except Exception:
            return None, True

        if not isinstance(payload, dict):
            return None, False

        normalized = normalize_cve_record(payload, source=self.name)
        return normalized, False
