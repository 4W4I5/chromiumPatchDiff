"""CLI entrypoint for realtime Chrome CVE enrichment."""

from __future__ import annotations

import argparse
import json
import re
import sys
import webbrowser
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from colorama import Fore, Style
from colorama import init as colorama_init

from chrome import Chrome
from clients.http_client import HttpClient
from config import PipelineConfig, SourceMode
from exporters.xlsx_exporter import write_compare_xlsx, write_enrichment_xlsx
from pipeline.orchestrator import EnrichmentOrchestrator
from sources.chromium_source import ChromiumMirrorSource
from sources.cve_local_source import CveLocalListSource


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch Chrome CVEs in realtime and enrich with Chromium commits + optional NVD data.")
    parser.add_argument(
        "version",
        nargs="?",
        help=(
            "Chrome version (e.g., 146.0.7680.178). In enrich mode this is the target version; "
            "in compare mode this can be used as the head version."
        ),
    )
    parser.add_argument(
        "--task",
        choices=["enrich", "compare"],
        help="Task to run: enrich (default) or compare.",
    )
    parser.add_argument(
        "--mode",
        choices=[mode.value for mode in SourceMode],
        help="CVE source mode override: auto, authenticated, or public",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum CVE records to process (default: 25)",
    )
    parser.add_argument(
        "--no-nvd",
        action="store_true",
        help="Disable optional NVD enrichment",
    )
    parser.add_argument(
        "--base-version",
        help=(
            "Optional base Chrome version. In enrich mode this scopes compare commits; "
            "in compare mode this is the left/older version (e.g., 146.0.7680.165)."
        ),
    )
    parser.add_argument(
        "--head-version",
        help="Optional head Chrome version for compare mode (e.g., 146.0.7680.178).",
    )
    parser.add_argument(
        "--compare-output",
        choices=["browser", "xlsx", "both"],
        default="browser",
        help="Compare task output mode: open browser, write XLSX, or both (default: browser).",
    )
    parser.add_argument(
        "--output",
        help="Optional output JSON file path",
    )
    parser.add_argument(
        "--xlsx-output",
        help=(
            "XLSX report output path. Defaults to reports/cve_enrichment_<version>.xlsx in enrich mode "
            "and reports/github_compare_<base>_to_<head>.xlsx in compare mode."
        ),
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        default=False,
        help="Print full JSON result to stdout (disabled by default)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Print step-by-step runtime progress to stderr",
    )
    return parser.parse_args()


def _version_sort_key(version: str) -> tuple[int, int, int, int]:
    try:
        parts = [int(item) for item in version.split(".") if item.strip()]
    except ValueError:
        return (0, 0, 0, 0)

    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def _major_minor_key(version: str) -> tuple[int, int]:
    major, minor, _, _ = _version_sort_key(version)
    return (major, minor)


def _fetch_recent_chrome_versions(limit: int | None = None, verbose: bool = False) -> list[str]:
    url = "https://chromium.googlesource.com/chromium/src.git/+refs"
    payload = ""
    headers = {
        "User-Agent": "chromiumPatchDiff/1.0 (+https://chromium.googlesource.com/chromium/src.git/+refs)",
        "Accept": "text/html,application/xhtml+xml",
    }

    for attempt in range(1, 4):
        try:
            response = requests.get(url, timeout=20, headers=headers)
            response.raise_for_status()
            payload = response.text
            break
        except requests.RequestException as exc:
            if verbose:
                print(
                    f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                    f"{Fore.YELLOW}Version list fetch attempt {attempt}/3 failed:{Style.RESET_ALL} {exc}",
                    file=sys.stderr,
                )

    if not payload:
        if verbose:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} " f"{Fore.YELLOW}Unable to load Chromium tag list after retries.{Style.RESET_ALL}",
                file=sys.stderr,
            )
        return []

    versions: set[str] = set()
    version_pattern = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(payload, "html.parser")
        tags_column = None
        for column in soup.select("div.RefList.RefList--column"):
            heading = column.find("h3")
            if heading and heading.get_text(strip=True).lower() == "tags":
                tags_column = column
                break

        anchors = tags_column.select("li.RefList-item a") if tags_column is not None else []
        for anchor in anchors:
            candidate = anchor.get_text(strip=True)
            if version_pattern.fullmatch(candidate):
                versions.add(candidate)

        if not versions:
            if verbose:
                print(
                    f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                    f"{Fore.YELLOW}Tags column parse was empty; scanning all refs/tags anchors.{Style.RESET_ALL}",
                    file=sys.stderr,
                )

            href_pattern = re.compile(r"/\+/refs/tags/(\d+\.\d+\.\d+\.\d+)$")
            for anchor in soup.select("a[href*='/+/refs/tags/']"):
                candidate = anchor.get_text(strip=True)
                if version_pattern.fullmatch(candidate):
                    versions.add(candidate)
                    continue

                href = (anchor.get("href") or "").strip()
                match = href_pattern.search(href)
                if match:
                    versions.add(match.group(1))
    except ModuleNotFoundError:
        if verbose:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                f"{Fore.YELLOW}bs4 is not installed; using regex fallback for Chromium tag parsing.{Style.RESET_ALL}",
                file=sys.stderr,
            )

        for candidate in re.findall(r"/\+/refs/tags/(\d+\.\d+\.\d+\.\d+)", payload):
            if version_pattern.fullmatch(candidate):
                versions.add(candidate)

    if verbose:
        print(
            f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} " f"{Fore.GREEN}Discovered {len(versions)} Chromium versions from tags.{Style.RESET_ALL}",
            file=sys.stderr,
        )

    sorted_versions = sorted(versions, key=_version_sort_key, reverse=True)
    if limit is None or limit <= 0:
        return sorted_versions
    return sorted_versions[:limit]


def _group_versions_by_major_minor(versions: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for version in versions:
        major, minor, _, _ = _version_sort_key(version)
        branch = f"{major}.{minor}"
        grouped.setdefault(branch, []).append(version)

    for branch in grouped:
        grouped[branch] = sorted(set(grouped[branch]), key=_version_sort_key, reverse=True)

    return grouped


def _prompt_choice(prompt: str) -> str:
    return input(prompt).strip().lower()


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _visible_len(text: str) -> int:
    return len(_strip_ansi(text))


def _pad_visible(text: str, width: int) -> str:
    return text + (" " * max(0, width - _visible_len(text)))


def _render_paginated_two_column(options: list[str], formatter, page: int, page_size: int = 20) -> tuple[int, int, int, int]:
    if not options:
        return (1, 0, 1, 0)

    normalized_page_size = max(2, page_size)
    total_items = len(options)
    total_pages = (total_items + normalized_page_size - 1) // normalized_page_size
    current_page = max(0, min(page, total_pages - 1))

    start_idx = current_page * normalized_page_size
    end_idx = min(start_idx + normalized_page_size, total_items)
    page_items = options[start_idx:end_idx]

    formatted_lines = [formatter(start_idx + offset + 1, item) for offset, item in enumerate(page_items)]
    rows = (len(formatted_lines) + 1) // 2

    left_lines = formatted_lines[:rows]
    right_lines = formatted_lines[rows:]
    left_width = max((_visible_len(line) for line in left_lines), default=0)

    for row_idx in range(rows):
        left = left_lines[row_idx]
        right = right_lines[row_idx] if row_idx < len(right_lines) else ""
        print(f"  {_pad_visible(left, left_width)}    {right}".rstrip())

    return (start_idx + 1, end_idx, total_pages, current_page)


def _normalize_version_parts(value: str) -> list[int]:
    parts: list[int] = []
    for chunk in value.split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if digits:
            parts.append(int(digits))
        else:
            parts.append(0)
    return parts


def _compare_versions(left: str, right: str) -> int:
    if not left or not right:
        return 0

    left_parts = _normalize_version_parts(left)
    right_parts = _normalize_version_parts(right)
    max_len = max(len(left_parts), len(right_parts))

    left_parts.extend([0] * (max_len - len(left_parts)))
    right_parts.extend([0] * (max_len - len(right_parts)))

    for l_item, r_item in zip(left_parts, right_parts):
        if l_item < r_item:
            return -1
        if l_item > r_item:
            return 1
    return 0


def _record_matches_full_version_for_menu(record: Any, full_version: str) -> bool:
    full_lower = full_version.lower()
    cve_blob = " ".join(
        [
            getattr(record, "title", ""),
            getattr(record, "description", ""),
            " ".join(getattr(record, "affected_versions", []) or []),
            " ".join(getattr(record, "references", []) or []),
        ]
    ).lower()

    if full_lower in cve_blob:
        return True

    raw = getattr(record, "raw", {}) or {}
    if not isinstance(raw, dict):
        return False

    containers = raw.get("containers", {}) if isinstance(raw.get("containers"), dict) else {}
    cna = containers.get("cna", {}) if isinstance(containers.get("cna"), dict) else {}
    affected = cna.get("affected", []) if isinstance(cna.get("affected"), list) else []

    for item in affected:
        if not isinstance(item, dict):
            continue
        versions = item.get("versions", []) if isinstance(item.get("versions"), list) else []
        for entry in versions:
            if not isinstance(entry, dict):
                continue

            status = str(entry.get("status", "") or "").strip().lower()
            if status and status != "affected":
                continue

            floor = str(entry.get("version", "") or "").strip()
            less_than = str(entry.get("lessThan", "") or "").strip()
            less_than_or_equal = str(entry.get("lessThanOrEqual", "") or "").strip()

            if floor.lower() in {"", "*", "n/a", "unspecified", "all", "0"}:
                floor = ""

            if floor and less_than and _compare_versions(floor, less_than) == 0:
                floor = ""

            if floor and _compare_versions(full_version, floor) < 0:
                continue
            if less_than and _compare_versions(full_version, less_than) >= 0:
                continue
            if less_than_or_equal and _compare_versions(full_version, less_than_or_equal) > 0:
                continue

            if floor and not less_than and not less_than_or_equal:
                if full_version == floor or full_version.startswith(f"{floor}."):
                    return True
                continue

            return True

    return False


def _build_menu_cve_counter(config: PipelineConfig, verbose: bool = False):
    local_source = CveLocalListSource(config)
    cache: dict[str, str] = {}
    unavailable = False
    max_count = 500
    warmed_branches: set[str] = set()
    cache_path = Path(".cache/menu_cve_counts.json")

    if cache_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                for key, value in payload.items():
                    if isinstance(key, str) and isinstance(value, str):
                        cache[key] = value
                if verbose:
                    print(
                        f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                        f"{Fore.GREEN}Loaded {len(cache)} cached menu CVE count entries from {cache_path}.{Style.RESET_ALL}",
                        file=sys.stderr,
                    )
        except Exception:
            cache = {}
            if verbose:
                print(
                    f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                    f"{Fore.YELLOW}Menu CVE count cache could not be read; starting with empty cache.{Style.RESET_ALL}",
                    file=sys.stderr,
                )

    def _persist_cache() -> None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
        if verbose:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                f"{Fore.GREEN}Saved {len(cache)} menu CVE count entries to {cache_path}.{Style.RESET_ALL}",
                file=sys.stderr,
            )

    def _format_count_label(value: int) -> str:
        return f"{max_count}+" if value >= max_count else str(value)

    def _count_label(version_hint: str, resolve: bool = False) -> str:
        nonlocal unavailable

        key = version_hint.strip()
        if not key:
            return "n/a"
        if key in cache:
            return cache[key]
        if not resolve:
            return "..."
        if unavailable:
            cache[key] = "n/a"
            return cache[key]

        records, warnings = local_source.search(key, limit=max_count)
        if warnings and any("folder not found" in warning.lower() for warning in warnings):
            unavailable = True
            cache[key] = "n/a"
            return cache[key]

        if verbose and warnings:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} " f"{Fore.YELLOW}Menu CVE count warning for '{key}': {warnings[0]}{Style.RESET_ALL}",
                file=sys.stderr,
            )

        count = len(records)
        label = _format_count_label(count)
        cache[key] = label
        _persist_cache()
        return label

    def _warm_branch_counts(branch: str, branch_versions: list[str]) -> None:
        nonlocal unavailable

        if unavailable:
            if verbose:
                print(
                    f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                    f"{Fore.YELLOW}Skipping menu CVE count warm-up for {branch}; local source unavailable.{Style.RESET_ALL}",
                    file=sys.stderr,
                )
            return

        if branch in warmed_branches:
            if verbose:
                print(
                    f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                    f"{Fore.GREEN}Menu CVE counts for branch {branch} already warmed in this session.{Style.RESET_ALL}",
                    file=sys.stderr,
                )
            return

        if verbose:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} " f"{Fore.GREEN}Loading menu CVE counts for branch {branch}...{Style.RESET_ALL}",
                file=sys.stderr,
            )

        records, warnings = local_source.search(branch, limit=max_count)
        if warnings and any("folder not found" in warning.lower() for warning in warnings):
            unavailable = True
            cache[branch] = "n/a"
            _persist_cache()
            if verbose:
                print(
                    f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                    f"{Fore.YELLOW}Local cvelist folder missing; menu CVE counts set to n/a.{Style.RESET_ALL}",
                    file=sys.stderr,
                )
            return

        cache[branch] = _format_count_label(len(records))

        for idx, full_version in enumerate(branch_versions, start=1):
            match_count = 0
            for record in records:
                if _record_matches_full_version_for_menu(record, full_version):
                    match_count += 1

            cache[full_version] = _format_count_label(match_count)

            if verbose and (idx == 1 or idx % 25 == 0 or idx == len(branch_versions)):
                print(
                    f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                    f"{Fore.GREEN}Menu CVE count progress for {branch}: {idx}/{len(branch_versions)} versions processed.{Style.RESET_ALL}",
                    file=sys.stderr,
                )

        warmed_branches.add(branch)
        _persist_cache()
        if verbose:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} " f"{Fore.GREEN}Completed menu CVE count warm-up for branch {branch}.{Style.RESET_ALL}",
                file=sys.stderr,
            )

    return _count_label, _warm_branch_counts


def _select_version_interactively(
    config: PipelineConfig,
    verbose: bool = False,
    selection_prompt: str = "No version supplied. Select major.minor branch first:",
    manual_prompt: str = "Enter Chrome version manually (or q to quit): ",
) -> str | None:
    if verbose:
        print(
            f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
            f"{Fore.GREEN}Loading Chromium tag list for interactive version selection...{Style.RESET_ALL}",
            file=sys.stderr,
        )

    versions = _fetch_recent_chrome_versions(limit=None, verbose=verbose)
    menu_cve_count, warm_branch_counts = _build_menu_cve_counter(config=config, verbose=verbose)

    if versions:
        grouped = _group_versions_by_major_minor(versions)
        branches = sorted(grouped.keys(), key=_major_minor_key, reverse=True)

        visible_branches = branches
        branch_page = 0

        def _format_branch_option(index: int, branch: str) -> str:
            latest = grouped[branch][0] if grouped.get(branch) else ""
            version_count = len(grouped.get(branch, []))
            cve_count = menu_cve_count(branch, resolve=False)
            return (
                f"{Fore.CYAN}{index:>4}.{Style.RESET_ALL} "
                f"{Fore.GREEN}{branch}{Style.RESET_ALL} "
                f"(versions: {Fore.YELLOW}{version_count}{Style.RESET_ALL}, "
                f"CVEs: {Fore.YELLOW}{cve_count}{Style.RESET_ALL}, "
                f"latest: {Fore.CYAN}{latest}{Style.RESET_ALL})"
            )

        while True:
            print(f"{Fore.MAGENTA}{selection_prompt}{Style.RESET_ALL}")
            start_num, end_num, total_pages, branch_page = _render_paginated_two_column(
                visible_branches,
                _format_branch_option,
                page=branch_page,
                page_size=20,
            )
            print(
                f"{Fore.BLUE}Page {branch_page + 1}/{total_pages}{Style.RESET_ALL} "
                f"showing {Fore.CYAN}{start_num}-{end_num}{Style.RESET_ALL} of {Fore.CYAN}{len(visible_branches)}{Style.RESET_ALL}"
            )
            print(f"  {Fore.CYAN}n.{Style.RESET_ALL} Next page    {Fore.CYAN}p.{Style.RESET_ALL} Previous page")
            print(f"  {Fore.CYAN}m.{Style.RESET_ALL} Enter version manually    {Fore.CYAN}q.{Style.RESET_ALL} Quit")

            choice = _prompt_choice(f"{Fore.MAGENTA}Enter branch selection [{start_num}-{end_num}, n, p, m, q]: {Style.RESET_ALL}")
            if choice in {"q", "quit", "exit"}:
                return None
            if choice in {"m", "manual"}:
                break
            if choice in {"n", "next"}:
                if branch_page + 1 < total_pages:
                    branch_page += 1
                else:
                    print(f"{Fore.YELLOW}Already on the last page.{Style.RESET_ALL}")
                continue
            if choice in {"p", "prev", "previous"}:
                if branch_page > 0:
                    branch_page -= 1
                else:
                    print(f"{Fore.YELLOW}Already on the first page.{Style.RESET_ALL}")
                continue
            if choice.isdigit():
                branch_index = int(choice)
                if start_num <= branch_index <= end_num:
                    selected_branch = visible_branches[branch_index - 1]
                    branch_versions = grouped.get(selected_branch, [])
                    if not branch_versions:
                        print(f"{Fore.YELLOW}No versions found in that branch. Try again.{Style.RESET_ALL}")
                        continue

                    if menu_cve_count(selected_branch, resolve=False) == "...":
                        print(
                            f"{Fore.YELLOW}Fetching CVE counts for branch {selected_branch}; please wait...{Style.RESET_ALL}",
                            flush=True,
                        )
                    warm_branch_counts(selected_branch, branch_versions)
                    if menu_cve_count(selected_branch, resolve=False) != "...":
                        print(
                            f"{Fore.GREEN}CVE counts ready for branch {selected_branch}.{Style.RESET_ALL}",
                            flush=True,
                        )

                    version_page = 0

                    def _format_version_option(index: int, full_version: str) -> str:
                        _, _, build, patch = _version_sort_key(full_version)
                        cve_count = menu_cve_count(full_version, resolve=False)
                        return (
                            f"{Fore.CYAN}{index:>4}.{Style.RESET_ALL} "
                            f"{Fore.GREEN}{build}.{patch}{Style.RESET_ALL} -> "
                            f"{Fore.CYAN}{full_version}{Style.RESET_ALL} "
                            f"(CVEs: {Fore.YELLOW}{cve_count}{Style.RESET_ALL})"
                        )

                    while True:
                        print(f"{Fore.MAGENTA}Select build.patch for branch " f"{Fore.GREEN}{selected_branch}{Fore.MAGENTA}:{Style.RESET_ALL}")
                        start_ver, end_ver, total_ver_pages, version_page = _render_paginated_two_column(
                            branch_versions,
                            _format_version_option,
                            page=version_page,
                            page_size=20,
                        )
                        print(
                            f"{Fore.BLUE}Page {version_page + 1}/{total_ver_pages}{Style.RESET_ALL} "
                            f"showing {Fore.CYAN}{start_ver}-{end_ver}{Style.RESET_ALL} of {Fore.CYAN}{len(branch_versions)}{Style.RESET_ALL}"
                        )
                        print(f"  {Fore.CYAN}n.{Style.RESET_ALL} Next page    {Fore.CYAN}p.{Style.RESET_ALL} Previous page")
                        print(f"  {Fore.CYAN}b.{Style.RESET_ALL} Back to branch list")
                        print(f"  {Fore.CYAN}m.{Style.RESET_ALL} Enter version manually    {Fore.CYAN}q.{Style.RESET_ALL} Quit")

                        version_choice = _prompt_choice(
                            f"{Fore.MAGENTA}Enter version selection [{start_ver}-{end_ver}, n, p, b, m, q]: {Style.RESET_ALL}"
                        )
                        if version_choice in {"q", "quit", "exit"}:
                            return None
                        if version_choice in {"m", "manual"}:
                            break
                        if version_choice in {"b", "back"}:
                            break
                        if version_choice in {"n", "next"}:
                            if version_page + 1 < total_ver_pages:
                                version_page += 1
                            else:
                                print(f"{Fore.YELLOW}Already on the last page.{Style.RESET_ALL}")
                            continue
                        if version_choice in {"p", "prev", "previous"}:
                            if version_page > 0:
                                version_page -= 1
                            else:
                                print(f"{Fore.YELLOW}Already on the first page.{Style.RESET_ALL}")
                            continue
                        if version_choice.isdigit():
                            selected_version_index = int(version_choice)
                            if start_ver <= selected_version_index <= end_ver:
                                return branch_versions[selected_version_index - 1]
                        print(f"{Fore.YELLOW}Invalid selection. Try again.{Style.RESET_ALL}")

                        # continue submenu loop
                    if version_choice in {"m", "manual"}:
                        break
                    if version_choice in {"b", "back"}:
                        continue
                elif 1 <= branch_index <= len(visible_branches):
                    print(f"{Fore.YELLOW}That item is on another page. Use n/p to navigate.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}Invalid selection. Try again.{Style.RESET_ALL}")
                continue

            print(f"{Fore.YELLOW}Invalid selection. Try again.{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}Could not load Chromium version list from remote tags." f" Falling back to manual input.{Style.RESET_ALL}")
    if verbose:
        print(
            f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} " f"{Fore.YELLOW}Version list unavailable; falling back to manual input.{Style.RESET_ALL}",
            file=sys.stderr,
        )
    manual = input(f"{Fore.MAGENTA}{manual_prompt}{Style.RESET_ALL}").strip()
    if manual.lower() in {"q", "quit", "exit"}:
        return None
    return manual


def _default_xlsx_output_path(version: str) -> Path:
    safe_version = version.replace(".", "_")
    return Path("reports") / f"cve_enrichment_{safe_version}.xlsx"


def _default_compare_xlsx_output_path(base_version: str, head_version: str) -> Path:
    safe_base = base_version.replace(".", "_")
    safe_head = head_version.replace(".", "_")
    return Path("reports") / f"github_compare_{safe_base}_to_{safe_head}.xlsx"


def _select_task_interactively() -> str | None:
    options = [
        ("enrich", "List CVEs for a given chrome version"),
        ("compare", "GitHub compare between two Chrome versions"),
    ]

    while True:
        print(f"{Fore.MAGENTA}Select a task:{Style.RESET_ALL}")
        for index, (_, label) in enumerate(options, start=1):
            print(f"  {Fore.CYAN}{index}.{Style.RESET_ALL} {Fore.GREEN}{label}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}q.{Style.RESET_ALL} Quit")

        choice = _prompt_choice(f"{Fore.MAGENTA}Enter task selection [1-{len(options)}, q]: {Style.RESET_ALL}")
        if choice in {"q", "quit", "exit"}:
            return None

        if choice.isdigit():
            selected_index = int(choice)
            if 1 <= selected_index <= len(options):
                return options[selected_index - 1][0]

        print(f"{Fore.YELLOW}Invalid selection. Try again.{Style.RESET_ALL}")


def _build_compare_url(repo: str, base_version: str, head_version: str) -> str:
    repo_path = repo.strip("/") or "chromium/chromium"
    return f"https://github.com/{repo_path}/compare/{base_version}...{head_version}"


def _resolve_compare_versions(args: argparse.Namespace, config: PipelineConfig) -> tuple[str, str] | None:
    base_version = (args.base_version or "").strip()
    head_version = (args.head_version or args.version or "").strip()

    if not base_version and not sys.stdin.isatty():
        print("Compare task requires --base-version in non-interactive mode.", file=sys.stderr)
        return None

    if not head_version and not sys.stdin.isatty():
        print("Compare task requires --head-version (or positional version) in non-interactive mode.", file=sys.stderr)
        return None

    if not base_version:
        base_version = (
            _select_version_interactively(
                config=config,
                verbose=args.verbose,
                selection_prompt="Select BASE (older) Chrome version for GitHub compare:",
                manual_prompt="Enter BASE version manually (or q to quit): ",
            )
            or ""
        )

    if not head_version:
        head_version = (
            _select_version_interactively(
                config=config,
                verbose=args.verbose,
                selection_prompt="Select HEAD (newer) Chrome version for GitHub compare:",
                manual_prompt="Enter HEAD version manually (or q to quit): ",
            )
            or ""
        )

    if not base_version or not head_version:
        return None

    return base_version, head_version


def _run_compare_task(args: argparse.Namespace, config: PipelineConfig) -> int:
    resolved_versions = _resolve_compare_versions(args=args, config=config)
    if not resolved_versions:
        print("No compare versions selected. Exiting.", file=sys.stderr)
        return 1

    base_version_raw, head_version_raw = resolved_versions

    try:
        canonical_base = Chrome(base_version_raw).getVersion()
        canonical_head = Chrome(head_version_raw).getVersion()
    except ValueError as exc:
        print(f"Invalid version format: {exc}", file=sys.stderr)
        return 2

    version_cmp = _compare_versions(canonical_base, canonical_head)
    if version_cmp == 0:
        print("Base and head versions are identical; compare requires two different versions.", file=sys.stderr)
        return 2
    if version_cmp > 0:
        print(
            f"Swapping versions so compare range is older...newer ({canonical_head}...{canonical_base}).",
            file=sys.stderr,
        )
        canonical_base, canonical_head = canonical_head, canonical_base

    compare_url = _build_compare_url(config.github_repo, canonical_base, canonical_head)
    warnings: list[str] = []
    commits: list[dict[str, Any]] = []

    needs_compare_commits = args.compare_output in {"xlsx", "both"} or bool(args.output) or args.print_json
    if needs_compare_commits:
        http = HttpClient(config)
        source = ChromiumMirrorSource(http, config)
        compare_commits, compare_warnings = source.get_compare_commits(
            base_version=canonical_base,
            head_version=canonical_head,
        )
        commits = [asdict(commit) for commit in compare_commits]
        warnings.extend(compare_warnings)

    result = {
        "task": "compare",
        "compare_repo": config.github_repo,
        "compare_base_version": canonical_base,
        "compare_head_version": canonical_head,
        "compare_url": compare_url,
        "compare_commit_count": len(commits),
        "commits": commits,
        "warnings": warnings,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    browser_message = ""
    if args.compare_output in {"browser", "both"}:
        try:
            opened = webbrowser.open(compare_url, new=2)
            if opened:
                browser_message = "Browser launch requested successfully."
            else:
                browser_message = "Browser launch did not confirm; use the printed compare URL manually."
        except Exception as exc:
            browser_message = f"Browser launch failed: {exc}"

    if args.compare_output in {"xlsx", "both"}:
        xlsx_output_path = Path(args.xlsx_output) if args.xlsx_output else _default_compare_xlsx_output_path(canonical_base, canonical_head)
        write_compare_xlsx(result, str(xlsx_output_path))
        print(f"Compare XLSX written to: {xlsx_output_path}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if args.print_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"GitHub compare URL: {compare_url}")
        if browser_message:
            print(browser_message)
        if warnings:
            print(f"Compare warnings: {len(warnings)}")

    return 0


def _run_enrichment_task(args: argparse.Namespace, config: PipelineConfig) -> int:
    selected_version = args.version
    if not selected_version:
        if not sys.stdin.isatty():
            print("No version supplied and no interactive terminal detected. Provide a version argument.", file=sys.stderr)
            return 2

        selected_version = _select_version_interactively(config=config, verbose=args.verbose)
        if not selected_version:
            print("No version selected. Exiting.", file=sys.stderr)
            return 1

    try:
        selected_version = Chrome(selected_version).getVersion()
    except ValueError as exc:
        print(f"Invalid version format: {exc}", file=sys.stderr)
        return 2

    orchestrator = EnrichmentOrchestrator(config, verbose=args.verbose)
    result = orchestrator.run(
        chrome_version=selected_version,
        limit=max(1, args.limit),
        include_nvd=not args.no_nvd,
        base_version=args.base_version,
    )

    json_output = json.dumps(result, indent=2)

    if args.print_json:
        print(json_output)
    else:
        print(
            (
                f"Completed enrichment for {result.get('input_version', '')}: "
                f"matched={result.get('matched_count', 0)}, "
                f"warnings={len(result.get('warnings', []) or [])}"
            )
        )

    has_output_records = bool(result.get("cves") or [])

    if args.output and has_output_records:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_output, encoding="utf-8")
        if args.verbose:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                f"{Fore.GREEN}Wrote JSON output to:{Style.RESET_ALL} {Fore.CYAN}{output_path}{Style.RESET_ALL}",
                file=sys.stderr,
            )
    elif args.output and args.verbose:
        print(
            f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
            f"{Fore.YELLOW}Skipped JSON export because no CVE output records were produced.{Style.RESET_ALL}",
            file=sys.stderr,
        )

    if has_output_records:
        xlsx_output_path = Path(args.xlsx_output) if args.xlsx_output else _default_xlsx_output_path(selected_version)
        write_enrichment_xlsx(result, str(xlsx_output_path))
        if args.verbose:
            print(
                f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
                f"{Fore.GREEN}Wrote XLSX output to:{Style.RESET_ALL} {Fore.CYAN}{xlsx_output_path}{Style.RESET_ALL}",
                file=sys.stderr,
            )
    elif args.verbose:
        print(
            f"{Fore.MAGENTA}[VERBOSE]{Style.RESET_ALL} "
            f"{Fore.YELLOW}Skipped XLSX export because no CVE output records were produced.{Style.RESET_ALL}",
            file=sys.stderr,
        )

    return 0


def main() -> int:
    args = parse_args()
    colorama_init(autoreset=True)

    config = PipelineConfig.from_env()
    if args.mode:
        config.cve_mode = SourceMode(args.mode)

    selected_task = args.task
    if not selected_task:
        if args.head_version:
            selected_task = "compare"
        elif args.version:
            selected_task = "enrich"
        elif not sys.stdin.isatty():
            print("No task or version supplied in non-interactive mode. Use --task with required arguments.", file=sys.stderr)
            return 2
        else:
            selected_task = _select_task_interactively()
            if not selected_task:
                print("No task selected. Exiting.", file=sys.stderr)
                return 1

    if selected_task == "compare":
        return _run_compare_task(args=args, config=config)

    return _run_enrichment_task(args=args, config=config)


if __name__ == "__main__":
    raise SystemExit(main())
