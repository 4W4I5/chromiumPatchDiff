# chromiumPatchDiff

Web-only Chromium vulnerability diff explorer.

This project lets you run analysis by either CVE ID or Chromium version, then compare patched and unpatched ranges across Chromium-related repositories with platform/component/path filtering.

## What It Does

- Runs as a FastAPI web application (no CLI workflow required).
- Supports two input modes:
  - CVE mode
  - Version mode
- Resolves patched and unpatched versions.
- Uses a blog-first CVE workflow:
  - Searches Chrome Releases Stable Desktop posts for the CVE.
  - Extracts all Chromium log links.
  - Chooses a base/head range from those links when available.
  - Falls back to metadata-driven version resolution when needed.
- Compares selected components (Chrome, Pdfium, Skia, V8) using GitHub compare data.
- Resolves Pdfium/Skia/V8 compare refs from Chromium DEPS pins so non-Chrome components use valid upstream SHAs.
- Produces directory taxonomy for changed files and exposes it for filtering.
- Generates DOCX reports from completed jobs.

## Stack

- FastAPI + Uvicorn
- Jinja2 templates + static JS/CSS
- Requests + BeautifulSoup
- python-docx

## Quick Start (PowerShell)

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

1. Install dependencies:

```powershell
pip install -r .\requirements.txt
```

1. Start the app:

```powershell
python .\main.py
```

1. Open:

- <http://127.0.0.1:8000>

You can change host/port with:

- WEB_HOST (default: 127.0.0.1)
- WEB_PORT (default: 8000)

Example:

```powershell
$env:WEB_HOST = "0.0.0.0"
$env:WEB_PORT = "8010"
python .\main.py
```

## API Overview

Base routes:

- GET /healthz
- GET /

API routes:

- POST /api/jobs
- GET /api/jobs/{job_id}
- GET /api/versions
- GET /api/cve/{cve_id}
- POST /api/reports/docx

### Typical Job Flow

1. Submit a job to POST /api/jobs.
2. Poll GET /api/jobs/{job_id} until status is completed or failed.
3. If completed, use POST /api/reports/docx with that job_id to download a report.

### Analysis Request Schema

```json
{
  "input_mode": "cve",
  "cve_id": "CVE-2026-5280",
  "version": "",
  "platform": "windows",
  "components": ["chrome", "pdfium", "skia", "v8"],
  "path_prefixes": ["third_party/blink/renderer/modules/webcodecs"],
  "file_extensions": [".cc", ".h"],
  "keyword": "webcodecs",
  "include_nvd": true,
  "limit": 25
}
```

For version mode, set:

- input_mode = version
- version = full Chromium version (for example 146.0.7680.178)

### Job Result Highlights

The completed result includes, among other fields:

- patched_version
- unpatched_version
- cve
- release_blog
  - query_cve_id
  - post_count
  - posts
  - selected_log_range
- compare
  - components
    - status (changed | unchanged | filtered_out | error)
    - resolved_refs (base/head/strategy per component)
    - filter_metrics (stage-by-stage file filtering counters)
  - available_directories
  - directory_file_counts
  - filters
- notes (informational pipeline notes, such as deferred enrichment)

Filter behavior notes:

- `keyword` / manual keywords are treated as hard filters.
- Auto CVE focus keywords are treated as soft ranking signals.
- In CVE mode with platform selected, commit/file platform matching is relaxed to a ranking signal by default, then CVE soft-focus file matching is applied with fallback to hard-filtered files when needed.
- warnings
- provenance

## Data Sources

- Chrome Releases Google Blog feed (CVE search, Stable Desktop filtering, log ranges)
- ChromiumDash (version/release catalog)
- GitHub compare and tags
- CVE Services API
- Public CVE source
- Local cvelist-style JSON dataset
- NVD API (optional enrichment)

## Local CVE Dataset Behavior

The local source checks these candidates for cvelist-style data:

- LOCAL_CVELIST_PATH (if set)
- <repo_root>/cve-list
- <repo_root>/cvelist
- C:\cve-list
- C:\cvelist
- <repo_root>/cves

If not found, local source is skipped with warnings.

## Configuration (Environment Variables)

### Web Server

- WEB_HOST: bind host (default 127.0.0.1)
- WEB_PORT: bind port (default 8000)

### CVE Sources

- CVE_SOURCE_MODE: auto | authenticated | public
- CVE_API_BASE
- CVE_PUBLIC_SEARCH_URL_TEMPLATE
- CVE_API_USER
- CVE_API_ORG
- CVE_API_KEY (no built-in default; set explicitly for authenticated mode)

### GitHub

- GITHUB_API_BASE
- GITHUB_REPO
- GITHUB_TOKEN
- GITHUB_MIN_REQUEST_INTERVAL_SECONDS

### NVD

- NVD_API_BASE
- NVD_API_KEY
- NVD_MIN_REQUEST_INTERVAL_SECONDS

### Local cvelist

- LOCAL_CVELIST_ENABLED
- LOCAL_CVELIST_PATH
- LOCAL_CVELIST_RECENT_YEARS

### Pipeline/HTTP

- PIPELINE_TIMEOUT_SECONDS
- PIPELINE_MAX_RETRIES
- PIPELINE_RETRY_BACKOFF_SECONDS
- PIPELINE_CACHE_ENABLED
- ENRICHED_CACHE_FILE
- ENRICHED_CACHE_TTL_SECONDS
- ENABLE_VERSION_CONFIDENCE_TIERS

### Chrome Releases Cache

- CHROME_RELEASES_CACHE_ENABLED
- CHROME_RELEASES_CACHE_FILE
- CHROME_RELEASES_CACHE_SOFT_TTL_SECONDS
- CHROME_RELEASES_CACHE_HARD_TTL_SECONDS
- CHROME_RELEASES_CACHE_FALLBACK_ON_RATE_LIMIT_OR_UNREACHABLE

## Web UI Notes

The page at / includes:

- CVE/version input mode switch
- Version mode input method switch
  - Manual typed version input
  - Dropdown-based version selection with optional major-version dropdown filter
- Platform and component filters
- Path, extension, and keyword filters
- Directory chip list from latest compare result
  - Click chips to append to path filters
- Release blog match panel
- Raw result payload view
- DOCX download action

## Project Layout (Key Paths)

- main.py: web entrypoint
- web/app.py: FastAPI app factory
- web/routes/api.py: API routes
- web/routes/pages.py: HTML page route
- web/services/analysis.py: orchestration for CVE/version modes
- sources/chrome_releases_source.py: Chrome Releases feed parsing and log extraction
- sources/chromium_source.py: compare and commit retrieval
- web/templates/index.html: UI template
- web/static/js/app.js: UI behavior
- web/static/css/site.css: UI styling
- exporters/docx_exporter.py: DOCX report generation

## Troubleshooting

- Dependency install issues:
  - Ensure the virtual environment is activated before pip install.
- Port already in use:
  - Change WEB_PORT to another value.
- Slow CVE jobs:
  - External source calls can be rate-limited.
  - Add GITHUB_TOKEN and NVD_API_KEY where possible.
- Local cvelist warnings:
  - Set LOCAL_CVELIST_PATH to a valid extracted cvelist root.

## License

No license file is currently defined in this repository.
