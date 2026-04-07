from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from clients.cache_store import FileCacheStore
from config import PipelineConfig
from web.job_store import JobStore
from web.routes import api_router, pages_router
from web.services import AnalysisService, CveEnrichmentService, VersionCatalogService


def create_app() -> FastAPI:
    app = FastAPI(
        title="Chromium Patch Diff Web",
        version="2.0.5",
        summary="Web-based CVE and Chromium patched/unpatched diff explorer",
    )

    base_dir = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(base_dir / "templates"))

    config = PipelineConfig.from_env()
    version_catalog_service = VersionCatalogService(config)
    cve_enrichment_service = CveEnrichmentService(config)
    analysis_service = AnalysisService(config, version_catalog_service, cve_enrichment_service)

    app.state.templates = templates
    app.state.config = config
    app.state.job_store = JobStore(ttl_seconds=21600)
    app.state.source_content_cache = FileCacheStore(
        config.source_content_cache_file,
        enabled=config.cache_enabled and config.source_content_enabled,
    )
    app.state.version_catalog_service = version_catalog_service
    app.state.cve_enrichment_service = cve_enrichment_service
    app.state.analysis_service = analysis_service

    app.mount("/static", StaticFiles(directory=str(base_dir / "static")), name="static")

    app.include_router(pages_router)
    app.include_router(api_router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "runtime": "web-only"}

    return app


app = create_app()
