from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from config import CompareComponent, ComparePlatform

router = APIRouter(tags=["pages"])


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    templates = request.app.state.templates

    component_labels = {
        CompareComponent.CHROME.value: "Chrome",
        CompareComponent.PDFIUM.value: "Pdfium",
        CompareComponent.SKIA.value: "Skia",
        CompareComponent.V8.value: "V8",
    }
    platform_labels = {
        ComparePlatform.WINDOWS.value: "Windows",
        ComparePlatform.LINUX.value: "Linux",
        ComparePlatform.MACOS.value: "macOS",
        ComparePlatform.ANDROID.value: "Android",
        ComparePlatform.ALL.value: "All platforms",
    }

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "components": [
                {"value": item.value, "label": component_labels.get(item.value, item.value.title())}
                for item in CompareComponent
            ],
            "platforms": [
                {"value": item.value, "label": platform_labels.get(item.value, item.value.title())}
                for item in ComparePlatform
            ],
            "default_platform": ComparePlatform.WINDOWS.value,
        },
    )
