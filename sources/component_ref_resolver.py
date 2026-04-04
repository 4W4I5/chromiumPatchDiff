from __future__ import annotations

import re
from dataclasses import dataclass

from clients.http_client import HttpClient
from config import CompareComponent, PipelineConfig


@dataclass(frozen=True)
class ComponentRefRange:
    base_ref: str
    head_ref: str
    strategy: str


class ChromiumComponentRefResolver:
    """
    Resolves per-component compare refs for Chromium ecosystem repos.

    For CHROME, the Chromium version refs are used directly.
    For PDFIUM/SKIA/V8, refs are resolved from Chromium DEPS pins so GitHub compare
    uses valid upstream commit SHAs instead of Chromium version tags.
    """

    _DEPS_RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/chromium/chromium/{ref}/DEPS"
    _SHA_RE = r"[0-9a-f]{7,64}"

    _REVISION_KEYS: dict[CompareComponent, tuple[str, ...]] = {
        CompareComponent.PDFIUM: ("pdfium_revision", "pdfium_git_revision"),
        CompareComponent.SKIA: ("skia_revision", "skia_git_revision"),
        CompareComponent.V8: ("v8_revision", "v8_git_revision"),
    }

    _INLINE_PIN_PATTERNS: dict[CompareComponent, tuple[re.Pattern[str], ...]] = {
        CompareComponent.PDFIUM: (
            re.compile(rf"pdfium(?:\.git)?@(?P<sha>{_SHA_RE})", flags=re.IGNORECASE),
        ),
        CompareComponent.SKIA: (
            re.compile(rf"skia(?:\.git)?@(?P<sha>{_SHA_RE})", flags=re.IGNORECASE),
        ),
        CompareComponent.V8: (
            re.compile(rf"v8(?:/v8)?(?:\.git)?@(?P<sha>{_SHA_RE})", flags=re.IGNORECASE),
        ),
    }

    def __init__(self, http: HttpClient, config: PipelineConfig):
        self._http = http
        self._config = config
        self._deps_pin_cache: dict[str, dict[CompareComponent, str]] = {}

    def resolve_component_refs(
        self,
        *,
        base_version: str,
        head_version: str,
        components: list[CompareComponent],
    ) -> tuple[dict[CompareComponent, ComponentRefRange], list[str]]:
        warnings: list[str] = []
        resolved: dict[CompareComponent, ComponentRefRange] = {}

        unique_components: list[CompareComponent] = []
        seen_components: set[str] = set()
        for component in components:
            if component.value in seen_components:
                continue
            seen_components.add(component.value)
            unique_components.append(component)

        non_chrome = [item for item in unique_components if item != CompareComponent.CHROME]
        base_pins: dict[CompareComponent, str] = {}
        head_pins: dict[CompareComponent, str] = {}

        if non_chrome:
            base_pins, base_warnings = self._get_deps_component_pins(base_version)
            head_pins, head_warnings = self._get_deps_component_pins(head_version)
            warnings.extend(base_warnings)
            warnings.extend(head_warnings)

        for component in unique_components:
            if component == CompareComponent.CHROME:
                resolved[component] = ComponentRefRange(
                    base_ref=base_version,
                    head_ref=head_version,
                    strategy="chromium-version-ref",
                )
                continue

            base_ref = base_pins.get(component, "")
            head_ref = head_pins.get(component, "")
            if base_ref and head_ref:
                resolved[component] = ComponentRefRange(
                    base_ref=base_ref,
                    head_ref=head_ref,
                    strategy="chromium-deps-pin",
                )
                continue

            missing_sides: list[str] = []
            if not base_ref:
                missing_sides.append("base")
            if not head_ref:
                missing_sides.append("head")

            warnings.append(
                f"[{component.value}] Could not resolve {'/'.join(missing_sides)} ref from Chromium DEPS "
                f"for compare range {base_version}...{head_version}; compare was skipped for this component."
            )

        return resolved, warnings

    def _get_deps_component_pins(self, chromium_ref: str) -> tuple[dict[CompareComponent, str], list[str]]:
        cached = self._deps_pin_cache.get(chromium_ref)
        if cached is not None:
            return dict(cached), []

        warnings: list[str] = []
        url = self._DEPS_RAW_URL_TEMPLATE.format(ref=chromium_ref)
        status, payload, error = self._http.try_get_text(url)
        if status >= 400 or not payload:
            warnings.append(f"[deps:{chromium_ref}] Failed to fetch DEPS from Chromium mirror: {error}")
            return {}, warnings

        pins = self._extract_component_pins(payload)
        self._deps_pin_cache[chromium_ref] = dict(pins)
        return pins, warnings

    def _extract_component_pins(self, deps_text: str) -> dict[CompareComponent, str]:
        pins: dict[CompareComponent, str] = {}

        for component, keys in self._REVISION_KEYS.items():
            revision = ""
            for key in keys:
                pattern = re.compile(rf"['\"]{re.escape(key)}['\"]\s*:\s*['\"](?P<sha>{self._SHA_RE})['\"]", flags=re.IGNORECASE)
                match = pattern.search(deps_text)
                if match:
                    revision = match.group("sha")
                    break

            if revision:
                pins[component] = revision
                continue

            for pattern in self._INLINE_PIN_PATTERNS.get(component, ()):
                match = pattern.search(deps_text)
                if match:
                    pins[component] = match.group("sha")
                    break

        return pins
