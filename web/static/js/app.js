const form = document.getElementById("analysis-form");
const modeSelect = document.getElementById("input-mode");
const cveField = document.getElementById("field-cve");
const versionField = document.getElementById("field-version");
const versionInputMethodSelect = document.getElementById("version-input-method");
const versionManualField = document.getElementById("version-manual-field");
const versionDropdownField = document.getElementById("version-dropdown-field");
const versionMajorSelect = document.getElementById("version-major");
const versionSelect = document.getElementById("version-select");
const versionDropdownHint = document.getElementById("version-dropdown-hint");
const statusNode = document.getElementById("job-status");
const progressNode = document.getElementById("job-progress");
const summaryNode = document.getElementById("summary");
const warningsNode = document.getElementById("warnings");
const releaseBlogNode = document.getElementById("release-blog");
const compareNode = document.getElementById("compare-results");
const cveNode = document.getElementById("cve-details");
const rawNode = document.getElementById("raw-json");
const copyRawPayloadBtn = document.getElementById("copy-raw-payload");
const copyRawFeedbackNode = document.getElementById("copy-raw-feedback");
const downloadDocxBtn = document.getElementById("download-docx");
const pathPrefixesInput = document.getElementById("path-prefixes");
const directoryCatalogNode = document.getElementById("directory-catalog");
const effectiveFocusNode = document.getElementById("effective-focus");
const advancedToggleBtn = document.getElementById("advanced-toggle");
const advancedPanel = document.getElementById("advanced-panel");

let activeJobId = "";
let pollingTimer = null;
let latestResult = null;
let availableVersions = [];
let versionsLoaded = false;
let latestRequestPayload = null;
const fullSourceCache = new Map();
let copyRawFeedbackTimer = null;

modeSelect.addEventListener("change", () => {
  const mode = modeSelect.value;
  cveField.classList.toggle("hidden", mode !== "cve");
  versionField.classList.toggle("hidden", mode !== "version");

  if (mode === "version") {
    syncVersionInputMethod();
    if (!versionsLoaded) {
      loadVersionOptions();
    }
  }
});

if (versionInputMethodSelect) {
  versionInputMethodSelect.addEventListener("change", () => {
    syncVersionInputMethod();
  });
}

if (versionMajorSelect) {
  versionMajorSelect.addEventListener("change", () => {
    populateVersionSelect(versionMajorSelect.value);
  });
}

if (advancedToggleBtn) {
  advancedToggleBtn.addEventListener("click", () => {
    setAdvancedPanelVisible(!isAdvancedPanelVisible());
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  stopPolling();
  resetView();

  const payload = buildPayload();
  if (!payload) {
    return;
  }

  setStatus("Submitting job...", 2);

  try {
    const response = await fetch("/api/jobs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `Request failed with ${response.status}`);
    }

    const data = await response.json();
    activeJobId = data.job_id;
    latestRequestPayload = payload;
    setStatus(`Job queued: ${activeJobId}`, 5);
    startPolling(activeJobId);
  } catch (error) {
    setStatus(`Error creating job: ${String(error)}`, 0);
  }
});

downloadDocxBtn.addEventListener("click", async () => {
  if (!activeJobId) {
    return;
  }

  downloadDocxBtn.disabled = true;
  downloadDocxBtn.textContent = "Building DOCX...";

  try {
    const response = await fetch("/api/reports/docx", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: activeJobId,
        file_name: buildReportFileName(latestResult),
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `DOCX export failed with ${response.status}`);
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = buildReportFileName(latestResult);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    setStatus(`DOCX export error: ${String(error)}`, 100);
  } finally {
    downloadDocxBtn.textContent = "Download DOCX Report";
    downloadDocxBtn.disabled = !latestResult;
  }
});

if (copyRawPayloadBtn) {
  copyRawPayloadBtn.addEventListener("click", async () => {
    const rawText = String((rawNode && rawNode.textContent) || "").trim();
    if (!rawText || rawText === "No result yet.") {
      setCopyRawFeedback("Nothing to copy yet.", true);
      return;
    }

    const copied = await copyTextToClipboard(rawText);
    if (copied) {
      setCopyRawFeedback("Raw payload copied to clipboard.");
      return;
    }

    setCopyRawFeedback("Clipboard copy failed. Select the payload and copy manually.", true);
  });
}

function isAdvancedPanelVisible() {
  return !!advancedPanel && !advancedPanel.classList.contains("hidden");
}

function setAdvancedPanelVisible(visible) {
  if (!advancedPanel || !advancedToggleBtn) {
    return;
  }

  const show = !!visible;
  advancedPanel.classList.toggle("hidden", !show);
  advancedToggleBtn.setAttribute("aria-expanded", show ? "true" : "false");
  advancedToggleBtn.textContent = show ? "Hide Advanced Filters" : "Show Advanced Filters";
}

function buildPayload() {
  const mode = modeSelect.value;
  const cveId = document.getElementById("cve-id").value.trim();
  const version = resolveSelectedVersion();
  const advancedVisible = isAdvancedPanelVisible();

  if (mode === "cve" && !cveId) {
    setStatus("CVE mode requires a CVE ID.", 0);
    return null;
  }

  if (mode === "version" && !version) {
    if (getVersionInputMode() === "dropdown") {
      setStatus("Version mode requires selecting a Chromium version from the dropdown.", 0);
    } else {
      setStatus("Version mode requires a Chromium version.", 0);
    }
    return null;
  }

  const selectedComponents = Array.from(document.querySelectorAll("input[name='components']:checked"))
    .map((node) => node.value)
    .filter(Boolean);

  const normalizedSelectedComponents = selectedComponents.length ? selectedComponents : ["chrome"];
  const isChromeOnly = normalizedSelectedComponents.length === 1 && normalizedSelectedComponents[0] === "chrome";
  const minimalMode = !advancedVisible && isChromeOnly;

  return {
    input_mode: mode,
    cve_id: cveId,
    version,
    minimal_mode: minimalMode,
    platform: advancedVisible ? document.getElementById("platform").value : "windows",
    components: normalizedSelectedComponents,
    path_prefixes: advancedVisible ? parseCsv(pathPrefixesInput.value) : [],
    file_extensions: advancedVisible ? parseCsv(document.getElementById("file-extensions").value) : [],
    keyword: advancedVisible ? document.getElementById("keyword").value.trim() : "",
    include_nvd: advancedVisible ? document.getElementById("include-nvd").checked : true,
    limit: advancedVisible ? Number(document.getElementById("limit").value || 25) : 25,
  };
}

function getVersionInputMode() {
  if (!versionInputMethodSelect) {
    return "manual";
  }
  return versionInputMethodSelect.value === "dropdown" ? "dropdown" : "manual";
}

function resolveSelectedVersion() {
  if (getVersionInputMode() === "dropdown") {
    return String((versionSelect && versionSelect.value) || "").trim();
  }
  return document.getElementById("version").value.trim();
}

function syncVersionInputMethod() {
  const isDropdown = getVersionInputMode() === "dropdown";

  if (versionManualField) {
    versionManualField.classList.toggle("hidden", isDropdown);
  }
  if (versionDropdownField) {
    versionDropdownField.classList.toggle("hidden", !isDropdown);
  }

  if (isDropdown && !versionsLoaded) {
    loadVersionOptions();
  }
}

function setVersionLoadingState(text) {
  if (!versionSelect) {
    return;
  }

  versionSelect.innerHTML = "";
  const option = document.createElement("option");
  option.value = "";
  option.textContent = String(text || "Loading versions...");
  versionSelect.appendChild(option);
}

async function loadVersionOptions() {
  if (!versionSelect || versionsLoaded) {
    return;
  }

  setVersionLoadingState("Loading versions...");

  try {
    const response = await fetch("/api/versions?limit=750");
    if (!response.ok) {
      throw new Error(`Version lookup failed with ${response.status}`);
    }

    const data = await response.json();
    const versions = Array.isArray(data.versions) ? data.versions : [];

    availableVersions = versions
      .map((value) => String(value || "").trim())
      .filter(Boolean);

    populateMajorOptions();
    populateVersionSelect("");
    versionsLoaded = true;

    if (versionDropdownHint) {
      versionDropdownHint.textContent = `Loaded ${availableVersions.length} versions. Use major version to narrow results.`;
    }
  } catch (error) {
    setVersionLoadingState("Could not load versions");
    if (versionDropdownHint) {
      versionDropdownHint.textContent = "Dropdown versions could not be loaded. Manual typed input is still available.";
    }
  }
}

function populateMajorOptions() {
  if (!versionMajorSelect) {
    return;
  }

  const previous = String(versionMajorSelect.value || "").trim();
  const majors = Array.from(
    new Set(
      availableVersions
        .map((value) => value.split(".")[0])
        .map((value) => value.trim())
        .filter((value) => /^\d+$/.test(value))
    )
  ).sort((left, right) => Number(right) - Number(left));

  versionMajorSelect.innerHTML = "";

  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = "All major versions";
  versionMajorSelect.appendChild(allOption);

  majors.forEach((major) => {
    const option = document.createElement("option");
    option.value = major;
    option.textContent = major;
    versionMajorSelect.appendChild(option);
  });

  if (previous && majors.includes(previous)) {
    versionMajorSelect.value = previous;
  }
}

function populateVersionSelect(major) {
  if (!versionSelect) {
    return;
  }

  const targetMajor = String(major || "").trim();
  const versions = targetMajor
    ? availableVersions.filter((value) => value.startsWith(`${targetMajor}.`))
    : availableVersions;

  versionSelect.innerHTML = "";

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = versions.length
    ? "Select a Chromium version"
    : "No versions available";
  versionSelect.appendChild(placeholder);

  versions.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    versionSelect.appendChild(option);
  });
}

function parseCsv(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderDiffText(preNode, rawDiffText) {
  if (!preNode) {
    return;
  }

  const text = String(rawDiffText || "");
  preNode.innerHTML = "";

  const lines = text ? text.split("\n") : ["No diff preview available."];
  lines.forEach((line) => {
    const lineNode = document.createElement("span");
    lineNode.className = "diff-line";

    if (line.startsWith("+") && !line.startsWith("+++")) {
      lineNode.classList.add("diff-line-add");
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      lineNode.classList.add("diff-line-remove");
    } else if (line.startsWith("@@")) {
      lineNode.classList.add("diff-line-hunk");
    } else if (
      line.startsWith("diff --") ||
      line.startsWith("index ") ||
      line.startsWith("+++") ||
      line.startsWith("---")
    ) {
      lineNode.classList.add("diff-line-meta");
    } else {
      lineNode.classList.add("diff-line-context");
    }

    lineNode.textContent = line || " ";
    preNode.appendChild(lineNode);
  });
}

async function copyTextToClipboard(text) {
  const value = String(text || "");
  if (!value) {
    return false;
  }

  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_error) {
      // Fallback to execCommand path below.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();

  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (_error) {
    copied = false;
  }

  document.body.removeChild(textarea);
  return copied;
}

function setCopyRawFeedback(message, isError = false) {
  if (!copyRawFeedbackNode) {
    return;
  }

  copyRawFeedbackNode.textContent = String(message || "");
  copyRawFeedbackNode.classList.remove("hidden", "copy-feedback-error");
  if (isError) {
    copyRawFeedbackNode.classList.add("copy-feedback-error");
  }

  if (copyRawFeedbackTimer !== null) {
    window.clearTimeout(copyRawFeedbackTimer);
  }

  copyRawFeedbackTimer = window.setTimeout(() => {
    if (copyRawFeedbackNode) {
      copyRawFeedbackNode.classList.add("hidden");
      copyRawFeedbackNode.textContent = "";
      copyRawFeedbackNode.classList.remove("copy-feedback-error");
    }
    copyRawFeedbackTimer = null;
  }, 2600);
}

function startPolling(jobId) {
  const poll = async () => {
    try {
      const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`);
      if (!response.ok) {
        throw new Error(`Polling failed with ${response.status}`);
      }

      const data = await response.json();
      setStatus(data.message || data.status, Number(data.progress || 0));

      if (data.status === "completed") {
        stopPolling();
        latestResult = data.result;
        renderResult(data.result);
        downloadDocxBtn.disabled = false;
        return;
      }

      if (data.status === "failed") {
        stopPolling();
        latestResult = null;
        renderError(data.error || "Unknown failure");
        downloadDocxBtn.disabled = true;
        return;
      }

      pollingTimer = window.setTimeout(poll, 1800);
    } catch (error) {
      stopPolling();
      setStatus(`Polling error: ${String(error)}`, 0);
    }
  };

  poll();
}

function stopPolling() {
  if (pollingTimer !== null) {
    window.clearTimeout(pollingTimer);
    pollingTimer = null;
  }
}

function setStatus(message, progress) {
  statusNode.textContent = String(message || "");
  progressNode.style.width = `${Math.max(0, Math.min(100, Number(progress || 0)))}%`;
}

function resetView() {
  activeJobId = "";
  latestResult = null;
  latestRequestPayload = null;
  fullSourceCache.clear();
  summaryNode.innerHTML = "";
  warningsNode.innerHTML = "";
  releaseBlogNode.innerHTML = "";
  compareNode.innerHTML = "";
  cveNode.innerHTML = "";
  rawNode.textContent = "No result yet.";
  if (copyRawPayloadBtn) {
    copyRawPayloadBtn.disabled = true;
  }
  if (copyRawFeedbackNode) {
    copyRawFeedbackNode.classList.add("hidden");
    copyRawFeedbackNode.textContent = "";
    copyRawFeedbackNode.classList.remove("copy-feedback-error");
  }
  if (copyRawFeedbackTimer !== null) {
    window.clearTimeout(copyRawFeedbackTimer);
    copyRawFeedbackTimer = null;
  }
  downloadDocxBtn.disabled = true;

  if (effectiveFocusNode) {
    effectiveFocusNode.innerHTML = "";
    const note = document.createElement("span");
    note.className = "muted-note";
    note.textContent = "Run an analysis to see applied auto-focus filters.";
    effectiveFocusNode.appendChild(note);
  }

  directoryCatalogNode.innerHTML = "";
  const hint = document.createElement("span");
  hint.className = "muted-note";
  hint.textContent = "Run an analysis to populate directory filters.";
  directoryCatalogNode.appendChild(hint);
}

function renderError(errorText) {
  warningsNode.innerHTML = "";
  const li = document.createElement("li");
  li.textContent = String(errorText || "Unknown error");
  warningsNode.appendChild(li);
  rawNode.textContent = String(errorText || "Unknown error");
  if (copyRawPayloadBtn) {
    copyRawPayloadBtn.disabled = true;
  }
}

function renderResult(result) {
  rawNode.textContent = JSON.stringify(result, null, 2);
  if (copyRawPayloadBtn) {
    copyRawPayloadBtn.disabled = false;
  }
  if (copyRawFeedbackNode) {
    copyRawFeedbackNode.classList.add("hidden");
    copyRawFeedbackNode.textContent = "";
    copyRawFeedbackNode.classList.remove("copy-feedback-error");
  }
  renderSummary(result);
  renderEffectiveFocus(result);
  renderWarnings(result.warnings || []);
  renderCve(result);
  renderReleaseBlog(result.release_blog || {});
  renderCompare(result.compare || {});
  renderDirectoryCatalog(result.compare || {});
}

function renderSummary(result) {
  summaryNode.innerHTML = "";
  const entries = [
    ["Input mode", result.input_mode || ""],
    ["Patched version", result.patched_version || ""],
    ["Unpatched version", result.unpatched_version || ""],
    ["Compare commits", String((result.compare || {}).total_commit_count || 0)],
    ["Compare files", String((result.compare || {}).total_file_count || 0)],
    ["Generated at", result.generated_at || ""],
  ];

  entries.forEach(([label, value]) => {
    const item = document.createElement("article");
    item.className = "summary-item";

    const title = document.createElement("strong");
    title.textContent = label;

    const body = document.createElement("span");
    body.textContent = value || "-";

    item.appendChild(title);
    item.appendChild(body);
    summaryNode.appendChild(item);
  });
}

function renderEffectiveFocus(result) {
  if (!effectiveFocusNode) {
    return;
  }

  effectiveFocusNode.innerHTML = "";
  const focus = (result && typeof result === "object" && result.effective_focus && typeof result.effective_focus === "object")
    ? result.effective_focus
    : {};

  const keywordList = Array.isArray(focus.keywords) ? focus.keywords : [];
  const autoKeywordList = Array.isArray(focus.auto_keywords) ? focus.auto_keywords : [];
  const releaseKeywordList = Array.isArray(focus.release_keywords) ? focus.release_keywords : [];
  const pathHintList = Array.isArray(focus.path_hints) ? focus.path_hints : [];
  const componentList = Array.isArray(focus.components)
    ? focus.components
    : Array.isArray((latestRequestPayload || {}).components)
      ? latestRequestPayload.components
      : [];

  const rows = [
    ["Mode", focus.minimal_mode ? "Minimal" : "Advanced"],
    ["Code scope", focus.code_scope || "changed-files-only"],
    ["Components", componentList.length ? componentList.join(", ") : "chrome"],
    ["Auto keywords", autoKeywordList.length ? autoKeywordList.join(", ") : "(none)"],
    ["Release keywords", releaseKeywordList.length ? releaseKeywordList.join(", ") : "(none)"],
    ["Path hints", pathHintList.length ? pathHintList.join(", ") : "(none)"],
    ["Effective keywords", keywordList.length ? keywordList.join(", ") : "(none)"],
  ];

  rows.forEach(([label, value]) => {
    const chip = document.createElement("article");
    chip.className = "focus-chip";

    const title = document.createElement("strong");
    title.textContent = label;

    const body = document.createElement("span");
    body.textContent = String(value || "-");

    chip.appendChild(title);
    chip.appendChild(body);
    effectiveFocusNode.appendChild(chip);
  });
}

function renderWarnings(warnings) {
  warningsNode.innerHTML = "";

  if (!Array.isArray(warnings) || !warnings.length) {
    const li = document.createElement("li");
    li.textContent = "No warnings";
    warningsNode.appendChild(li);
    return;
  }

  warnings.forEach((warning) => {
    const li = document.createElement("li");
    li.textContent = String(warning);
    warningsNode.appendChild(li);
  });
}

function renderCve(result) {
  cveNode.innerHTML = "";

  const cve = result.cve || result.primary_cve || ((result.enrichment || {}).cves || [])[0];
  if (!cve) {
    cveNode.textContent = "No CVE detail payload available.";
    return;
  }

  const rows = [
    ["CVE", cve.cve_id || ""],
    ["Source", cve.source || ""],
    ["Published", cve.published || ""],
    ["Updated", cve.updated || ""],
    ["Match reason", cve.match_reason || ""],
    ["Match confidence", String(cve.match_confidence || "")],
    ["NVD severity", String((cve.nvd || {}).severity || "")],
    ["NVD score", String((cve.nvd || {}).cvss_score || "")],
  ];

  const grid = document.createElement("div");
  grid.className = "table-grid";

  rows.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "table-row";

    const key = document.createElement("strong");
    key.textContent = label;

    const val = document.createElement("span");
    val.textContent = value || "-";

    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  });

  cveNode.appendChild(grid);

  if (cve.description) {
    const p = document.createElement("p");
    p.textContent = cve.description;
    cveNode.appendChild(p);
  }
}

function renderCompare(compare) {
  compareNode.innerHTML = "";

  const components = Array.isArray(compare.components) ? compare.components : [];
  if (!components.length) {
    compareNode.textContent = "No compare components returned.";
    return;
  }

  components.forEach((component) => {
    const card = document.createElement("article");
    card.className = "component-card";

    const head = document.createElement("div");
    head.className = "component-head";

    const title = document.createElement("h4");
    title.textContent = `${component.component || "component"} (${component.repo || ""})`;

    const stats = document.createElement("span");
    stats.className = "mono";
    stats.textContent = `commits=${component.commit_count || 0} files=${component.file_count || 0}`;

    head.appendChild(title);
    head.appendChild(stats);
    card.appendChild(head);

    const commits = Array.isArray(component.commits) ? component.commits : [];
    const mappedCommits = commits.filter((item) => Array.isArray(item.mapped_release_cves) && item.mapped_release_cves.length);
    if (mappedCommits.length) {
      const mappedCveSet = new Set();
      mappedCommits.forEach((item) => {
        (item.mapped_release_cves || []).forEach((cve) => {
          const normalized = String(cve || "").trim();
          if (normalized) {
            mappedCveSet.add(normalized);
          }
        });
      });

      const mappedLine = document.createElement("p");
      mappedLine.className = "mono";
      mappedLine.textContent = `mapped_cve_commits=${mappedCommits.length} cves=${Array.from(mappedCveSet).join(", ") || "(none)"}`;
      card.appendChild(mappedLine);
    }

    const url = document.createElement("a");
    url.href = component.compare_url || "#";
    url.textContent = component.compare_url || "Compare URL";
    url.target = "_blank";
    url.rel = "noopener noreferrer";
    url.className = "mono";
    card.appendChild(url);

    const details = document.createElement("div");
    details.className = "details-grid";

    const directories = Array.isArray(component.available_directories) ? component.available_directories : [];
    if (directories.length) {
      const directorySummary = document.createElement("p");
      directorySummary.className = "mono";
      directorySummary.textContent = `directories=${directories.length}`;
      card.appendChild(directorySummary);
    }

    const files = Array.isArray(component.files) ? component.files : [];
    files.forEach((file) => {
      const node = document.createElement("details");
      const summary = document.createElement("summary");
      summary.appendChild(document.createTextNode(`${file.filename || "unknown"} [${file.status || ""}] `));

      const additionsNode = document.createElement("span");
      additionsNode.className = "diff-count-add";
      additionsNode.textContent = `+${file.additions || 0}`;
      summary.appendChild(additionsNode);

      summary.appendChild(document.createTextNode("/"));

      const deletionsNode = document.createElement("span");
      deletionsNode.className = "diff-count-remove";
      deletionsNode.textContent = `-${file.deletions || 0}`;
      summary.appendChild(deletionsNode);

      const fileActions = document.createElement("div");
      fileActions.className = "file-actions";

      const fullSourceHost = document.createElement("div");
      fullSourceHost.className = "full-source-host";

      if (file.file_key) {
        const sourceBtn = document.createElement("button");
        sourceBtn.type = "button";
        sourceBtn.className = "secondary inline-button";
        sourceBtn.textContent = "Load Full Source Diff";
        sourceBtn.addEventListener("click", () => {
          loadFullSourceForFile({
            component: component.component || "",
            file,
            hostNode: fullSourceHost,
            buttonNode: sourceBtn,
          });
        });
        fileActions.appendChild(sourceBtn);
      }

      const patch = document.createElement("pre");
      patch.className = "diff-preview";
      renderDiffText(patch, file.patch || "(No patch text)");

      node.appendChild(summary);
      node.appendChild(fileActions);
      node.appendChild(patch);
      node.appendChild(fullSourceHost);
      details.appendChild(node);
    });

    if (!files.length) {
      const empty = document.createElement("p");
      empty.textContent = "No files matched current filters.";
      details.appendChild(empty);
    }

    card.appendChild(details);
    compareNode.appendChild(card);
  });
}

function renderReleaseBlog(releaseBlog) {
  releaseBlogNode.innerHTML = "";

  const payload = (releaseBlog && typeof releaseBlog === "object") ? releaseBlog : {};
  const posts = Array.isArray(payload.posts) ? payload.posts : [];
  const selected = (payload.selected_log_range && typeof payload.selected_log_range === "object")
    ? payload.selected_log_range
    : null;

  const summary = document.createElement("p");
  summary.className = "release-summary";
  summary.textContent = `${posts.length} Stable Desktop post(s) matched.`;
  releaseBlogNode.appendChild(summary);

  const queryBugIds = Array.isArray(payload.query_cve_bug_ids) ? payload.query_cve_bug_ids : [];
  if (queryBugIds.length) {
    const bugLine = document.createElement("p");
    bugLine.className = "mono";
    bugLine.textContent = `mapped_bug_ids=${queryBugIds.join(", ")}`;
    releaseBlogNode.appendChild(bugLine);
  }

  if (selected) {
    const selectedNode = document.createElement("div");
    selectedNode.className = "release-selected";

    const rangeLine = document.createElement("p");
    const base = String(selected.base_version || "").trim();
    const head = String(selected.head_version || "").trim();
    rangeLine.textContent = `Selected range: ${base && head ? `${base}..${head}` : "(unavailable)"}`;
    selectedNode.appendChild(rangeLine);

    if (selected.post_url) {
      const postLink = document.createElement("a");
      postLink.href = String(selected.post_url);
      postLink.target = "_blank";
      postLink.rel = "noopener noreferrer";
      postLink.textContent = String(selected.post_title || "Release post");
      selectedNode.appendChild(postLink);
    }

    if (selected.log_url) {
      const logLink = document.createElement("a");
      logLink.href = String(selected.log_url);
      logLink.target = "_blank";
      logLink.rel = "noopener noreferrer";
      logLink.className = "mono";
      logLink.textContent = String(selected.log_url);
      selectedNode.appendChild(logLink);
    }

    releaseBlogNode.appendChild(selectedNode);
  }

  if (!posts.length) {
    const empty = document.createElement("p");
    empty.textContent = "No matching Stable Desktop release posts were found for this CVE query.";
    releaseBlogNode.appendChild(empty);
    return;
  }

  const list = document.createElement("div");
  list.className = "release-list";

  posts.forEach((post) => {
    if (!post || typeof post !== "object") {
      return;
    }

    const card = document.createElement("article");
    card.className = "release-card";

    const titleLink = document.createElement("a");
    titleLink.href = String(post.url || "#");
    titleLink.target = "_blank";
    titleLink.rel = "noopener noreferrer";
    titleLink.textContent = String(post.title || "Chrome Release post");
    card.appendChild(titleLink);

    const meta = document.createElement("p");
    meta.className = "release-meta";
    meta.textContent = `published=${String(post.published || "")} updated=${String(post.updated || "")}`;
    card.appendChild(meta);

    const cves = Array.isArray(post.matched_cves) ? post.matched_cves : [];
    if (cves.length) {
      const cveLine = document.createElement("p");
      cveLine.className = "mono";
      cveLine.textContent = `cves=${cves.join(", ")}`;
      card.appendChild(cveLine);
    }

    const bugIds = Array.isArray(post.matched_bug_ids) ? post.matched_bug_ids : [];
    if (bugIds.length) {
      const bugIdLine = document.createElement("p");
      bugIdLine.className = "mono";
      bugIdLine.textContent = `bug_ids=${bugIds.join(", ")}`;
      card.appendChild(bugIdLine);
    }

    const logLinks = Array.isArray(post.log_links) ? post.log_links : [];
    if (logLinks.length) {
      const logList = document.createElement("ul");
      logList.className = "release-log-list";

      logLinks.forEach((log) => {
        if (!log || typeof log !== "object") {
          return;
        }

        const li = document.createElement("li");
        const a = document.createElement("a");
        a.href = String(log.url || "#");
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.className = "mono";

        const base = String(log.base_version || "").trim();
        const head = String(log.head_version || "").trim();
        const range = (base && head) ? `${base}..${head}` : "range-unparsed";
        a.textContent = `${range} -> ${String(log.url || "")}`;

        li.appendChild(a);
        logList.appendChild(li);
      });

      card.appendChild(logList);
    }

    list.appendChild(card);
  });

  releaseBlogNode.appendChild(list);
}

function renderDirectoryCatalog(compare) {
  directoryCatalogNode.innerHTML = "";

  const payload = (compare && typeof compare === "object") ? compare : {};
  const rows = Array.isArray(payload.directory_file_counts) ? payload.directory_file_counts : [];

  if (!rows.length) {
    const empty = document.createElement("span");
    empty.className = "muted-note";
    empty.textContent = "No directory taxonomy was returned for this result.";
    directoryCatalogNode.appendChild(empty);
    return;
  }

  rows.forEach((row) => {
    if (!row || typeof row !== "object") {
      return;
    }

    const directory = String(row.directory || "").trim();
    if (!directory) {
      return;
    }

    const fileCount = Number(row.file_count || 0);
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip-button";
    chip.textContent = `${directory} (${fileCount})`;
    chip.addEventListener("click", () => appendPathPrefix(directory));
    directoryCatalogNode.appendChild(chip);
  });
}

async function loadFullSourceForFile({ component, file, hostNode, buttonNode }) {
  if (!hostNode || !file || !file.file_key) {
    return;
  }
  if (!activeJobId) {
    return;
  }

  const cacheKey = String(file.file_key);
  const cached = fullSourceCache.get(cacheKey);
  if (cached) {
    renderFullSourcePayload(cached, hostNode);
    return;
  }

  if (buttonNode) {
    buttonNode.disabled = true;
    buttonNode.textContent = "Loading Full Source...";
  }

  hostNode.innerHTML = "";
  const loading = document.createElement("p");
  loading.className = "muted-note";
  loading.textContent = "Fetching full source files for this changed file...";
  hostNode.appendChild(loading);

  try {
    const response = await fetch(`/api/jobs/${encodeURIComponent(activeJobId)}/files/content`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        file_key: cacheKey,
        max_diff_lines: 1200,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `Source content fetch failed with ${response.status}`);
    }

    const payload = await response.json();
    payload.component = payload.component || component;
    fullSourceCache.set(cacheKey, payload);
    renderFullSourcePayload(payload, hostNode);
  } catch (error) {
    hostNode.innerHTML = "";
    const warning = document.createElement("p");
    warning.className = "full-source-error";
    warning.textContent = `Could not load full source content: ${String(error)}`;
    hostNode.appendChild(warning);
  } finally {
    if (buttonNode) {
      buttonNode.disabled = false;
      buttonNode.textContent = "Load Full Source Diff";
    }
  }
}

function renderFullSourcePayload(payload, hostNode) {
  hostNode.innerHTML = "";

  const meta = document.createElement("p");
  meta.className = "mono";
  meta.textContent = `${payload.component || "component"} :: ${payload.filename || "file"} (${payload.base_version || "base"} -> ${payload.head_version || "head"})`;
  hostNode.appendChild(meta);

  const warnings = Array.isArray(payload.warnings) ? payload.warnings : [];
  if (warnings.length) {
    const list = document.createElement("ul");
    list.className = "warning-list compact";
    warnings.forEach((warning) => {
      const item = document.createElement("li");
      item.textContent = String(warning);
      list.appendChild(item);
    });
    hostNode.appendChild(list);
  }

  const diffDetails = document.createElement("details");
  const diffSummary = document.createElement("summary");
  diffSummary.textContent = "Unified diff preview";
  const diffPre = document.createElement("pre");
  diffPre.className = "diff-preview";
  renderDiffText(diffPre, payload.unified_diff_preview || "No diff preview available.");
  diffDetails.appendChild(diffSummary);
  diffDetails.appendChild(diffPre);
  hostNode.appendChild(diffDetails);

  const split = document.createElement("div");
  split.className = "source-split";

  const basePanel = document.createElement("section");
  basePanel.className = "source-panel";
  const baseTitle = document.createElement("h5");
  baseTitle.textContent = `Unpatched (${payload.base_version || "base"})`;
  const basePre = document.createElement("pre");
  basePre.textContent = String(payload.base_content || "No base content available.");
  basePanel.appendChild(baseTitle);
  basePanel.appendChild(basePre);

  const headPanel = document.createElement("section");
  headPanel.className = "source-panel";
  const headTitle = document.createElement("h5");
  headTitle.textContent = `Patched (${payload.head_version || "head"})`;
  const headPre = document.createElement("pre");
  headPre.textContent = String(payload.head_content || "No head content available.");
  headPanel.appendChild(headTitle);
  headPanel.appendChild(headPre);

  split.appendChild(basePanel);
  split.appendChild(headPanel);
  hostNode.appendChild(split);
}

function appendPathPrefix(prefix) {
  const normalized = String(prefix || "").trim();
  if (!normalized) {
    return;
  }

  const existing = parseCsv(pathPrefixesInput.value);
  if (existing.includes(normalized)) {
    return;
  }

  existing.push(normalized);
  pathPrefixesInput.value = existing.join(", ");
}

function buildReportFileName(result) {
  const patched = (result && result.patched_version) ? String(result.patched_version).replace(/\./g, "_") : "patched";
  const unpatched = (result && result.unpatched_version) ? String(result.unpatched_version).replace(/\./g, "_") : "base";
  return `chromium_patch_diff_${unpatched}_to_${patched}.docx`;
}

syncVersionInputMethod();
setAdvancedPanelVisible(false);
if (modeSelect.value === "version") {
  loadVersionOptions();
}
