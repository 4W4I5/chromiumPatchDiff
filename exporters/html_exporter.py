from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _safe_json(data: dict[str, Any]) -> str:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True)


def write_compare_html(result: dict[str, Any], output_path: str) -> None:
    payload = {
        "task": result.get("task", "compare"),
        "compare_repo": result.get("compare_repo", ""),
        "compare_component": result.get("compare_component", ""),
        "compare_platform": result.get("compare_platform", ""),
        "compare_release_channel": result.get("compare_release_channel", ""),
        "compare_base_version": result.get("compare_base_version", ""),
        "compare_head_version": result.get("compare_head_version", ""),
        "compare_url": result.get("compare_url", ""),
        "compare_commit_count": int(result.get("compare_commit_count", 0) or 0),
        "compare_file_count": int(result.get("compare_file_count", 0) or 0),
        "compare_path_prefixes": list(result.get("compare_path_prefixes", []) or []),
        "compare_file_extensions": list(result.get("compare_file_extensions", []) or []),
        "compare_keyword": result.get("compare_keyword", ""),
        "compare_meta": dict(result.get("compare_meta", {}) or {}),
        "warnings": list(result.get("warnings", []) or []),
        "commits": list(result.get("commits", []) or []),
        "files": list(result.get("files", []) or []),
        "generated_at": result.get("generated_at", ""),
    }

    html_template = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>chromiumPatchDiff - Compare Report</title>
  <style>
    :root {{
      --bg: #f4f7f5;
      --surface: #ffffff;
      --surface-muted: #eff4f0;
      --text: #183127;
      --muted: #5b7568;
      --accent: #0c7a4f;
      --accent-2: #d66f1e;
      --border: #d8e4dc;
      --danger: #ab3535;
      --mono: "Consolas", "Cascadia Mono", monospace;
      --sans: "Segoe UI", "Trebuchet MS", sans-serif;
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(circle at 10% 0%, #dff4e7 0%, transparent 40%),
        radial-gradient(circle at 90% 100%, #fbe8d9 0%, transparent 45%),
        var(--bg);
      min-height: 100vh;
    }}

    .layout {{
      display: grid;
      grid-template-columns: 280px 1fr;
      gap: 14px;
      padding: 14px;
    }}

    .panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 20px rgba(10, 40, 28, 0.06);
    }}

    .panel-head {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(120deg, var(--surface-muted), #f8fbf9);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }}

    .panel-head h2 {{
      margin: 0;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
    }}

    .panel-body {{
      padding: 12px;
    }}

    .filters label {{
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 4px;
    }}

    .filters input,
    .filters select {{
      width: 100%;
      margin-bottom: 10px;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
      font-size: 13px;
      font-family: var(--sans);
      background: #fff;
      color: var(--text);
    }}

    .filters button {{
      width: 100%;
      border: none;
      border-radius: 8px;
      padding: 9px;
      font-weight: 700;
      color: #fff;
      background: var(--accent);
      cursor: pointer;
    }}

    .header-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      font-size: 12px;
      color: var(--muted);
    }}

    .chip {{
      border-radius: 999px;
      background: var(--surface-muted);
      border: 1px solid var(--border);
      padding: 5px 8px;
    }}

    .content-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 14px;
    }}

    .list {{
      max-height: 360px;
      overflow: auto;
      border-top: 1px solid var(--border);
    }}

    .item {{
      border-bottom: 1px solid var(--border);
      padding: 8px 10px;
      cursor: pointer;
      transition: background 120ms ease;
    }}

    .item:hover {{ background: #f7fbf8; }}
    .item.active {{ background: #eaf6ef; border-left: 3px solid var(--accent); }}

    .item-title {{
      margin: 0 0 4px;
      font-size: 13px;
      font-weight: 600;
      word-break: break-word;
    }}

    .item-sub {{
      margin: 0;
      font-size: 12px;
      color: var(--muted);
      font-family: var(--mono);
      word-break: break-all;
    }}

    .warning {{
      background: #fef0e5;
      border: 1px solid #f2c7a7;
      color: #8a4d20;
      border-radius: 8px;
      padding: 8px;
      margin-bottom: 8px;
      font-size: 12px;
    }}

    .diff {{
      margin-top: 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      background: #fff;
    }}

    .diff-head {{
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      font-size: 12px;
      color: var(--muted);
      display: flex;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }}

    pre {{
      margin: 0;
      padding: 12px;
      font-size: 12px;
      line-height: 1.35;
      font-family: var(--mono);
      overflow: auto;
      background: #fcfffd;
      max-height: 420px;
    }}

    .footer-link {{
      margin-top: 12px;
      font-size: 12px;
      color: var(--muted);
    }}

    .footer-link a {{ color: var(--accent); }}

    @media (max-width: 980px) {{
      .layout {{ grid-template-columns: 1fr; }}
      .content-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class=\"layout\">
    <aside class=\"panel\">
      <div class=\"panel-head\"><h2>Filters</h2></div>
      <div class=\"panel-body filters\">
        <label for=\"f-component\">Component</label>
        <select id=\"f-component\">
          <option value=\"all\">All</option>
          <option value=\"chrome\">Chrome</option>
          <option value=\"pdfium\">Pdfium</option>
          <option value=\"skia\">Skia</option>
          <option value=\"v8\">V8</option>
        </select>

        <label for=\"f-platform\">Platform</label>
        <select id=\"f-platform\">
          <option value=\"all\">All</option>
          <option value=\"windows\">Windows</option>
          <option value=\"linux\">Linux</option>
          <option value=\"macos\">macOS</option>
          <option value=\"android\">Android</option>
        </select>

        <label for=\"f-release\">Release Channel</label>
        <select id=\"f-release\">
          <option value=\"all\">All</option>
          <option value=\"stable\">Stable</option>
          <option value=\"beta\">Beta</option>
          <option value=\"dev\">Dev</option>
          <option value=\"canary\">Canary</option>
        </select>

        <label for=\"f-path\">Path Prefix</label>
        <input id=\"f-path\" placeholder=\"e.g. v8/\" />

        <label for=\"f-ext\">Extension</label>
        <input id=\"f-ext\" placeholder=\"e.g. .cc\" />

        <label for=\"f-keyword\">Keyword</label>
        <input id=\"f-keyword\" placeholder=\"commit or patch keyword\" />

        <button id=\"apply\">Apply</button>
      </div>
    </aside>

    <main>
      <section class=\"panel\">
        <div class=\"panel-head\">
          <h2>Compare Summary</h2>
        </div>
        <div class=\"panel-body\">
          <div class=\"header-meta\" id=\"meta\"></div>
          <div id=\"warnings\"></div>
          <div class=\"footer-link\">GitHub Compare: <a id=\"compare-link\" href=\"#\" target=\"_blank\" rel=\"noopener\">open</a></div>
        </div>
      </section>

      <section class=\"content-grid\">
        <div class=\"panel\">
          <div class=\"panel-head\"><h2>Commits</h2></div>
          <div class=\"list\" id=\"commits\"></div>
        </div>

        <div class=\"panel\">
          <div class=\"panel-head\"><h2>Files</h2></div>
          <div class=\"list\" id=\"files\"></div>
        </div>
      </section>

      <section class=\"diff\">
        <div class=\"diff-head\" id=\"diff-head\">Select a file to inspect patch lines.</div>
        <pre id=\"diff-body\"></pre>
      </section>
    </main>
  </div>

    <script id=\"compare-data\" type=\"application/json\">__COMPARE_PAYLOAD_JSON__</script>
  <script>
    const data = JSON.parse(document.getElementById('compare-data').textContent || '{}');

    const commitsRoot = document.getElementById('commits');
    const filesRoot = document.getElementById('files');
    const diffHead = document.getElementById('diff-head');
    const diffBody = document.getElementById('diff-body');
    const warningsRoot = document.getElementById('warnings');
    const metaRoot = document.getElementById('meta');

    const fPath = document.getElementById('f-path');
    const fExt = document.getElementById('f-ext');
    const fKeyword = document.getElementById('f-keyword');
    const fComponent = document.getElementById('f-component');
    const fPlatform = document.getElementById('f-platform');
    const fRelease = document.getElementById('f-release');
    const applyBtn = document.getElementById('apply');

    if (fComponent && data.compare_component) {
      fComponent.value = (data.compare_component || '').toLowerCase();
    }
    if (fPlatform && data.compare_platform) {
      fPlatform.value = (data.compare_platform || '').toLowerCase();
    }
    if (fRelease && data.compare_release_channel) {
      fRelease.value = (data.compare_release_channel || '').toLowerCase();
    }

    document.getElementById('compare-link').href = data.compare_url || '#';
    document.getElementById('compare-link').textContent = data.compare_url || 'unavailable';

    function metaChip(label, value) {
      const span = document.createElement('span');
      span.className = 'chip';
      span.textContent = `${label}: ${value}`;
      return span;
    }

    metaRoot.appendChild(metaChip('repo', data.compare_repo || 'n/a'));
    metaRoot.appendChild(metaChip('component', data.compare_component || 'n/a'));
    metaRoot.appendChild(metaChip('platform', data.compare_platform || 'n/a'));
    metaRoot.appendChild(metaChip('channel', data.compare_release_channel || 'n/a'));
    metaRoot.appendChild(metaChip('range', `${data.compare_base_version || '?'}...${data.compare_head_version || '?'}`));
    metaRoot.appendChild(metaChip('commits', data.compare_commit_count || 0));
    metaRoot.appendChild(metaChip('files', data.compare_file_count || 0));

    (data.warnings || []).forEach((warning) => {
      const div = document.createElement('div');
      div.className = 'warning';
      div.textContent = warning;
      warningsRoot.appendChild(div);
    });

    function renderCommits(commits) {
      commitsRoot.innerHTML = '';
      if (!commits.length) {
        commitsRoot.innerHTML = '<div class="item"><p class="item-title">No commits matched filters.</p></div>';
        return;
      }
      commits.forEach((commit) => {
        const item = document.createElement('div');
        item.className = 'item';
        const title = commit.title || '(no title)';
        const sha = (commit.sha || '').slice(0, 12);
        item.innerHTML = `<p class="item-title">${title}</p><p class="item-sub">${sha} | ${commit.author || 'unknown'}</p>`;
        if (commit.url) {
          item.addEventListener('click', () => window.open(commit.url, '_blank', 'noopener'));
        }
        commitsRoot.appendChild(item);
      });
    }

    function renderFiles(files) {
      filesRoot.innerHTML = '';
      if (!files.length) {
        filesRoot.innerHTML = '<div class="item"><p class="item-title">No files matched filters.</p></div>';
        diffHead.textContent = 'No file selected.';
        diffBody.textContent = '';
        return;
      }

      files.forEach((file, index) => {
        const item = document.createElement('div');
        item.className = 'item';
        item.innerHTML = `<p class="item-title">${file.filename || '(unknown file)'}</p><p class="item-sub">+${file.additions || 0} -${file.deletions || 0} (${file.status || 'modified'})</p>`;
        item.addEventListener('click', () => {
          document.querySelectorAll('#files .item').forEach((node) => node.classList.remove('active'));
          item.classList.add('active');
          diffHead.textContent = `${file.filename || ''} | +${file.additions || 0} -${file.deletions || 0}`;
          diffBody.textContent = file.patch || '(no patch snippet returned by GitHub compare API)';
        });
        filesRoot.appendChild(item);

        if (index === 0) {
          item.classList.add('active');
          diffHead.textContent = `${file.filename || ''} | +${file.additions || 0} -${file.deletions || 0}`;
          diffBody.textContent = file.patch || '(no patch snippet returned by GitHub compare API)';
        }
      });
    }

    function platformPathRules(platform) {
      const rules = {
        windows: ['win/', 'windows/', '_win', 'win32', 'win64', 'platform/win'],
        linux: ['linux/', '_linux', 'platform/linux', 'ozone/', 'x11/', 'wayland/'],
        macos: ['mac/', 'macos/', 'darwin/', '_mac', 'platform/mac'],
        android: ['android/', '_android', 'platform/android', 'java/org/chromium/'],
      };
      return rules[platform] || [];
    }

    function platformMessageRules(platform) {
      const rules = {
        windows: ['windows', 'win32', 'win64', ' win '],
        linux: ['linux', 'x11', 'wayland', 'ozone'],
        macos: ['mac', 'macos', 'darwin'],
        android: ['android', 'play services', 'chromium android'],
      };
      return rules[platform] || [];
    }

    function pathMatchesPlatform(path, platform) {
      if (!platform || platform === 'all') return true;
      const lowerPath = (path || '').toLowerCase();
      return platformPathRules(platform).some((rule) => lowerPath.includes(rule));
    }

    function messageMatchesPlatform(message, platform) {
      if (!platform || platform === 'all') return true;
      const lowerMsg = ` ${(message || '').toLowerCase()} `;
      return platformMessageRules(platform).some((rule) => lowerMsg.includes(rule));
    }

    function applyFilters() {
      const pathPrefix = (fPath.value || '').trim().toLowerCase();
      const ext = (fExt.value || '').trim().toLowerCase();
      const keyword = (fKeyword.value || '').trim().toLowerCase();
      const component = (fComponent.value || 'all').toLowerCase();
      const platform = (fPlatform.value || 'all').toLowerCase();
      const release = (fRelease.value || 'all').toLowerCase();

      if (component !== 'all' && component !== (data.compare_component || '').toLowerCase()) {
        renderCommits([]);
        renderFiles([]);
        return;
      }

      if (release !== 'all' && release !== (data.compare_release_channel || '').toLowerCase()) {
        renderCommits([]);
        renderFiles([]);
        return;
      }

      const commits = (data.commits || []).filter((commit) => {
        if (!messageMatchesPlatform(`${commit.title || ''}\n${commit.message || ''}`, platform)) return false;
        if (!keyword) return true;
        const blob = `${commit.title || ''}\n${commit.message || ''}`.toLowerCase();
        return blob.includes(keyword);
      });

      const files = (data.files || []).filter((file) => {
        const name = (file.filename || '').toLowerCase();
        const patch = (file.patch || '').toLowerCase();
        if (!pathMatchesPlatform(name, platform)) return false;
        const normalizedPrefix = pathPrefix.startsWith('/') ? pathPrefix.slice(1) : pathPrefix;
        if (normalizedPrefix && !name.startsWith(normalizedPrefix)) return false;
        if (ext) {
          const normalizedExt = ext.startsWith('.') ? ext : `.${ext}`;
          if (!name.endsWith(normalizedExt)) return false;
        }
        if (keyword && !(name.includes(keyword) || patch.includes(keyword))) return false;
        return true;
      });

      renderCommits(commits);
      renderFiles(files);
    }

    applyBtn.addEventListener('click', applyFilters);
    applyFilters();
  </script>
</body>
</html>
"""

    html = html_template.replace("__COMPARE_PAYLOAD_JSON__", _safe_json(payload))
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
