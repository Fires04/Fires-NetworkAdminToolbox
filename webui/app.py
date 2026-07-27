#!/usr/bin/env python3
"""
webui/app.py - single-process web front-end combining two module shapes
into one toolbox, on one host:port:

- cli_scripts/  -- clidescribe-based CLI scripts, auto-discovered via
  `--describe`; a form + run button + console output is generated for
  each one automatically. Each run is a one-shot subprocess (there's no
  long-running process to mount for a run-and-exit script).
- apps/         -- full standalone ASGI web apps, one per subfolder with
  an app.yaml manifest (see mounts.py), mounted directly at /app/<name>
  in this same process -- no subprocess, no separate port, no HTTP proxy
  hop. html_rewrite.py patches up the mounted app's own HTML so it still
  works despite not being served from the domain root it assumes.

Both are drop-in-a-folder, zero-central-config: add a script or an app
folder and it shows up here with no other code changes.

Run:
    python3 webui/app.py

Then open http://127.0.0.1:5000/.
"""
import asyncio
import html
import json
import subprocess
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from html_rewrite import RootPathRewrite
from mounts import discover_apps

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "cli_scripts"
EXCLUDE_FILES = {"clidescribe.py"}
DESCRIBE_TIMEOUT = 5
RUN_TIMEOUT = 60

sys.path.insert(0, str(SCRIPTS_DIR))
import clidescribe  # noqa: E402  (needs SCRIPTS_DIR on sys.path first)

app = FastAPI()
app.mount("/static", StaticFiles(directory=Path(__file__).resolve().parent / "static"), name="static")

APPS = discover_apps()
for _name, _cfg in APPS.items():
    app.mount(f"/app/{_name}", RootPathRewrite(_cfg["app"], f"/app/{_name}", _name))


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def discover_tools():
    """Return {tool_name: {"path": Path, "schema": dict}} for every *.py file
    in SCRIPTS_DIR that answers `--describe` with valid clidescribe JSON."""
    tools = {}
    for path in sorted(SCRIPTS_DIR.glob("*.py")):
        if path.name in EXCLUDE_FILES:
            continue
        try:
            result = subprocess.run(
                [sys.executable, str(path), "--describe"],
                capture_output=True, text=True, timeout=DESCRIBE_TIMEOUT,
            )
            schema = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            continue
        if not isinstance(schema, dict) or "arguments" not in schema:
            continue
        tools[path.stem] = {"path": path, "schema": schema}
    return tools


# ---------------------------------------------------------------------------
# HTML (kept inline -- this is a small personal-toolbox prototype, not a
# templated multi-page app)
# ---------------------------------------------------------------------------

PAGE_HEAD = """<!doctype html>
<html lang="en" data-bs-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="/static/bootstrap.min.css">
<style>
  body {{ padding-bottom: 3rem; }}
  .navbar-brand {{ font-weight: 600; }}
  .tool-card {{ transition: transform .1s ease, border-color .1s ease; }}
  .tool-card:hover {{ transform: translateY(-2px); border-color: var(--bs-primary); }}
  .console {{
    background: #0d1117; color: #c9d1d9; border-radius: .5rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: .9rem; min-height: 420px; height: 100%;
    padding: 1rem; white-space: pre-wrap; word-break: break-word;
    overflow-y: auto; border: 1px solid #30363d;
  }}
  .console .placeholder-text {{ color: #6e7681; font-style: italic; }}
  .cmdline {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: .85rem; background: rgba(110,118,129,.15);
    border: 1px solid var(--bs-border-color); border-radius: .375rem;
    padding: .5rem .75rem; word-break: break-all;
  }}
  .status-badge {{ font-size: .8rem; }}
  .form-col {{ position: sticky; top: 1rem; }}
  @media (max-width: 991.98px) {{ .form-col {{ position: static; }} }}
</style>
</head><body>
<nav class="navbar navbar-expand navbar-dark bg-dark border-bottom border-secondary mb-4">
  <div class="container">
    <a class="navbar-brand" href="/">PyFNetwork Toolbox</a>
  </div>
</nav>
<div class="container">
"""
PAGE_TAIL = """
</div>
<script src="/static/bootstrap.bundle.min.js"></script>
</body></html>"""


def _display_name(name):
    """Turn a module's folder/file slug into a human-friendly title, e.g.
    "protocol_tester" -> "Protocol Tester", "switch-visualizer" ->
    "Switch Visualizer" -- applied uniformly so every module (CLI tool or
    app) gets the same title formatting with no per-module naming code."""
    return name.replace("-", " ").replace("_", " ").title()


def _tool_card(name, description, href, badge_text, badge_class):
    search_key = html.escape(f"{name} {description}".lower())
    return f"""
    <div class="col-md-6 col-lg-4 mb-3 tool-card-wrap" data-search="{search_key}">
      <a href="{href}" class="text-decoration-none">
        <div class="card tool-card h-100 bg-body-tertiary border-secondary-subtle">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-start">
              <h5 class="card-title text-body">{html.escape(_display_name(name))}</h5>
              <span class="badge {badge_class} status-badge">{badge_text}</span>
            </div>
            <p class="card-text text-body-secondary small">{html.escape(description)}</p>
          </div>
        </div>
      </a>
    </div>"""


def _module_section(section_id, title, cards, empty_text):
    return f"""
<section class="module-section mb-4" id="section-{section_id}">
  <h2 class="h6 text-uppercase text-body-secondary mb-3">{html.escape(title)}</h2>
  <div class="row">{cards}</div>
  <p class="text-body-secondary fst-italic mb-0 section-empty" style="display:none">{html.escape(empty_text)}</p>
</section>"""


def render_index(tools, apps):
    tool_cards = "".join(
        _tool_card(name, t["schema"].get("description", ""),
                   f"/tool/{name}", "CLI tool", "text-bg-secondary")
        for name, t in tools.items()
    )
    app_cards = "".join(
        _tool_card(name, cfg.get("description", ""), f"/app/{name}/", "Web app", "text-bg-info")
        for name, cfg in apps.items()
    )

    sections = ""
    if tools:
        sections += _module_section("cli", "CLI tools", tool_cards, "No CLI tools match your search.")
    if apps:
        sections += _module_section("apps", "Web apps", app_cards, "No web apps match your search.")
    if not tools and not apps:
        sections = '<p class="text-body-secondary fst-italic">No modules found.</p>'

    body = f"""
<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-1">
  <h1 class="h3 mb-0">Tool collection</h1>
  <input type="search" id="tool-search" class="form-control" style="max-width:280px"
         placeholder="Search tools..." autocomplete="off">
</div>
<p class="text-body-secondary mb-4">CLI tools (<code>--describe</code>-based) and full web-app modules, all in one place.</p>
{sections}

<script>
const search = document.getElementById('tool-search');
if (search) {{
  search.addEventListener('input', () => {{
    const q = search.value.trim().toLowerCase();
    document.querySelectorAll('.module-section').forEach(section => {{
      let visible = 0;
      section.querySelectorAll('.tool-card-wrap').forEach(card => {{
        const match = card.dataset.search.includes(q);
        card.style.display = match ? '' : 'none';
        if (match) visible++;
      }});
      const empty = section.querySelector('.section-empty');
      if (empty) empty.style.display = (visible === 0 && q) ? '' : 'none';
    }});
  }});
}}
</script>
"""
    return PAGE_HEAD.format(title="Tool collection") + body + PAGE_TAIL


def _field_html(arg):
    name = arg["name"]
    label = name.replace("_", " ")
    help_text = html.escape(arg.get("help", ""))
    field_id = f"f_{name}"
    help_html = f'<div class="form-text">{help_text}</div>' if help_text else ""

    if arg["type"] == "boolean":
        checked = "checked" if arg.get("default") else ""
        return f"""
<div class="form-check mb-3">
  <input type="checkbox" class="form-check-input" id="{field_id}" name="{name}" {checked}>
  <label class="form-check-label" for="{field_id}">{html.escape(label)}</label>
  {help_html}
</div>"""

    label_html = f'<label for="{field_id}" class="form-label text-capitalize">{html.escape(label)}</label>'

    if arg["type"] == "enum":
        options = ['<option value="">-- select --</option>']
        default = arg.get("default")
        for choice in arg.get("choices", []):
            sel = "selected" if choice == default else ""
            options.append(f'<option value="{html.escape(choice)}" {sel}>{html.escape(choice)}</option>')
        return f"""
<div class="mb-3">
  {label_html}
  <select class="form-select" id="{field_id}" name="{name}">{"".join(options)}</select>
  {help_html}
</div>"""

    if arg["positional"] and arg["multiple"]:
        return f"""
<div class="mb-3">
  {label_html}
  <textarea class="form-control" id="{field_id}" name="{name}" rows="3"
            placeholder="one per line, or comma-separated"></textarea>
  {help_html}
</div>"""

    input_type = "password" if "password" in name.lower() else \
                 "number" if arg["type"] in ("integer", "number") else "text"
    default = arg.get("default")
    value_attr = f'value="{html.escape(str(default))}"' if default not in (None, False) else ""
    step_attr = 'step="any"' if arg["type"] == "number" else ""
    return f"""
<div class="mb-3">
  {label_html}
  <input type="{input_type}" class="form-control" id="{field_id}" name="{name}" {value_attr} {step_attr}>
  {help_html}
</div>"""


def render_tool_page(name, schema):
    fields = "".join(_field_html(arg) for arg in schema["arguments"])
    body = f"""
<p><a href="/" class="link-secondary text-decoration-none">&larr; all tools</a></p>
<h1 class="h3">{html.escape(_display_name(name))}</h1>
<p class="text-body-secondary">{html.escape(schema.get("description", ""))}</p>

<div class="row g-4">
  <div class="col-lg-5">
    <div class="form-col">
      <form id="tool-form">
        {fields}
        <button type="submit" class="btn btn-primary" id="run-btn">Run</button>
      </form>
    </div>
  </div>

  <div class="col-lg-7">
    <div class="d-flex justify-content-between align-items-center mb-2">
      <span class="fw-semibold">Console</span>
      <span id="status-badge" class="badge text-bg-secondary status-badge">idle</span>
    </div>
    <div id="cmdline" class="cmdline mb-2" style="display:none"></div>
    <div id="output" class="console"><span class="placeholder-text">Output will appear here after you run the tool.</span></div>
  </div>
</div>

<script>
const form = document.getElementById('tool-form');
const runBtn = document.getElementById('run-btn');
const out = document.getElementById('output');
const cmd = document.getElementById('cmdline');
const badge = document.getElementById('status-badge');

form.addEventListener('submit', async function(e) {{
  e.preventDefault();
  const data = {{}};
  for (const el of form.elements) {{
    if (!el.name) continue;
    if (el.type === 'checkbox') {{ data[el.name] = el.checked; }}
    else {{ data[el.name] = el.value; }}
  }}

  runBtn.disabled = true;
  runBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Running...';
  badge.textContent = 'running';
  badge.className = 'badge text-bg-warning status-badge';
  cmd.style.display = 'none';
  out.textContent = 'Running...';

  try {{
    const resp = await fetch(window.location.pathname + '/run', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(data)
    }});
    const result = await resp.json();
    cmd.textContent = '$ ' + result.cmdline;
    cmd.style.display = 'block';
    badge.textContent = result.ok ? 'ok' : 'failed';
    badge.className = 'badge status-badge ' + (result.ok ? 'text-bg-success' : 'text-bg-danger');
    out.textContent = result.output || '(no output)';
  }} catch (err) {{
    badge.textContent = 'error';
    badge.className = 'badge text-bg-danger status-badge';
    out.textContent = 'Request failed: ' + err;
  }} finally {{
    runBtn.disabled = false;
    runBtn.textContent = 'Run';
  }}
}});
</script>
"""
    return PAGE_HEAD.format(title=_display_name(name)) + body + PAGE_TAIL


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    return render_index(discover_tools(), APPS)


@app.get("/tool/{name}", response_class=HTMLResponse)
def tool_page(name: str):
    tools = discover_tools()
    if name not in tools:
        return RedirectResponse("/")
    return render_tool_page(name, tools[name]["schema"])


def _run_tool_blocking(name, values):
    """Everything here is blocking (subprocess.run, twice over) -- must run
    off the event loop thread (see tool_run) or it stalls every other
    request, including any concurrent one a running tool makes back into
    this same server."""
    tools = discover_tools()
    if name not in tools:
        return {"ok": False, "cmdline": "", "output": f"unknown tool: {name}"}, 404

    schema = tools[name]["schema"]
    path = tools[name]["path"]
    argv = clidescribe.build_argv(schema, values)
    full_cmd = [sys.executable, str(path)] + argv

    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
        output = result.stdout + result.stderr
        ok = result.returncode == 0
    except subprocess.TimeoutExpired:
        output = f"(timed out after {RUN_TIMEOUT}s)"
        ok = False

    return {
        "ok": ok,
        "cmdline": " ".join([Path(full_cmd[0]).name, path.name] + argv),
        "output": output,
    }, 200


@app.post("/tool/{name}/run")
async def tool_run(name: str, request: Request):
    values = await request.json()
    body, status = await asyncio.to_thread(_run_tool_blocking, name, values)
    return JSONResponse(body, status_code=status)


if __name__ == "__main__":
    print(f"Scanning tools in: {SCRIPTS_DIR}")
    for tool_name in discover_tools():
        print(f"  found: {tool_name}")
    for app_name in APPS:
        print(f"  found app: {app_name} (mounted at /app/{app_name})")
    uvicorn.run(app, host="0.0.0.0", port=5000)
