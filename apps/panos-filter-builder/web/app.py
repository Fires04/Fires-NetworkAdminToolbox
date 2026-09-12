"""PAN-OS Filter Builder -- FastAPI web application.

Builds a Monitor > Logs > Traffic filter query string from multiple fields
(address, zone, port, app, action, bytes, ...) combined with AND/OR --
generalizes an older single-purpose tool that only handled addr.src/addr.dst.

Everything (the field catalog, value validation, filter-string generation,
saved presets) runs client-side in templates/index.html -- there is no
per-request state or parsing to do server-side, so this app is just the
static page. Kept as its own FastAPI app (rather than a cli_scripts/
clidescribe tool) because the interaction -- add/reorder/remove filter
blocks, live preview -- doesn't fit a single one-shot form.
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="PAN-OS Filter Builder")

BASE_DIR = Path(__file__).resolve().parent
_INDEX_HTML = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=_INDEX_HTML)
