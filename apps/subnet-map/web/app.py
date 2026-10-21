"""Subnet Map -- FastAPI web application.

Visualizes one or more IPv4 networks as an address-space bar: allocated
child subnets as proportionally-sized colored blocks, unallocated space as
clickable gaps you can drop a new subnet of any size into. Any block can be
drilled into to keep subdividing it, recursively.

Everything (CIDR math, the allocation tree, rendering, import/export)
runs client-side in templates/index.html -- there is no per-request state
or parsing to do server-side, so this app is just the static page. State
lives in the browser's own localStorage (per browser/device, same as
panos-filter-builder); Import/Export JSON is the escape hatch to move it
between browsers or hand-build it (including via an AI -- the page's own
Help panel has a ready-to-copy prompt describing the JSON schema).
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Subnet Map")

BASE_DIR = Path(__file__).resolve().parent
_INDEX_HTML = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=_INDEX_HTML)
