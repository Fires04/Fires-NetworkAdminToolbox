"""mounts.py - discovery for the apps/ modules.

Mirrors the cli_scripts/ auto-discovery convention (drop a file in, it
shows up -- no central registry) for a different module shape: full
standalone ASGI web apps instead of run-and-exit scripts. Each subfolder
of apps/ with an app.yaml manifest is picked up automatically, its ASGI
application object is imported in-process, and app.py mounts it directly
at /app/<name> -- same process, same port, no subprocess and no network
hop involved.
"""
import importlib
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APPS_DIR = PROJECT_ROOT / "apps"
MANIFEST_NAME = "app.yaml"


def discover_apps():
    """Return {name: {"description": str, "dir": Path, "app": <ASGI app object>}}
    for every apps/<name>/app.yaml manifest found. The manifest's "app" key
    is "module.path:attribute", e.g. "web.app:app" -- imported with
    apps/<name> temporarily on sys.path so the module's own internal
    imports (e.g. `import switch_viz`) resolve.

    Note: since this loads every app's entry-point module into the same
    process, two apps that both used an identically-named internal
    package (e.g. both had their own top-level `web` package) would
    collide in sys.modules. Not a concern with a single app registered;
    worth revisiting if that ever happens.
    """
    apps = {}
    if not APPS_DIR.is_dir():
        return apps

    for entry in sorted(APPS_DIR.iterdir()):
        manifest_path = entry / MANIFEST_NAME
        if not entry.is_dir() or not manifest_path.exists():
            continue

        with open(manifest_path) as f:
            cfg = yaml.safe_load(f) or {}

        module_path, _, attr = cfg["app"].partition(":")
        sys.path.insert(0, str(entry))
        try:
            module = importlib.import_module(module_path)
        finally:
            sys.path.remove(str(entry))

        apps[entry.name] = {
            "description": cfg.get("description", ""),
            "dir": entry,
            "app": getattr(module, attr),
        }
    return apps
