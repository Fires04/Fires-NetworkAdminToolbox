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

    Every app's entry-point module is imported into the same process, and
    the natural name for an app's own web-serving package is just `web` --
    unsurprisingly, more than one app here independently picked exactly
    that. Without care, the second and third such app wouldn't get their
    own module imported at all: Python caches `web` in sys.modules after
    the first import, so `importlib.import_module("web.app")` for the next
    app would silently hand back the *first* app's already-cached module,
    and every app mounted after that would end up serving the first app's
    page. To avoid that, every module newly added to sys.modules during one
    app's import is discarded again right after grabbing that app's ASGI
    object out of it -- the object itself keeps working fine (it's already
    in hand), but the *name* is free again for the next app to import under.
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
        modules_before = set(sys.modules)
        try:
            module = importlib.import_module(module_path)
            app_obj = getattr(module, attr)
        finally:
            sys.path.remove(str(entry))
            for name in set(sys.modules) - modules_before:
                del sys.modules[name]

        apps[entry.name] = {
            "description": cfg.get("description", ""),
            "dir": entry,
            "app": app_obj,
        }
    return apps
