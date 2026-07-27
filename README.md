# PyFNetwork

A small personal toolbox combining two kinds of modules into one web UI,
on one host:port:

```
PyFTools/
  cli_scripts/     -- clidescribe-based CLI scripts (run, print output, exit)
  apps/            -- full standalone ASGI web apps, one folder each
  webui/           -- the FastAPI app that ties both together
```

Both are drop-in-a-folder, zero-central-config: add a script or an app
folder and it shows up in the UI automatically, no other code changes.

Everything runs as **one process, one port**. `apps/` modules aren't
spawned as child processes on their own ports and reverse-proxied over
HTTP -- their ASGI application object is imported and mounted directly
into the same process (`webui/mounts.py` + `app.mount(...)`), the same
way you'd mount a router in any Starlette/FastAPI app. No subprocess
supervision, no per-app port, no HTTP hop.

## `cli_scripts/`

`cli_scripts/protocol_tester.py` ("Protocol Tester" in the UI) - a reusable
CLI tester for whether a host actually *speaks* a given application
protocol (OPC UA, HTTP(S), SSH, FTP, SMTP(S), POP3(S), IMAP(S), RDP, SMB,
Modbus TCP, DNS, NTP, or plain TCP), not just whether a port is open. See
`protocol_tester.py --protocols` for the full list, and `-h` for all
options.

### The `clidescribe` convention

`cli_scripts/clidescribe.py` is a small, dependency-free helper any
argparse-based script in this folder can use to describe itself as JSON:

```python
import clidescribe

def build_parser():
    parser = argparse.ArgumentParser(...)
    parser.add_argument(...)
    clidescribe.add_describe_flag(parser)   # registers --describe
    return parser

def main():
    parser = build_parser()
    if clidescribe.maybe_describe(parser):  # must run BEFORE parse_args()
        return
    args = parser.parse_args()
    ...
```

Any script that does this answers `python3 script.py --describe` with a
JSON schema (name, description, and every argument's flags/type/choices/
default/help/positional/multiple). That's the whole contract -- nothing
web-specific needs to live in the tool itself.

Add a new tool by writing a normal argparse script in `cli_scripts/` and
wiring in those two `clidescribe` calls. It shows up in the web UI
automatically.

A CLI-only flag that doesn't make sense as a web form field (e.g. a "list
choices and exit" flag when the choices already populate an enum dropdown)
can be hidden from the auto-generated form with `clidescribe.hide_from_schema(action)`
while it keeps working normally on the command line.

## `apps/`

Each subfolder of `apps/` with an `app.yaml` manifest is a full standalone
ASGI web app (its own routes, its own dependencies) that gets **mounted
directly into the toolbox's own process** at `/app/<folder-name>/` --
`webui/mounts.py` imports its application object and `webui/app.py` calls
`app.mount(...)`, exactly like mounting a router in any FastAPI project.
No child process, no extra port.

`apps/switch-visualizer/` (from
[NetworkAdminToolbox](https://github.com/Fires04/NetworkAdminToolbox)) is
an example: a FastAPI app (`web.app:app`) with its own `pyproject.toml`.

### Adding an app module

1. Drop the project under `apps/<name>/`, with its own ASGI application
   object exposed somewhere importable (e.g. `web/app.py` defining
   `app = FastAPI(...)`).
2. Add `apps/<name>/app.yaml`:
   ```yaml
   description: "One-line description shown on the toolbox card"
   app: "web.app:app"    # "module.path:attribute" -- the ASGI app object
   ```
3. If it has its own dependencies, wire `pip install ./apps/<name>` (or its
   requirements file) into the `Dockerfile`.

A WSGI-only app (e.g. Flask/Django) can still be mounted by wrapping it in
Starlette's `WSGIMiddleware` before returning it -- ASGI is the common
denominator, not a requirement that every app be written against it.

Since every app's entry-point module is imported into the same process,
two apps that both happened to use an identically-named internal package
(e.g. both had their own top-level `web` package) would collide in
`sys.modules`. Not a concern with how few apps live here today; worth
revisiting if it ever comes up.

`webui/html_rewrite.py` rewrites root-absolute path literals (`fetch('/x')`,
`href="/x"`) in an app's HTML responses so it still works when mounted
under `/app/<name>/` instead of the domain root it assumes -- this is a
property of reusing an app that assumes root deployment, not of how it's
mounted, so it stays regardless of the in-process approach.

## Web UI

```
pip install -r webui/requirements.txt
python3 webui/app.py
```

Then open http://127.0.0.1:5000/. The home page lists CLI tools and web
apps in separate sections, with a search box that filters both live.

### Docker

The whole toolbox (CLI scripts + apps) builds into a single image running
a single process on a single port:

```
docker build -t pyfnetwork-toolbox .
docker run -d -p 5000:5000 pyfnetwork-toolbox
```

or with `docker-compose.yml`:

```
docker compose up -d --build
```

Only the toolbox's own port is exposed -- each app's internal port
(`apps/*/app.yaml`) stays bound to `127.0.0.1` inside the container.
