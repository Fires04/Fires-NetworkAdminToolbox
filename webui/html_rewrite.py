"""html_rewrite.py - lets a mounted app be reachable under /app/<name>/
even though its own HTML/JS assumes it's served from the domain root.

Mounting an ASGI app under a path prefix (see mounts.py + app.py) makes
Starlette route requests to it correctly server-side, but the app's own
served HTML can still contain root-absolute path literals written for a
root deployment (fetch('/x'), href="/x", `/x` in inline JS) -- the
*browser* resolves those against the domain root, not the mount prefix,
since the page has no idea it's been mounted elsewhere. RootPathRewrite
fixes that by rewriting such literals in HTML responses only.
"""
import re


# Root-absolute path literals worth rewriting, scoped to contexts where a
# JS regex literal (e.g. `.replace(/&/g, ...)`) can't appear -- a blind
# "quote immediately followed by /" match also fires inside those regex
# literals (the closing "/" of /"/g reads as a quote-then-slash) and
# corrupts them. Each pattern here anchors on something a regex literal
# argument never has: an HTML attribute name, or the literal "fetch(".
_ATTR_PATH_RE = re.compile(r'((?:href|src|action)=)([\'"])/(?!/)')
_FETCH_PATH_RE = re.compile(r'(fetch\(\s*)([\'"`])/(?!/)')
_TEMPLATE_PATH_RE = re.compile(r'(`)/(?!/)')

_BANNER_CSS = (
    "position:sticky;top:0;z-index:9999;background:#20232a;color:#e6e6e6;"
    "font:13px/1 -apple-system,Segoe UI,sans-serif;padding:.5rem 1rem;"
    "display:flex;gap:.75rem;align-items:center;border-bottom:1px solid #3a3f4b;"
)
_BANNER_LINK_CSS = "color:#8ab4f8;text-decoration:none;"


def _display_name(name):
    return name.replace("-", " ").replace("_", " ").title()


def _inject_banner(html_text, name):
    banner = (
        f'<div style="{_BANNER_CSS}">'
        f'<a href="/" style="{_BANNER_LINK_CSS}">&larr; PyFNetwork Toolbox</a>'
        f'<span style="opacity:.6">/ {_display_name(name)}</span>'
        f'</div>'
    )
    if "<body" in html_text:
        return re.sub(r'(<body[^>]*>)', r'\1' + banner, html_text, count=1)
    return banner + html_text


def rewrite_html(body_bytes, prefix, name):
    text = body_bytes.decode("utf-8", errors="replace")
    text = _ATTR_PATH_RE.sub(rf'\1\2{prefix}/', text)
    text = _FETCH_PATH_RE.sub(rf'\1\2{prefix}/', text)
    text = _TEMPLATE_PATH_RE.sub(rf'\1{prefix}/', text)
    text = _inject_banner(text, name)
    return text.encode("utf-8")


class RootPathRewrite:
    """ASGI middleware: wraps a mounted app, rewriting root-absolute path
    literals in its HTML responses. Non-HTML responses (JSON, images, ...)
    pass through untouched and unbuffered."""

    def __init__(self, app, prefix, name):
        self.app = app
        self.prefix = prefix
        self.name = name

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        state = {"is_html": False, "start": None, "chunks": []}

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                state["is_html"] = any(
                    k.lower() == b"content-type" and b"text/html" in v
                    for k, v in headers
                )
                if not state["is_html"]:
                    return await send(message)
                state["start"] = message
                return

            if message["type"] == "http.response.body":
                if not state["is_html"]:
                    return await send(message)

                state["chunks"].append(message.get("body", b""))
                if message.get("more_body", False):
                    return

                body = rewrite_html(b"".join(state["chunks"]), self.prefix, self.name)
                headers = [
                    (k, v) for k, v in state["start"].get("headers", [])
                    if k.lower() != b"content-length"
                ]
                headers.append((b"content-length", str(len(body)).encode()))
                await send({**state["start"], "headers": headers})
                await send({"type": "http.response.body", "body": body, "more_body": False})
                return

            await send(message)

        await self.app(scope, receive, wrapped_send)
