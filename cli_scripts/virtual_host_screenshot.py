#!/usr/bin/env python3
"""
virtual_host_screenshot.py - render a URL in a real browser and capture a
screenshot, optionally resolving its hostname to a specific IP instead of
whatever DNS would normally return.

Two uses in one tool:
- IP given: virtual-host testing -- checking what a backend serves before
  flipping DNS/a load balancer, without touching /etc/hosts, for pages
  where a text/headers preview isn't enough to tell what's actually being
  served (a JS-rendered app, a branded error page, a login screen, ...).
- IP omitted: a plain "what does this page look like from here" screenshot,
  resolved normally -- e.g. to see a site the way a visitor in this
  server's location/network would, independent of virtual-host testing.

When an IP is given, uses Chromium's own --host-resolver-rules flag to
override DNS for exactly this hostname, so the browser still uses the real
Host header and TLS SNI -- it just dials the given IP instead of whatever
DNS would normally return.

Usage:
    virtual_host_screenshot.py example.com
    virtual_host_screenshot.py example.com 10.0.0.5
    virtual_host_screenshot.py example.com 10.0.0.5 --full-page --insecure
"""
import argparse
import socket
import sys

try:
    import clidescribe
except ImportError:
    clidescribe = None

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


def _redirect_warnings(response):
    """Chromium follows redirects transparently during navigation -- walk the
    chain back from the final response's request (via .redirected_from) so
    the ones it hid, e.g. the classic http->https upgrade, still show up as
    a warning instead of silently vanishing into the final screenshot."""
    if response is None:
        return []
    hops = []
    req = response.request
    while req.redirected_from:
        hops.append(req.redirected_from)
        req = req.redirected_from
    hops.reverse()

    warnings = []
    for hop in hops:
        hop_resp = hop.response()
        status = hop_resp.status if hop_resp else "?"
        to_url = hop.redirected_to.url if hop.redirected_to else "?"
        warnings.append(f"redirected ({status}) {hop.url} -> {to_url}")
    return warnings


def take_screenshot(hostname, ip, port, scheme, path, width, height, timeout, insecure, full_page):
    url = f"{scheme}://{hostname}:{port}{path}" if port not in (80, 443) else f"{scheme}://{hostname}{path}"

    with sync_playwright() as p:
        browser = p.chromium.launch(args=[f"--host-resolver-rules=MAP {hostname} {ip}"])
        try:
            # Default headless Chromium identifies itself as a bot in two
            # obvious ways: "HeadlessChrome" in the User-Agent, and
            # navigator.webdriver == true. Plenty of sites' anti-bot/geo
            # scripts key off exactly that (as opposed to the actual visitor
            # IP) and quietly serve nothing -- which defeats the point of a
            # tool meant to show what a *real* visitor to your own site
            # would see. Presenting an ordinary-looking fingerprint here is
            # the correct default for that purpose, not evasion.
            context = browser.new_context(
                viewport={"width": width, "height": height},
                ignore_https_errors=insecure,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
                ),
            )
            context.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            )
            page = context.new_page()

            # A page that looks broken/unstyled in the screenshot is usually
            # missing an asset -- either it 404'd/500'd on *this* backend, or
            # it lives on a different hostname that our IP override doesn't
            # apply to and so didn't resolve. Both are exactly the kind of
            # thing this tool exists to catch, so surface them as warnings
            # instead of leaving "why does this look broken" a mystery.
            #
            # A resource that 404s/500s also fires requestfailed right after
            # (Chromium aborts loading it as a stylesheet/script/etc.) -- key
            # both by URL so that duplicate is collapsed into the one with
            # the actual HTTP status, keeping requestfailed only for hops
            # that never got a response at all (DNS failure, connection
            # refused, ...).
            response_warnings = {}
            failed_warnings = {}
            page.on("response", lambda resp: response_warnings.setdefault(
                resp.url, f"{resp.status} {resp.url}"
            ) if resp.status >= 400 else None)
            page.on("requestfailed", lambda req: failed_warnings.setdefault(
                req.url, f"failed to load {req.url} ({req.failure or 'unknown error'})"
            ))

            response = page.goto(url, timeout=timeout * 1000, wait_until="load")
            # A short settle window catches near-immediate background
            # requests/animations that fire right after "load" without
            # resorting to Playwright's flaky "networkidle" wait strategy.
            page.wait_for_timeout(500)

            asset_warnings = list(response_warnings.values()) + [
                w for url, w in failed_warnings.items() if url not in response_warnings
            ]
            warnings = _redirect_warnings(response) + asset_warnings
            png_bytes = page.screenshot(full_page=full_page)
            status = response.status if response else None
            final_url = page.url
            title = page.title()
        finally:
            browser.close()

    return status, final_url, title, png_bytes, warnings


def build_parser():
    parser = argparse.ArgumentParser(
        prog="virtual_host_screenshot.py",
        description="Render a URL in headless Chromium and capture a screenshot. Give an IP "
                     "for virtual-host testing (resolves the hostname to that IP instead of "
                     "DNS, without editing /etc/hosts); omit it for a plain screenshot of the "
                     "page as seen from here, resolved normally.",
    )
    parser.add_argument("hostname", help="hostname to browse to (Host header + TLS SNI)")
    parser.add_argument("ip", nargs="?", default=None,
                         help="IP address to resolve that hostname to (default: resolve "
                              "normally via DNS)")
    parser.add_argument("--scheme", choices=["https", "http"], default="https",
                         help="protocol to use (default: https)")
    parser.add_argument("--port", type=int, default=None,
                         help="port to connect to (default: 443 for https, 80 for http)")
    parser.add_argument("--path", default="/",
                         help="request path (default: /)")
    parser.add_argument("--width", type=int, default=1280, help="viewport width (default: 1280)")
    parser.add_argument("--height", type=int, default=800, help="viewport height (default: 800)")
    parser.add_argument("--full-page", action="store_true",
                         help="capture the full scrollable page, not just the viewport")
    parser.add_argument("--timeout", type=float, default=15.0,
                         help="page load timeout in seconds (default: 15)")
    parser.add_argument("--insecure", action="store_true",
                         help="ignore TLS certificate errors (self-signed / not-yet-cutover certs)")
    if clidescribe:
        clidescribe.add_describe_flag(parser)
    return parser


def main():
    parser = build_parser()
    if clidescribe and clidescribe.maybe_describe(parser):
        return
    args = parser.parse_args()

    if sync_playwright is None:
        print("playwright is not installed (pip install playwright && playwright install chromium)")
        sys.exit(1)

    ip = args.ip
    if ip is None:
        try:
            ip = socket.gethostbyname(args.hostname)
        except socket.gaierror as e:
            print(f"{args.hostname} [FAIL] DNS resolution failed: {e}")
            sys.exit(1)

    port = args.port if args.port is not None else (443 if args.scheme == "https" else 80)

    try:
        status, final_url, title, png_bytes, warnings = take_screenshot(
            args.hostname, ip, port, args.scheme, args.path,
            args.width, args.height, args.timeout, args.insecure, args.full_page,
        )
    except Exception as e:
        print(f"{args.hostname} @ {ip:<15} [FAIL] {e}")
        sys.exit(1)

    for w in warnings:
        print(f"  ⚠ {w}")

    tag = "OK  " if status and status < 400 else "FAIL"
    print(f"{args.hostname} @ {ip:<15} [{tag}] HTTP {status} -- {title!r}")
    if final_url.rstrip("/") != f"{args.scheme}://{args.hostname}{args.path}".rstrip("/"):
        print(f"  final URL: {final_url}")

    if clidescribe:
        clidescribe.emit_image(png_bytes)
    sys.exit(0 if status and status < 400 else 1)


if __name__ == "__main__":
    main()
