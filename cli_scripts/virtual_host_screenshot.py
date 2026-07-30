#!/usr/bin/env python3
"""
virtual_host_screenshot.py - render a URL in a real browser while resolving
its hostname to a specific IP, and capture a screenshot.

Same use case as virtual_host_tester.py (checking what a virtual host
serves on a given backend before flipping DNS/a load balancer, without
touching /etc/hosts) but for pages where a text/headers preview isn't
enough to tell what's actually being served -- a JS-rendered app, a
branded error page, a login screen, etc.

Uses Chromium's own --host-resolver-rules flag to override DNS for exactly
this hostname, so the browser still uses the real Host header and TLS SNI
-- it just dials the given IP instead of whatever DNS would normally
return.

Usage:
    virtual_host_screenshot.py example.com 10.0.0.5
    virtual_host_screenshot.py example.com 10.0.0.5 --output shot.png
    virtual_host_screenshot.py example.com 10.0.0.5 --full-page --insecure
"""
import argparse
import sys

try:
    import clidescribe
except ImportError:
    clidescribe = None

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


def take_screenshot(hostname, ip, port, scheme, path, width, height, timeout, insecure, full_page):
    url = f"{scheme}://{hostname}:{port}{path}" if port not in (80, 443) else f"{scheme}://{hostname}{path}"

    with sync_playwright() as p:
        browser = p.chromium.launch(args=[f"--host-resolver-rules=MAP {hostname} {ip}"])
        try:
            context = browser.new_context(
                viewport={"width": width, "height": height},
                ignore_https_errors=insecure,
            )
            page = context.new_page()
            response = page.goto(url, timeout=timeout * 1000, wait_until="load")
            png_bytes = page.screenshot(full_page=full_page)
            status = response.status if response else None
            final_url = page.url
            title = page.title()
        finally:
            browser.close()

    return status, final_url, title, png_bytes


def build_parser():
    parser = argparse.ArgumentParser(
        prog="virtual_host_screenshot.py",
        description="Render a URL in headless Chromium while resolving the hostname to a "
                     "specific IP, and capture a screenshot -- for virtual-host testing "
                     "without editing /etc/hosts.",
    )
    parser.add_argument("hostname", help="hostname to browse to (Host header + TLS SNI)")
    parser.add_argument("ip", help="IP address to resolve that hostname to")
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

    port = args.port if args.port is not None else (443 if args.scheme == "https" else 80)

    try:
        status, final_url, title, png_bytes = take_screenshot(
            args.hostname, args.ip, port, args.scheme, args.path,
            args.width, args.height, args.timeout, args.insecure, args.full_page,
        )
    except Exception as e:
        print(f"{args.hostname} @ {args.ip:<15} [FAIL] {e}")
        sys.exit(1)

    tag = "OK  " if status and status < 400 else "FAIL"
    print(f"{args.hostname} @ {args.ip:<15} [{tag}] HTTP {status} -- {title!r}")
    if final_url.rstrip("/") != f"{args.scheme}://{args.hostname}{args.path}".rstrip("/"):
        print(f"  final URL: {final_url}")

    if clidescribe:
        clidescribe.emit_image(png_bytes)
    sys.exit(0 if status and status < 400 else 1)


if __name__ == "__main__":
    main()
