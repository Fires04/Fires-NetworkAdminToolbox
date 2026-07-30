#!/usr/bin/env python3
"""
virtual_host_tester.py - fetch a URL from a specific IP while sending a
different Host header (and TLS SNI), without touching /etc/hosts.

The classic use case: a server hosts multiple virtual hosts, and you want
to check what "example.com" serves on a *specific* backend/IP before
flipping DNS or a load balancer -- the same thing `curl --resolve` or
`curl -H "Host: ..."` gives you, but as a describable module in this
toolbox.

Usage:
    virtual_host_tester.py example.com 10.0.0.5
    virtual_host_tester.py example.com 10.0.0.5 --scheme http --port 8080
    virtual_host_tester.py example.com 10.0.0.5 -v
    virtual_host_tester.py example.com 10.0.0.5 --insecure
    virtual_host_tester.py example.com 10.0.0.5 --method HEAD --path /health
"""
import argparse
import http.client
import socket
import ssl
import sys
import urllib.parse

try:
    import clidescribe
except ImportError:
    clidescribe = None


# ---------------------------------------------------------------------------
# Connections that dial a fixed IP but keep the Host header / TLS SNI on the
# hostname -- the same trick `curl --resolve host:port:ip` uses.
# ---------------------------------------------------------------------------

class ResolveOverrideHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, resolve_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._resolve_ip = resolve_ip

    def connect(self):
        self.sock = socket.create_connection((self._resolve_ip, self.port), self.timeout)


class ResolveOverrideHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, resolve_ip, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._resolve_ip = resolve_ip

    def connect(self):
        sock = socket.create_connection((self._resolve_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch(hostname, ip, port, scheme, path, method, timeout, insecure, data):
    if scheme == "https":
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        conn = ResolveOverrideHTTPSConnection(hostname, port, ip, timeout, context)
    else:
        conn = ResolveOverrideHTTPConnection(hostname, port, ip, timeout)

    cert = None
    try:
        conn.connect()
        if scheme == "https":
            cert = conn.sock.getpeercert()

        conn.request(method, path, body=data, headers={"Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(65536)
        return {
            "ok": True,
            "status": resp.status,
            "reason": resp.reason,
            "headers": resp.getheaders(),
            "body": body,
            "cert": cert,
        }
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"TLS certificate verification failed: {e}"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "error": "connection timed out"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "connection refused (port closed)"}
    except OSError as e:
        return {"ok": False, "error": f"connection error: {e}"}
    finally:
        conn.close()


def follow_chain(hostname, ip, port, scheme, path, method, timeout, insecure, data, max_redirects):
    """Fetch, and if the response is a redirect, keep following it -- printing
    a warning at each hop -- instead of just reporting the Location header
    and stopping. A hop that stays on the same hostname (the common
    http->https upgrade) keeps using the IP override; a hop to a different
    hostname falls back to normal DNS, since forcing an unrelated domain
    onto this IP would be misleading rather than useful.
    """
    warnings = []
    cur_host, cur_ip, cur_port, cur_scheme, cur_path = hostname, ip, port, scheme, path
    cur_method, cur_data = method, data

    for hop in range(max_redirects + 1):
        result = fetch(cur_host, cur_ip, cur_port, cur_scheme, cur_path, cur_method, timeout, insecure, cur_data)
        if not result["ok"] or not (300 <= result["status"] < 400):
            return result, warnings, (cur_host, cur_ip)

        location = dict(result["headers"]).get("Location")
        if not location:
            return result, warnings, (cur_host, cur_ip)

        if max_redirects == 0:
            warnings.append(f"redirects to: {location} (not following, --no-follow-redirects)")
            return result, warnings, (cur_host, cur_ip)

        if hop == max_redirects:
            warnings.append(f"stopped after {max_redirects} redirects (still redirecting to {location})")
            return result, warnings, (cur_host, cur_ip)

        base = f"{cur_scheme}://{cur_host}{cur_path}"
        target = urllib.parse.urlparse(urllib.parse.urljoin(base, location))
        new_host = target.hostname or cur_host
        new_scheme = target.scheme or cur_scheme
        new_port = target.port or (443 if new_scheme == "https" else 80)
        new_path = target.path or "/"
        if target.query:
            new_path += "?" + target.query

        warnings.append(f"redirected ({result['status']}) {cur_scheme}://{cur_host}{cur_path} -> {location}")

        if new_host == cur_host:
            new_ip = cur_ip
        else:
            new_ip = new_host  # different host -- let normal DNS resolve it instead of forcing our IP
            warnings.append(f"redirect target host differs ({new_host}) -- switching to normal DNS resolution")

        cur_host, cur_ip, cur_port, cur_scheme, cur_path = new_host, new_ip, new_port, new_scheme, new_path
        cur_method, cur_data = ("GET" if result["status"] in (301, 302, 303) else cur_method), (None if result["status"] in (301, 302, 303) else cur_data)

    return result, warnings, (cur_host, cur_ip)


def print_result(hostname, ip, result, warnings, final_target, verbose):
    label = f"{hostname} @ {ip}"
    for w in warnings:
        print(f"  ⚠ {w}")

    if not result["ok"]:
        print(f"{label:<40} [FAIL] {result['error']}")
        return False

    status, reason = result["status"], result["reason"]
    tag = "OK  " if status < 400 else "FAIL"
    if final_target != (hostname, ip):
        print(f"{label:<40} [{tag}] HTTP {status} {reason}  (final: {final_target[0]} @ {final_target[1]})")
    else:
        print(f"{label:<40} [{tag}] HTTP {status} {reason}")

    if result["cert"]:
        subject = dict(x[0] for x in result["cert"].get("subject", []))
        san = [v for k, v in result["cert"].get("subjectAltName", []) if k == "DNS"]
        print(f"  cert subject: {subject.get('commonName', '?')}  SAN: {', '.join(san) or '-'}")

    if verbose:
        print("  headers:")
        for k, v in result["headers"]:
            print(f"    {k}: {v}")
        preview = result["body"][:500]
        try:
            text = preview.decode("utf-8", errors="replace")
        except Exception:
            text = repr(preview)
        print("  body preview:")
        for line in text.splitlines()[:20]:
            print(f"    {line}")

    return status < 400


def build_parser():
    parser = argparse.ArgumentParser(
        prog="virtual_host_tester.py",
        description="Fetch a URL from a specific IP with a chosen Host header/SNI, "
                     "to test virtual hosts without editing /etc/hosts.",
    )
    parser.add_argument("hostname", help="hostname to send as Host header and TLS SNI")
    parser.add_argument("ip", help="IP address to actually connect to")
    parser.add_argument("--scheme", choices=["https", "http"], default="https",
                         help="protocol to use (default: https)")
    parser.add_argument("--port", type=int, default=None,
                         help="port to connect to (default: 443 for https, 80 for http)")
    parser.add_argument("--path", default="/",
                         help="request path (default: /)")
    parser.add_argument("--method", choices=["GET", "HEAD", "POST"], default="GET",
                         help="HTTP method (default: GET)")
    parser.add_argument("--data", default=None,
                         help="request body for POST")
    parser.add_argument("--timeout", type=float, default=5.0,
                         help="timeout in seconds (default: 5)")
    parser.add_argument("--insecure", action="store_true",
                         help="skip TLS certificate verification (self-signed / not-yet-cutover certs)")
    parser.add_argument("--no-follow-redirects", action="store_true",
                         help="report a redirect instead of following it (default: follow, with a warning per hop)")
    parser.add_argument("--max-redirects", type=int, default=5,
                         help="maximum redirects to follow (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="show response headers and a body preview")
    if clidescribe:
        clidescribe.add_describe_flag(parser)
    return parser


def main():
    parser = build_parser()
    if clidescribe and clidescribe.maybe_describe(parser):
        return
    args = parser.parse_args()

    port = args.port if args.port is not None else (443 if args.scheme == "https" else 80)
    data = args.data.encode() if args.data else None
    max_redirects = 0 if args.no_follow_redirects else args.max_redirects

    result, warnings, final_target = follow_chain(
        args.hostname, args.ip, port, args.scheme, args.path,
        args.method, args.timeout, args.insecure, data, max_redirects,
    )
    ok = print_result(args.hostname, args.ip, result, warnings, final_target, args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
