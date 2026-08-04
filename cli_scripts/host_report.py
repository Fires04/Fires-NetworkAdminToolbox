#!/usr/bin/env python3
"""
host_report.py - ping + DNS report (A, MX records) for a list of
hosts/IPs, printed as a formatted table.

Usage:
    host_report.py example.com 8.8.8.8 mail.example.com
    host_report.py --resolver 10.0.0.1 internal-host.corp.local
    host_report.py --no-ping example.com www.example.com
    host_report.py --extract "web1.example.com (10.0.0.5) is down, cc mx01.example.com"

--extract is EXPERIMENTAL: instead of treating the given argument(s) as a
literal list of hosts, it treats them as one blob of free text and pulls
out anything that looks like a hostname (hostname.tld / www.hostname.tld,
alphabetic TLD) or an IPv4 address via regex. A hand-written pattern like
this will both miss unusual real names and pick up look-alike noise -- it's
a rough first pass over a log/ticket/email, not a guarantee of completeness
or precision.

DNS (A/MX) lookups are done with a small hand-rolled UDP query (stdlib
only, no dnspython) against a single resolver of your choosing -- the same
approach protocol_tester.py's `dns` protocol test uses, just for A/MX
records specifically rather than a generic reachability check. Ping shells
out to the system `ping` binary, same as protocol_tester.py's --ping.
"""
import argparse
import ipaddress
import platform
import random
import re
import socket
import struct
import subprocess

try:
    import clidescribe
except ImportError:
    clidescribe = None


# ---------------------------------------------------------------------------
# DNS: hand-rolled A/MX query over UDP (stdlib only)
# ---------------------------------------------------------------------------

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DnsError(Exception):
    pass


def _default_resolver():
    """First nameserver in /etc/resolv.conf, falling back to a public
    resolver if that file doesn't exist or has none (e.g. Windows)."""
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return "1.1.1.1"


def _build_query(qname, qtype):
    txid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = qname.rstrip(".").split(".")
    question = b"".join(struct.pack("B", len(label)) + label.encode("ascii") for label in labels)
    question += b"\x00" + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return txid, header + question


def _skip_name(data, offset):
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length


def _parse_name(data, offset):
    """Parse a (possibly compressed) DNS name starting at offset. Returns
    (name, offset_immediately_after_this_name_field) -- the second value
    accounts for a compression pointer without following it for the
    "what comes next in the packet" bookkeeping."""
    labels = []
    jumped = False
    return_offset = None
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                return_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), (return_offset if jumped else offset)


def dns_query(qname, qtype, server, timeout=3.0, port=53):
    """Send one DNS query, return (rcode, answers) where answers is a list
    of ('A', ip, ttl) / ('MX', (preference, exchange), ttl) tuples. Raises
    DnsError on timeout, transport error, or a malformed response.
    """
    txid, packet = _build_query(qname, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (server, port))
            resp, _ = s.recvfrom(4096)
        except socket.timeout:
            raise DnsError(f"query to {server} timed out")
        except OSError as e:
            raise DnsError(f"query to {server} failed: {e}")

    if len(resp) < 12:
        raise DnsError("malformed response (too short)")
    resp_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", resp[:12])
    if resp_id != txid:
        raise DnsError("transaction ID mismatch (stale/spoofed packet?)")

    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(resp, offset) + 4  # + QTYPE/QCLASS

    answers = []
    for _ in range(ancount):
        _name, offset = _parse_name(resp, offset)
        if offset + 10 > len(resp):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", resp[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(resp):
            break
        if rtype == 1 and rdlength == 4:  # A
            answers.append(("A", ".".join(str(b) for b in resp[offset:offset + 4]), ttl))
        elif rtype == 15 and rdlength >= 3:  # MX
            preference = struct.unpack(">H", resp[offset:offset + 2])[0]
            exchange, _ = _parse_name(resp, offset + 2)
            answers.append(("MX", (preference, exchange), ttl))
        offset += rdlength

    return rcode, answers


def lookup_a(hostname, resolver, timeout):
    """Returns (ips, error): ips is a list (possibly empty), error is a
    short human-readable string when the list is empty/unavailable, else
    None."""
    try:
        rcode, answers = dns_query(hostname, 1, resolver, timeout=timeout)
    except DnsError as e:
        return None, str(e)
    if rcode != 0:
        return [], RCODE_NAMES.get(rcode, f"RCODE {rcode}")
    return [ip for rtype, ip, _ttl in answers if rtype == "A"], None


def lookup_mx(hostname, resolver, timeout):
    try:
        rcode, answers = dns_query(hostname, 15, resolver, timeout=timeout)
    except DnsError as e:
        return None, str(e)
    if rcode != 0:
        return [], RCODE_NAMES.get(rcode, f"RCODE {rcode}")
    return sorted(val for rtype, val, _ttl in answers if rtype == "MX"), None


# ---------------------------------------------------------------------------
# Ping (cross-platform: Windows / Linux)
# ---------------------------------------------------------------------------

def ping(ip, timeout=2.0):
    """Returns (ok, latency_ms): ok is True/False, or None if the `ping`
    binary itself isn't available; latency_ms is None when not parseable."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=timeout + 2, text=True)
    except subprocess.TimeoutExpired:
        return False, None
    except FileNotFoundError:
        return None, None

    if result.returncode != 0:
        return False, None
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", result.stdout, re.I)
    return True, (float(m.group(1)) if m else None)


# ---------------------------------------------------------------------------
# Target parsing / extraction
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# hostname.tld / www.hostname.tld -- an alphabetic-only final label (the
# TLD) is what keeps this from also matching IPv4 addresses, which always
# end in a numeric label.
_HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_targets(text):
    """Regex-pull IPv4 addresses and hostname-shaped tokens out of a blob of
    free text. See the --extract help / module docstring for the "rough
    first pass, not a guarantee" caveat."""
    found = _IPV4_RE.findall(text) + _HOSTNAME_RE.findall(text)
    return list(dict.fromkeys(item.lower() for item in found))


def parse_target_list(items):
    """Literal-mode target parsing: each arg may itself contain a
    comma/newline-separated list (matches clidescribe's own multi-value
    convention), flattened and de-duplicated while preserving order."""
    flat = []
    for item in items:
        flat.extend(p.strip() for p in item.replace(",", "\n").splitlines() if p.strip())
    return list(dict.fromkeys(flat))


# ---------------------------------------------------------------------------
# Report building / table output
# ---------------------------------------------------------------------------

def build_row(target, resolver, dns_timeout, ping_timeout, skip_ping):
    row = {"target": target}

    if is_ip(target):
        row["ip"] = target
        row["a_records"] = target
        row["mx_records"] = "-"
    else:
        ips, a_err = lookup_a(target, resolver, dns_timeout)
        if ips is None:
            row["a_records"], row["ip"] = f"ERROR: {a_err}", None
        elif not ips:
            row["a_records"], row["ip"] = (f"none ({a_err})" if a_err else "none"), None
        else:
            row["a_records"], row["ip"] = ", ".join(ips), ips[0]

        mx, mx_err = lookup_mx(target, resolver, dns_timeout)
        if mx is None:
            row["mx_records"] = f"ERROR: {mx_err}"
        elif not mx:
            row["mx_records"] = f"none ({mx_err})" if mx_err else "none"
        else:
            row["mx_records"] = ", ".join(f"{pref} {exchange}" for pref, exchange in mx)

    if skip_ping:
        row["ping"] = "skipped"
    elif row.get("ip"):
        ok, latency = ping(row["ip"], timeout=ping_timeout)
        if ok is None:
            row["ping"] = "n/a (no ping binary)"
        elif ok:
            row["ping"] = f"OK {latency:.1f} ms" if latency is not None else "OK"
        else:
            row["ping"] = "FAIL"
    else:
        row["ping"] = "n/a (no IP)"

    return row


def format_table(headers, rows, max_col_width=60):
    widths = [min(max(len(h), *(len(r[i]) for r in rows)) if rows else len(h), max_col_width)
              for i, h in enumerate(headers)]

    def fmt_row(cells):
        out = []
        for i, cell in enumerate(cells):
            w = widths[i]
            out.append((cell[:w - 1] + "…") if len(cell) > w else cell.ljust(w))
        return "  ".join(out).rstrip()

    lines = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="host_report.py",
        description="Ping + DNS report (A, MX records) for a list of hosts/IPs, as a table.",
    )
    parser.add_argument("targets", nargs="*", metavar="HOST",
                         help="hostnames and/or IP addresses to report on (or, with --extract, "
                              "a blob of free text to pull them out of)")
    parser.add_argument("--extract", action="store_true",
                         help="EXPERIMENTAL: treat the given argument(s) as free text instead of "
                              "a literal host list, and regex-extract hostname.tld / "
                              "www.hostname.tld -shaped names and IPv4 addresses out of it. A "
                              "hand-written pattern can both miss real names and pick up "
                              "look-alike noise -- treat this as a rough first pass, not a "
                              "guarantee.")
    parser.add_argument("--resolver", default=None,
                         help="DNS server to query for A/MX records (default: first nameserver "
                              "in /etc/resolv.conf, falling back to 1.1.1.1)")
    parser.add_argument("--dns-timeout", type=float, default=3.0,
                         help="DNS query timeout in seconds (default: 3)")
    parser.add_argument("--ping-timeout", type=float, default=2.0,
                         help="ping timeout in seconds (default: 2)")
    parser.add_argument("--no-ping", action="store_true",
                         help="skip the ping check, only report DNS records")
    if clidescribe:
        clidescribe.add_describe_flag(parser)
    return parser


def main():
    parser = build_parser()
    if clidescribe and clidescribe.maybe_describe(parser):
        return
    args = parser.parse_args()

    if not args.targets:
        parser.error("at least one hostname/IP is required (or a text blob with --extract)")

    if args.extract:
        targets = extract_targets(" ".join(args.targets))
        if not targets:
            print("--extract: no hostname- or IPv4-shaped tokens found in the given text")
            return
    else:
        targets = parse_target_list(args.targets)

    resolver = args.resolver or _default_resolver()

    rows = []
    for target in targets:
        try:
            rows.append(build_row(target, resolver, args.dns_timeout, args.ping_timeout, args.no_ping))
        except Exception as e:
            rows.append({"target": target, "ping": "-", "a_records": f"ERROR: {e}", "mx_records": "-"})

    print(f"DNS resolver: {resolver}\n")
    headers = ["Host/IP", "Ping", "A record(s)", "MX record(s)"]
    table = [[r["target"], r["ping"], r["a_records"], r["mx_records"]] for r in rows]
    print(format_table(headers, table))


if __name__ == "__main__":
    main()
