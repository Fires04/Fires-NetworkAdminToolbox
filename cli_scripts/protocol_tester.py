#!/usr/bin/env python3
"""
protocol_tester.py - reusable network protocol connectivity tester.

Checks whether a host actually speaks a given application protocol, not just
whether a TCP port is open (a "port open" nc/telnet check can be misleading -
some devices/firewalls accept the TCP handshake but never answer at the
application layer).

Usage:
    protocol_tester.py --protocols
    protocol_tester.py -p opc 10.83.225.40 10.83.225.46 10.83.225.48
    protocol_tester.py -p opc --ping --timeout 5 10.83.225.46
    protocol_tester.py -p tcp --port 22 10.83.225.46
    protocol_tester.py -p https 10.83.225.46
    protocol_tester.py -p https -v 10.83.225.46           (extended cert info)
    protocol_tester.py -p https --check-chain -v 10.83.225.46   (validate full chain)
    protocol_tester.py -p http 10.83.225.46                (auto-follows a
                                                           http->https redirect
                                                           with a https test)
    protocol_tester.py -p dns 10.83.1.21
    protocol_tester.py -p smb -v 10.83.225.10
    protocol_tester.py -p modbus 10.83.225.40
    protocol_tester.py -p smtp -v mail.example.com
    protocol_tester.py -p smtp -v --user me@example.com --password secret mail.example.com
"""
import argparse
import base64
import datetime
import os
import platform
import random
import re
import socket
import ssl
import struct
import subprocess

try:
    import clidescribe  # optional: enables `--describe` (see clidescribe.py)
except ImportError:
    clidescribe = None
import tempfile
import urllib.parse


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def parse_http_response(resp):
    """Parse raw HTTP response bytes into (status_code, status_line, headers)."""
    try:
        head, _, _ = resp.partition(b'\r\n\r\n')
        lines = head.split(b'\r\n')
        status_line = lines[0].decode(errors='replace')
        parts = status_line.split(' ', 2)
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        headers = {}
        for line in lines[1:]:
            if b':' in line:
                k, _, v = line.partition(b':')
                headers[k.decode(errors='replace').strip().lower()] = v.decode(errors='replace').strip()
        return status_code, status_line, headers
    except Exception:
        return None, None, {}


def _get_cert_chain_info(ip, port, timeout):
    """Connect over TLS and inspect the server's certificate (stdlib only).

    Returns a dict describing the negotiated TLS session and the leaf
    certificate: validity window, subject/issuer, SAN, and whether the
    chain is trusted by the system's default CA store. Certificate parsing
    works even for self-signed / internal certificates (the leaf cert is
    temporarily trusted as its own CA just to get Python's parsed dict out
    of it); the separate trust check against the real system CA store is
    what tells you if it's *actually* trusted.
    """
    ctx_open = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_open.check_hostname = False
    ctx_open.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx_open.wrap_socket(sock, server_hostname=ip) as ssock:
            der = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher = ssock.cipher()

    if der is None:
        raise ValueError("server completed TLS handshake but presented no certificate")

    pem = ssl.DER_cert_to_PEM_cert(der)

    parsed = {}
    parse_error = None
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp:
            tmp.write(pem)
            tmp_path = tmp.name

        ctx_parse = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_parse.check_hostname = False
        ctx_parse.verify_mode = ssl.CERT_REQUIRED
        # Without this flag, OpenSSL refuses to treat a non-CA leaf cert as a
        # trust anchor (it insists on a self-signed/CA root). Real CA-issued
        # certs (e.g. Let's Encrypt) are never self-signed, so this is
        # required for the "trust the exact cert we just saw" trick below to
        # work for anything other than a self-signed certificate.
        ctx_parse.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        ctx_parse.load_verify_locations(cafile=tmp_path)

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx_parse.wrap_socket(sock, server_hostname=ip) as ssock:
                parsed = ssock.getpeercert() or {}
    except (ssl.SSLError, OSError) as e:
        # Best-effort: if for some reason we still can't re-verify against
        # the pinned leaf cert, fall back to reporting just the TLS session
        # info from the first connection instead of failing the whole test.
        parsed = {}
        parse_error = str(e)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _fmt_name(name_tuples):
        parts = [f"{k}={v}" for rdn in (name_tuples or ()) for k, v in rdn]
        return ", ".join(parts) if parts else "(unknown)"

    subject = _fmt_name(parsed.get('subject'))
    issuer = _fmt_name(parsed.get('issuer'))
    serial = parsed.get('serialNumber', '(unknown)')
    san = [v for k, v in parsed.get('subjectAltName', ())]

    not_before_str = parsed.get('notBefore')
    not_after_str = parsed.get('notAfter')
    days_left = None
    valid_now = None
    if not_before_str and not_after_str:
        not_before = datetime.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_before_str), tz=datetime.timezone.utc)
        not_after = datetime.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_after_str), tz=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        valid_now = not_before <= now <= not_after
        days_left = (not_after - now).days

    # Separate check: does this chain to a CA the system actually trusts?
    # (kept apart from the parsing step above, which always "trusts" the
    # leaf cert on purpose just to be able to read its fields)
    trusted = False
    trust_error = None
    try:
        ctx_trust = ssl.create_default_context()
        ctx_trust.check_hostname = False
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx_trust.wrap_socket(sock, server_hostname=ip):
                trusted = True
    except ssl.SSLCertVerificationError as e:
        trust_error = getattr(e, 'verify_message', str(e))
    except OSError as e:
        trust_error = f"connection error during trust check: {e}"

    return {
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "san": san,
        "not_before": not_before_str,
        "not_after": not_after_str,
        "valid_now": valid_now,
        "days_left": days_left,
        "trusted": trusted,
        "trust_error": trust_error,
        "parse_error": parse_error,
    }


def _describe_pem_cert(pem, timeout):
    """Parse subject/issuer/validity out of one PEM certificate via `openssl
    x509` -- the counterpart to _get_full_chain_info's `openssl s_client`
    call, used to fill in per-certificate details for every hop in the chain
    (not just the leaf)."""
    fields = {}
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-serial"],
            input=pem.encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return fields
    for line in proc.stdout.decode(errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "subject":
            fields["subject"] = value
        elif key == "issuer":
            fields["issuer"] = value
        elif key == "notBefore":
            fields["not_before"] = value
        elif key == "notAfter":
            fields["not_after"] = value
        elif key == "serial":
            fields["serial"] = value
    return fields


def _get_full_chain_info(ip, port, sni_hostname, timeout):
    """Fetch the *whole* certificate chain as the server actually sends it --
    leaf plus every intermediate -- via the system `openssl` CLI, since
    Python's own `ssl` module (see _get_cert_chain_info above) only ever
    exposes the leaf certificate. Reports each certificate's validity window
    plus the overall chain verification result against the system trust
    store, e.g. an expired intermediate is exactly the kind of failure that's
    invisible if you only ever look at the leaf cert.

    Raises RuntimeError (with a human-readable reason) if openssl isn't
    available, times out, or the handshake yields no certificates at all.
    """
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{ip}:{port}",
             "-servername", sni_hostname, "-showcerts", "-verify", "10"],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("openssl CLI not available on this system (needed for --check-chain)")
    except subprocess.TimeoutExpired:
        raise RuntimeError("openssl s_client timed out while fetching the chain")

    output = proc.stdout.decode(errors="replace")
    pem_blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)
    if not pem_blocks:
        raise RuntimeError("no certificates returned by 'openssl s_client -showcerts'")

    now = datetime.datetime.now(datetime.timezone.utc)
    chain = []
    errors = []
    for depth, pem in enumerate(pem_blocks):
        fields = _describe_pem_cert(pem, timeout)
        entry = {"depth": depth, **fields}

        valid_now, days_left = None, None
        if fields.get("not_before") and fields.get("not_after"):
            not_before = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(fields["not_before"]), tz=datetime.timezone.utc)
            not_after = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(fields["not_after"]), tz=datetime.timezone.utc)
            valid_now = not_before <= now <= not_after
            days_left = (not_after - now).days
        entry["valid_now"], entry["days_left"] = valid_now, days_left
        chain.append(entry)

        who = fields.get("subject", f"chain position {depth}")
        if valid_now is False:
            if days_left is not None and days_left < 0:
                errors.append(f"[{depth}] {who}: EXPIRED {-days_left} days ago")
            else:
                errors.append(f"[{depth}] {who}: not yet valid")
        elif valid_now is True and days_left is not None and days_left < 14:
            errors.append(f"[{depth}] {who}: expires soon, {days_left} days left")

    verify_match = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", output)
    verify_code = int(verify_match.group(1)) if verify_match else None
    verify_message = verify_match.group(2) if verify_match else "unknown (could not parse openssl output)"
    verify_ok = verify_code == 0
    if not verify_ok:
        errors.append(f"chain verification failed: {verify_message}")

    return {
        "chain": chain,
        "verify_ok": verify_ok,
        "verify_message": verify_message,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Protocol test implementations
#
# Each test function takes (ip, port, timeout, **kwargs) and returns
# (ok, message, details). `details` is a dict of extra fields only printed
# when -v/--verbose is set (some keys, like redirect info, are also used
# internally by main()). `**kwargs` carries protocol-specific extras such as
# --user/--password for SMTP; every other protocol just ignores them.
# ---------------------------------------------------------------------------

def test_opcua(ip, port, timeout, **kwargs):
    """OPC UA: TCP connect + Hello/Acknowledge handshake (SecurityPolicy=None).

    This only verifies the transport-level Hello/Acknowledge exchange. It does
    NOT open a secure channel or a session, so it cannot detect problems that
    occur later in the OPC UA handshake (e.g. OpenSecureChannelRequest).
    """
    url = f"opc.tcp://{ip}:{port}"
    body = struct.pack('<IIIII', 0, 65536, 65536, 0, 0)
    u = url.encode('utf-8')
    body += struct.pack('<i', len(u)) + u
    hello = b'HELF' + struct.pack('<I', 8 + len(body)) + body

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(hello)
            try:
                resp = s.recv(4096)
            except socket.timeout:
                return False, "TCP open, but no response to Hello (timeout) -> OPC UA not responding", {}

            if not resp:
                return False, "TCP open, connection closed with no data -> OPC UA not responding", {}

            tag = resp[:3]
            if tag == b'ACK':
                details = {}
                if len(resp) >= 28:
                    (proto_version, recv_buf, send_buf,
                     max_msg, max_chunk) = struct.unpack('<IIIII', resp[8:28])
                    details = {
                        "protocol_version": proto_version,
                        "receive_buffer_size": recv_buf,
                        "send_buffer_size": send_buf,
                        "max_message_size": max_msg,
                        "max_chunk_count": max_chunk,
                    }
                return True, "OK, server replied ACK -> OPC UA is running and responding", details
            elif tag == b'ERR':
                code = struct.unpack('<I', resp[8:12])[0] if len(resp) >= 12 else 0
                return False, f"server replied ERR, code {code:#x} -> process is running but rejected the handshake", {}
            else:
                return False, f"unexpected response: {resp!r}", {}
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_tcp(ip, port, timeout, **kwargs):
    """Generic TCP: just check whether the port accepts a connection."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, "OK, TCP port is open", {}
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_http(ip, port, timeout, **kwargs):
    """HTTP: TCP connect + minimal HEAD request, checks for a valid status line.

    If the server answers with a 3xx redirect to an https:// URL, this is
    flagged in `details` (redirect_to_https / redirect_location) so the
    caller can automatically follow up with an HTTPS test.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode('ascii'))
            try:
                resp = s.recv(4096)
            except socket.timeout:
                return False, "TCP open, but no HTTP response (timeout)", {}

            if not resp.startswith(b'HTTP/'):
                return False, f"unexpected response: {resp[:80]!r}", {}

            status_code, status_line, headers = parse_http_response(resp)
            details = {"status_code": status_code, "headers": headers}

            if status_code and 300 <= status_code < 400 and 'location' in headers:
                location = headers['location']
                is_https = location.lower().startswith('https://')
                details["redirect_location"] = location
                details["redirect_to_https"] = is_https
                return True, f"OK, server responded: {status_line} -> redirects to {location}", details

            return True, f"OK, server responded: {status_line}", details
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_https(ip, port, timeout, check_chain=False, **kwargs):
    """HTTPS: TLS handshake + certificate validity/trust check + HEAD request.

    With check_chain=True (--check-chain), also fetches the full certificate
    chain (leaf + every intermediate) via the openssl CLI and validates each
    one individually -- catches e.g. an expired intermediate CA, which the
    single-cert trust check above can't distinguish from other verification
    failures.
    """
    try:
        info = _get_cert_chain_info(ip, port, timeout)
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed: {e}", {}
    except ValueError as e:
        return False, str(e), {}
    except OSError as e:
        return False, f"connection error: {e}", {}

    # Best-effort HTTP probe over the TLS session (separate connection);
    # failure here doesn't invalidate the certificate result above.
    status_code, status_line, headers = None, None, {}
    redirect_extra = {}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.settimeout(timeout)
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode('ascii'))
                resp = ssock.recv(4096)
        status_code, status_line, headers = parse_http_response(resp)
        if status_code and 300 <= status_code < 400 and 'location' in headers:
            redirect_extra = {"redirect_location": headers['location']}
    except Exception:
        pass

    if info["valid_now"] is False:
        if info["days_left"] is not None and info["days_left"] < 0:
            cert_status = f"EXPIRED {-info['days_left']} days ago"
        else:
            cert_status = "NOT YET VALID"
    elif info["valid_now"] is True:
        cert_status = f"valid, expires in {info['days_left']} days"
    else:
        cert_status = "validity unknown (could not parse certificate fields)"

    trust_status = "yes" if info["trusted"] else "no (self-signed or untrusted CA)"

    message = (f"OK, TLS handshake succeeded ({info['tls_version']}) -> "
               f"cert {cert_status}, trusted by system CA: {trust_status}")
    if status_line:
        message += f" | HTTP: {status_line}"

    details = {
        "cipher": info["cipher"],
        "subject": info["subject"],
        "issuer": info["issuer"],
        "serial": info["serial"],
        "san": info["san"],
        "not_before": info["not_before"],
        "not_after": info["not_after"],
        "trust_error": info["trust_error"],
        "parse_error": info["parse_error"],
        "status_code": status_code,
        "headers": headers,
    }
    details.update(redirect_extra)

    if check_chain:
        try:
            chain_info = _get_full_chain_info(ip, port, ip, timeout)
        except RuntimeError as e:
            details["chain_error"] = str(e)
            message += f" | chain check failed: {e}"
        else:
            details["chain"] = chain_info["chain"]
            details["chain_verify_ok"] = chain_info["verify_ok"]
            details["chain_verify_message"] = chain_info["verify_message"]
            details["chain_errors"] = chain_info["errors"]
            n = len(chain_info["chain"])
            if chain_info["errors"]:
                message += f" | chain ({n} certs): {'; '.join(chain_info['errors'])}"
            else:
                message += f" | chain ({n} certs): OK"

    return True, message, details


def test_ssh(ip, port, timeout, **kwargs):
    """SSH: TCP connect, reads the server's SSH version banner (no auth)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(256)
            except socket.timeout:
                return False, "TCP open, but no SSH banner (timeout)", {}
            if not banner:
                return False, "TCP open, connection closed with no data", {}
            text = banner.decode(errors='replace').strip()
            if text.startswith("SSH-"):
                return True, f"OK, server banner: {text}", {"banner": text}
            return False, f"unexpected banner: {text!r}", {}
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_ftp(ip, port, timeout, **kwargs):
    """FTP: TCP connect, reads the server's greeting banner (no auth)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(256)
            except socket.timeout:
                return False, "TCP open, but no FTP banner (timeout)", {}
            if not banner:
                return False, "TCP open, connection closed with no data", {}
            text = banner.decode(errors='replace').strip()
            if text[:3].isdigit() and text[0] == '2':
                return True, f"OK, server banner: {text}", {"banner": text}
            return False, f"unexpected banner: {text!r}", {}
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_rdp(ip, port, timeout, **kwargs):
    """RDP: TPKT/X.224 Connection Request, checks for a Connection Confirm."""
    request = bytes([
        0x03, 0x00, 0x00, 0x13,              # TPKT header (version, reserved, length=19)
        0x0e,                                 # X.224 length indicator
        0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,   # X.224 CR TPDU (code, dst-ref, src-ref, class)
        0x01, 0x00, 0x08, 0x00,               # RDP Negotiation Request header (type, flags, length)
        0x03, 0x00, 0x00, 0x00,               # requestedProtocols = SSL | HYBRID (NLA)
    ])
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)
            try:
                resp = s.recv(4096)
            except socket.timeout:
                return False, "TCP open, but no RDP response (timeout)", {}
            if len(resp) < 6 or resp[0] != 0x03:
                return False, f"unexpected response (not TPKT/RDP): {resp[:32]!r}", {}

            x224_code = resp[5]
            if (x224_code & 0xF0) != 0xD0:
                return False, f"unexpected response (not an X.224 Connection Confirm): {resp[:32]!r}", {}

            details = {}
            msg = "OK, RDP responded (X.224 Connection Confirm)"
            if len(resp) >= 19 and resp[11] in (0x02, 0x03):
                neg_type = resp[11]
                value = struct.unpack('<I', resp[15:19])[0]
                if neg_type == 0x02:
                    proto_names = {0: "RDP Standard Security", 1: "TLS", 2: "CredSSP (NLA)", 3: "RDSTLS"}
                    details["negotiated_protocol"] = proto_names.get(value, f"{value:#x}")
                    msg += f", negotiated protocol: {details['negotiated_protocol']}"
                else:
                    details["failure_code"] = f"{value:#x}"
                    msg += f", negotiation FAILURE code {details['failure_code']}"
            return True, msg, details
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_smb(ip, port, timeout, **kwargs):
    """SMB: SMB2 Negotiate Protocol request, reports the negotiated dialect."""
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]

    header = bytearray(64)
    header[0:4] = b'\xfeSMB'
    header[4:6] = struct.pack('<H', 64)   # StructureSize
    header[12:14] = struct.pack('<H', 0)  # Command = NEGOTIATE
    header[14:16] = struct.pack('<H', 1)  # CreditRequest

    body = bytearray()
    body += struct.pack('<H', 36)                # StructureSize
    body += struct.pack('<H', len(dialects))     # DialectCount
    body += struct.pack('<H', 1)                  # SecurityMode = signing enabled
    body += struct.pack('<H', 0)                  # Reserved
    body += struct.pack('<I', 0)                  # Capabilities
    body += b'\x00' * 16                          # ClientGuid
    body += struct.pack('<Q', 0)                  # ClientStartTime
    for d in dialects:
        body += struct.pack('<H', d)

    smb_payload = bytes(header) + bytes(body)
    packet = struct.pack('>I', len(smb_payload)) + smb_payload  # NetBIOS session header

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            try:
                resp = s.recv(4096)
            except socket.timeout:
                return False, "TCP open, but no SMB response (timeout)", {}
            if len(resp) < 8 or resp[4:8] != b'\xfeSMB':
                return False, f"unexpected response (not SMB2): {resp[:32]!r}", {}

            details = {}
            if len(resp) >= 74:
                dialect = struct.unpack('<H', resp[72:74])[0]
                dialect_names = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0",
                                  0x0302: "3.0.2", 0x0311: "3.1.1"}
                details["dialect"] = dialect_names.get(dialect, f"{dialect:#06x}")
                return True, f"OK, SMB2 negotiate succeeded, dialect: {details['dialect']}", details
            return True, "OK, SMB2 response received", details
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_modbus(ip, port, timeout, **kwargs):
    """Modbus TCP: Read Holding Registers request (PLC/industrial protocol).

    An exception response (function code with the high bit set) still counts
    as success here -- it proves a real Modbus stack answered, it just
    rejected this particular register/unit id.
    """
    unit_id = 1
    function = 0x03
    pdu = struct.pack('>BHH', function, 0, 1)  # read 1 holding register at address 0
    mbap = struct.pack('>HHHB', 1, 0, len(pdu) + 1, unit_id)
    request = mbap + pdu

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(request)
            try:
                resp = s.recv(256)
            except socket.timeout:
                return False, "TCP open, but no Modbus response (timeout)", {}
            if len(resp) < 8:
                return False, f"unexpected/short response: {resp!r}", {}

            _trans_id, proto_id, _length, resp_unit_id = struct.unpack('>HHHB', resp[:7])
            if proto_id != 0:
                return False, f"unexpected response (not Modbus, protocol id {proto_id})", {}

            func = resp[7]
            details = {"unit_id": resp_unit_id}
            if func == function:
                byte_count = resp[8] if len(resp) > 8 else 0
                details["byte_count"] = byte_count
                return True, f"OK, Modbus responded (Read Holding Registers OK, {byte_count} data bytes)", details
            elif func == (function | 0x80):
                exc_names = {1: "ILLEGAL FUNCTION", 2: "ILLEGAL DATA ADDRESS", 3: "ILLEGAL DATA VALUE",
                             4: "SLAVE DEVICE FAILURE", 6: "SLAVE DEVICE BUSY"}
                exc_code = resp[8] if len(resp) > 8 else None
                details["exception_code"] = exc_names.get(exc_code, exc_code)
                return True, f"OK, Modbus responded (exception: {details['exception_code']}) -> Modbus is running, just rejected this request", details
            else:
                return False, f"unexpected function code in response: {func:#x}", {}
    except socket.timeout:
        return False, "timed out (no TCP connection)", {}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {}
    except OSError as e:
        return False, f"connection error: {e}", {}


def _skip_dns_name(data, offset):
    """Skip over a (possibly compressed) DNS name, return the offset after it."""
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length


def test_dns(ip, port, timeout, **kwargs):
    """DNS: UDP query for a well-known name, checks for a valid response.

    Any well-formed response (NOERROR, NXDOMAIN, REFUSED, ...) counts as the
    server "speaking DNS" -- the rcode is reported so you can see what it
    actually said.
    """
    rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                   4: "NOTIMP", 5: "REFUSED"}
    qname = "www.example.com"
    txid = random.randint(0, 65535)
    header = struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    question = b''.join(struct.pack('B', len(part)) + part.encode() for part in qname.split('.')) + b'\x00'
    question += struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    query = header + question

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (ip, port))
            try:
                resp, _ = s.recvfrom(4096)
            except socket.timeout:
                return False, "no response (UDP timeout) -> DNS not responding", {}

        if len(resp) < 12:
            return False, f"malformed response ({len(resp)} bytes)", {}

        resp_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack('>HHHHHH', resp[:12])
        if resp_id != txid:
            return False, "response transaction ID mismatch (possible spoofed/stale packet)", {}

        rcode = flags & 0x000F
        rcode_name = rcode_names.get(rcode, f"RCODE {rcode}")

        offset = 12
        for _ in range(qdcount):
            offset = _skip_dns_name(resp, offset) + 4  # + QTYPE/QCLASS

        answers = []
        for _ in range(ancount):
            offset = _skip_dns_name(resp, offset)
            if offset + 10 > len(resp):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack('>HHIH', resp[offset:offset + 10])
            offset += 10
            rdata = resp[offset:offset + rdlength]
            if rtype == 1 and rdlength == 4:
                answers.append('.'.join(str(b) for b in rdata))
            offset += rdlength

        details = {"query": qname, "rcode": rcode_name, "answer_count": ancount, "answers": answers}
        msg = f"OK, DNS server responded: {rcode_name}, {ancount} answer(s)"
        if answers:
            msg += f" ({', '.join(answers)})"
        return True, msg, details
    except OSError as e:
        return False, f"connection error: {e}", {}


def test_ntp(ip, port, timeout, **kwargs):
    """NTP: UDP time query, reports stratum and the server's reported time."""
    packet = bytearray(48)
    packet[0] = 0x1B  # LI=0, VN=3, Mode=3 (client)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(bytes(packet), (ip, port))
            try:
                resp, _ = s.recvfrom(128)
            except socket.timeout:
                return False, "no response (UDP timeout) -> NTP not responding", {}

        if len(resp) < 48:
            return False, f"malformed response ({len(resp)} bytes)", {}

        mode = resp[0] & 0x07
        stratum = resp[1]
        if mode != 4:
            return False, f"unexpected NTP mode in response ({mode})", {}

        seconds = struct.unpack('>I', resp[40:44])[0]
        unix_time = seconds - 2208988800  # NTP epoch (1900) -> Unix epoch (1970)
        server_time = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
        server_time_str = server_time.strftime('%Y-%m-%d %H:%M:%S UTC')

        if stratum == 0:
            stratum_desc = "unsynchronized / kiss-of-death"
        elif stratum == 1:
            stratum_desc = "primary reference"
        else:
            stratum_desc = f"secondary, stratum {stratum}"

        details = {"stratum": stratum, "server_time_utc": server_time_str}
        return True, f"OK, NTP server responded ({stratum_desc}), server time: {server_time_str}", details
    except OSError as e:
        return False, f"connection error: {e}", {}


def _recv_smtp_reply(sock, timeout):
    """Read one SMTP reply (possibly multi-line) and return it as a list of lines."""
    sock.settimeout(timeout)
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        text = buf.decode(errors='replace')
        lines = [l for l in text.split("\r\n") if l != ""] or text.split("\r\n")
        if lines and len(lines[-1]) >= 4 and lines[-1][3] == ' ':
            return lines
    return [l for l in buf.decode(errors='replace').split("\r\n") if l]


def _recv_line(sock, timeout):
    """Read a single CRLF-terminated line (used by the line-oriented POP3/IMAP
    protocols). Byte-at-a-time is fine here: responses are small and this
    keeps the framing correct without needing a persistent read buffer."""
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors='replace').rstrip("\r\n")


def _smtp_session(sock, ip, timeout, user, password, transcript, allow_starttls):
    """Run the EHLO -> [STARTTLS] -> [AUTH LOGIN] -> QUIT conversation over an
    already-connected socket (plain for STARTTLS-capable smtp, or already
    wrapped in TLS for smtps). Returns (ok, message, details).

    Note: on a successful STARTTLS upgrade this reassigns the local `sock`
    variable to the wrapped TLS socket; `send`/`recv` below close over that
    same variable, so they automatically start using the encrypted socket
    for every call made after the upgrade.
    """
    def send(line):
        transcript.append((">", line))
        sock.sendall((line + "\r\n").encode("ascii", errors="replace"))

    def recv():
        lines = _recv_smtp_reply(sock, timeout)
        for line in lines:
            transcript.append(("<", line))
        return lines

    banner = recv()
    if not banner or not (banner[0][:1] == '2'):
        return False, f"unexpected/no banner: {banner!r}", {"transcript": transcript}

    local_name = socket.gethostname()
    send(f"EHLO {local_name}")
    ehlo_resp = recv()
    used_helo = False
    capabilities = []

    if not ehlo_resp or ehlo_resp[0][:3] != "250":
        send(f"HELO {local_name}")
        helo_resp = recv()
        used_helo = True
        if not helo_resp or helo_resp[0][:3] != "250":
            send("QUIT")
            recv()
            return False, "server rejected both EHLO and HELO", {"transcript": transcript}
    else:
        capabilities = [l[4:] for l in ehlo_resp if len(l) > 4]

    starttls_used = False
    if allow_starttls and any(c.strip().upper() == "STARTTLS" for c in capabilities):
        send("STARTTLS")
        tls_resp = recv()
        if tls_resp and tls_resp[0].startswith("220"):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
            starttls_used = True
            # RFC 3207: capabilities must be re-negotiated after STARTTLS.
            send(f"EHLO {local_name}")
            ehlo_resp2 = recv()
            if ehlo_resp2 and ehlo_resp2[0][:3] == "250":
                capabilities = [l[4:] for l in ehlo_resp2 if len(l) > 4]

    auth_result = None
    if user is not None and password is not None:
        send("AUTH LOGIN")
        r1 = recv()
        if r1 and r1[0].startswith("334"):
            send(base64.b64encode(user.encode()).decode())
            r2 = recv()
            if r2 and r2[0].startswith("334"):
                send(base64.b64encode(password.encode()).decode())
                r3 = recv()
                auth_result = "success" if (r3 and r3[0].startswith("235")) else \
                    f"failed ({r3[0] if r3 else 'no response'})"
            else:
                auth_result = f"failed ({r2[0] if r2 else 'no response'})"
        else:
            auth_result = f"AUTH LOGIN not accepted ({r1[0] if r1 else 'no response'})"

    send("QUIT")
    recv()

    details = {
        "banner": banner[0] if banner else None,
        "used_helo_fallback": used_helo,
        "starttls_used": starttls_used,
        "capabilities": capabilities,
        "auth_result": auth_result,
        "transcript": transcript,
    }
    msg = f"OK, server banner: {banner[0]}"
    if starttls_used:
        msg += ", upgraded via STARTTLS"
    if capabilities:
        msg += f", {len(capabilities)} EHLO capabilities"
    elif used_helo:
        msg += " (EHLO not supported, fell back to HELO)"
    if auth_result:
        msg += f", AUTH LOGIN: {auth_result}"
    return True, msg, details


def test_smtp(ip, port, timeout, user=None, password=None, **kwargs):
    """SMTP (ports 25/587): EHLO/HELO handshake, showing the conversation (-v).

    If the server advertises STARTTLS after EHLO, the connection is
    automatically upgraded to TLS before AUTH is attempted -- this is what
    port 587 (submission) normally requires. If --user/--password are
    supplied, also attempts AUTH LOGIN and reports whether the credentials
    were accepted.
    """
    transcript = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return _smtp_session(s, ip, timeout, user, password, transcript, allow_starttls=True)
    except socket.timeout:
        return False, "timed out (no TCP connection)", {"transcript": transcript}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {"transcript": transcript}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed during STARTTLS upgrade: {e}", {"transcript": transcript}
    except OSError as e:
        return False, f"connection error: {e}", {"transcript": transcript}


def test_smtps(ip, port, timeout, user=None, password=None, **kwargs):
    """SMTPS (port 465): implicit TLS from the first byte, same conversation
    as `smtp` (EHLO, optional AUTH LOGIN, QUIT) but already encrypted.
    """
    transcript = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                s.settimeout(timeout)
                ok, msg, details = _smtp_session(s, ip, timeout, user, password, transcript, allow_starttls=False)
                if details:
                    details["tls"] = f"implicit TLS ({s.version()})"
                    if ok:
                        msg = msg.replace("OK, server banner:", f"OK ({s.version()}), server banner:", 1)
                return ok, msg, details
    except socket.timeout:
        return False, "timed out (no TCP connection)", {"transcript": transcript}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {"transcript": transcript}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed: {e}", {"transcript": transcript}
    except OSError as e:
        return False, f"connection error: {e}", {"transcript": transcript}


def _pop3_session(sock, ip, timeout, user, password, transcript, allow_stls):
    """POP3 conversation: greeting -> CAPA -> [STLS] -> [USER/PASS] -> QUIT.

    Same "reassign the closed-over `sock`" trick as _smtp_session: after a
    successful STLS upgrade, send/recv_line below transparently switch to
    the encrypted socket for every subsequent call.
    """
    def send(line):
        transcript.append((">", line))
        sock.sendall((line + "\r\n").encode("ascii", errors="replace"))

    def recv_line():
        line = _recv_line(sock, timeout)
        transcript.append(("<", line))
        return line

    def recv_multiline():
        lines = []
        while True:
            line = recv_line()
            if line == ".":
                break
            lines.append(line)
        return lines

    greeting = recv_line()
    if not greeting.startswith("+OK"):
        return False, f"unexpected/no greeting: {greeting!r}", {"transcript": transcript}

    send("CAPA")
    capa_resp = recv_line()
    capabilities = []
    if capa_resp.startswith("+OK"):
        capabilities = recv_multiline()

    stls_used = False
    if allow_stls and any(c.strip().upper() == "STLS" for c in capabilities):
        send("STLS")
        stls_resp = recv_line()
        if stls_resp.startswith("+OK"):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
            stls_used = True
            send("CAPA")
            capa_resp2 = recv_line()
            if capa_resp2.startswith("+OK"):
                capabilities = recv_multiline()

    login_result = None
    if user is not None and password is not None:
        send(f"USER {user}")
        user_resp = recv_line()
        if user_resp.startswith("+OK"):
            send(f"PASS {password}")
            pass_resp = recv_line()
            login_result = "success" if pass_resp.startswith("+OK") else f"failed ({pass_resp})"
        else:
            login_result = f"USER rejected ({user_resp})"

    send("QUIT")
    recv_line()

    details = {
        "greeting": greeting,
        "stls_used": stls_used,
        "capabilities": capabilities,
        "login_result": login_result,
        "transcript": transcript,
    }
    msg = f"OK, server greeting: {greeting}"
    if stls_used:
        msg += ", upgraded via STLS"
    if capabilities:
        msg += f", {len(capabilities)} capabilities"
    if login_result:
        msg += f", login: {login_result}"
    return True, msg, details


def test_pop3(ip, port, timeout, user=None, password=None, **kwargs):
    """POP3 (port 110): greeting + CAPA, auto-upgrades via STLS if offered.

    If --user/--password are supplied, also attempts a USER/PASS login and
    reports whether it succeeded.
    """
    transcript = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return _pop3_session(s, ip, timeout, user, password, transcript, allow_stls=True)
    except socket.timeout:
        return False, "timed out (no TCP connection)", {"transcript": transcript}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {"transcript": transcript}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed during STLS upgrade: {e}", {"transcript": transcript}
    except OSError as e:
        return False, f"connection error: {e}", {"transcript": transcript}


def test_pop3s(ip, port, timeout, user=None, password=None, **kwargs):
    """POP3S (port 995): implicit TLS from the first byte."""
    transcript = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                s.settimeout(timeout)
                ok, msg, details = _pop3_session(s, ip, timeout, user, password, transcript, allow_stls=False)
                if details:
                    details["tls"] = f"implicit TLS ({s.version()})"
                    if ok:
                        msg = msg.replace("OK, server greeting:", f"OK ({s.version()}), server greeting:", 1)
                return ok, msg, details
    except socket.timeout:
        return False, "timed out (no TCP connection)", {"transcript": transcript}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {"transcript": transcript}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed: {e}", {"transcript": transcript}
    except OSError as e:
        return False, f"connection error: {e}", {"transcript": transcript}


def _imap_session(sock, ip, timeout, user, password, transcript, allow_starttls):
    """IMAP conversation: greeting -> CAPABILITY -> [STARTTLS] -> [LOGIN] -> LOGOUT."""
    tag_counter = [0]

    def next_tag():
        tag_counter[0] += 1
        return f"a{tag_counter[0]}"

    def send(line):
        transcript.append((">", line))
        sock.sendall((line + "\r\n").encode("ascii", errors="replace"))

    def recv_line():
        line = _recv_line(sock, timeout)
        transcript.append(("<", line))
        return line

    def recv_until_tag(tag):
        lines = []
        while True:
            line = recv_line()
            lines.append(line)
            if line.startswith(tag + " "):
                break
        return lines

    greeting = recv_line()
    if not (greeting.startswith("* OK") or greeting.startswith("* PREAUTH")):
        return False, f"unexpected/no greeting: {greeting!r}", {"transcript": transcript}

    tag = next_tag()
    send(f"{tag} CAPABILITY")
    lines = recv_until_tag(tag)
    capabilities = []
    for l in lines:
        if l.upper().startswith("* CAPABILITY"):
            capabilities = l.split()[2:]
    final = lines[-1] if lines else ""
    if f"{tag} OK" not in final:
        return False, f"CAPABILITY command failed: {final!r}", {"transcript": transcript}

    starttls_used = False
    if allow_starttls and any(c.upper() == "STARTTLS" for c in capabilities):
        tag = next_tag()
        send(f"{tag} STARTTLS")
        lines = recv_until_tag(tag)
        final = lines[-1] if lines else ""
        if f"{tag} OK" in final:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
            starttls_used = True
            tag = next_tag()
            send(f"{tag} CAPABILITY")
            lines = recv_until_tag(tag)
            for l in lines:
                if l.upper().startswith("* CAPABILITY"):
                    capabilities = l.split()[2:]

    login_result = None
    if user is not None and password is not None:
        tag = next_tag()
        send(f'{tag} LOGIN "{user}" "{password}"')
        lines = recv_until_tag(tag)
        final = lines[-1] if lines else ""
        login_result = "success" if f"{tag} OK" in final else f"failed ({final})"

    tag = next_tag()
    send(f"{tag} LOGOUT")
    recv_until_tag(tag)

    details = {
        "greeting": greeting,
        "starttls_used": starttls_used,
        "capabilities": capabilities,
        "login_result": login_result,
        "transcript": transcript,
    }
    msg = f"OK, server greeting: {greeting}"
    if starttls_used:
        msg += ", upgraded via STARTTLS"
    if capabilities:
        msg += f", {len(capabilities)} capabilities"
    if login_result:
        msg += f", login: {login_result}"
    return True, msg, details


def test_imap(ip, port, timeout, user=None, password=None, **kwargs):
    """IMAP (port 143): greeting + CAPABILITY, auto-upgrades via STARTTLS if offered.

    If --user/--password are supplied, also attempts a LOGIN and reports
    whether it succeeded.
    """
    transcript = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return _imap_session(s, ip, timeout, user, password, transcript, allow_starttls=True)
    except socket.timeout:
        return False, "timed out (no TCP connection)", {"transcript": transcript}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {"transcript": transcript}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed during STARTTLS upgrade: {e}", {"transcript": transcript}
    except OSError as e:
        return False, f"connection error: {e}", {"transcript": transcript}


def test_imaps(ip, port, timeout, user=None, password=None, **kwargs):
    """IMAPS (port 993): implicit TLS from the first byte."""
    transcript = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                s.settimeout(timeout)
                ok, msg, details = _imap_session(s, ip, timeout, user, password, transcript, allow_starttls=False)
                if details:
                    details["tls"] = f"implicit TLS ({s.version()})"
                    if ok:
                        msg = msg.replace("OK, server greeting:", f"OK ({s.version()}), server greeting:", 1)
                return ok, msg, details
    except socket.timeout:
        return False, "timed out (no TCP connection)", {"transcript": transcript}
    except ConnectionRefusedError:
        return False, "connection refused (port closed)", {"transcript": transcript}
    except ssl.SSLError as e:
        return False, f"TLS handshake failed: {e}", {"transcript": transcript}
    except OSError as e:
        return False, f"connection error: {e}", {"transcript": transcript}


PROTOCOLS = {
    "opc": {
        "port": 4840,
        "description": "OPC UA - TCP connect + Hello/Acknowledge handshake",
        "test": test_opcua,
    },
    "http": {
        "port": 80,
        "description": "HTTP - TCP connect + HEAD request (auto-follows redirects to https)",
        "test": test_http,
    },
    "https": {
        "port": 443,
        "description": "HTTPS - TLS handshake + certificate validity/trust check (add --check-chain to validate the full chain)",
        "test": test_https,
    },
    "ssh": {
        "port": 22,
        "description": "SSH - TCP connect, reads the SSH version banner",
        "test": test_ssh,
    },
    "ftp": {
        "port": 21,
        "description": "FTP - TCP connect, reads the FTP greeting banner",
        "test": test_ftp,
    },
    "smtp": {
        "port": 25,
        "description": "SMTP (25/587) - EHLO conversation, auto-upgrades via STARTTLS if offered, optional --user/--password AUTH test",
        "test": test_smtp,
    },
    "smtps": {
        "port": 465,
        "description": "SMTPS (465) - implicit TLS from the start, same EHLO/AUTH conversation as smtp",
        "test": test_smtps,
    },
    "pop3": {
        "port": 110,
        "description": "POP3 (110) - greeting+CAPA, auto-upgrades via STLS if offered, optional --user/--password login test",
        "test": test_pop3,
    },
    "pop3s": {
        "port": 995,
        "description": "POP3S (995) - implicit TLS from the start, same POP3 conversation",
        "test": test_pop3s,
    },
    "imap": {
        "port": 143,
        "description": "IMAP (143) - greeting+CAPABILITY, auto-upgrades via STARTTLS if offered, optional --user/--password login test",
        "test": test_imap,
    },
    "imaps": {
        "port": 993,
        "description": "IMAPS (993) - implicit TLS from the start, same IMAP conversation",
        "test": test_imaps,
    },
    "rdp": {
        "port": 3389,
        "description": "RDP - X.224/TPKT connection request, checks for Connection Confirm",
        "test": test_rdp,
    },
    "smb": {
        "port": 445,
        "description": "SMB - SMB2 Negotiate Protocol request, reports negotiated dialect",
        "test": test_smb,
    },
    "modbus": {
        "port": 502,
        "description": "Modbus TCP - Read Holding Registers request (PLC/industrial protocol)",
        "test": test_modbus,
    },
    "dns": {
        "port": 53,
        "description": "DNS - UDP query for a well-known name, checks for a valid response",
        "test": test_dns,
    },
    "ntp": {
        "port": 123,
        "description": "NTP - UDP time query, reports stratum and server time",
        "test": test_ntp,
    },
    "tcp": {
        "port": None,
        "description": "Generic TCP - just checks whether the port opens (requires --port)",
        "test": test_tcp,
    },
}


# ---------------------------------------------------------------------------
# Ping (cross-platform: Windows / Linux / WSL)
# ---------------------------------------------------------------------------

def ping(ip, timeout=2):
    """Send a single ICMP echo request. Returns (ok, message)."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2)
        if result.returncode == 0:
            return True, "OK, host replies to ping"
        return False, "no reply to ping (0% received)"
    except subprocess.TimeoutExpired:
        return False, "ping timed out"
    except FileNotFoundError:
        return False, "ping command not available on this system"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_details(protocol, details):
    """Print extended (-v) information for a completed protocol test."""
    if not details:
        return

    if protocol in ("http", "https"):
        if details.get("status_code") is not None:
            print(f"    status code   : {details['status_code']}")
        headers = details.get("headers") or {}
        if headers:
            print("    headers       :")
            for k, v in headers.items():
                print(f"      {k}: {v}")

    if protocol == "https":
        if details.get("subject"):
            print(f"    subject       : {details['subject']}")
        if details.get("issuer"):
            print(f"    issuer        : {details['issuer']}")
        if details.get("serial"):
            print(f"    serial number : {details['serial']}")
        if details.get("san"):
            print(f"    SAN           : {', '.join(details['san'])}")
        if details.get("not_before"):
            print(f"    valid from    : {details['not_before']}")
        if details.get("not_after"):
            print(f"    valid until   : {details['not_after']}")
        if details.get("cipher"):
            print(f"    cipher suite  : {details['cipher']}")
        if details.get("trust_error"):
            print(f"    trust error   : {details['trust_error']}")
        if details.get("parse_error"):
            print(f"    parse error   : {details['parse_error']}")
        if details.get("chain"):
            print(f"    chain ({len(details['chain'])} certs):")
            for c in details["chain"]:
                if c.get("valid_now") is True:
                    status = f"valid, {c.get('days_left')}d left"
                elif c.get("valid_now") is False:
                    status = "EXPIRED" if (c.get("days_left") or 0) < 0 else "NOT YET VALID"
                else:
                    status = "unknown"
                print(f"      [{c['depth']}] {c.get('subject', '?')}")
                print(f"          issuer: {c.get('issuer', '?')}  [{status}]")
            verify_status = "ok" if details.get("chain_verify_ok") else f"FAILED: {details.get('chain_verify_message')}"
            print(f"    chain verify  : {verify_status}")
        if details.get("chain_error"):
            print(f"    chain check   : FAILED ({details['chain_error']})")

    if protocol == "opc":
        for key in ("protocol_version", "receive_buffer_size", "send_buffer_size",
                    "max_message_size", "max_chunk_count"):
            if key in details:
                print(f"    {key:<14}: {details[key]}")

    if protocol in ("ssh", "ftp"):
        if details.get("banner"):
            print(f"    banner        : {details['banner']}")

    if protocol == "rdp":
        if details.get("negotiated_protocol"):
            print(f"    negotiated    : {details['negotiated_protocol']}")
        if details.get("failure_code"):
            print(f"    failure code  : {details['failure_code']}")

    if protocol == "smb":
        if details.get("dialect"):
            print(f"    dialect       : {details['dialect']}")

    if protocol == "modbus":
        for key in ("unit_id", "byte_count", "exception_code"):
            if key in details:
                print(f"    {key:<14}: {details[key]}")

    if protocol == "dns":
        if details.get("query"):
            print(f"    query name    : {details['query']}")
        if details.get("rcode"):
            print(f"    rcode         : {details['rcode']}")
        if "answer_count" in details:
            print(f"    answer count  : {details['answer_count']}")
        if details.get("answers"):
            print(f"    answers       : {', '.join(details['answers'])}")

    if protocol == "ntp":
        if "stratum" in details:
            print(f"    stratum       : {details['stratum']}")
        if details.get("server_time_utc"):
            print(f"    server time   : {details['server_time_utc']}")

    if protocol in ("smtp", "smtps"):
        if details.get("tls"):
            print(f"    TLS           : {details['tls']}")
        if details.get("starttls_used"):
            print("    STARTTLS      : upgraded")
        if details.get("capabilities"):
            print(f"    capabilities  : {', '.join(details['capabilities'])}")
        if details.get("auth_result"):
            print(f"    AUTH LOGIN    : {details['auth_result']}")
        if details.get("transcript"):
            print("    conversation  :")
            for direction, line in details["transcript"]:
                arrow = "C ->" if direction == ">" else "S <-"
                print(f"      {arrow} {line}")

    if protocol in ("pop3", "pop3s"):
        if details.get("tls"):
            print(f"    TLS           : {details['tls']}")
        if details.get("stls_used"):
            print("    STLS          : upgraded")
        if details.get("capabilities"):
            print(f"    capabilities  : {', '.join(details['capabilities'])}")
        if details.get("login_result"):
            print(f"    login         : {details['login_result']}")
        if details.get("transcript"):
            print("    conversation  :")
            for direction, line in details["transcript"]:
                arrow = "C ->" if direction == ">" else "S <-"
                print(f"      {arrow} {line}")

    if protocol in ("imap", "imaps"):
        if details.get("tls"):
            print(f"    TLS           : {details['tls']}")
        if details.get("starttls_used"):
            print("    STARTTLS      : upgraded")
        if details.get("capabilities"):
            print(f"    capabilities  : {', '.join(details['capabilities'])}")
        if details.get("login_result"):
            print(f"    login         : {details['login_result']}")
        if details.get("transcript"):
            print("    conversation  :")
            for direction, line in details["transcript"]:
                arrow = "C ->" if direction == ">" else "S <-"
                print(f"      {arrow} {line}")


def run_and_print(protocol, ip, port, timeout, verbose, label=None, **extra):
    """Run one protocol test against one host and print the result line(s)."""
    cfg = PROTOCOLS[protocol]
    try:
        ok, msg, details = cfg["test"](ip, port, timeout, **extra)
    except Exception as e:
        ok, msg, details = False, f"unexpected error: {e}", {}

    status = "OK  " if ok else "FAIL"
    tag = (label or protocol).upper()
    print(f"{ip:<16} [{tag:<5} {status}] {msg}")
    if verbose:
        print_details(protocol, details)
    return ok, msg, details


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_protocols():
    print("Available protocols:")
    for name, cfg in PROTOCOLS.items():
        default_port = cfg["port"] if cfg["port"] is not None else "required via --port"
        print(f"  {name:<7} default port: {str(default_port):<20} {cfg['description']}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="protocol_tester.py",
        description="Reusable protocol connectivity tester (TCP/UDP + application-layer handshake checks).",
    )
    parser.add_argument("-p", "--protocol", choices=PROTOCOLS.keys(),
                         help="protocol to test (see --protocols for the list)")
    protocols_action = parser.add_argument("--protocols", action="store_true",
                         help="list available protocols and exit")
    if clidescribe:
        clidescribe.hide_from_schema(protocols_action)
    parser.add_argument("--ping", action="store_true",
                         help="also perform a ping check before the protocol test")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="show extended per-protocol information (headers, certificate "
                              "details, full SMTP conversation, etc.)")
    parser.add_argument("--port", type=int, default=None,
                         help="override the default port for the selected protocol")
    parser.add_argument("--timeout", type=float, default=3.0,
                         help="timeout in seconds (default: 3)")
    parser.add_argument("--user", default=None,
                         help="username for login/AUTH (smtp/smtps/pop3/pop3s/imap/imaps only)")
    parser.add_argument("--password", default=None,
                         help="password for login/AUTH (smtp/smtps/pop3/pop3s/imap/imaps only)")
    parser.add_argument("--check-chain", action="store_true",
                         help="fetch and validate the FULL certificate chain (leaf + every "
                              "intermediate, not just the leaf), reporting each certificate's "
                              "subject/issuer/expiry and any chain verification errors (https "
                              "only; requires the openssl CLI)")
    parser.add_argument("targets", nargs="*", metavar="IP",
                         help="one or more IP addresses / hostnames to test")
    if clidescribe:
        clidescribe.add_describe_flag(parser)
    return parser


def main():
    parser = build_parser()
    if clidescribe and clidescribe.maybe_describe(parser):
        return
    args = parser.parse_args()

    if args.protocols:
        print_protocols()
        return

    if not args.protocol:
        parser.error("-p/--protocol is required (use --protocols to list available protocols)")

    if not args.targets:
        parser.error("at least one IP address / hostname is required")

    cfg = PROTOCOLS[args.protocol]
    port = args.port if args.port is not None else cfg["port"]
    if port is None:
        parser.error(f"protocol '{args.protocol}' has no default port, please specify --port")

    extra = {}
    if args.protocol in ("smtp", "smtps", "pop3", "pop3s", "imap", "imaps"):
        extra = {"user": args.user, "password": args.password}
    elif args.protocol == "https":
        extra = {"check_chain": args.check_chain}

    for ip in args.targets:
        if args.ping:
            ok, msg = ping(ip, timeout=min(args.timeout, 2))
            status = "OK  " if ok else "FAIL"
            print(f"{ip:<16} [PING {status}] {msg}")

        ok, msg, details = run_and_print(args.protocol, ip, port, args.timeout, args.verbose, **extra)

        # If an HTTP test hit a redirect to https://, automatically follow up
        # with an HTTPS test against the redirect target.
        if args.protocol == "http" and ok and details.get("redirect_to_https"):
            location = details.get("redirect_location", "")
            parsed = urllib.parse.urlsplit(location)
            target_host = parsed.hostname or ip
            target_port = parsed.port or 443
            print(f"{ip:<16} [HTTP->HTTPS] redirect detected -> testing {target_host}:{target_port}")
            run_and_print("https", target_host, target_port, args.timeout, args.verbose,
                          check_chain=args.check_chain)


if __name__ == "__main__":
    main()
