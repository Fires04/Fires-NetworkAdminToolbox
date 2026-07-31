"""cert_inspector.parser -- certificate parsing and chain-building via the
system `openssl` CLI.

Same approach as cli_scripts/protocol_tester.py's --check-chain (shell out
to `openssl x509`/`s_client` rather than add a Python X.509 dependency), but
this module is otherwise independent -- no shared code between the two,
they just happen to solve overlapping problems the same stdlib-adjacent way.
"""
import datetime
import re
import ssl
import subprocess
import tempfile
from pathlib import Path

_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def _run(args, input_bytes=b"", timeout=10):
    return subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)


def normalize_to_pem_blocks(raw: bytes):
    """Accept PEM text (one or more concatenated certificates -- a full
    exported chain file is just this) or a single DER-encoded certificate.
    Returns a list of PEM blocks, in whatever order they were given -- chain
    building doesn't assume leaf-first, it works the real order out from
    issuer/subject relationships. Does NOT handle PKCS#12 (.pfx/.p12) --
    those need a password, see extract_pkcs12_certs.
    """
    text = raw.decode("utf-8", errors="ignore")
    blocks = _PEM_RE.findall(text)
    if blocks:
        return blocks
    if not raw.strip():
        return []
    try:
        proc = _run(["openssl", "x509", "-inform", "DER", "-outform", "PEM"], input_bytes=raw)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return _PEM_RE.findall(proc.stdout.decode(errors="replace"))


def extract_pkcs12_certs(raw: bytes, password: str = ""):
    """Extract every certificate (leaf + any chain certs bundled alongside
    it) from a PKCS#12 (.pfx/.p12) container -- the common Windows/IIS
    export format, which bundles the private key together with the cert(s)
    behind a password, in a binary structure `openssl x509` can't read
    directly.

    The password goes in over stdin (`-passin stdin`), not as a `-passin
    pass:...` argument, so it never shows up in this process's argv (e.g.
    to another local user running `ps aux` during the brief subprocess
    call).

    OpenSSL 3.x refuses by default to read older PKCS#12 files encrypted
    with RC2/3DES (still common from older Windows/Java tooling) unless
    `-legacy` is passed; this tries the modern default first and only
    retries with `-legacy` if that comes back empty.

    Raises RuntimeError (wrong password, corrupt file, not PKCS#12 at all)
    with openssl's own message if nothing could be extracted.
    """
    with tempfile.TemporaryDirectory() as d:
        pfx_path = Path(d) / "in.pfx"
        pfx_path.write_bytes(raw)
        base_args = ["openssl", "pkcs12", "-in", str(pfx_path), "-nokeys", "-passin", "stdin"]
        stdin = (password + "\n").encode()

        try:
            proc = _run(base_args, input_bytes=stdin)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(str(e))
        blocks = _PEM_RE.findall(proc.stdout.decode(errors="replace"))
        if blocks:
            return blocks

        try:
            proc = _run(base_args + ["-legacy"], input_bytes=stdin)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(str(e))
        out = proc.stdout.decode(errors="replace")
        blocks = _PEM_RE.findall(out)
        if blocks:
            return blocks

    raise RuntimeError(
        "could not read this as a PKCS#12 (.pfx/.p12) file -- "
        + (f"wrong password? ({out.strip()[-200:]})" if out.strip() else "wrong password or corrupt file"))


def _field(text, name):
    m = re.search(rf"^{name}=(.*)$", text, re.M)
    return m.group(1).strip() if m else None


def _first(pattern, text):
    m = re.search(pattern, text)
    return m.group(1) if m else None


def _parse_ext_block(text, header):
    """Extract the body under an 'X509v3 <header>:' / 'Authority Information
    Access:' line in `openssl x509 -text` output, using indentation to find
    where it ends -- a fixed-width regex can't tell "still part of this
    extension" apart from "next field entirely", since both are indented
    relative to the certificate as a whole. Blank lines inside a block
    (e.g. between CRL distribution point entries) don't end it; the next
    line at the header's own indentation or shallower does.
    """
    lines = text.splitlines()
    header_indent, critical, start = None, False, None
    header_re = re.compile(rf"^([ \t]*){re.escape(header)}:\s*(critical)?\s*$")
    for i, line in enumerate(lines):
        m = header_re.match(line)
        if m:
            header_indent = len(m.group(1))
            critical = bool(m.group(2))
            start = i + 1
            break
    if start is None:
        return None

    body_lines = []
    for line in lines[start:]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= header_indent:
            break
        body_lines.append(line.strip())
    return {"critical": critical, "value": "\n".join(body_lines)}


def _extract_prefixed(value, prefix):
    if not value:
        return []
    out = []
    for part in value.split(","):
        part = part.strip()
        if part.upper().startswith(prefix.upper() + ":"):
            out.append(part.split(":", 1)[1].strip())
    return out


def describe_cert(pem: str, index: int, timeout=10) -> dict:
    """Parse one PEM certificate into a dict covering everything useful for
    debugging: identity (subject/issuer/serial/SAN), validity window,
    extensions (basic constraints, key usage, AIA, CRL distribution points,
    key identifiers), fingerprints, and the full `openssl x509 -text` dump
    for anything not explicitly broken out above.
    """
    cert = {"index": index, "raw_text": None, "parse_error": None}
    try:
        proc = _run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-serial",
             "-startdate", "-enddate", "-fingerprint", "-sha256", "-text"],
            input_bytes=pem.encode(), timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        cert["parse_error"] = str(e)
        return cert

    out = proc.stdout.decode(errors="replace")
    if proc.returncode != 0 or "subject=" not in out:
        cert["parse_error"] = out.strip()[:500] or "openssl could not parse this certificate"
        return cert

    cert["subject"] = _field(out, "subject")
    cert["issuer"] = _field(out, "issuer")
    cert["serial"] = _field(out, "serial")
    not_before_s = _field(out, "notBefore")
    not_after_s = _field(out, "notAfter")
    cert["not_before"] = not_before_s
    cert["not_after"] = not_after_s
    cert["fingerprint_sha256"] = _field(out, "SHA256 Fingerprint")

    try:
        fp1 = _run(["openssl", "x509", "-noout", "-fingerprint"], input_bytes=pem.encode(), timeout=timeout)
        cert["fingerprint_sha1"] = _field(fp1.stdout.decode(errors="replace"), "SHA1 Fingerprint")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        cert["fingerprint_sha1"] = None

    cert["valid_now"] = cert["days_left"] = cert["not_yet_valid"] = cert["expired"] = None
    if not_before_s and not_after_s:
        try:
            not_before = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(not_before_s), tz=datetime.timezone.utc)
            not_after = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(not_after_s), tz=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            cert["valid_now"] = not_before <= now <= not_after
            cert["days_left"] = (not_after - now).days
            cert["not_yet_valid"] = now < not_before
            cert["expired"] = now > not_after
        except ValueError:
            pass

    text_m = re.search(r"(Certificate:\n.*)", out, re.S)
    raw_text = text_m.group(1) if text_m else out
    cert["raw_text"] = raw_text

    cert["version"] = _first(r"Version:\s*(\d+)", raw_text)
    cert["signature_algorithm"] = _first(r"Signature Algorithm:\s*(\S+)", raw_text)
    cert["public_key_algorithm"] = _first(r"Public Key Algorithm:\s*(\S+)", raw_text)
    cert["public_key_size"] = _first(r"Public-Key:\s*\(([^)]+)\)", raw_text)

    san = _parse_ext_block(raw_text, "X509v3 Subject Alternative Name")
    cert["subject_alt_name"] = san["value"] if san else None
    cert["dns_names"] = _extract_prefixed(san["value"] if san else "", "DNS")

    bc = _parse_ext_block(raw_text, "X509v3 Basic Constraints")
    cert["basic_constraints"] = bc["value"] if bc else None
    cert["is_ca"] = bool(bc and "CA:TRUE" in bc["value"].upper())

    ku = _parse_ext_block(raw_text, "X509v3 Key Usage")
    cert["key_usage"] = ku["value"] if ku else None
    eku = _parse_ext_block(raw_text, "X509v3 Extended Key Usage")
    cert["extended_key_usage"] = eku["value"] if eku else None
    ski = _parse_ext_block(raw_text, "X509v3 Subject Key Identifier")
    cert["subject_key_id"] = ski["value"] if ski else None
    aki = _parse_ext_block(raw_text, "X509v3 Authority Key Identifier")
    cert["authority_key_id"] = aki["value"] if aki else None
    aia = _parse_ext_block(raw_text, "Authority Information Access")
    cert["authority_info_access"] = aia["value"] if aia else None
    crl = _parse_ext_block(raw_text, "X509v3 CRL Distribution Points")
    cert["crl_distribution_points"] = crl["value"] if crl else None

    return cert


def _norm(s):
    return (s or "").strip().lower()


def build_chains(certs):
    """Link certificates by issuer==subject DN matching and split the set
    into one or more leaf-to-root chains -- a bundle can legitimately
    contain more than one chain, or unrelated leftover certs.

    Returns (chains, issued_by): `chains` is a list of index-lists (leaf
    first, root last -- as far as the uploaded set goes), `issued_by` maps
    a cert's index to the index of whatever cert in the set issued it, for
    whichever certs that could be resolved.
    """
    for c in certs:
        c["self_signed"] = bool(c.get("subject")) and _norm(c.get("subject")) == _norm(c.get("issuer"))

    by_subject = {}
    for c in certs:
        by_subject.setdefault(_norm(c.get("subject")), []).append(c)

    issued_by = {}
    for c in certs:
        if c.get("parse_error") or c["self_signed"]:
            continue
        for candidate in by_subject.get(_norm(c.get("issuer")), []):
            if candidate is not c:
                issued_by[c["index"]] = candidate["index"]
                break

    pointed_to = set(issued_by.values())
    leaves = [c["index"] for c in certs if c["index"] not in pointed_to]

    chains = []
    for leaf_idx in leaves:
        chain, seen, idx = [], set(), leaf_idx
        while idx is not None and idx not in seen:
            seen.add(idx)
            chain.append(idx)
            idx = issued_by.get(idx)
        chains.append(chain)
    return chains, issued_by


def hostname_matches(dns_names, hostname):
    """True/False, or None if there's nothing to check against."""
    hostname = (hostname or "").strip().lower()
    if not hostname:
        return None
    for name in dns_names:
        name = name.strip().lower()
        if name == hostname:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            if hostname.endswith(suffix) and hostname.count(".") == name.count("."):
                return True
    return False


def fetch_chain_from_host(hostname, port, timeout=8.0):
    """Connect to hostname:port and fetch the certificate chain exactly as
    the server sends it, via `openssl s_client -showcerts` (a real TLS
    connection, not a Python ssl.getpeercert() call, which only ever
    exposes the leaf certificate). Raises RuntimeError on failure.
    """
    try:
        proc = _run(
            ["openssl", "s_client", "-connect", f"{hostname}:{port}",
             "-servername", hostname, "-showcerts", "-verify", "10"],
            input_bytes=b"", timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("openssl CLI not available on this system")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"connection to {hostname}:{port} timed out")

    out = proc.stdout.decode(errors="replace")
    pem_blocks = _PEM_RE.findall(out)

    proto_cipher = re.search(r"New,\s*([\w.\-]+),\s*Cipher is (\S+)", out)
    tls_version = proto_cipher.group(1) if proto_cipher else None
    cipher = proto_cipher.group(2) if proto_cipher else None

    verify_m = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", out)
    verify_ok = (verify_m.group(1) == "0") if verify_m else None
    verify_message = verify_m.group(2) if verify_m else None

    if not pem_blocks:
        raise RuntimeError(
            "no certificates received -- connection or TLS handshake failed:\n" + out.strip()[-500:])

    return {
        "pem_blocks": pem_blocks,
        "tls_version": tls_version,
        "cipher": cipher,
        "verify_ok": verify_ok,
        "verify_message": verify_message,
    }


def verify_chain_locally(leaf_pem, other_pems, timeout=8.0):
    """Validate a leaf certificate against the system's default trust store
    using `openssl verify`, with any other certs in the uploaded chain
    (intermediates, and a root if one was included) as `-untrusted`
    candidates to complete the path. This is the offline counterpart to
    fetch_chain_from_host's live verify -- same trust store, no network
    connection required, useful for a bundle exported from a server rather
    than fetched live.
    """
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        leaf_path = d / "leaf.pem"
        leaf_path.write_text(leaf_pem)
        args = ["openssl", "verify"]
        if other_pems:
            untrusted_path = d / "untrusted.pem"
            untrusted_path.write_text("\n".join(other_pems))
            args += ["-untrusted", str(untrusted_path)]
        args.append(str(leaf_path))
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return {"ok": None, "message": f"local verification unavailable: {e}"}

    return {"ok": proc.returncode == 0, "message": proc.stdout.decode(errors="replace").strip()}
