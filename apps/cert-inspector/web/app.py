"""Certificate Inspector -- FastAPI web application.

Drag & drop (or paste, or fetch live from a host) a certificate or bundle
and see the *whole* chain -- not just the leaf -- with per-certificate
validity, extensions, fingerprints, a visual chain diagram, and chain
verification against the system trust store (live or offline). All X.509
parsing goes through the system `openssl` CLI (cert_inspector/parser.py),
the same approach cli_scripts/protocol_tester.py's --check-chain uses, but
this app is otherwise independent of it -- no shared code between the two.
"""
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from cert_inspector.parser import (
    build_chains,
    describe_cert,
    extract_pkcs12_certs,
    fetch_chain_from_host,
    hostname_matches,
    normalize_to_pem_blocks,
    verify_chain_locally,
)

app = FastAPI(title="Certificate Inspector")

BASE_DIR = Path(__file__).resolve().parent
_INDEX_HTML = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=_INDEX_HTML)


def _build_result(pem_blocks, expected_hostname=None, live_extra=None, verify_locally=False):
    certs = [describe_cert(pem, i) for i, pem in enumerate(pem_blocks)]
    chains, _issued_by = build_chains(certs)

    warnings = []
    chains_out = []
    for chain in chains:
        leaf = certs[chain[0]]
        entry = {"indices": chain}

        if expected_hostname:
            match = hostname_matches(leaf.get("dns_names") or [], expected_hostname)
            entry["hostname_match"] = match
            if match is False:
                warnings.append(
                    f"leaf certificate (index {chain[0]}) SAN does not include '{expected_hostname}'")

        for idx in chain:
            c = certs[idx]
            if c.get("parse_error"):
                warnings.append(f"[{idx}] could not be parsed: {c['parse_error']}")
            elif c.get("expired"):
                warnings.append(f"[{idx}] {c.get('subject')}: EXPIRED {-c['days_left']} days ago")
            elif c.get("not_yet_valid"):
                warnings.append(f"[{idx}] {c.get('subject')}: not yet valid")

        if verify_locally:
            entry["local_verify"] = verify_chain_locally(
                pem_blocks[chain[0]], [pem_blocks[i] for i in chain[1:]])
            if entry["local_verify"]["ok"] is False:
                warnings.append(f"chain at index {chain[0]}: system trust verification failed")
            chain_trusted = entry["local_verify"]["ok"] is True
        else:
            chain_trusted = bool(live_extra and live_extra.get("verify_ok"))

        # A server is only supposed to send the leaf + intermediates -- the
        # root is expected to already be in the client's trust store, not
        # sent over the wire, so "the chain we were handed doesn't include a
        # root" is completely normal and not itself a problem. Only surface
        # it as a warning when we *also* know trust verification didn't
        # actually succeed (missing intermediate, untrusted root, etc.) --
        # otherwise it's just noise on top of a perfectly fine chain.
        top = certs[chain[-1]]
        if not top.get("self_signed") and not top.get("parse_error") and not chain_trusted:
            warnings.append(
                f"chain ending at index {chain[-1]} is incomplete: no certificate for issuer "
                f"'{top.get('issuer')}' was included, and chain verification did not succeed -- "
                f"likely a missing intermediate")

        chains_out.append(entry)

    result = {"certs": certs, "chains": chains_out, "warnings": warnings}
    if live_extra:
        result.update(live_extra)
    return result


@app.post("/api/parse")
async def api_parse(
    files: Annotated[list[UploadFile], File()] = [],
    pem_text: Annotated[str, Form()] = "",
    hostname: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
):
    # b"\n".join (not unconditional concatenation) so a single uploaded
    # file's bytes pass through completely unmodified -- prepending a
    # separator before binary content (DER, PKCS#12) corrupts its ASN.1
    # structure, even though it's harmless/needed between PEM text blocks.
    file_contents = [await f.read() for f in files if f.filename]
    parts = ([pem_text.encode()] if pem_text else []) + file_contents
    raw = b"\n".join(parts)

    pem_blocks = normalize_to_pem_blocks(raw)
    pkcs12_error = None
    if not pem_blocks and raw.strip():
        # Not PEM text and not a bare DER certificate -- the remaining
        # likely case for binary input is a PKCS#12 (.pfx/.p12) bundle.
        # Try each uploaded file's own exact bytes (not the joined blob --
        # PKCS#12 is one binary structure, it doesn't concatenate like PEM).
        for content in (file_contents or [raw]):
            try:
                pem_blocks = extract_pkcs12_certs(content, password)
                pkcs12_error = None
                break
            except RuntimeError as e:
                pkcs12_error = str(e)

    if not pem_blocks:
        return JSONResponse(
            {"error": pkcs12_error or
             "no certificate found (drop a PEM/DER/PFX file, a PEM bundle, or paste PEM text)"},
            status_code=400,
        )
    return _build_result(pem_blocks, expected_hostname=hostname or None, verify_locally=True)


@app.post("/api/check")
async def api_check(
    hostname: Annotated[str, Form()],
    port: Annotated[int, Form()] = 443,
    timeout: Annotated[float, Form()] = 8.0,
):
    try:
        fetched = fetch_chain_from_host(hostname, port, timeout)
    except RuntimeError as e:
        return JSONResponse({"error": str(e)}, status_code=502)

    return _build_result(
        fetched["pem_blocks"],
        expected_hostname=hostname,
        live_extra={
            "tls_version": fetched["tls_version"],
            "cipher": fetched["cipher"],
            "verify_ok": fetched["verify_ok"],
            "verify_message": fetched["verify_message"],
        },
    )
