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

        top = certs[chain[-1]]
        if not top.get("self_signed") and not top.get("parse_error"):
            warnings.append(
                f"chain ending at index {chain[-1]} is incomplete: no certificate for issuer "
                f"'{top.get('issuer')}' was included (fine if that's a trusted root you just "
                f"didn't upload; a real problem if it's a missing intermediate)")

        if verify_locally:
            entry["local_verify"] = verify_chain_locally(
                pem_blocks[chain[0]], [pem_blocks[i] for i in chain[1:]])
            if entry["local_verify"]["ok"] is False:
                warnings.append(f"chain at index {chain[0]}: system trust verification failed")

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
):
    raw = pem_text.encode()
    for f in files:
        if f.filename:
            raw += b"\n" + await f.read()

    pem_blocks = normalize_to_pem_blocks(raw)
    if not pem_blocks:
        return JSONResponse(
            {"error": "no certificate found (drop a PEM/DER file, a PEM bundle, or paste PEM text)"},
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
