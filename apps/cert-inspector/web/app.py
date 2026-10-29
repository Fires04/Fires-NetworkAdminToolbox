"""Certificate Inspector -- FastAPI web application.

Drag & drop (or paste, or fetch live from a host) a certificate or bundle
and see the *whole* chain -- not just the leaf -- with per-certificate
validity, extensions, fingerprints, a visual chain diagram, and chain
verification against the system trust store (live or offline). All X.509
parsing goes through the system `openssl` CLI (cert_inspector/parser.py),
the same approach cli_scripts/protocol_tester.py's --check-chain uses, but
this app is otherwise independent of it -- no shared code between the two.

Also covers two one-off key/cert operations that don't fit the read-only
inspector above (cert_inspector/keys.py, also openssl-CLI-backed but no
shared code with parser.py): decrypting a password-protected private key,
and merging a key + certificate into a PKCS#12 (.pfx) for Windows/IIS
import. Grouped into this same app (rather than a separate one) since all
three are "do something with a cert/key file" and a user reaching for one
is likely to want another.
"""
import re
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from cert_inspector.keys import build_pfx, decrypt_private_key, is_key_encrypted
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


async def _read_key_input(key_file: UploadFile | None, key_text: str) -> bytes:
    if key_file is not None and key_file.filename:
        return await key_file.read()
    return key_text.encode()


@app.post("/api/decrypt-key")
async def api_decrypt_key(
    key_file: Annotated[UploadFile | None, File()] = None,
    key_text: Annotated[str, Form()] = "",
    passphrase: Annotated[str, Form()] = "",
):
    raw = await _read_key_input(key_file, key_text)
    if not raw.strip():
        return JSONResponse({"error": "paste a key or choose a file"}, status_code=400)

    try:
        pem, key_format = decrypt_private_key(raw, passphrase)
    except RuntimeError as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    return {"pem": pem, "format": key_format, "was_encrypted": is_key_encrypted(raw)}


@app.post("/api/merge-pfx")
async def api_merge_pfx(
    key_file: Annotated[UploadFile | None, File()] = None,
    key_text: Annotated[str, Form()] = "",
    key_passphrase: Annotated[str, Form()] = "",
    cert_file: Annotated[UploadFile | None, File()] = None,
    cert_text: Annotated[str, Form()] = "",
    chain_file: Annotated[UploadFile | None, File()] = None,
    chain_text: Annotated[str, Form()] = "",
    export_password: Annotated[str, Form()] = "",
    friendly_name: Annotated[str, Form()] = "",
    legacy: Annotated[bool, Form()] = False,
):
    key_raw = await _read_key_input(key_file, key_text)
    cert_raw = await _read_key_input(cert_file, cert_text)
    chain_raw = await _read_key_input(chain_file, chain_text)

    if not key_raw.strip():
        return JSONResponse({"error": "private key is required"}, status_code=400)
    if not cert_raw.strip():
        return JSONResponse({"error": "certificate is required"}, status_code=400)
    if not export_password:
        return JSONResponse({"error": "set a password for the .pfx file"}, status_code=400)

    try:
        pfx_bytes = build_pfx(
            key_raw, key_passphrase, cert_raw, chain_raw or None,
            export_password, friendly_name=friendly_name, legacy=legacy,
        )
    except RuntimeError as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    # Sanitize before it lands in a Content-Disposition header value --
    # friendly_name is free user text (not just the pkcs12 -name field).
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", friendly_name).strip("_") or "certificate"
    filename = f"{safe_name}.pfx"
    return Response(
        content=pfx_bytes,
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
