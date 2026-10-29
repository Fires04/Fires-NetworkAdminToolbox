"""Certificate Tools -- FastAPI web application.

Two small, independent operations around private keys and certificates
that don't fit cert-inspector (which only ever reads/diagnoses, never
produces a new file):

1. Decrypt a password-protected RSA private key (e.g. the key exported by
   a Mikrotik router for use in an OpenVPN client config) into a plain PEM
   that can be pasted straight into a config file.
2. Merge a private key + its certificate (+ optional CA/intermediate
   chain) into a single password-protected PKCS#12 (.pfx) file -- the
   format Windows/IIS's "Import certificate" wants, where OpenSSL normally
   hands you three separate PEM files instead.

All crypto work goes through the system `openssl` CLI (cert_tools/crypto.py).
"""
import re
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from cert_tools.crypto import build_pfx, decrypt_private_key, is_key_encrypted

app = FastAPI(title="Certificate Tools")

BASE_DIR = Path(__file__).resolve().parent
_INDEX_HTML = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=_INDEX_HTML)


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
