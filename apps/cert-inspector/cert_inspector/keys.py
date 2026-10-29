"""cert_inspector.keys -- private key decryption and PKCS#12 (.pfx)
bundling via the system `openssl` CLI.

Separate module from parser.py (shells out to `openssl` too, but a
different subcommand family and no shared code) -- parser.py only ever
reads/diagnoses certificates, this module decrypts a key or produces a new
file, so keeping them apart avoids one giant file mixing both concerns.

Passphrases are always fed over stdin (`-passin stdin` / `-passout stdin`),
never as a `-passin pass:...` / `-passout pass:...` argument, so they never
show up in this process's argv (e.g. to another local user running `ps aux`
during the brief subprocess call).
"""
import subprocess
import tempfile
from pathlib import Path

_ENCRYPTED_MARKERS = (b"ENCRYPTED PRIVATE KEY", b"Proc-Type: 4,ENCRYPTED", b"Proc-Type:4,ENCRYPTED")


def _run(args, input_bytes=b"", timeout=15):
    return subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)


def is_key_encrypted(raw: bytes) -> bool:
    return any(marker in raw for marker in _ENCRYPTED_MARKERS)


def decrypt_private_key(raw: bytes, passphrase: str = ""):
    """Decrypt a PEM private key (traditional PKCS#1 "RSA PRIVATE KEY" with
    a Proc-Type/DEK-Info header -- the classic Mikrotik/OpenVPN export -- or
    a modern PKCS#8 "ENCRYPTED PRIVATE KEY") and return (pem_text, format).

    `openssl rsa` auto-detects either input shape and, with `-traditional`,
    always writes the decrypted key back out as a traditional "RSA PRIVATE
    KEY" PEM -- the form OpenVPN-style configs expect to paste straight in
    -- regardless of which shape it was encrypted in. It only works for RSA
    keys though, so EC/other keys fall back to the generic `openssl pkey`
    (which has no -traditional equivalent and always writes PKCS#8).

    `-passin stdin` must be omitted entirely for an already-unencrypted key
    -- passing it anyway makes openssl try to read a password it doesn't
    need and fail with "Error reading password from BIO", even on an empty
    passphrase.
    """
    encrypted = is_key_encrypted(raw)
    passin = (passphrase + "\n").encode()

    with tempfile.TemporaryDirectory() as td:
        in_path = Path(td) / "in.key"
        in_path.write_bytes(raw)
        out_path = Path(td) / "out.key"

        rsa_args = ["openssl", "rsa", "-in", str(in_path), "-traditional", "-out", str(out_path)]
        if encrypted:
            rsa_args[2:2] = ["-passin", "stdin"]
        proc = _run(rsa_args, input_bytes=passin if encrypted else b"")
        if proc.returncode == 0 and out_path.exists():
            return out_path.read_text(), "rsa"
        rsa_err = proc.stderr.decode(errors="replace").strip()

        pkey_args = ["openssl", "pkey", "-in", str(in_path), "-out", str(out_path)]
        if encrypted:
            pkey_args[2:2] = ["-passin", "stdin"]
        proc2 = _run(pkey_args, input_bytes=passin if encrypted else b"")
        if proc2.returncode == 0 and out_path.exists():
            return out_path.read_text(), "pkey"
        pkey_err = proc2.stderr.decode(errors="replace").strip()

        if encrypted and not passphrase:
            raise RuntimeError("this key is encrypted -- enter its passphrase")
        raise RuntimeError(rsa_err or pkey_err or "could not read key -- wrong passphrase or unsupported format")


def build_pfx(key_pem: bytes, key_passphrase: str, cert_pem: bytes, chain_pem: bytes | None,
              export_password: str, friendly_name: str = "", legacy: bool = False) -> bytes:
    """Bundle a private key + its certificate (+ optional intermediate/CA
    chain) into a password-protected PKCS#12 (.pfx) file -- the single-file
    format Windows/IIS's certificate import expects.

    The key is decrypted first (if needed) via decrypt_private_key, so the
    `openssl pkcs12 -export` call below only ever has to deal with *one*
    password (the new .pfx export password) -- no juggling two passwords
    through stdin in the same subprocess call.

    `legacy=True` adds `-legacy`, switching the .pfx's encryption from
    OpenSSL 3.x's AES-256/PBKDF2 default to the old RC2/3DES scheme --
    older Windows Server/IIS releases (pre-dating OpenSSL-3-aware patches)
    fail to import a modern-encrypted .pfx with no useful error message, so
    this is a real, commonly-hit compatibility switch, not a security
    downgrade offered for its own sake.
    """
    plain_key_pem, _fmt = decrypt_private_key(key_pem, key_passphrase)

    with tempfile.TemporaryDirectory() as td:
        key_path = Path(td) / "key.pem"
        key_path.write_text(plain_key_pem)
        cert_path = Path(td) / "cert.pem"
        cert_path.write_bytes(cert_pem)
        out_path = Path(td) / "out.pfx"

        args = ["openssl", "pkcs12", "-export",
                "-inkey", str(key_path), "-in", str(cert_path),
                "-out", str(out_path), "-passout", "stdin",
                "-name", friendly_name or "certificate"]
        if chain_pem:
            chain_path = Path(td) / "chain.pem"
            chain_path.write_bytes(chain_pem)
            args += ["-certfile", str(chain_path)]
        if legacy:
            args += ["-legacy"]

        proc = _run(args, input_bytes=(export_password + "\n").encode())
        if proc.returncode != 0 or not out_path.exists():
            raise RuntimeError(proc.stderr.decode(errors="replace").strip() or "openssl pkcs12 export failed")
        return out_path.read_bytes()
