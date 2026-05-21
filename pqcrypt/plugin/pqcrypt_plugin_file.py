#!/usr/bin/env python3
"""
pqcrypt-plugin-file — Reference PQCrypt plugin.

Stores a passphrase-wrapped ML-KEM-1024 private key on disk and exposes it
to the PQCrypt library via the binary frame protocol defined in
./pqcrypt-plugin-protocol.md.

Key file format (v1.1; backward-compatible v1 still supported on read):

    pqck-key-v1.1
    <base64url(salt[16] || nonce[12] || pk[1568] || wrapped_sk[3168] || aead_tag[16])>

Where:
    K_wrap     = Argon2id(passphrase, salt, m=64 MiB, t=3, p=1, 32 bytes)
    wrapped_sk = AES-256-GCM-Encrypt(K_wrap, nonce, sk, aad=KEYFILE_HEADER)
    pk is stored in cleartext alongside the wrapped sk so the `pubkey`
    subcommand can return the recipient URI without unwrapping (the public
    key is non-secret by definition).

The v1 format omitted pk; v1.1 adds it. The header line distinguishes:
    "pqck-key-v1"   = legacy format, no pk in keyfile (PQCK-00008)
    "pqck-key-v1.1" = v1.1 format, pk embedded     (PQCK-00016)
Reads of either format work; new keys are written in v1.1.

This plugin supports three subcommands:

    pqcrypt-plugin-file keygen --out FILE
        Generate a new ML-KEM-1024 keypair, prompt for a passphrase, wrap
        the private key, and write it to FILE.

    pqcrypt-plugin-file pubkey --in FILE
        Print the base64url-encoded public (encapsulation) key from FILE.

    pqcrypt-plugin-file serve --in FILE
        Run the plugin-protocol loop on stdin/stdout. The library invokes
        this mode via `exec("pqcrypt-plugin-file", "serve", "--in", path)`.

The serve mode is the only one used by the PQCrypt library itself. The
keygen/pubkey modes are CLI convenience.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Import the protocol primitives and PQCrypt itself.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "python"))
import protocol  # noqa: E402  pylint: disable=wrong-import-position
import pqcrypt  # noqa: E402  pylint: disable=wrong-import-position

# Argon2id parameters per whitepaper §11.
ARGON2ID_MEMORY_KIB = 64 * 1024   # 64 MiB
ARGON2ID_TIME_COST = 3
ARGON2ID_PARALLELISM = 1
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
KEYFILE_HEADER_V1 = "pqck-key-v1"
KEYFILE_HEADER_V11 = "pqck-key-v1.1"
KEYFILE_HEADER_WRITE = KEYFILE_HEADER_V11

PLUGIN_NAME = "file"


# ---------------------------------------------------------------------------
# Argon2id key derivation
# ---------------------------------------------------------------------------


def _derive_kwrap(passphrase: bytes, salt: bytes) -> bytes:
    """
    Derive a 32-byte K_wrap from `passphrase` and `salt`.

    Prefers the `argon2-cffi` package; falls back to PBKDF2-HMAC-SHA-512 with
    a documented warning when Argon2 is unavailable. Production deployments
    SHOULD install argon2-cffi.
    """
    try:
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=ARGON2ID_TIME_COST,
            memory_cost=ARGON2ID_MEMORY_KIB,
            parallelism=ARGON2ID_PARALLELISM,
            hash_len=32,
            type=Type.ID,
        )
    except ImportError:
        sys.stderr.write(
            "pqcrypt-plugin-file: argon2-cffi not installed; falling back to "
            "PBKDF2-HMAC-SHA-512 with 600k iterations. Install argon2-cffi for "
            "the whitepaper-specified KDF.\n"
        )
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=32, salt=salt, iterations=600_000
        )
        return kdf.derive(passphrase)


# ---------------------------------------------------------------------------
# Key wrap / unwrap
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyFile:
    salt: bytes        # 16 bytes
    nonce: bytes       # 12 bytes
    wrapped_sk: bytes  # ciphertext only (3168 bytes)
    tag: bytes         # 16-byte AEAD tag
    pk: bytes = b""    # 1568 bytes (v1.1+); empty for legacy v1 files

    def serialize(self) -> bytes:
        # New keys always written in v1.1 format with pk embedded.
        if not self.pk or len(self.pk) != pqcrypt.MLKEM1024_PK_BYTES:
            raise ValueError("pk must be 1568 bytes for v1.1 keyfiles")
        blob = self.salt + self.nonce + self.pk + self.wrapped_sk + self.tag
        b64 = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
        return (KEYFILE_HEADER_WRITE + "\n" + b64 + "\n").encode("ascii")

    @classmethod
    def parse(cls, raw: bytes) -> "KeyFile":
        text = raw.decode("ascii", errors="replace").strip()
        lines = text.splitlines()
        if len(lines) != 2:
            raise ValueError("key file must be exactly two lines")
        header = lines[0]
        pad = (-len(lines[1])) % 4
        blob = base64.urlsafe_b64decode(lines[1] + "=" * pad)
        sk_len = pqcrypt.MLKEM1024_SK_BYTES
        pk_len = pqcrypt.MLKEM1024_PK_BYTES
        if header == KEYFILE_HEADER_V11:
            expected_total = SALT_BYTES + NONCE_BYTES + pk_len + sk_len + TAG_BYTES
            if len(blob) != expected_total:
                raise ValueError(
                    f"v1.1 key file body length {len(blob)} != expected {expected_total}"
                )
            off = 0
            salt = blob[off:off + SALT_BYTES]; off += SALT_BYTES
            nonce = blob[off:off + NONCE_BYTES]; off += NONCE_BYTES
            pk = blob[off:off + pk_len]; off += pk_len
            wrapped_sk = blob[off:off + sk_len]; off += sk_len
            tag = blob[off:off + TAG_BYTES]
            return cls(salt=salt, nonce=nonce, wrapped_sk=wrapped_sk, tag=tag, pk=pk)
        elif header == KEYFILE_HEADER_V1:
            expected_total = SALT_BYTES + NONCE_BYTES + sk_len + TAG_BYTES
            if len(blob) != expected_total:
                raise ValueError(
                    f"v1 key file body length {len(blob)} != expected {expected_total}"
                )
            return cls(
                salt=blob[:SALT_BYTES],
                nonce=blob[SALT_BYTES:SALT_BYTES + NONCE_BYTES],
                wrapped_sk=blob[SALT_BYTES + NONCE_BYTES:SALT_BYTES + NONCE_BYTES + sk_len],
                tag=blob[SALT_BYTES + NONCE_BYTES + sk_len:],
                pk=b"",
            )
        else:
            raise ValueError(
                f"key file header must be {KEYFILE_HEADER_V1!r} or {KEYFILE_HEADER_V11!r}, "
                f"got {header!r}"
            )


def _wrap_sk(sk: bytes, pk: bytes, passphrase: bytes) -> KeyFile:
    """v1.1 key wrap: produces a KeyFile carrying both pk and wrapped sk.

    The AEAD AAD is the v1.1 header so the wrap is bound to the format
    identifier and cannot be replayed against a v1 reader.
    """
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    k_wrap = _derive_kwrap(passphrase, salt)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aead_blob = AESGCM(k_wrap).encrypt(
        nonce, sk, associated_data=KEYFILE_HEADER_WRITE.encode()
    )
    wrapped_sk = aead_blob[:-TAG_BYTES]
    tag = aead_blob[-TAG_BYTES:]
    return KeyFile(salt=salt, nonce=nonce, wrapped_sk=wrapped_sk, tag=tag, pk=pk)


def _unwrap_sk(kf: KeyFile, passphrase: bytes) -> bytes:
    """Unwrap sk from a KeyFile. Picks AAD by format version (v1 vs v1.1)."""
    k_wrap = _derive_kwrap(passphrase, kf.salt)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aad = (KEYFILE_HEADER_V11 if kf.pk else KEYFILE_HEADER_V1).encode()
    try:
        return AESGCM(k_wrap).decrypt(
            kf.nonce, kf.wrapped_sk + kf.tag, associated_data=aad
        )
    except Exception:
        raise SystemExit("pqcrypt-plugin-file: key unwrap failed (wrong passphrase or corrupt file)")


# ---------------------------------------------------------------------------
# Passphrase prompt
# ---------------------------------------------------------------------------


def _read_passphrase(confirm: bool = False) -> bytes:
    env = os.environ.get("PQCRYPT_PASSPHRASE")
    if env is not None:
        return env.encode("utf-8")
    p = getpass.getpass("passphrase: ")
    if confirm:
        p2 = getpass.getpass("passphrase (confirm): ")
        if p != p2:
            raise SystemExit("pqcrypt-plugin-file: passphrases did not match")
    return p.encode("utf-8")


# ---------------------------------------------------------------------------
# Recipient ID (URI form: pqck1file1<base64url(public_key)>)
# ---------------------------------------------------------------------------


def _recipient_uri(public_bytes: bytes) -> str:
    return protocol.RecipientId(plugin=PLUGIN_NAME, payload=public_bytes).encode()


# ---------------------------------------------------------------------------
# Subcommand: keygen
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    priv, pub = pqcrypt.generate_keypair()
    sk = priv.to_bytes()
    pk = pub.to_bytes()
    passphrase = _read_passphrase(confirm=True)
    kf = _wrap_sk(sk, pk, passphrase)  # v1.1 — pk embedded
    out_path = Path(args.out)
    out_path.write_bytes(kf.serialize())
    out_path.chmod(0o600)
    print(f"wrote {out_path} (recipient = {_recipient_uri(pk)})")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: pubkey
# ---------------------------------------------------------------------------


def cmd_pubkey(args: argparse.Namespace) -> int:
    """Print the public-key URI for the given key file.

    v1.1 keyfiles embed pk in cleartext; no passphrase prompt needed.
    Legacy v1 keyfiles do not embed pk; for those we exit non-zero.
    """
    kf = KeyFile.parse(Path(args.input).read_bytes())
    if kf.pk:
        print(_recipient_uri(kf.pk))
        return 0
    sys.stderr.write(
        "pqcrypt-plugin-file pubkey: legacy v1 keyfile does not embed pk. "
        "Re-run `keygen` to produce a v1.1 keyfile.\n"
    )
    return 1


# ---------------------------------------------------------------------------
# Subcommand: serve  (plugin-protocol loop)
# ---------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    """
    Run the plugin-protocol loop. The library writes WRAP_KEY/UNWRAP_KEY
    frames; we respond with OK or ERROR. On EOF, we exit cleanly.

    v1 reference plugin scope:
      - UNWRAP_KEY: decapsulate an envelope-bound KEM ciphertext using the
        unwrapped private key. Body of UNWRAP_KEY = the 1568-byte KEM ct.
        Body of OK response = the 32-byte shared secret.
      - WRAP_KEY: NOT implemented in v1. PQCrypt's sender path runs in-
        process and uses the recipient's public key directly; the WRAP_KEY
        frame is reserved for future plugins that interpose on encrypt.
    """
    passphrase = _read_passphrase()
    kf = KeyFile.parse(Path(args.input).read_bytes())
    sk = _unwrap_sk(kf, passphrase)
    priv = pqcrypt.PrivateKey(sk)

    r = sys.stdin.buffer
    w = sys.stdout.buffer
    try:
        while True:
            frame = protocol.read_frame(r)
            if frame is None:
                return 0
            if frame.type == protocol.FRAME_UNWRAP_KEY:
                # Body is the ML-KEM-1024 ciphertext (1568 bytes).
                if len(frame.body) != pqcrypt.MLKEM1024_CT_BYTES:
                    protocol.write_error(
                        w,
                        f"UNWRAP_KEY: expected {pqcrypt.MLKEM1024_CT_BYTES}-byte "
                        f"KEM ct, got {len(frame.body)}",
                    )
                    continue
                ss = pqcrypt.MLKem1024.decaps(sk, frame.body)
                protocol.write_ok(w, ss)
            elif frame.type == protocol.FRAME_WRAP_KEY:
                protocol.write_error(
                    w, "WRAP_KEY: not implemented in v1 reference plugin"
                )
            elif frame.type == protocol.FRAME_RECIPIENT_STANZA:
                # Echo our recipient identifier back so the caller can
                # confirm it routed to the correct plugin.
                # We rebuild it by re-deriving the ek; for v1 we just send DONE.
                protocol.write_done(w)
            else:
                protocol.write_error(w, f"unknown frame type 0x{frame.type:02x}")
    except protocol.ProtocolError as e:
        protocol.write_error(w, str(e))
        return 2
    finally:
        # Best-effort zeroize.
        try:
            sk_bytearray = bytearray(sk)
            for i in range(len(sk_bytearray)):
                sk_bytearray[i] = 0
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="pqcrypt-plugin-file")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="generate and wrap a new ML-KEM-1024 keypair")
    pk.add_argument("--out", required=True, help="key file path (will be chmod 600)")
    pk.set_defaults(func=cmd_keygen)

    pp = sub.add_parser("pubkey", help="print the public key URI for an existing key file")
    pp.add_argument("--in", dest="input", required=True, help="key file path")
    pp.set_defaults(func=cmd_pubkey)

    ps = sub.add_parser("serve", help="run the plugin protocol loop on stdin/stdout")
    ps.add_argument("--in", dest="input", required=True, help="key file path")
    ps.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
