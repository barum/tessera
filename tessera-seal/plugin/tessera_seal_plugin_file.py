#!/usr/bin/env python3
"""
tessera-seal-plugin-file — Reference TesseraSeal plugin.

Stores a passphrase-wrapped ML-KEM-1024 private key on disk and exposes it
to the TesseraSeal library via the binary frame protocol defined in
./tessera-seal-plugin-protocol.md.

Key file format (v1.1 + KDF block; backward-compatible reads of older
layouts still supported):

    tseal-key-v1.1
    <base64url(salt[16] || nonce[12] || pk[1568] || wrapped_sk[3168] ||
               aead_tag[16] || kdf_id[1] || kdf_p0[4] || kdf_p1[4] || kdf_p2[4])>

Where:
    kdf_id 0x01 = Argon2id            (p0=memory_kib, p1=time_cost, p2=parallelism)
    kdf_id 0x02 = PBKDF2-HMAC-SHA-512 (p0=iterations, p1=0, p2=0; explicit opt-in only)
    K_wrap     = KDF(passphrase, salt, params-from-kdf-block, 32 bytes)
    wrapped_sk = AES-256-GCM-Encrypt(K_wrap, nonce, sk,
                                     aad=KEYFILE_HEADER || kdf_block)
    pk is stored in cleartext alongside the wrapped sk so the `pubkey`
    subcommand can return the recipient URI without unwrapping (the public
    key is non-secret by definition).

The KDF block (TSEAL-00040) makes the key-derivation choice explicit and
authenticated: `unwrap` selects the KDF from the file, never from the
environment, and `wrap` fails closed when argon2-cffi is missing unless the
caller explicitly opts into PBKDF2 (`allow_pbkdf2=True` / `--allow-pbkdf2`).

Backward compatibility on read (legacy layouts, distinguished by header
line + exact blob length):
    "tseal-key-v1"          = legacy v1, no pk, no KDF block (PQCK-00008)
    "tseal-key-v1.1" (no KDF block) = legacy v1.1, pk embedded (PQCK-00016)
Legacy files predate the KDF block; they unwrap via the legacy derive path
(Argon2id preferred, PBKDF2 fallback when argon2-cffi is absent — the
pre-TSEAL-00040 behavior). New keys are always written with the KDF block.

This plugin supports three subcommands:

    tessera-seal-plugin-file keygen --out FILE
        Generate a new ML-KEM-1024 keypair, prompt for a passphrase, wrap
        the private key, and write it to FILE.

    tessera-seal-plugin-file pubkey --in FILE
        Print the base64url-encoded public (encapsulation) key from FILE.

    tessera-seal-plugin-file serve --in FILE
        Run the plugin-protocol loop on stdin/stdout. The library invokes
        this mode via `exec("tessera-seal-plugin-file", "serve", "--in", path)`.

The serve mode is the only one used by the TesseraSeal library itself. The
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

# Import the protocol primitives and TesseraSeal itself.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "python"))
import protocol  # noqa: E402  pylint: disable=wrong-import-position
import tessera_seal  # noqa: E402  pylint: disable=wrong-import-position

# Argon2id parameters per whitepaper §11.
ARGON2ID_MEMORY_KIB = 64 * 1024   # 64 MiB
ARGON2ID_TIME_COST = 3
ARGON2ID_PARALLELISM = 1
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
KEYFILE_HEADER_V1 = "tseal-key-v1"
KEYFILE_HEADER_V11 = "tseal-key-v1.1"
KEYFILE_HEADER_WRITE = KEYFILE_HEADER_V11

# KDF block (TSEAL-00040): kdf_id(1) || p0(4) || p1(4) || p2(4), big-endian.
KDF_ARGON2ID = 0x01            # p0=memory_kib, p1=time_cost, p2=parallelism
KDF_PBKDF2_HMAC_SHA512 = 0x02  # p0=iterations, p1=0, p2=0
KDF_BLOCK_BYTES = 13

# Defensive upper bounds applied when parsing an (attacker-controllable)
# KDF block from disk, so a forged keyfile cannot drive resource exhaustion.
KDF_MAX_ARGON2ID_MEMORY_KIB = 4 * 1024 * 1024   # 4 GiB
KDF_MAX_ARGON2ID_TIME_COST = 1024
KDF_MAX_ARGON2ID_PARALLELISM = 64
KDF_MAX_PBKDF2_ITERATIONS = 100_000_000

PLUGIN_NAME = "file"


# ---------------------------------------------------------------------------
# Key derivation (KDF selected by the keyfile's KDF block — never by the
# environment; see TSEAL-00040)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KdfParams:
    """Parsed KDF block: which passphrase KDF wrapped this keyfile, and how."""
    kdf_id: int
    p0: int = 0
    p1: int = 0
    p2: int = 0

    def encode(self) -> bytes:
        import struct
        return struct.pack(">BIII", self.kdf_id, self.p0, self.p1, self.p2)

    @classmethod
    def decode(cls, raw: bytes) -> "KdfParams":
        import struct
        if len(raw) != KDF_BLOCK_BYTES:
            raise ValueError(f"KDF block must be {KDF_BLOCK_BYTES} bytes, got {len(raw)}")
        kdf_id, p0, p1, p2 = struct.unpack(">BIII", raw)
        if kdf_id == KDF_ARGON2ID:
            if not (0 < p0 <= KDF_MAX_ARGON2ID_MEMORY_KIB):
                raise ValueError(f"Argon2id memory_kib out of range: {p0}")
            if not (0 < p1 <= KDF_MAX_ARGON2ID_TIME_COST):
                raise ValueError(f"Argon2id time_cost out of range: {p1}")
            if not (0 < p2 <= KDF_MAX_ARGON2ID_PARALLELISM):
                raise ValueError(f"Argon2id parallelism out of range: {p2}")
        elif kdf_id == KDF_PBKDF2_HMAC_SHA512:
            if not (0 < p0 <= KDF_MAX_PBKDF2_ITERATIONS):
                raise ValueError(f"PBKDF2 iterations out of range: {p0}")
            if p1 != 0 or p2 != 0:
                raise ValueError("PBKDF2 KDF block reserved params must be zero")
        else:
            raise ValueError(f"unknown keyfile KDF id 0x{kdf_id:02x}")
        return cls(kdf_id=kdf_id, p0=p0, p1=p1, p2=p2)


def _derive_argon2id(passphrase: bytes, salt: bytes, params: KdfParams) -> bytes:
    """Argon2id derive. Hard-fails when argon2-cffi is missing — NO silent
    substitution of a different KDF (TSEAL-00040)."""
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        raise SystemExit(
            "tessera-seal-plugin-file: this operation requires Argon2id but "
            "argon2-cffi is not installed. Install argon2-cffi; refusing to "
            "substitute a different KDF."
        ) from None
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=params.p1,
        memory_cost=params.p0,
        parallelism=params.p2,
        hash_len=32,
        type=Type.ID,
    )


def _derive_pbkdf2(passphrase: bytes, salt: bytes, params: KdfParams) -> bytes:
    """PBKDF2-HMAC-SHA-512 derive (explicit opt-in wrap path / file-selected
    unwrap path only)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(), length=32, salt=salt, iterations=params.p0
    )
    return kdf.derive(passphrase)


def _derive_kwrap_from_params(passphrase: bytes, salt: bytes, params: KdfParams) -> bytes:
    """Derive K_wrap using exactly the KDF named by the keyfile's KDF block."""
    if params.kdf_id == KDF_ARGON2ID:
        return _derive_argon2id(passphrase, salt, params)
    if params.kdf_id == KDF_PBKDF2_HMAC_SHA512:
        return _derive_pbkdf2(passphrase, salt, params)
    raise SystemExit(f"tessera-seal-plugin-file: unknown keyfile KDF id 0x{params.kdf_id:02x}")


def _derive_kwrap_legacy(passphrase: bytes, salt: bytes) -> bytes:
    """
    Legacy derive path — ONLY for reading keyfiles written before the KDF
    block existed (v1 and KDF-block-less v1.1). Preserves the pre-TSEAL-00040
    behavior: prefer argon2-cffi, fall back to PBKDF2-HMAC-SHA-512 with a
    documented warning. New wraps never take this path.
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
            "tessera-seal-plugin-file: argon2-cffi not installed; trying the "
            "legacy PBKDF2-HMAC-SHA-512 fallback for this pre-KDF-block "
            "keyfile. Install argon2-cffi and re-run `keygen` to produce a "
            "keyfile with an explicit KDF block.\n"
        )
        return _derive_pbkdf2(
            passphrase, salt, KdfParams(KDF_PBKDF2_HMAC_SHA512, PBKDF2_ITERATIONS)
        )


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
    kdf: Optional[KdfParams] = None  # None for legacy (pre-TSEAL-00040) files

    def aad(self) -> bytes:
        """AEAD AAD binding the format identifier (and, when present, the
        KDF block) so neither can be swapped without failing the wrap tag."""
        if self.kdf is not None:
            return KEYFILE_HEADER_V11.encode() + self.kdf.encode()
        return (KEYFILE_HEADER_V11 if self.pk else KEYFILE_HEADER_V1).encode()

    def serialize(self) -> bytes:
        # New keys always written in v1.1 format with pk + KDF block embedded.
        if not self.pk or len(self.pk) != tessera_seal.MLKEM1024_PK_BYTES:
            raise ValueError("pk must be 1568 bytes for v1.1 keyfiles")
        if self.kdf is None:
            raise ValueError("new v1.1 keyfiles must carry a KDF block (TSEAL-00040)")
        blob = (
            self.salt + self.nonce + self.pk + self.wrapped_sk + self.tag
            + self.kdf.encode()
        )
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
        sk_len = tessera_seal.MLKEM1024_SK_BYTES
        pk_len = tessera_seal.MLKEM1024_PK_BYTES
        if header == KEYFILE_HEADER_V11:
            base_total = SALT_BYTES + NONCE_BYTES + pk_len + sk_len + TAG_BYTES
            if len(blob) == base_total:
                kdf = None  # legacy v1.1 file, written before the KDF block
            elif len(blob) == base_total + KDF_BLOCK_BYTES:
                kdf = KdfParams.decode(blob[base_total:])
            else:
                raise ValueError(
                    f"v1.1 key file body length {len(blob)} != expected "
                    f"{base_total} (legacy) or {base_total + KDF_BLOCK_BYTES} (KDF block)"
                )
            off = 0
            salt = blob[off:off + SALT_BYTES]; off += SALT_BYTES
            nonce = blob[off:off + NONCE_BYTES]; off += NONCE_BYTES
            pk = blob[off:off + pk_len]; off += pk_len
            wrapped_sk = blob[off:off + sk_len]; off += sk_len
            tag = blob[off:off + TAG_BYTES]
            return cls(salt=salt, nonce=nonce, wrapped_sk=wrapped_sk, tag=tag,
                       pk=pk, kdf=kdf)
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


def _argon2_available() -> bool:
    try:
        from argon2.low_level import hash_secret_raw  # noqa: F401
        return True
    except ImportError:
        return False


def _wrap_sk(sk: bytes, pk: bytes, passphrase: bytes,
             allow_pbkdf2: bool = False) -> KeyFile:
    """v1.1 key wrap: produces a KeyFile carrying pk, wrapped sk, and an
    explicit KDF block (TSEAL-00040).

    Fails closed when argon2-cffi is missing UNLESS the caller explicitly
    passes `allow_pbkdf2=True`. The decision is environment-independent: no
    env var can enable the PBKDF2 path. The AEAD AAD is the v1.1 header
    concatenated with the KDF block, so neither the format identifier nor the
    KDF choice/params can be altered without failing the wrap tag.
    """
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    if _argon2_available():
        kdf = KdfParams(KDF_ARGON2ID, ARGON2ID_MEMORY_KIB,
                        ARGON2ID_TIME_COST, ARGON2ID_PARALLELISM)
    elif allow_pbkdf2:
        sys.stderr.write(
            "tessera-seal-plugin-file: wrapping with PBKDF2-HMAC-SHA-512 "
            f"({PBKDF2_ITERATIONS} iterations) at the caller's explicit "
            "request (allow_pbkdf2). Install argon2-cffi for the "
            "whitepaper-specified KDF.\n"
        )
        kdf = KdfParams(KDF_PBKDF2_HMAC_SHA512, PBKDF2_ITERATIONS)
    else:
        raise SystemExit(
            "tessera-seal-plugin-file: argon2-cffi is not installed; refusing "
            "to wrap a key with a weaker KDF. Install argon2-cffi, or opt in "
            "explicitly with --allow-pbkdf2 (allow_pbkdf2=True)."
        )
    k_wrap = _derive_kwrap_from_params(passphrase, salt, kdf)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aad = KEYFILE_HEADER_WRITE.encode() + kdf.encode()
    aead_blob = AESGCM(k_wrap).encrypt(nonce, sk, associated_data=aad)
    wrapped_sk = aead_blob[:-TAG_BYTES]
    tag = aead_blob[-TAG_BYTES:]
    return KeyFile(salt=salt, nonce=nonce, wrapped_sk=wrapped_sk, tag=tag,
                   pk=pk, kdf=kdf)


def _unwrap_sk(kf: KeyFile, passphrase: bytes) -> bytes:
    """Unwrap sk from a KeyFile.

    The KDF is selected from the file's KDF block — never from the
    environment (TSEAL-00040). Files without a KDF block (legacy v1 / v1.1)
    unwrap via the legacy derive path. AAD is picked by format layout.
    """
    if kf.kdf is not None:
        k_wrap = _derive_kwrap_from_params(passphrase, kf.salt, kf.kdf)
    else:
        k_wrap = _derive_kwrap_legacy(passphrase, kf.salt)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        return AESGCM(k_wrap).decrypt(
            kf.nonce, kf.wrapped_sk + kf.tag, associated_data=kf.aad()
        )
    except Exception:
        raise SystemExit("tessera-seal-plugin-file: key unwrap failed (wrong passphrase or corrupt file)")


# ---------------------------------------------------------------------------
# Passphrase prompt
# ---------------------------------------------------------------------------


def _read_passphrase(confirm: bool = False) -> bytes:
    env = os.environ.get("TESSERA_SEAL_PASSPHRASE")
    if env is not None:
        return env.encode("utf-8")
    p = getpass.getpass("passphrase: ")
    if confirm:
        p2 = getpass.getpass("passphrase (confirm): ")
        if p != p2:
            raise SystemExit("tessera-seal-plugin-file: passphrases did not match")
    return p.encode("utf-8")


# ---------------------------------------------------------------------------
# Recipient ID (URI form: tseal1file1<base64url(public_key)>)
# ---------------------------------------------------------------------------


def _recipient_uri(public_bytes: bytes) -> str:
    return protocol.RecipientId(plugin=PLUGIN_NAME, payload=public_bytes).encode()


# ---------------------------------------------------------------------------
# Subcommand: keygen
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    priv, pub = tessera_seal.generate_keypair()
    sk = priv.to_bytes()
    pk = pub.to_bytes()
    passphrase = _read_passphrase(confirm=True)
    # v1.1 — pk + KDF block embedded. PBKDF2 only on explicit --allow-pbkdf2.
    kf = _wrap_sk(sk, pk, passphrase, allow_pbkdf2=bool(args.allow_pbkdf2))
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
        "tessera-seal-plugin-file pubkey: legacy v1 keyfile does not embed pk. "
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
      - WRAP_KEY: NOT implemented in v1. TesseraSeal's sender path runs in-
        process and uses the recipient's public key directly; the WRAP_KEY
        frame is reserved for future plugins that interpose on encrypt.
    """
    passphrase = _read_passphrase()
    kf = KeyFile.parse(Path(args.input).read_bytes())
    sk = _unwrap_sk(kf, passphrase)
    priv = tessera_seal.PrivateKey(sk)

    r = sys.stdin.buffer
    w = sys.stdout.buffer
    try:
        while True:
            frame = protocol.read_frame(r)
            if frame is None:
                return 0
            if frame.type == protocol.FRAME_UNWRAP_KEY:
                # Body is the ML-KEM-1024 ciphertext (1568 bytes).
                if len(frame.body) != tessera_seal.MLKEM1024_CT_BYTES:
                    protocol.write_error(
                        w,
                        f"UNWRAP_KEY: expected {tessera_seal.MLKEM1024_CT_BYTES}-byte "
                        f"KEM ct, got {len(frame.body)}",
                    )
                    continue
                ss = tessera_seal.MLKem1024.decaps(sk, frame.body)
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
    parser = argparse.ArgumentParser(prog="tessera-seal-plugin-file")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="generate and wrap a new ML-KEM-1024 keypair")
    pk.add_argument("--out", required=True, help="key file path (will be chmod 600)")
    pk.add_argument(
        "--allow-pbkdf2",
        action="store_true",
        help="explicitly permit the PBKDF2-HMAC-SHA-512 fallback KDF when "
             "argon2-cffi is not installed (default: fail closed)",
    )
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
