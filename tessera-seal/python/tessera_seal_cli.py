#!/usr/bin/env python3
"""tessera-seal — command-line interface for the TesseraSeal Python reference.

Invocation forms:

    tessera-seal <subcommand> ...                      (installed console command,
                                                        `pip install -e tessera-seal/python`)
    python3 tessera-seal/python/cli.py <subcommand> ...   (from a repo checkout)

Subcommands (synopsis matches the argparse definitions below exactly):

    tessera-seal keygen --out FILE [--suite 0x01]
        Generate a fresh ML-KEM-1024 keypair and write a v1.1 keyfile.
        Only --suite 0x01 is supported today; any other value is rejected
        with a nonzero exit (hybrid keyfiles land in v1.4, TSEAL-00030..34).

    tessera-seal pubkey --in FILE
        Print the recipient URI (tseal1file1<base64url>) from a v1.1 keyfile.

    tessera-seal encrypt --recipient URI [--ad AD] [--in FILE] [--out FILE]
                         [--suite 0x01|0x02]
        Encrypt stdin (or --in FILE) to stdout (or --out FILE). A hybrid
        (suite 0x06) recipient URI forces suite 0x06; passing --suite 0x06
        with a non-hybrid recipient is rejected.

    tessera-seal decrypt --keyfile FILE [--ad AD] [--in FILE] [--out FILE]
        Decrypt stdin (or --in FILE) to stdout (or --out FILE).

    tessera-seal info [--in FILE]
        Print envelope header fields (variant, suite, timestamp_ms, counter,
        kem_ct_len, ad_len, envelope_len) from stdin or --in FILE.

The CLI delegates to the plugin protocol for key custody: `decrypt` invokes
`tessera-seal-plugin-file serve --in <keyfile>` to unwrap the per-envelope key
without ever loading the long-term sk into the CLI's own memory. `encrypt`
parses the recipient URI directly (the public key is in cleartext).

Examples:

    # Generate a keypair (suite 0x01). Hybrid keyfiles (--suite 0x06) are
    # planned for v1.4 (TSEAL-00030..34); until then keygen rejects any
    # --suite other than 0x01 with a nonzero exit.
    tessera-seal keygen --out alice.tseal-key

    # Print the recipient URI for a v1.1 keyfile
    tessera-seal pubkey --in alice.tseal-key
    tseal1file1AwhmGKR_dpVBjqaFNhNAiVGZOuFc-fgZi...

    # Encrypt a file to Alice
    echo "secret" | tessera-seal encrypt --recipient tseal1file1AwhmGK... > msg.tseal

    # Decrypt
    tessera-seal decrypt --keyfile alice.tseal-key --in msg.tseal --out msg.txt
"""
from __future__ import annotations

import argparse
import io
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "plugin"))

import tessera_seal  # noqa: E402
import protocol  # type: ignore  # noqa: E402  (plugin/protocol.py)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


PLUGIN_PATH = str(HERE.parent / "plugin" / "tessera_seal_plugin_file.py")


def _parse_suite(s: str) -> int:
    s = s.lower()
    if s in ("0x01", "1", "aesgcm", "aes-gcm"):
        return tessera_seal.SUITE_MLKEM1024_AESGCM
    if s in ("0x02", "2", "chacha", "chacha20"):
        return tessera_seal.SUITE_MLKEM1024_CHACHA
    if s in ("0x06", "6", "hybrid", "xwing"):
        return tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    raise SystemExit(f"tessera-seal: unknown suite {s!r}")


def _suite_to_str(s: int) -> str:
    return {
        tessera_seal.SUITE_MLKEM1024_AESGCM: "0x01 (ML-KEM-1024 + AES-256-GCM)",
        tessera_seal.SUITE_MLKEM1024_CHACHA: "0x02 (ML-KEM-1024 + ChaCha20-Poly1305)",
        tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM: "0x06 (hybrid X25519+ML-KEM-1024 + AES-256-GCM)",
    }.get(s, f"0x{s:02x} (unknown)")


def _read_input(args) -> bytes:
    if args.input:
        return Path(args.input).read_bytes()
    return sys.stdin.buffer.read()


def _write_output(args, data: bytes) -> None:
    if args.output:
        Path(args.output).write_bytes(data)
    else:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def cmd_keygen(args) -> int:
    # The reference keyfile plugin's keygen path only emits suite 0x01
    # (ML-KEM-1024 + AES-256-GCM) keypairs today — it has no --suite
    # parameter and calls tessera_seal.generate_keypair() with the default
    # suite. Honoring any other value here would silently hand the user a
    # different key than the one they asked for (TSEAL-00039), so reject
    # everything except an explicit 0x01.
    suite = _parse_suite(args.suite)
    if suite != tessera_seal.SUITE_MLKEM1024_AESGCM:
        sys.stderr.write(
            f"tessera-seal keygen: --suite {_suite_to_str(suite)} is not supported: "
            "hybrid keyfiles land in v1.4 (TSEAL-00030..34); "
            "keygen currently supports --suite 0x01 only\n"
        )
        return 2
    # Delegate to the reference plugin so the on-disk format stays the
    # single source of truth.
    cmd = [sys.executable, PLUGIN_PATH, "keygen", "--out", args.out]
    return subprocess.call(cmd)


# ---------------------------------------------------------------------------
# pubkey
# ---------------------------------------------------------------------------


def cmd_pubkey(args) -> int:
    cmd = [sys.executable, PLUGIN_PATH, "pubkey", "--in", args.input]
    return subprocess.call(cmd)


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------


def _recipient_from_uri(uri: str) -> tessera_seal.PublicKey:
    rid = protocol.parse_recipient(uri)
    if rid.plugin != "file":
        raise SystemExit(f"tessera-seal: only the 'file' plugin is supported by the CLI; got {rid.plugin!r}")
    pk = rid.payload
    if len(pk) == tessera_seal.MLKEM1024_PK_BYTES:
        return tessera_seal.PublicKey(pk, suite=tessera_seal.SUITE_MLKEM1024_AESGCM)
    if len(pk) == tessera_seal.HYBRID_PK_BYTES:
        return tessera_seal.PublicKey(pk, suite=tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM)
    raise SystemExit(
        f"tessera-seal: recipient URI payload length {len(pk)} is not a valid public-key size"
    )


def cmd_encrypt(args) -> int:
    pub = _recipient_from_uri(args.recipient)
    # Suite must be consistent with the public key form: hybrid recipient
    # forces hybrid; otherwise honor the --suite flag.
    if pub.suite == tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM:
        suite = pub.suite
        if args.suite and _parse_suite(args.suite) != suite:
            sys.stderr.write(
                "tessera-seal encrypt: --suite ignored; hybrid recipient forces suite 0x06\n"
            )
    else:
        suite = _parse_suite(args.suite) if args.suite else tessera_seal.SUITE_MLKEM1024_AESGCM
        if suite == tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM:
            raise SystemExit("tessera-seal encrypt: non-hybrid recipient cannot use --suite 0x06")
    pt = _read_input(args)
    ad = args.ad.encode("utf-8") if args.ad else b""
    env = tessera_seal.encrypt(pt, pub, suite=suite, associated_data=ad)
    _write_output(args, env)
    sys.stderr.write(f"tessera-seal encrypt: wrote {len(env)} bytes (suite {_suite_to_str(suite)})\n")
    return 0


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


def cmd_decrypt(args) -> int:
    """Decrypt by invoking the plugin's serve mode to do the KEM decapsulation.

    Flow:
      1. Read envelope from stdin/--in.
      2. Slice out the KEM_CT.
      3. Pipe an UNWRAP_KEY frame to `tessera-seal-plugin-file serve --in keyfile`.
      4. Plugin returns the shared secret in an OK frame.
      5. CLI runs the rest of the decrypt path (KDF + AEAD + UtC commit)
         locally using the unwrapped shared secret.

    Note: the plugin protocol's UNWRAP_KEY currently returns the raw ML-KEM
    shared secret (32 bytes). For hybrid suites, the plugin would need to
    return the combined 32-byte session secret; the v1.1 reference plugin
    handles non-hybrid only. Hybrid decrypt via CLI lands with the v1.4
    hybrid plugin work (TSEAL-00030..34).
    """
    env = _read_input(args)
    h = tessera_seal.peek_header(env)
    if h.suite == tessera_seal.SUITE_HYBRID_X25519_MLKEM1024_AESGCM:
        sys.stderr.write(
            "tessera-seal decrypt: hybrid suite 0x06 decrypt via plugin is not yet "
            "supported; the v1.1 plugin returns only the ML-KEM half "
            "of the hybrid shared secret. Use the in-process Python decrypt "
            "(tessera_seal.decrypt) directly with the raw private key for hybrid "
            "envelopes, or wait for the v1.4 hybrid plugin work (TSEAL-00030..34).\n"
        )
        return 2

    kem_ct = env[tessera_seal.HEADER_BYTES : tessera_seal.HEADER_BYTES + h.kem_ct_len]

    # Build UNWRAP_KEY frame and pipe to plugin serve.
    frame = struct.pack(">I", 1 + len(kem_ct)) + bytes([protocol.FRAME_UNWRAP_KEY]) + kem_ct
    plugin_env = os.environ.copy()
    proc = subprocess.run(
        [sys.executable, PLUGIN_PATH, "serve", "--in", args.keyfile],
        input=frame, capture_output=True, timeout=120, env=plugin_env,
    )
    if proc.returncode != 0:
        sys.stderr.write("tessera-seal decrypt: plugin failed:\n")
        sys.stderr.write(proc.stderr.decode("utf-8", errors="replace"))
        return proc.returncode
    resp = protocol.read_frame(io.BytesIO(proc.stdout))
    if resp is None or resp.type == protocol.FRAME_ERROR:
        sys.stderr.write(f"tessera-seal decrypt: plugin error: {resp.body.decode() if resp else 'no response'}\n")
        return 1
    if resp.type != protocol.FRAME_OK:
        sys.stderr.write(f"tessera-seal decrypt: unexpected plugin frame type 0x{resp.type:02x}\n")
        return 1
    ss = resp.body
    if len(ss) != tessera_seal.MLKEM1024_SS_BYTES:
        sys.stderr.write(f"tessera-seal decrypt: plugin returned ss of {len(ss)} bytes (expected 32)\n")
        return 1

    # Replay the decrypt path locally with the unwrapped shared secret.
    # We pass `ss` directly into tessera_seal's internals (the public API takes
    # a PrivateKey; we want to bypass key custody since the plugin already
    # holds the sk). Build a minimal wrapper.
    ad = args.ad.encode("utf-8") if args.ad else b""
    pt = _decrypt_with_session_secret(env, ss, ad)
    if pt is None:
        sys.stderr.write("tessera-seal decrypt: authentication failed\n")
        return 1
    _write_output(args, pt)
    return 0


def _decrypt_with_session_secret(env: bytes, ss_mlkem: bytes, expected_ad: bytes) -> Optional[bytes]:
    """Mirror tessera_seal.decrypt() but take the ML-KEM shared secret as input
    (not the private key). Used by the CLI when the plugin has already done
    Decaps. Only handles non-hybrid suites."""
    h = tessera_seal.peek_header(env)
    header = env[:tessera_seal.HEADER_BYTES]
    p = tessera_seal.HEADER_BYTES
    kem_ct = env[p:p + h.kem_ct_len]; p += h.kem_ct_len
    ad = env[p:p + h.ad_len]; p += h.ad_len
    nonce = env[p:p + tessera_seal.AEAD_NONCE_BYTES]; p += tessera_seal.AEAD_NONCE_BYTES
    aead_ct_len = len(env) - p - tessera_seal.AEAD_TAG_BYTES - tessera_seal.COMMIT_BYTES
    aead_ct = env[p:p + aead_ct_len]; p += aead_ct_len
    aead_tag = env[p:p + tessera_seal.AEAD_TAG_BYTES]; p += tessera_seal.AEAD_TAG_BYTES
    commit_wire = env[p:p + tessera_seal.COMMIT_BYTES]

    # Verify AD length matches and AD bytes match.
    if h.ad_len != len(expected_ad) or ad != expected_ad:
        return None

    k_aead, derived_nonce, k_commit = tessera_seal._derive_session_keys(header, ss_mlkem)
    if nonce != derived_nonce:
        return None
    expected_commit = tessera_seal._utc_commit(k_commit, header, kem_ct, ad, aead_ct)
    if commit_wire != expected_commit:
        return None
    try:
        return tessera_seal._aead_decrypt(
            h.suite, k_aead, nonce, aead_ct + aead_tag, header + kem_ct + ad
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


def cmd_info(args) -> int:
    env = _read_input(args)
    h = tessera_seal.peek_header(env)
    print(f"variant       : 0x{h.variant:02x}")
    print(f"suite         : {_suite_to_str(h.suite)}")
    print(f"timestamp_ms  : {h.timestamp_ms}")
    print(f"counter       : {h.counter}")
    print(f"kem_ct_len    : {h.kem_ct_len}")
    print(f"ad_len        : {h.ad_len}")
    print(f"envelope_len  : {len(env)}")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tessera-seal",
        description=f"Post-quantum encryption envelope CLI (TesseraSeal reference {tessera_seal.__version__}).",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"tessera-seal {tessera_seal.__version__}",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_kg = sub.add_parser("keygen", help="generate a new keypair")
    p_kg.add_argument("--out", required=True, help="output keyfile path")
    p_kg.add_argument(
        "--suite",
        default="0x01",
        help="key suite; only 0x01 is supported today (hybrid keyfiles land in v1.4, TSEAL-00030..34)",
    )
    p_kg.set_defaults(func=cmd_keygen)

    p_pk = sub.add_parser("pubkey", help="print recipient URI for a keyfile")
    p_pk.add_argument("--in", dest="input", required=True, help="keyfile path")
    p_pk.set_defaults(func=cmd_pubkey)

    p_en = sub.add_parser("encrypt", help="encrypt to a recipient")
    p_en.add_argument("--recipient", required=True, help="tseal1<plugin>1<base64url> URI")
    p_en.add_argument("--ad", default="", help="associated data (UTF-8 string)")
    p_en.add_argument("--in", dest="input", help="input plaintext file (default: stdin)")
    p_en.add_argument("--out", dest="output", help="output envelope file (default: stdout)")
    p_en.add_argument("--suite", help="suite override (default: 0x01 for non-hybrid keys)")
    p_en.set_defaults(func=cmd_encrypt)

    p_de = sub.add_parser("decrypt", help="decrypt with a keyfile via plugin protocol")
    p_de.add_argument("--keyfile", required=True, help="keyfile path")
    p_de.add_argument("--ad", default="", help="associated data (UTF-8 string)")
    p_de.add_argument("--in", dest="input", help="input envelope file (default: stdin)")
    p_de.add_argument("--out", dest="output", help="output plaintext file (default: stdout)")
    p_de.set_defaults(func=cmd_decrypt)

    p_in = sub.add_parser("info", help="print envelope header")
    p_in.add_argument("--in", dest="input", help="input envelope file (default: stdin)")
    p_in.set_defaults(func=cmd_info)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
