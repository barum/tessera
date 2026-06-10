#!/usr/bin/env python3
"""tessera-id — command-line interface for the TesseraID Python reference.

Invocation forms:

    tessera-id <subcommand> ...                      (installed console command,
                                                      `pip install -e tessera-id/python`)
    python3 tessera-id/python/cli.py <subcommand> ...   (from a repo checkout)

Subcommands (synopsis matches the argparse definitions below exactly):

    tessera-id new
        Generate a Standard (variant 0x01) TesseraID and print its canonical
        Base64URL form (55 chars).

    tessera-id new-hlc
        Generate an HLC (variant 0x02) TesseraID and print its canonical
        Base64URL form (55 chars).

    tessera-id decode STRING
        Decode a TesseraID string — Base64URL (55 chars) or Crockford Base32
        (66 chars), auto-detected by length — and print its fields plus both
        text encodings. Invalid input (bad length, bad chars, non-canonical
        pad bits, unknown variant byte) exits nonzero.

    tessera-id encode (--b32 | --b64) HEX
        Encode 82 hex chars (the 41-byte wire form) into the chosen text
        encoding. The variant byte is validated; unknown variants exit
        nonzero (decoders MUST reject them, so the CLI refuses to mint them).

Exit status: 0 on success, 1 on invalid input, 2 on usage error.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tessera_id  # noqa: E402

_VARIANT_NAMES = {
    tessera_id.VARIANT_STANDARD: "Standard",
    tessera_id.VARIANT_HLC: "HLC",
}


def _time_utc(timestamp_ms: int) -> str:
    """Best-effort ISO-8601 rendering; 48-bit timestamps can exceed datetime's
    year-9999 ceiling, so fall back to a marker instead of raising."""
    try:
        dt = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return "(out of datetime range)"


def _decode_string(s: str) -> bytes:
    """Decode a TesseraID text form, auto-detected by length (55 = Base64URL,
    66 = Crockford Base32). Raises tessera_id.TesseraIDError on any failure."""
    if len(s) == 55:
        return tessera_id.decode_b64(s)
    if len(s) == 66:
        return tessera_id.decode_b32(s)
    raise tessera_id.InvalidEncoding(
        f"expected 55 chars (Base64URL) or 66 chars (Crockford Base32), got {len(s)}"
    )


def _print_decoded(raw: bytes) -> None:
    d = tessera_id.decode(raw)
    variant_name = _VARIANT_NAMES.get(d.variant, "unknown")
    print(f"variant       : 0x{d.variant:02x} ({variant_name})")
    print(f"timestamp_ms  : {d.timestamp_ms}")
    print(f"time_utc      : {_time_utc(d.timestamp_ms)}")
    print(f"counter       : {d.counter}")
    print(f"random        : {d.random.hex()}")
    print(f"base64url     : {tessera_id.encode_b64(raw)}")
    print(f"crockford     : {tessera_id.encode_b32(raw)}")
    print(f"hex           : {raw.hex()}")


def cmd_new(args) -> int:
    print(tessera_id.encode_b64(tessera_id.new()))
    return 0


def cmd_new_hlc(args) -> int:
    print(tessera_id.encode_b64(tessera_id.new_hlc()))
    return 0


def cmd_decode(args) -> int:
    try:
        raw = _decode_string(args.string)
        _print_decoded(raw)
    except tessera_id.TesseraIDError as e:
        sys.stderr.write(f"tessera-id decode: {e}\n")
        return 1
    return 0


def cmd_encode(args) -> int:
    try:
        raw = bytes.fromhex(args.hex)
    except ValueError as e:
        sys.stderr.write(f"tessera-id encode: invalid hex: {e}\n")
        return 1
    try:
        # decode() enforces the 41-byte length and rejects unknown variant
        # bytes — the CLI must not mint strings every decoder rejects.
        tessera_id.decode(raw)
        print(tessera_id.encode_b32(raw) if args.b32 else tessera_id.encode_b64(raw))
    except tessera_id.TesseraIDError as e:
        sys.stderr.write(f"tessera-id encode: {e}\n")
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tessera-id",
        description=f"41-byte sortable post-quantum-era identifier CLI (TesseraID reference {tessera_id.__version__}).",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"tessera-id {tessera_id.__version__}",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_new = sub.add_parser("new", help="generate a Standard (0x01) TesseraID, print Base64URL")
    p_new.set_defaults(func=cmd_new)

    p_hlc = sub.add_parser("new-hlc", help="generate an HLC (0x02) TesseraID, print Base64URL")
    p_hlc.set_defaults(func=cmd_new_hlc)

    p_dec = sub.add_parser("decode", help="decode a Base64URL (55) or Crockford (66) string")
    p_dec.add_argument("string", help="TesseraID text form (encoding auto-detected by length)")
    p_dec.set_defaults(func=cmd_decode)

    p_enc = sub.add_parser("encode", help="encode 82 hex chars (41 bytes) into a text form")
    enc_group = p_enc.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("--b32", action="store_true", help="emit Crockford Base32 (66 chars)")
    enc_group.add_argument("--b64", action="store_true", help="emit Base64URL (55 chars)")
    p_enc.add_argument("hex", help="41-byte wire form as 82 hex chars")
    p_enc.set_defaults(func=cmd_encode)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
