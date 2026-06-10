#!/usr/bin/env python3
"""tessera-hash — command-line interface for the TesseraHash Python reference.

Invocation forms:

    tessera-hash <subcommand> ...                      (installed console command,
                                                        `pip install -e tessera-hash/python`)
    python3 tessera-hash/python/cli.py <subcommand> ...   (from a repo checkout)

Subcommands (synopsis matches the argparse definitions below exactly):

    tessera-hash hash (FILE | --stdin)
        Compute a 73-byte TesseraHash over the file's (or stdin's) content and
        print its canonical Base64URL form (98 chars). The header carries a
        fresh generation timestamp; the 64-byte SHAKE-256 tail is a pure
        function of the content.

    tessera-hash verify HASH (FILE | --stdin)
        Verify that HASH's 64-byte tail equals SHAKE-256(content, 64) of the
        file (or stdin). HASH may be Base64URL (98 chars) or Crockford Base32
        (117 chars), auto-detected by length. Exit 0 and print "OK" on match;
        exit 1 on mismatch or invalid input. The timestamp/counter header is
        provenance metadata and plays no role in verification.

    tessera-hash decode STRING
        Decode a TesseraHash string — Base64URL (98 chars) or Crockford Base32
        (117 chars), auto-detected by length — and print its fields plus both
        text encodings. Invalid input (bad length, bad chars, non-canonical
        pad bits, variant byte != 0x03) exits nonzero.

Exit status: 0 on success, 1 on invalid input or verification failure, 2 on
usage error.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tessera_hash  # noqa: E402


def _time_utc(timestamp_ms: int) -> str:
    """Best-effort ISO-8601 rendering; 48-bit timestamps can exceed datetime's
    year-9999 ceiling, so fall back to a marker instead of raising."""
    try:
        dt = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return "(out of datetime range)"


def _read_content(args, command: str) -> Optional[bytes]:
    """Read content from the FILE positional or stdin (--stdin). Exactly one
    source must be given; returns None (after printing an error) otherwise."""
    if args.stdin and args.file is not None:
        sys.stderr.write(f"tessera-hash {command}: give either FILE or --stdin, not both\n")
        return None
    if args.stdin:
        return sys.stdin.buffer.read()
    if args.file is not None:
        try:
            return Path(args.file).read_bytes()
        except OSError as e:
            sys.stderr.write(f"tessera-hash {command}: cannot read {args.file!r}: {e}\n")
            return None
    sys.stderr.write(f"tessera-hash {command}: missing input; give FILE or --stdin\n")
    return None


def _decode_string(s: str) -> bytes:
    """Decode a TesseraHash text form, auto-detected by length (98 = Base64URL,
    117 = Crockford Base32). Raises tessera_hash.TesseraHashError on failure."""
    if len(s) == tessera_hash.ENCODED_LEN_B64:
        return tessera_hash.decode_b64(s)
    if len(s) == tessera_hash.ENCODED_LEN_B32:
        return tessera_hash.decode_b32(s)
    raise tessera_hash.InvalidEncoding(
        f"expected {tessera_hash.ENCODED_LEN_B64} chars (Base64URL) or "
        f"{tessera_hash.ENCODED_LEN_B32} chars (Crockford Base32), got {len(s)}"
    )


def cmd_hash(args) -> int:
    content = _read_content(args, "hash")
    if content is None:
        return 1
    raw = tessera_hash.Generator().new(content)
    print(tessera_hash.encode_b64(raw))
    return 0


def cmd_verify(args) -> int:
    try:
        raw = _decode_string(args.hash)
    except tessera_hash.TesseraHashError as e:
        sys.stderr.write(f"tessera-hash verify: {e}\n")
        return 1
    content = _read_content(args, "verify")
    if content is None:
        return 1
    if tessera_hash.verify(raw, content):
        print("OK")
        return 0
    sys.stderr.write("tessera-hash verify: MISMATCH — tail does not match SHAKE-256(content)\n")
    return 1


def cmd_decode(args) -> int:
    try:
        raw = _decode_string(args.string)
        d = tessera_hash.decode(raw)
    except tessera_hash.TesseraHashError as e:
        sys.stderr.write(f"tessera-hash decode: {e}\n")
        return 1
    print(f"variant       : 0x{d.variant:02x} (TesseraHash)")
    print(f"timestamp_ms  : {d.timestamp_ms}")
    print(f"time_utc      : {_time_utc(d.timestamp_ms)}")
    print(f"counter       : {d.counter}")
    print(f"tail          : {d.tail.hex()}")
    print(f"base64url     : {tessera_hash.encode_b64(raw)}")
    print(f"crockford     : {tessera_hash.encode_b32(raw)}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tessera-hash",
        description=f"73-byte SHAKE-256 content identifier CLI (TesseraHash reference {tessera_hash.__version__}).",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"tessera-hash {tessera_hash.__version__}",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_hash = sub.add_parser("hash", help="hash a file (or stdin), print Base64URL (98 chars)")
    p_hash.add_argument("file", nargs="?", default=None, help="input file (or use --stdin)")
    p_hash.add_argument("--stdin", action="store_true", help="read content from stdin")
    p_hash.set_defaults(func=cmd_hash)

    p_ver = sub.add_parser("verify", help="verify a TesseraHash against a file (or stdin)")
    p_ver.add_argument("hash", help="TesseraHash text form (Base64URL 98 or Crockford 117 chars)")
    p_ver.add_argument("file", nargs="?", default=None, help="input file (or use --stdin)")
    p_ver.add_argument("--stdin", action="store_true", help="read content from stdin")
    p_ver.set_defaults(func=cmd_verify)

    p_dec = sub.add_parser("decode", help="decode a Base64URL (98) or Crockford (117) string")
    p_dec.add_argument("string", help="TesseraHash text form (encoding auto-detected by length)")
    p_dec.set_defaults(func=cmd_decode)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
