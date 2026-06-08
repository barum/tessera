"""
protocol.py — TesseraSeal plugin wire-protocol primitives (Python).

The protocol is binary, length-prefixed frames over stdin/stdout, modeled
on the C2SP age-plugin specification. See ./tessera-seal-plugin-protocol.md for
the normative description.

Each frame:

    4 bytes  uint32 big-endian   length (covers the type byte and body)
    1 byte   uint8               frame type
    N bytes                      body  (length - 1 bytes)

Frame types (v1):

    0x01  RECIPIENT_STANZA   library -> plugin
    0x02  WRAP_KEY           library -> plugin
    0x03  UNWRAP_KEY         library -> plugin
    0x10  OK                 plugin  -> library
    0x11  ERROR              plugin  -> library  (UTF-8 string body)
    0x1F  DONE               plugin  -> library  (empty body)

This module is intentionally minimal: it gives a plugin author the tools to
read/write frames without dragging in a heavy I/O framework. The reference
plugin (`tessera-seal-plugin-file`) wires this with `sys.stdin.buffer` and
`sys.stdout.buffer`.
"""
from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional


# --- Frame type tags ---------------------------------------------------------

FRAME_RECIPIENT_STANZA = 0x01
FRAME_WRAP_KEY = 0x02
FRAME_UNWRAP_KEY = 0x03
FRAME_OK = 0x10
FRAME_ERROR = 0x11
FRAME_DONE = 0x1F

MAX_FRAME_BODY_BYTES = 1 << 24  # 16 MiB hard cap on a single frame's body


class ProtocolError(Exception):
    """Raised on malformed protocol input."""


@dataclass(frozen=True)
class Frame:
    type: int
    body: bytes


def read_frame(r: BinaryIO) -> Optional[Frame]:
    """
    Read a single frame from `r`. Returns None on clean EOF (no length
    prefix arrived). Raises ProtocolError on partial reads or malformed
    length fields.
    """
    hdr = r.read(4)
    if not hdr:
        return None
    if len(hdr) != 4:
        raise ProtocolError("truncated length prefix")
    (total_len,) = struct.unpack(">I", hdr)
    if total_len < 1:
        raise ProtocolError("frame length too small (no type byte)")
    if total_len > MAX_FRAME_BODY_BYTES + 1:
        raise ProtocolError(f"frame too large: {total_len} bytes")
    rest = r.read(total_len)
    if len(rest) != total_len:
        raise ProtocolError("truncated frame body")
    frame_type = rest[0]
    body = rest[1:]
    return Frame(type=frame_type, body=body)


def write_frame(w: BinaryIO, frame_type: int, body: bytes = b"") -> None:
    """
    Write a single frame to `w` and flush. `body` may be empty.
    """
    if frame_type < 0 or frame_type > 0xFF:
        raise ProtocolError("frame type must fit in a byte")
    if len(body) > MAX_FRAME_BODY_BYTES:
        raise ProtocolError(f"frame body too large: {len(body)} > {MAX_FRAME_BODY_BYTES}")
    w.write(struct.pack(">I", 1 + len(body)))
    w.write(bytes([frame_type]))
    if body:
        w.write(body)
    w.flush()


def write_ok(w: BinaryIO, payload: bytes = b"") -> None:
    write_frame(w, FRAME_OK, payload)


def write_error(w: BinaryIO, message: str) -> None:
    write_frame(w, FRAME_ERROR, message.encode("utf-8"))


def write_done(w: BinaryIO) -> None:
    write_frame(w, FRAME_DONE)


# --- Recipient identifier (URI form) ----------------------------------------

RECIPIENT_PREFIX = "tseal1"


@dataclass(frozen=True)
class RecipientId:
    """Parsed recipient URI: tseal1<plugin>1<base64url-payload>."""
    plugin: str
    payload: bytes

    def encode(self) -> str:
        import base64 as _b64
        b64 = _b64.urlsafe_b64encode(self.payload).rstrip(b"=").decode("ascii")
        return f"{RECIPIENT_PREFIX}{self.plugin}1{b64}"


def parse_recipient(uri: str) -> RecipientId:
    """Parse the URI form tseal1<plugin>1<base64url-payload>."""
    if not uri.startswith(RECIPIENT_PREFIX):
        raise ProtocolError(f"recipient URI must start with {RECIPIENT_PREFIX!r}")
    body = uri[len(RECIPIENT_PREFIX):]
    sep = body.find("1")
    if sep < 1:
        raise ProtocolError("recipient URI missing plugin/payload separator")
    plugin = body[:sep]
    payload_b64 = body[sep + 1:]
    # Padding may be missing — append.
    pad = (-len(payload_b64)) % 4
    import base64 as _b64
    try:
        payload = _b64.urlsafe_b64decode(payload_b64 + ("=" * pad))
    except Exception as e:  # noqa: BLE001
        raise ProtocolError(f"bad recipient base64url payload: {e}") from None
    if not plugin or not plugin.replace("-", "").isalnum():
        raise ProtocolError(f"invalid plugin name: {plugin!r}")
    return RecipientId(plugin=plugin, payload=payload)
