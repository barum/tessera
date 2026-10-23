"""Generates conformance vectors in vectors/ (tessera style: JSON list of named records)."""
import json
import os

import tessera_mark as tm

MASTER = bytes(range(0x40, 0x60))
TENANT = b"tenant-demo"
# 41-byte TesseraID-shaped asset / session ids (fixed bytes, variant 0x01 at offset 6).
ASSET_ID = bytes.fromhex("019a1b2c3d4e01000a") + bytes([0x11]) * 32
ASSET_HASH = bytes.fromhex("019a1b2c3d4e030001") + bytes([0x22]) * 64
HERE = os.path.dirname(os.path.abspath(__file__))


def session_id(i: int) -> bytes:
    return bytes.fromhex("019a1b2c3d4f01") + i.to_bytes(2, "big") + bytes([0x33 ^ (i & 0xFF)]) * 32


def build():
    k_asset = tm.derive_asset_key(MASTER, TENANT, ASSET_ID, ASSET_HASH)
    codec, invalid = [], []
    for p in tm.PROFILES.values():
        m = tm.Mark(k_asset, p)
        for idx in (0, 1, 2, 1000, (1 << p.code_bits) - 1):
            code = m.encode_index(idx)
            sid = session_id(idx & 0xFFFF)
            codec.append({
                "name": f"{p.name.lower()}_index_{idx}", "op": "allocate", "profile": p.name,
                "index": idx, "session_id_hex": sid.hex(),
                "expected": {
                    "code": code, "check": m.check(code), "channel_word": m.channel_word(code),
                    "text": tm.to_text(p, code),
                    "record_hex": tm.encode_record(ASSET_ID, p, code).hex(),
                    "binding_hex": m.binding(code, sid).hex(),
                    "segments_0_15": m.sequence(code, 16),
                },
            })
    good = tm.encode_record(ASSET_ID, tm.BY_NAME["TM32"], 7)
    for v in (0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0xFF):
        bad = bytearray(good)
        bad[6] = v
        invalid.append({"name": f"variant_0x{v:02x}", "op": "decode_record",
                        "input_hex": bad.hex(), "error": "UNKNOWN_VARIANT"})
    for pid in (0x00, 0x06, 0xFF):
        bad = bytearray(good)
        bad[7] = pid
        invalid.append({"name": f"profile_0x{pid:02x}", "op": "decode_record",
                        "input_hex": bad.hex(), "error": "UNKNOWN_PROFILE"})
    bad = bytearray(good)
    bad[11] = 0x01
    invalid += [
        {"name": "noncanonical_high_bits", "op": "decode_record", "input_hex": bad.hex(),
         "error": "NONCANONICAL"},
        {"name": "short_record", "op": "decode_record", "input_hex": good[:15].hex(),
         "error": "INVALID_LEN"},
    ]
    header = {"master_key_hex": MASTER.hex(), "tenant": TENANT.decode(),
              "asset_id_hex": ASSET_ID.hex(), "asset_hash_hex": ASSET_HASH.hex(),
              "asset_key_hex": k_asset.hex(), "asset_tag_hex": tm.asset_tag(ASSET_ID).hex()}
    return header, codec, invalid


def main():
    header, codec, invalid = build()
    out = os.path.join(HERE, "..", "conformance", "vectors")
    os.makedirs(out, exist_ok=True)
    for name, body in (("context", header), ("allocate", codec), ("invalid", invalid)):
        with open(os.path.join(out, f"{name}.json"), "w") as f:
            json.dump(body, f, indent=2)
            f.write("\n")
    print(f"wrote {len(codec)} allocate + {len(invalid)} invalid vectors to {out}")


if __name__ == "__main__":
    main()
