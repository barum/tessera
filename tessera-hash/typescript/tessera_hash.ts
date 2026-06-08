/**
 * TesseraHash — Post-Quantum Content Identifier (TypeScript implementation).
 *
 * 73-byte sortable content identifier with a 512-bit SHAKE-256 tail.
 * Variant byte 0x03. Sibling to TesseraID, NOT a hash function.
 *
 * SHAKE-256 from Node's built-in crypto module (Node 18+).
 */

import { createHash, timingSafeEqual } from "node:crypto";

export const TESSERA_HASH_SIZE_BYTES = 73 as const;
export const TESSERA_HASH_TAIL_BYTES = 64 as const;
export const TESSERA_HASH_TAIL_OFFSET = 9 as const;

export const VARIANT_HASH = 0x03 as const;

export const TESSERA_HASH_ENCODED_LEN_B64 = 98 as const;
export const TESSERA_HASH_ENCODED_LEN_B32 = 117 as const;

export const TESSERA_HASH_MIN_TIMESTAMP_MS = 1_700_000_000_000 as const;

const MAX_COUNTER = 0xffff;
const MAX_TIMESTAMP_MS = 0xffff_ffff_ffff; // 2^48 - 1

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CROCKFORD_DECODE: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
    const c = CROCKFORD_ALPHABET.charCodeAt(i);
    t[c] = i;
    if (c >= 65 && c <= 90) t[c + 32] = i;
  }
  t[73] = 1; t[105] = 1;
  t[76] = 1; t[108] = 1;
  t[79] = 0; t[111] = 0;
  return t;
})();

export class TesseraHashError extends Error {
  constructor(msg: string) { super(`tessera_hash: ${msg}`); this.name = "TesseraHashError"; }
}

let nowMsOverrideTesseraHash: number | null = null;
export function setTesseraHashNowMsForTesting(value: number | null): void {
  nowMsOverrideTesseraHash = value;
}
const nowMs = (): number => nowMsOverrideTesseraHash !== null ? nowMsOverrideTesseraHash : Date.now();

function shake256(content: Uint8Array): Uint8Array {
  const h = createHash("shake256", { outputLength: TESSERA_HASH_TAIL_BYTES });
  h.update(content);
  return new Uint8Array(h.digest());
}

function writeHeader(out: Uint8Array, ts: number, counter: number): void {
  const tsHi = Math.floor(ts / 0x100000000);
  const tsLo = ts >>> 0;
  out[0] = (tsHi >>> 8) & 0xff;
  out[1] = tsHi & 0xff;
  out[2] = (tsLo >>> 24) & 0xff;
  out[3] = (tsLo >>> 16) & 0xff;
  out[4] = (tsLo >>> 8) & 0xff;
  out[5] = tsLo & 0xff;
  out[6] = VARIANT_HASH;
  out[7] = (counter >>> 8) & 0xff;
  out[8] = counter & 0xff;
}

function readTimestamp(b: Uint8Array): number {
  const tsHi = (b[0] << 8) | b[1];
  const tsLo = ((b[2] << 24) | (b[3] << 16) | (b[4] << 8) | b[5]) >>> 0;
  return tsHi * 0x100000000 + tsLo;
}

/** Returns just the 64-byte SHAKE-256 tail. */
export function tesseraHashHashOnly(content: Uint8Array): Uint8Array {
  return shake256(content);
}

/** Construct a TesseraHash with explicit (timestamp_ms, counter). */
export function tesseraHashAt(content: Uint8Array, timestampMs: number, counter = 0): Uint8Array {
  if (timestampMs < 0 || timestampMs > MAX_TIMESTAMP_MS) {
    throw new TesseraHashError("timestamp_ms out of range");
  }
  if (counter < 0 || counter > MAX_COUNTER) {
    throw new TesseraHashError("counter out of range");
  }
  const out = new Uint8Array(TESSERA_HASH_SIZE_BYTES);
  writeHeader(out, timestampMs, counter);
  out.set(shake256(content), TESSERA_HASH_TAIL_OFFSET);
  return out;
}

export class TesseraHashGenerator {
  private lastTs = 0;
  private counter = 0;

  setStateForTesting(ts: number, counter: number): void {
    this.lastTs = ts;
    this.counter = counter;
  }

  newId(content: Uint8Array): Uint8Array {
    const tail = shake256(content);
    let ts = nowMs();
    if (ts < this.lastTs) ts = this.lastTs;
    if (ts === this.lastTs) {
      const next = this.counter + 1;
      if (next > MAX_COUNTER) {
        while (nowMs() <= this.lastTs) { /* spin */ }
        ts = nowMs();
        this.counter = 0;
      } else {
        this.counter = next;
      }
    } else {
      this.counter = 0;
    }
    this.lastTs = ts;

    const out = new Uint8Array(TESSERA_HASH_SIZE_BYTES);
    writeHeader(out, ts, this.counter);
    out.set(tail, TESSERA_HASH_TAIL_OFFSET);
    return out;
  }
}

export interface TesseraHashDecoded {
  variant: number;
  timestampMs: number;
  counter: number;
  tail: Uint8Array;
  raw: Uint8Array;
}

export function tesseraHashDecode(raw: Uint8Array): TesseraHashDecoded {
  if (raw.length !== TESSERA_HASH_SIZE_BYTES) {
    throw new TesseraHashError(`must be ${TESSERA_HASH_SIZE_BYTES} bytes, got ${raw.length}`);
  }
  if (raw[6] !== VARIANT_HASH) {
    throw new TesseraHashError(`variant must be 0x03, got 0x${raw[6].toString(16).padStart(2, "0")}`);
  }
  return {
    variant: raw[6],
    timestampMs: readTimestamp(raw),
    counter: (raw[7] << 8) | raw[8],
    tail: raw.slice(TESSERA_HASH_TAIL_OFFSET),
    raw,
  };
}

/** Constant-time verify of the tail against SHAKE-256(content). */
export function tesseraHashVerify(raw: Uint8Array, content: Uint8Array): boolean {
  if (raw.length !== TESSERA_HASH_SIZE_BYTES) return false;
  if (raw[6] !== VARIANT_HASH) return false;
  const expected = shake256(content);
  // Node's timingSafeEqual requires equal-length Buffers.
  return timingSafeEqual(
    Buffer.from(raw.subarray(TESSERA_HASH_TAIL_OFFSET)),
    Buffer.from(expected),
  );
}

export function tesseraHashValidateMinTimestamp(raw: Uint8Array): boolean {
  if (raw.length !== TESSERA_HASH_SIZE_BYTES) return false;
  return readTimestamp(raw) >= TESSERA_HASH_MIN_TIMESTAMP_MS;
}

// ---- Base64URL ----

const b64url = (() => {
  return {
    encode: (b: Uint8Array): string => {
      let bin = "";
      for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
      return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    },
    decode: (s: string): Uint8Array => {
      const padded = s.replaceAll("-", "+").replaceAll("_", "/")
        + "=".repeat((4 - (s.length % 4)) % 4);
      const bin = atob(padded);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
  };
})();

export function tesseraHashEncodeBase64URL(raw: Uint8Array): string {
  if (raw.length !== TESSERA_HASH_SIZE_BYTES) {
    throw new TesseraHashError(`expected ${TESSERA_HASH_SIZE_BYTES} bytes, got ${raw.length}`);
  }
  return b64url.encode(raw);
}

export function tesseraHashDecodeBase64URL(s: string): Uint8Array {
  if (s.length !== TESSERA_HASH_ENCODED_LEN_B64) {
    throw new TesseraHashError(`Base64URL must be ${TESSERA_HASH_ENCODED_LEN_B64} chars`);
  }
  const bytes = b64url.decode(s);
  if (bytes.length !== TESSERA_HASH_SIZE_BYTES) {
    throw new TesseraHashError(`decoded length ${bytes.length} != ${TESSERA_HASH_SIZE_BYTES}`);
  }
  // Canonicalization: re-encode and compare.
  if (b64url.encode(bytes) !== s) {
    throw new TesseraHashError("non-canonical Base64URL (pad bits non-zero)");
  }
  if (bytes[6] !== VARIANT_HASH) {
    throw new TesseraHashError(`variant must be 0x03, got 0x${bytes[6].toString(16).padStart(2, "0")}`);
  }
  return bytes;
}

// ---- Crockford Base32 ----

export function tesseraHashEncodeCrockford(raw: Uint8Array): string {
  if (raw.length !== TESSERA_HASH_SIZE_BYTES) {
    throw new TesseraHashError(`expected ${TESSERA_HASH_SIZE_BYTES} bytes, got ${raw.length}`);
  }
  const out: string[] = new Array(TESSERA_HASH_ENCODED_LEN_B32);
  let buf = 0;
  let bits = 0;
  let idx = 0;
  for (let i = 0; i < raw.length; i++) {
    buf = (buf << 8) | raw[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out[idx++] = CROCKFORD_ALPHABET[(buf >>> bits) & 0x1f];
      buf &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    out[idx++] = CROCKFORD_ALPHABET[(buf << (5 - bits)) & 0x1f];
  }
  return out.join("");
}

export function tesseraHashDecodeCrockford(s: string): Uint8Array {
  if (s.length !== TESSERA_HASH_ENCODED_LEN_B32) {
    throw new TesseraHashError(`Crockford must be ${TESSERA_HASH_ENCODED_LEN_B32} chars`);
  }
  const out = new Uint8Array(TESSERA_HASH_SIZE_BYTES);
  let buf = 0;
  let bits = 0;
  let idx = 0;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const v = code < 128 ? CROCKFORD_DECODE[code] : -1;
    if (v < 0) throw new TesseraHashError(`invalid Crockford char ${s[i]}`);
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (idx >= TESSERA_HASH_SIZE_BYTES) throw new TesseraHashError("Crockford overflow");
      out[idx++] = (buf >>> bits) & 0xff;
      buf &= (1 << bits) - 1;
    }
  }
  if (idx !== TESSERA_HASH_SIZE_BYTES) throw new TesseraHashError("Crockford decode short");
  if (bits > 0 && (buf & ((1 << bits) - 1)) !== 0) {
    throw new TesseraHashError("non-canonical Crockford (pad bits non-zero)");
  }
  if (out[6] !== VARIANT_HASH) {
    throw new TesseraHashError(`variant must be 0x03, got 0x${out[6].toString(16).padStart(2, "0")}`);
  }
  return out;
}
