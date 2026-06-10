/**
 * TesseraID — Post-Quantum Identifier (TypeScript implementation)
 *
 * 41-byte time-sortable identifier with 256 bits of post-quantum-resistant
 * randomness. Two variants share the same wire format:
 *
 *   Variant 0x01 — Standard wall-clock + monotonic counter
 *   Variant 0x02 — Hybrid Logical Clock (HLC) for distributed causality
 *
 * Layout (41 bytes):
 *
 *   0       6      7       9                              41
 *   +-------+------+-------+------------------------------+
 *   |  TS   | VER  |  CTR  |          Random              |
 *   | 48 b  |  8 b | 16 b  |           256 b              |
 *   +-------+------+-------+------------------------------+
 *
 * Targets: Node 18+, modern browsers (with Web Crypto). Pure TS, no deps.
 */

import { randomFillSync as nodeRandomFillSync } from "node:crypto";

export const SIZE_BYTES = 41 as const;
export const RANDOM_FIELD_BYTES = 32 as const;

export const VARIANT_STANDARD = 0x01 as const;
export const VARIANT_HLC = 0x02 as const;

const MAX_COUNTER = 0xffff;
const HLC_MAX_DRIFT_MS = 60_000;

/** Project epoch — optional, non-normative defensive bound. The standard
 *  decoder accepts all timestamps; validateMinTimestamp() returns true
 *  only for TesseraIDs at or after this. */
export const MIN_TIMESTAMP_MS = 1_700_000_000_000 as const;

export const ENCODED_LEN_B64 = 55 as const;
export const ENCODED_LEN_B32 = 66 as const;

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// Pre-built decode table for Crockford Base32 (handles ambiguity + lowercase).
const CROCKFORD_DECODE: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
    const c = CROCKFORD_ALPHABET.charCodeAt(i);
    t[c] = i;
    if (c >= 65 && c <= 90) t[c + 32] = i; // lowercase
  }
  // Crockford ambiguity mappings.
  t[73] = 1; t[105] = 1;            // I, i → 1
  t[76] = 1; t[108] = 1;            // L, l → 1
  t[79] = 0; t[111] = 0;            // O, o → 0
  return t;
})();

// ---------------------------------------------------------------------------
// CSPRNG abstraction
// ---------------------------------------------------------------------------

const fillRandom: (buf: Uint8Array) => void = (() => {
  // Prefer Node crypto if available (it always is in modern Node).
  if (typeof nodeRandomFillSync === "function") {
    return (buf: Uint8Array) => { nodeRandomFillSync(buf); };
  }
  // Browser / Deno / Bun fallback.
  const g = globalThis as { crypto?: { getRandomValues?: (b: Uint8Array) => void } };
  if (g.crypto?.getRandomValues) {
    return (buf: Uint8Array) => { g.crypto!.getRandomValues!(buf); };
  }
  throw new Error("tessera_id: no CSPRNG available in this environment");
})();

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class TesseraIDError extends Error {
  constructor(msg: string) { super(msg); this.name = "TesseraIDError"; }
}
export class HLCDriftError extends TesseraIDError {
  constructor(driftMs: number) {
    super(`tessera_id: observed HLC ${driftMs} ms ahead of physical clock`);
    this.name = "HLCDriftError";
  }
}
export class InvalidEncodingError extends TesseraIDError {
  constructor(msg: string) { super(`tessera_id: ${msg}`); this.name = "InvalidEncodingError"; }
}
export class UnknownVariantError extends TesseraIDError {
  constructor(b: number) {
    super(`tessera_id: unknown variant byte 0x${b.toString(16).padStart(2, "0")}`);
    this.name = "UnknownVariantError";
  }
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

// Test-only clock override. Set via setNowMsForTesting; pass null to restore.
// Accepts either a fixed value or a function so tests can drive multi-read
// paths (e.g. the counter-exhaust spin) deterministically.
let nowMsOverride: number | (() => number) | null = null;
export function setNowMsForTesting(value: number | (() => number) | null): void {
  nowMsOverride = value;
}

// 48-bit ms timestamp uses two halves to avoid JS BigInt cost on hot path.
// JS Number is safe for integers up to 2^53; 2^48 - 1 fits comfortably.
const nowMs = (): number =>
  nowMsOverride === null
    ? Date.now()
    : typeof nowMsOverride === "function"
      ? nowMsOverride()
      : nowMsOverride;

function writeHeader(
  out: Uint8Array,
  ts: number,
  variant: number,
  counter: number,
): void {
  // Big-endian 48-bit timestamp written as 16-bit hi + 32-bit lo.
  // Math.floor(ts / 2^32) avoids BigInt; for ts < 2^48 this is exact.
  const tsHi = Math.floor(ts / 0x100000000);
  const tsLo = ts >>> 0;
  out[0] = (tsHi >>> 8) & 0xff;
  out[1] = tsHi & 0xff;
  out[2] = (tsLo >>> 24) & 0xff;
  out[3] = (tsLo >>> 16) & 0xff;
  out[4] = (tsLo >>> 8) & 0xff;
  out[5] = tsLo & 0xff;
  out[6] = variant;
  out[7] = (counter >>> 8) & 0xff;
  out[8] = counter & 0xff;
}

function readTimestamp(b: Uint8Array): number {
  const tsHi = (b[0] << 8) | b[1];
  // Apply >>> 0 to the FULL OR result so the final value is treated as
  // unsigned. Applying it only to (b[2] << 24) doesn't help because the
  // outer | re-interprets the result as signed int32.
  const tsLo = ((b[2] << 24) | (b[3] << 16) | (b[4] << 8) | b[5]) >>> 0;
  // tsHi is at most 16 bits; tsLo is unsigned 32-bit. Sum stays exact for
  // 48-bit values, well within Number.MAX_SAFE_INTEGER (53-bit).
  return tsHi * 0x100000000 + tsLo;
}

// ---------------------------------------------------------------------------
// Standard generator
// ---------------------------------------------------------------------------

export class StandardGenerator {
  private lastTs = 0;
  private counter = 0;

  // Test-only: force internal (lastTs, counter) state.
  setStateForTesting(lastTs: number, counter: number): void {
    this.lastTs = lastTs;
    this.counter = counter;
  }

  newId(): Uint8Array {
    const out = new Uint8Array(SIZE_BYTES);
    // Single random fill: 1 byte counter step + 32-byte tail.
    const rnd = new Uint8Array(RANDOM_FIELD_BYTES + 1);
    fillRandom(rnd);

    let ts = nowMs();
    if (ts < this.lastTs) ts = this.lastTs;

    if (ts === this.lastTs) {
      const step = 1 + (rnd[0] & 0x0f);
      const next = this.counter + step;
      if (next > MAX_COUNTER) {
        // Counter exhausted in this ms — spin until the clock passes
        // lastTs (spec sec03: `while now <= last_ts`; matches the C
        // reference). The <= bound also covers a clock regression
        // observed mid-exhaust: with `===` the loop would exit
        // immediately on a regressed clock and lastTs would move
        // backward, breaking strict monotonicity.
        do { ts = nowMs(); } while (ts <= this.lastTs);
        this.counter = rnd[0];
      } else {
        this.counter = next;
      }
    } else {
      this.counter = rnd[0];
    }
    this.lastTs = ts;

    writeHeader(out, ts, VARIANT_STANDARD, this.counter);
    out.set(rnd.subarray(1), 9);
    return out;
  }
}

// ---------------------------------------------------------------------------
// HLC generator
// ---------------------------------------------------------------------------

export class HLCGenerator {
  private l = 0;
  private c = 0;

  // Test-only: force internal (l, c) state.
  setStateForTesting(l: number, c: number): void {
    this.l = l;
    this.c = c;
  }

  newId(observe?: Uint8Array): Uint8Array {
    const out = new Uint8Array(SIZE_BYTES);
    const rnd = new Uint8Array(RANDOM_FIELD_BYTES);
    fillRandom(rnd);

    const pt = nowMs();
    const lOld = this.l;
    const cOld = this.c;

    let lNew: number;
    let cNew: number;

    if (observe) {
      if (observe.length !== SIZE_BYTES) {
        throw new InvalidEncodingError(`observe must be ${SIZE_BYTES} bytes`);
      }
      const lMsg = readTimestamp(observe);
      const cMsg = (observe[7] << 8) | observe[8];

      if (lMsg - pt > HLC_MAX_DRIFT_MS) {
        throw new HLCDriftError(lMsg - pt);
      }

      lNew = Math.max(lOld, lMsg, pt);
      if (lNew === lOld && lNew === lMsg) {
        cNew = Math.max(cOld, cMsg) + 1;
      } else if (lNew === lOld) {
        cNew = cOld + 1;
      } else if (lNew === lMsg) {
        cNew = cMsg + 1;
      } else {
        cNew = 0;
      }
    } else if (lOld >= pt) {
      // Includes the equality case: in the same logical tick as the
      // previous event, the counter must advance (not reset to 0).
      lNew = lOld;
      cNew = cOld + 1;
    } else {
      lNew = pt;
      cNew = 0;
    }

    if (cNew > MAX_COUNTER) {
      lNew += 1;
      cNew = 0;
    }

    this.l = lNew;
    this.c = cNew;

    writeHeader(out, lNew, VARIANT_HLC, cNew);
    out.set(rnd, 9);
    return out;
  }
}

// ---------------------------------------------------------------------------
// Module-level convenience
// ---------------------------------------------------------------------------

const defaultStandard = new StandardGenerator();
const defaultHLC = new HLCGenerator();

export const newTesseraId = (): Uint8Array => defaultStandard.newId();
export const newHlcTesseraId = (observe?: Uint8Array): Uint8Array =>
  defaultHLC.newId(observe);

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

export interface DecodedTesseraID {
  variant: number;
  timestampMs: number;
  counter: number;
  random: Uint8Array;
  raw: Uint8Array;
  isHlc: boolean;
}

export function decode(raw: Uint8Array): DecodedTesseraID {
  if (raw.length !== SIZE_BYTES) {
    throw new InvalidEncodingError(`expected ${SIZE_BYTES} bytes, got ${raw.length}`);
  }
  const variant = raw[6];
  if (variant !== VARIANT_STANDARD && variant !== VARIANT_HLC) {
    throw new UnknownVariantError(variant);
  }
  return {
    variant,
    timestampMs: readTimestamp(raw),
    counter: (raw[7] << 8) | raw[8],
    random: raw.subarray(9),
    raw,
    isHlc: variant === VARIANT_HLC,
  };
}

// ---------------------------------------------------------------------------
// Base64URL encoding (canonical wire format)
// ---------------------------------------------------------------------------

// Use Node's Buffer if present (faster); fall back to manual impl in browsers.
type Base64Codec = {
  encode: (bytes: Uint8Array) => string;
  decode: (s: string) => Uint8Array;
};

const base64url: Base64Codec = (() => {
  type NodeBuffer = Uint8Array & {
    toString(encoding: "base64url"): string;
  };
  type BufferCtor = {
    from(s: string, encoding: "base64url"): NodeBuffer;
    from(b: Uint8Array): NodeBuffer;
  };
  const g = globalThis as unknown as { Buffer?: BufferCtor };
  if (typeof g.Buffer !== "undefined") {
    return {
      encode: (b) => g.Buffer!.from(b).toString("base64url"),
      decode: (s) => new Uint8Array(g.Buffer!.from(s, "base64url")),
    };
  }
  // Browser fallback via btoa/atob.
  return {
    encode: (b) => {
      let bin = "";
      for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
      return btoa(bin)
        .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    },
    decode: (s) => {
      const padded = s.replaceAll("-", "+").replaceAll("_", "/")
        + "=".repeat((4 - (s.length % 4)) % 4);
      const bin = atob(padded);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
  };
})();

export function encodeBase64URL(raw: Uint8Array): string {
  if (raw.length !== SIZE_BYTES) {
    throw new InvalidEncodingError(`expected ${SIZE_BYTES} bytes, got ${raw.length}`);
  }
  return base64url.encode(raw);
}

export function decodeBase64URL(s: string): Uint8Array {
  if (s.length !== ENCODED_LEN_B64) {
    throw new InvalidEncodingError(`Base64URL must be ${ENCODED_LEN_B64} chars`);
  }
  const bytes = base64url.decode(s);
  if (bytes.length !== SIZE_BYTES) {
    throw new InvalidEncodingError(`decoded length ${bytes.length} != ${SIZE_BYTES}`);
  }
  // Enforce canonical form: the final character carries 4 bits of value
  // plus 2 bits of zero padding. Inputs whose pad bits are non-zero are
  // rejected (matching the C reference and spec sec03).
  if (base64url.encode(bytes) !== s) {
    throw new InvalidEncodingError("non-canonical Base64URL (pad bits non-zero)");
  }
  // Validate variant byte: text decoders reject unknown variants at
  // decode, matching decodeCrockford and decode().
  if (bytes[6] !== VARIANT_STANDARD && bytes[6] !== VARIANT_HLC) {
    throw new UnknownVariantError(bytes[6]);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Crockford Base32 encoding
// ---------------------------------------------------------------------------

export function encodeCrockford(raw: Uint8Array): string {
  if (raw.length !== SIZE_BYTES) {
    throw new InvalidEncodingError(`expected ${SIZE_BYTES} bytes, got ${raw.length}`);
  }
  const out: string[] = new Array(ENCODED_LEN_B32);
  let buf = 0;
  let bits = 0;
  let idx = 0;
  for (let i = 0; i < raw.length; i++) {
    buf = (buf << 8) | raw[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out[idx++] = CROCKFORD_ALPHABET[(buf >>> bits) & 0x1f];
      // Trim buf to avoid integer overflow as bits accumulate.
      buf &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    out[idx++] = CROCKFORD_ALPHABET[(buf << (5 - bits)) & 0x1f];
  }
  return out.join("");
}

/** Non-normative defensive helper. Returns true iff the TesseraID's timestamp
 *  is at or after MIN_TIMESTAMP_MS. The standard decoder accepts all
 *  values; callers MAY opt into this check. */
export function validateMinTimestamp(raw: Uint8Array): boolean {
  if (raw.length !== SIZE_BYTES) return false;
  return readTimestamp(raw) >= MIN_TIMESTAMP_MS;
}

export function decodeCrockford(s: string): Uint8Array {
  if (s.length !== ENCODED_LEN_B32) {
    throw new InvalidEncodingError(`Crockford must be ${ENCODED_LEN_B32} chars`);
  }
  const out = new Uint8Array(SIZE_BYTES);
  let buf = 0;
  let bits = 0;
  let idx = 0;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const v = code < 128 ? CROCKFORD_DECODE[code] : -1;
    if (v < 0) throw new InvalidEncodingError(`invalid Crockford char ${s[i]}`);
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[idx++] = (buf >>> bits) & 0xff;
      buf &= (1 << bits) - 1;
    }
  }
  if (idx !== SIZE_BYTES) {
    throw new InvalidEncodingError("Crockford decode short");
  }
  if (bits > 0 && (buf & ((1 << bits) - 1)) !== 0) {
    throw new InvalidEncodingError("Crockford overflow bits set");
  }
  // Validate variant byte.
  if (out[6] !== VARIANT_STANDARD && out[6] !== VARIANT_HLC) {
    throw new UnknownVariantError(out[6]);
  }
  return out;
}
