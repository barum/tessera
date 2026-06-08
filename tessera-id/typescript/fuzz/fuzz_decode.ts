// TypeScript decoder fuzz harness.
//
// Drives randomized inputs into decodeBase64URL, decodeCrockford, and
// decode for ITERS iterations and asserts no panic, bijection on success,
// and constructed-valid round-trip.
//
// Usage: tsc && node dist/fuzz/fuzz_decode.js [ITERS]
//   ITERS defaults to 200000.

import {
  SIZE_BYTES, ENCODED_LEN_B64, ENCODED_LEN_B32,
  VARIANT_STANDARD, VARIANT_HLC,
  encodeBase64URL, decodeBase64URL,
  encodeCrockford, decodeCrockford,
  decode,
  TesseraIDError,
} from "../tessera_id.js";

const B64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const CR_ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOilo";

class Rng {
  s: Uint32Array = new Uint32Array(4);
  constructor(seed: number) {
    this.s[0] = seed & 0xffffffff;
    this.s[1] = Math.floor(seed / 0x100000000) & 0xffffffff;
    this.s[2] = (this.s[0] * 0x9e3779b9) >>> 0;
    this.s[3] = (this.s[1] * 0x85ebca77) >>> 0;
  }
  next(): number {
    const r = ((((this.s[0] * 5) >>> 0) << 7) | (((this.s[0] * 5) >>> 0) >>> 25)) >>> 0;
    const result = (r * 9) >>> 0;
    const t = (this.s[1] << 9) >>> 0;
    this.s[2] = (this.s[2] ^ this.s[0]) >>> 0;
    this.s[3] = (this.s[3] ^ this.s[1]) >>> 0;
    this.s[1] = (this.s[1] ^ this.s[2]) >>> 0;
    this.s[0] = (this.s[0] ^ this.s[3]) >>> 0;
    this.s[2] = (this.s[2] ^ t) >>> 0;
    this.s[3] = ((this.s[3] << 11) | (this.s[3] >>> 21)) >>> 0;
    return result;
  }
  range(n: number): number { return n === 0 ? 0 : this.next() % n; }
}

function fuzzB64(rng: Rng): void {
  let s = "";
  for (let i = 0; i < ENCODED_LEN_B64; i++) s += B64_ALPHA[rng.range(64)];
  try {
    const raw = decodeBase64URL(s);
    if (encodeBase64URL(raw) !== s) {
      throw new Error(`b64 not bijective: in=${s} out=${encodeBase64URL(raw)}`);
    }
  } catch (e) {
    if (!(e instanceof TesseraIDError)) {
      console.error(`b64 unexpected error: ${e} on ${s}`);
      process.exit(1);
    }
  }
}

function fuzzCrockford(rng: Rng): void {
  let s = "";
  for (let i = 0; i < ENCODED_LEN_B32; i++) s += CR_ALPHA[rng.range(CR_ALPHA.length)];
  try {
    const raw = decodeCrockford(s);
    const canonical = encodeCrockford(raw);
    const raw2 = decodeCrockford(canonical);
    for (let i = 0; i < SIZE_BYTES; i++) {
      if (raw[i] !== raw2[i]) {
        console.error(`crockford canonical roundtrip mismatch`);
        process.exit(1);
      }
    }
  } catch (e) {
    if (!(e instanceof TesseraIDError)) {
      console.error(`crockford unexpected error: ${e} on ${s}`);
      process.exit(1);
    }
  }
}

function fuzzValid(rng: Rng): void {
  const tsHi = rng.next() & 0xffff;
  const tsLo = rng.next() >>> 0;
  const ts = tsHi * 0x100000000 + tsLo;
  const variant = (rng.next() & 1) ? VARIANT_HLC : VARIANT_STANDARD;
  const counter = rng.next() & 0xffff;
  const raw = new Uint8Array(SIZE_BYTES);
  raw[0] = (tsHi >>> 8) & 0xff;
  raw[1] = tsHi & 0xff;
  raw[2] = (tsLo >>> 24) & 0xff;
  raw[3] = (tsLo >>> 16) & 0xff;
  raw[4] = (tsLo >>> 8) & 0xff;
  raw[5] = tsLo & 0xff;
  raw[6] = variant;
  raw[7] = (counter >>> 8) & 0xff;
  raw[8] = counter & 0xff;
  for (let i = 9; i < SIZE_BYTES; i++) raw[i] = rng.next() & 0xff;
  const d = decode(raw);
  if (d.variant !== variant) { console.error("variant mismatch"); process.exit(1); }
  if (d.timestampMs !== ts)  { console.error(`ts mismatch ${d.timestampMs} vs ${ts}`); process.exit(1); }
  if (d.counter !== counter) { console.error("counter mismatch"); process.exit(1); }
}

const iters = process.argv[2] ? parseInt(process.argv[2], 10) : 200_000;
const seed = parseInt(process.env.TESSERA_ID_FUZZ_SEED ?? "20260519", 10);
const rng = new Rng(seed);
console.log(`fuzz_decode: ITERS=${iters} SEED=${seed}`);
for (let i = 0; i < iters; i++) {
  fuzzB64(rng);
  fuzzCrockford(rng);
  fuzzValid(rng);
  if (i > 0 && i % 10_000 === 0) console.log(`  ${i} iterations OK`);
}
console.log(`OK: ${iters} iterations × 3 cases = ${iters * 3} ops`);
