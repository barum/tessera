/**
 * Keccak-f[1600], SHAKE256, cSHAKE256 and KMAC256 (FIPS 202, NIST SP 800-185).
 *
 * Node's crypto module has SHAKE256 but no cSHAKE/KMAC, so the sponge is implemented here with
 * 32-bit lane halves. Reference implementation: correctness first, not constant-time.
 */

const RC: readonly number[] = [
  0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000, 0x80008000, 0x80000000,
  0x0000808b, 0x00000000, 0x80000001, 0x00000000, 0x80008081, 0x80000000, 0x00008009, 0x80000000,
  0x0000008a, 0x00000000, 0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
  0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000, 0x00008003, 0x80000000,
  0x00008002, 0x80000000, 0x00000080, 0x80000000, 0x0000800a, 0x00000000, 0x8000000a, 0x80000000,
  0x80008081, 0x80000000, 0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
];
// Rotation offsets indexed by lane x + 5y.
const ROT: readonly number[] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const RATE = 136;

/** Permutes 25 lanes stored as lo/hi uint32 pairs (s[2i] = lo, s[2i+1] = hi). */
function keccakF(s: Uint32Array): void {
  const c = new Uint32Array(10);
  const b = new Uint32Array(50);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      c[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      c[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    for (let x = 0; x < 5; x++) {
      const p = (x + 4) % 5;
      const q = (x + 1) % 5;
      const lo = c[2 * p] ^ ((c[2 * q] << 1) | (c[2 * q + 1] >>> 31));
      const hi = c[2 * p + 1] ^ ((c[2 * q + 1] << 1) | (c[2 * q] >>> 31));
      for (let y = 0; y < 25; y += 5) {
        s[2 * (x + y)] ^= lo;
        s[2 * (x + y) + 1] ^= hi;
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const i = x + 5 * y;
        const r = ROT[i];
        let lo = s[2 * i];
        let hi = s[2 * i + 1];
        if (r >= 32) {
          [lo, hi] = [hi, lo];
        }
        const k = r % 32;
        const nlo = k ? (lo << k) | (hi >>> (32 - k)) : lo;
        const nhi = k ? (hi << k) | (lo >>> (32 - k)) : hi;
        const j = y + 5 * ((2 * x + 3 * y) % 5);
        b[2 * j] = nlo;
        b[2 * j + 1] = nhi;
      }
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        const i = x + y;
        const i1 = ((x + 1) % 5) + y;
        const i2 = ((x + 2) % 5) + y;
        s[2 * i] = b[2 * i] ^ (~b[2 * i1] & b[2 * i2]);
        s[2 * i + 1] = b[2 * i + 1] ^ (~b[2 * i1 + 1] & b[2 * i2 + 1]);
      }
    }
    s[0] ^= RC[2 * round];
    s[1] ^= RC[2 * round + 1];
  }
}

function sponge(data: Uint8Array, suffix: number, outLen: number): Uint8Array {
  const padded = new Uint8Array(Math.ceil((data.length + 1) / RATE) * RATE);
  padded.set(data);
  padded[data.length] = suffix;
  padded[padded.length - 1] |= 0x80;
  const s = new Uint32Array(50);
  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 4; i++) {
      const o = off + 4 * i;
      s[i] ^= padded[o] | (padded[o + 1] << 8) | (padded[o + 2] << 16) | (padded[o + 3] << 24);
    }
    keccakF(s);
  }
  const out = new Uint8Array(outLen);
  let n = 0;
  for (;;) {
    for (let i = 0; i < RATE && n < outLen; i++, n++) out[n] = (s[i >> 2] >>> (8 * (i & 3))) & 0xff;
    if (n >= outLen) return out;
    keccakF(s);
  }
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function beBytes(x: bigint): number[] {
  const out: number[] = [];
  do {
    out.unshift(Number(x & 0xffn));
    x >>= 8n;
  } while (x > 0n);
  return out;
}

export function leftEncode(x: number | bigint): Uint8Array {
  const b = beBytes(BigInt(x));
  return Uint8Array.from([b.length, ...b]);
}

export function rightEncode(x: number | bigint): Uint8Array {
  const b = beBytes(BigInt(x));
  return Uint8Array.from([...b, b.length]);
}

export function encodeString(s: Uint8Array): Uint8Array {
  return concat(leftEncode(8 * s.length), s);
}

function bytepad(x: Uint8Array, w: number): Uint8Array {
  const z = concat(leftEncode(w), x);
  return concat(z, new Uint8Array((w - (z.length % w)) % w));
}

export function shake256(data: Uint8Array, outLen: number): Uint8Array {
  return sponge(data, 0x1f, outLen);
}

export function cshake256(data: Uint8Array, outLen: number, n: Uint8Array, s: Uint8Array): Uint8Array {
  if (n.length === 0 && s.length === 0) return shake256(data, outLen);
  return sponge(concat(bytepad(concat(encodeString(n), encodeString(s)), RATE), data), 0x04, outLen);
}

const KMAC = new TextEncoder().encode("KMAC");

/** KMAC256(K, X, L = 8 * outLen, S). */
export function kmac256(key: Uint8Array, data: Uint8Array, outLen: number, custom: Uint8Array): Uint8Array {
  const x = concat(bytepad(encodeString(key), RATE), data, rightEncode(8 * outLen));
  return cshake256(x, outLen, KMAC, custom);
}
