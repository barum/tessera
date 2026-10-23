/**
 * FF1 format-preserving encryption (NIST SP 800-38G §5.1) with AES-256, for TesseraMark's
 * optional FIPS PRP mode. Numerals are bigint, so any radix/length is supported.
 */

import { createCipheriv } from "node:crypto";

export class Ff1 {
  private readonly key: Uint8Array;
  private readonly radix: number;

  constructor(key: Uint8Array, radix: number) {
    if (key.length !== 32) throw new RangeError("FF1 key must be 32 bytes");
    if (radix < 2 || radix > 65536) throw new RangeError("FF1 radix out of range");
    this.key = key;
    this.radix = radix;
  }

  private ciph(block: Uint8Array): Uint8Array {
    const c = createCipheriv("aes-256-ecb", this.key, null);
    c.setAutoPadding(false);
    return new Uint8Array(c.update(block));
  }

  private prf(data: Uint8Array): Uint8Array {
    let y: Uint8Array = new Uint8Array(16);
    for (let o = 0; o < data.length; o += 16) {
      const x = new Uint8Array(16);
      for (let i = 0; i < 16; i++) x[i] = y[i] ^ data[o + i];
      y = this.ciph(x);
    }
    return y;
  }

  private num(d: number[]): bigint {
    const r = BigInt(this.radix);
    return d.reduce((a, v) => a * r + BigInt(v), 0n);
  }

  private str(x: bigint, m: number): number[] {
    const r = BigInt(this.radix);
    const out = new Array<number>(m).fill(0);
    for (let i = m - 1; i >= 0; i--) {
      out[i] = Number(x % r);
      x /= r;
    }
    return out;
  }

  private params(n: number, t: number) {
    const u = Math.floor(n / 2);
    const v = n - u;
    const max = BigInt(this.radix) ** BigInt(v) - 1n;
    const b = Math.ceil(max.toString(2).length / 8);
    const d = 4 * Math.ceil(b / 4) + 4;
    const p = new Uint8Array(16);
    p.set([1, 2, 1, (this.radix >> 16) & 0xff, (this.radix >> 8) & 0xff, this.radix & 0xff, 10, u % 256]);
    new DataView(p.buffer).setUint32(8, n);
    new DataView(p.buffer).setUint32(12, t);
    return { u, v, b, d, p };
  }

  private roundY(p: Uint8Array, tweak: Uint8Array, i: number, x: number[], b: number, d: number): bigint {
    const pad = (16 - ((tweak.length + b + 1) % 16)) % 16;
    const q = new Uint8Array(tweak.length + pad + 1 + b);
    q.set(tweak);
    q[tweak.length + pad] = i;
    let nx = this.num(x);
    for (let k = q.length - 1; k > q.length - 1 - b; k--) {
      q[k] = Number(nx & 0xffn);
      nx >>= 8n;
    }
    const pq = new Uint8Array(p.length + q.length);
    pq.set(p);
    pq.set(q, p.length);
    const r = this.prf(pq);
    const s: number[] = Array.from(r);
    for (let j = 1; s.length < d; j++) {
      const blk = Uint8Array.from(r);
      for (let k = 0; k < 4; k++) blk[15 - k] ^= (j >>> (8 * k)) & 0xff;
      s.push(...this.ciph(blk));
    }
    return s.slice(0, d).reduce((a, v) => (a << 8n) | BigInt(v), 0n);
  }

  encrypt(tweak: Uint8Array, x: number[]): number[] {
    const { u, v, b, d, p } = this.params(x.length, tweak.length);
    let a = x.slice(0, u);
    let bb = x.slice(u);
    for (let i = 0; i < 10; i++) {
      const m = i % 2 === 0 ? u : v;
      const mod = BigInt(this.radix) ** BigInt(m);
      const c = (this.num(a) + this.roundY(p, tweak, i, bb, b, d)) % mod;
      a = bb;
      bb = this.str(c, m);
    }
    return [...a, ...bb];
  }

  decrypt(tweak: Uint8Array, y: number[]): number[] {
    const { u, v, b, d, p } = this.params(y.length, tweak.length);
    let a = y.slice(0, u);
    let bb = y.slice(u);
    for (let i = 9; i >= 0; i--) {
      const m = i % 2 === 0 ? u : v;
      const mod = BigInt(this.radix) ** BigInt(m);
      const c = (((this.num(bb) - this.roundY(p, tweak, i, a, b, d)) % mod) + mod) % mod;
      bb = a;
      a = this.str(c, m);
    }
    return [...a, ...bb];
  }
}
