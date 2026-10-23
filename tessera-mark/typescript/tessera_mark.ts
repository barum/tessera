/**
 * TesseraMark — keyed compact forensic mark, variant byte 0x05 (TypeScript implementation).
 *
 * A short (24–64 bit) keyed code: a keyed permutation of a per-asset allocation index, carried in
 * A/B segment watermarks and similar channels. Codes are bigint. Normative text: ../SPEC.md.
 */

import { concat, encodeString, kmac256, leftEncode, shake256 } from "./keccak.js";
import { Ff1 } from "./ff1.js";

export { Ff1 } from "./ff1.js";
export { kmac256 } from "./keccak.js";

export const VARIANT_MARK = 0x05 as const;
export const RECORD_LEN = 16 as const;
export const FEISTEL_ROUNDS = 12 as const;
export const MIN_KEY_LEN = 32 as const;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";
const te = new TextEncoder();
const CUSTOM = "TesseraMark v1";

export type MarkErrorCode =
  | "SHORT_KEY" | "BAD_PROFILE" | "INDEX_RANGE" | "CODE_RANGE" | "INVALID_LEN" | "UNKNOWN_VARIANT"
  | "UNKNOWN_PROFILE" | "NONCANONICAL" | "TOO_MANY_ERASURES" | "CHECK_FAILED" | "AMBIGUOUS"
  | "BAD_TEXT" | "BAD_CHECK";

export class MarkError extends Error {
  readonly code: MarkErrorCode;
  constructor(code: MarkErrorCode) {
    super(code);
    this.name = "MarkError";
    this.code = code;
  }
}

export type ProfileName = "TM24" | "TM32" | "TM40" | "TM48" | "TM64";

export interface Profile {
  readonly name: ProfileName;
  readonly id: number;
  readonly codeBits: number;
  readonly checkBits: number;
}

export const PROFILES: readonly Profile[] = [
  { name: "TM24", id: 0x01, codeBits: 24, checkBits: 12 },
  { name: "TM32", id: 0x02, codeBits: 32, checkBits: 16 },
  { name: "TM40", id: 0x03, codeBits: 40, checkBits: 16 },
  { name: "TM48", id: 0x04, codeBits: 48, checkBits: 16 },
  { name: "TM64", id: 0x05, codeBits: 64, checkBits: 16 },
];

export function profile(nameOrId: string | number): Profile {
  const p = PROFILES.find((x) =>
    typeof nameOrId === "number" ? x.id === nameOrId : x.name === nameOrId.toUpperCase());
  if (!p) throw new MarkError("UNKNOWN_PROFILE");
  return p;
}

export const channelBits = (p: Profile): number => p.codeBits + p.checkBits;
export const maxErasures = (p: Profile): number => Math.max(0, p.checkBits - 12);

function toBytes(x: bigint, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

const fromBytes = (b: Uint8Array): bigint => b.reduce((a, v) => (a << 8n) | BigInt(v), 0n);

/** K_asset = KMAC256(K_master, enc(tenant)||enc(asset_id)||enc(asset_hash), 256, ...). */
export function deriveAssetKey(master: Uint8Array, tenant: Uint8Array, assetId: Uint8Array,
  assetHash: Uint8Array = new Uint8Array()): Uint8Array {
  if (master.length < MIN_KEY_LEN) throw new MarkError("SHORT_KEY");
  const ctx = concat(encodeString(tenant), encodeString(assetId), encodeString(assetHash));
  return kmac256(master, ctx, 32, te.encode(`${CUSTOM} asset key`));
}

/** 6-byte public routing tag of an asset. */
export function assetTag(assetId: Uint8Array): Uint8Array {
  return shake256(concat(te.encode(`${CUSTOM} asset tag`), encodeString(assetId)), 6);
}

export type PrpMode = "kmac" | "ff1";

export interface Decoded {
  code: bigint;
  index: bigint;
  agreement: number;
  erasures: number;
}

/** Codec for one asset and profile. */
export class Mark {
  readonly profile: Profile;
  readonly mode: PrpMode;
  private readonly kPrp: Uint8Array;
  private readonly kChk: Uint8Array;
  private readonly kWht: Uint8Array;
  private readonly kBnd: Uint8Array;
  private readonly ff1: Ff1 | null;

  private constructor(key: Uint8Array, p: Profile, mode: PrpMode) {
    if (key.length < MIN_KEY_LEN) throw new MarkError("SHORT_KEY");
    if (p.codeBits % 2) throw new MarkError("BAD_PROFILE");
    const sub = (label: string) =>
      kmac256(key, concat(te.encode(label), Uint8Array.of(p.id)), 32, te.encode(`${CUSTOM} subkey`));
    this.profile = p;
    this.mode = mode;
    this.kPrp = sub("prp");
    this.kChk = sub("check");
    this.kWht = sub("whiten");
    this.kBnd = sub("bind");
    this.ff1 = mode === "ff1" ? new Ff1(sub("ff1"), 2) : null;
  }

  static create(assetKey: Uint8Array, p: ProfileName | Profile, mode: PrpMode = "kmac"): Mark {
    return new Mark(assetKey, typeof p === "string" ? profile(p) : p, mode);
  }

  private get max(): bigint {
    return (1n << BigInt(this.profile.codeBits)) - 1n;
  }

  private round(r: number, half: bigint): bigint {
    const h = this.profile.codeBits / 2;
    const nb = Math.ceil(h / 8);
    const out = kmac256(this.kPrp, concat(leftEncode(r), toBytes(half, nb)), nb, te.encode("prp"));
    return fromBytes(out) & ((1n << BigInt(h)) - 1n);
  }

  private bits(v: bigint): number[] {
    const n = this.profile.codeBits;
    return Array.from({ length: n }, (_, i) => Number((v >> BigInt(n - 1 - i)) & 1n));
  }

  private static unbits(d: number[]): bigint {
    return d.reduce((a, b) => (a << 1n) | BigInt(b), 0n);
  }

  encodeIndex(index: bigint): bigint {
    if (index < 0n || index > this.max) throw new MarkError("INDEX_RANGE");
    if (this.ff1) return Mark.unbits(this.ff1.encrypt(Uint8Array.of(this.profile.id), this.bits(index)));
    const h = BigInt(this.profile.codeBits / 2);
    let l = index >> h;
    let r = index & ((1n << h) - 1n);
    for (let i = 0; i < FEISTEL_ROUNDS; i++) [l, r] = [r, l ^ this.round(i, r)];
    return (l << h) | r;
  }

  decodeCode(code: bigint): bigint {
    if (code < 0n || code > this.max) throw new MarkError("CODE_RANGE");
    if (this.ff1) return Mark.unbits(this.ff1.decrypt(Uint8Array.of(this.profile.id), this.bits(code)));
    const h = BigInt(this.profile.codeBits / 2);
    let l = code >> h;
    let r = code & ((1n << h) - 1n);
    for (let i = FEISTEL_ROUNDS - 1; i >= 0; i--) [l, r] = [r ^ this.round(i, l), l];
    return (l << h) | r;
  }

  private codeBytes(code: bigint): Uint8Array {
    return toBytes(code, Math.ceil(this.profile.codeBits / 8));
  }

  check(code: bigint): bigint {
    const c = this.profile.checkBits;
    const tag = kmac256(this.kChk, this.codeBytes(code), Math.ceil(c / 8), te.encode("check"));
    return fromBytes(tag) >> BigInt((8 - (c % 8)) % 8);
  }

  channelWord(code: bigint): bigint {
    return (code << BigInt(this.profile.checkBits)) | this.check(code);
  }

  splitWord(word: bigint): [bigint, boolean] {
    const c = BigInt(this.profile.checkBits);
    const code = word >> c;
    return [code, (word & ((1n << c) - 1n)) === this.check(code)];
  }

  binding(code: bigint, sessionId: Uint8Array): Uint8Array {
    return kmac256(this.kBnd, concat(this.codeBytes(code), encodeString(sessionId)), 32, te.encode("bind"));
  }

  whiten(segment: bigint): number {
    return kmac256(this.kWht, toBytes(segment, 8), 1, te.encode("whiten"))[0] & 1;
  }

  segmentVariant(code: bigint, segment: bigint): number {
    const l = BigInt(channelBits(this.profile));
    const pos = segment % l;
    const bit = Number((this.channelWord(code) >> (l - 1n - pos)) & 1n);
    return bit ^ this.whiten(segment);
  }

  sequence(code: bigint, start: bigint, count: number): number[] {
    return Array.from({ length: count }, (_, i) => this.segmentVariant(code, start + BigInt(i)));
  }

  decodeObservations(obs: ReadonlyArray<readonly [bigint, number]>): Decoded {
    const l = channelBits(this.profile);
    const votes = Array.from({ length: l }, () => [0, 0]);
    for (const [s, v] of obs) votes[Number(s % BigInt(l))][(v ^ this.whiten(s)) & 1]++;
    let word = 0n;
    const erased: number[] = [];
    votes.forEach(([z, o], pos) => {
      word <<= 1n;
      if (z === o) erased.push(pos);
      else if (o > z) word |= 1n;
    });
    if (erased.length > maxErasures(this.profile)) throw new MarkError("TOO_MANY_ERASURES");
    const hits: bigint[] = [];
    for (let fill = 0; fill < 1 << erased.length; fill++) {
      let w = word;
      erased.forEach((pos, i) => {
        if ((fill >> i) & 1) w |= 1n << BigInt(l - 1 - pos);
      });
      const [code, ok] = this.splitWord(w);
      if (ok) hits.push(code);
    }
    if (hits.length !== 1) throw new MarkError(hits.length ? "AMBIGUOUS" : "CHECK_FAILED");
    const code = hits[0];
    const agree = obs.filter(([s, v]) => this.segmentVariant(code, s) === v).length;
    return { code, index: this.decodeCode(code), agreement: agree / Math.max(1, obs.length), erasures: erased.length };
  }

  scoreCandidates(obs: ReadonlyArray<readonly [bigint, number]>, codes: bigint[]): Array<[number, bigint]> {
    return codes
      .map((c): [number, bigint] => [obs.filter(([s, v]) => this.segmentVariant(c, s) === v).length, c])
      .sort((a, b) => b[0] - a[0] || (b[1] > a[1] ? 1 : b[1] < a[1] ? -1 : 0));
  }
}

/** 16-byte record: ATAG(6) || 0x05 || PROFILE || CODE(8, BE). */
export class MarkRecord {
  readonly bytes: Uint8Array;
  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  static create(assetId: Uint8Array, p: Profile, code: bigint): MarkRecord {
    if (code < 0n || code >= 1n << BigInt(p.codeBits)) throw new MarkError("CODE_RANGE");
    return new MarkRecord(concat(assetTag(assetId), Uint8Array.of(VARIANT_MARK, p.id), toBytes(code, 8)));
  }

  static fromBytes(raw: Uint8Array): MarkRecord {
    if (raw.length !== RECORD_LEN) throw new MarkError("INVALID_LEN");
    if (raw[6] !== VARIANT_MARK) throw new MarkError("UNKNOWN_VARIANT");
    const p = profile(raw[7]);
    if (fromBytes(raw.subarray(8)) >> BigInt(p.codeBits)) throw new MarkError("NONCANONICAL");
    return new MarkRecord(Uint8Array.from(raw));
  }

  get profile(): Profile {
    return profile(this.bytes[7]);
  }

  get code(): bigint {
    return fromBytes(this.bytes.subarray(8));
  }

  get assetTag(): Uint8Array {
    return this.bytes.slice(0, 6);
  }
}

const textCheck = (p: Profile, code: bigint): string =>
  CROCKFORD[Number(((BigInt(p.id) << BigInt(p.codeBits)) | code) % 37n)];

export function toText(p: Profile, code: bigint): string {
  if (code < 0n || code >= 1n << BigInt(p.codeBits)) throw new MarkError("CODE_RANGE");
  const nch = Math.ceil(p.codeBits / 5);
  const v = code << BigInt(nch * 5 - p.codeBits);
  let body = "";
  for (let i = 0; i < nch; i++) body += CROCKFORD[Number((v >> BigInt(5 * (nch - 1 - i))) & 31n)];
  return `${p.name}-${body}-${textCheck(p, code)}`;
}

export function fromText(text: string): [Profile, bigint] {
  const t = text.trim().toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1");
  const parts = t.split("-");
  if (parts.length !== 3) throw new MarkError("BAD_TEXT");
  const [name, body, check] = parts;
  const p = PROFILES.find((x) => x.name === name);
  if (!p || body.length !== Math.ceil(p.codeBits / 5) || check.length !== 1) throw new MarkError("BAD_TEXT");
  let v = 0n;
  for (const ch of body) {
    const d = CROCKFORD.indexOf(ch);
    if (d < 0 || d >= 32) throw new MarkError("BAD_TEXT");
    v = (v << 5n) | BigInt(d);
  }
  const pad = BigInt(body.length * 5 - p.codeBits);
  if (v & ((1n << pad) - 1n)) throw new MarkError("NONCANONICAL");
  const code = v >> pad;
  if (textCheck(p, code) !== check) throw new MarkError("BAD_CHECK");
  return [p, code];
}

/** Union bound `min(1, candidates · P[Bin(observations, 1/2) >= agreements])` (SPEC §5.2). */
export function falseMatchProbability(candidates: number, observations: number, agreements: number): number {
  if (agreements <= 0 || observations <= 0) return 1;
  let lnC = 0;
  for (let i = 0; i < agreements; i++) lnC += Math.log(observations - i) - Math.log(i + 1);
  let tail = 0;
  for (let k = agreements; k <= observations; k++) {
    tail += Math.exp(lnC - observations * Math.LN2);
    if (k < observations) lnC += Math.log(observations - k) - Math.log(k + 1);
  }
  return Math.min(1, candidates * tail);
}
