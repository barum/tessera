/** Conformance + behaviour tests for the TypeScript TesseraMark implementation. */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ff1, MarkError, MarkRecord, Mark, assetTag, deriveAssetKey, falseMatchProbability, fromText,
  kmac256, profile, toText } from "./tessera_mark.js";

const here = dirname(fileURLToPath(import.meta.url));
const vecDir = join(here, "..", "..", "conformance", "vectors");
// Integers above 2^53 are quoted before parsing so they survive as exact bigint strings.
const load = (n: string): any =>
  JSON.parse(readFileSync(join(vecDir, `${n}.json`), "utf8").replace(/:\s*(\d{16,})/g, ': "$1"'));
const hex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const te = new TextEncoder();

let passed = 0;
function test(name: string, fn: () => void): void {
  fn();
  passed++;
  console.log(`ok - ${name}`);
}
function throwsCode(fn: () => unknown, code: string): void {
  assert.throws(fn, (e: unknown) => e instanceof MarkError && e.code === code);
}

test("KMAC256 NIST SP 800-185 sample 6", () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
  const out = kmac256(key, Uint8Array.of(0, 1, 2, 3), 64, te.encode("My Tagged Application"));
  assert.equal(toHex(out), "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
    + "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");
});

test("FF1 NIST SP 800-38G samples 7-9 (AES-256)", () => {
  const key = hex("2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94");
  const cases: Array<[number, string, string, string]> = [
    [10, "", "0123456789", "6657667009"],
    [10, "39383736353433323130", "0123456789", "1001623463"],
    [36, "3737373770717273373737", "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"],
  ];
  for (const [radix, t, pt, ct] of cases) {
    const f = new Ff1(key, radix);
    const digits = [...pt].map((c) => parseInt(c, 36));
    const out = f.encrypt(hex(t), digits);
    assert.equal(out.map((d) => d.toString(36)).join(""), ct);
    assert.deepEqual(f.decrypt(hex(t), out), digits);
  }
});

const ctx = load("context");
const assetId = hex(ctx.asset_id_hex);
const key = deriveAssetKey(hex(ctx.master_key_hex), te.encode(ctx.tenant), assetId, hex(ctx.asset_hash_hex));

test("context: asset key and tag", () => {
  assert.equal(toHex(key), ctx.asset_key_hex);
  assert.equal(toHex(assetTag(assetId)), ctx.asset_tag_hex);
});

test("allocate vectors", () => {
  const vs = load("allocate");
  assert.equal(vs.length, 25);
  for (const v of vs) {
    const p = profile(v.profile);
    const m = Mark.create(key, p);
    const e = v.expected;
    const code = m.encodeIndex(BigInt(v.index));
    assert.equal(code, BigInt(e.code), v.name);
    assert.equal(m.decodeCode(code), BigInt(v.index), v.name);
    assert.equal(m.check(code), BigInt(e.check), v.name);
    assert.equal(m.channelWord(code), BigInt(e.channel_word), v.name);
    assert.equal(toText(p, code), e.text, v.name);
    assert.deepEqual(fromText(e.text), [p, code]);
    const rec = MarkRecord.create(assetId, p, code);
    assert.equal(toHex(rec.bytes), e.record_hex, v.name);
    assert.equal(MarkRecord.fromBytes(rec.bytes).code, code);
    assert.equal(toHex(m.binding(code, hex(v.session_id_hex))), e.binding_hex, v.name);
    assert.deepEqual(m.sequence(code, 0n, 16), e.segments_0_15, v.name);
  }
});

test("invalid record vectors", () => {
  for (const v of load("invalid")) throwsCode(() => MarkRecord.fromBytes(hex(v.input_hex)), v.error);
});

test("FF1 mode vectors (cross-checked with Rust)", () => {
  for (const v of load("ff1")) {
    const m = Mark.create(key, v.profile, "ff1");
    const code = m.encodeIndex(BigInt(v.index));
    assert.equal(code, BigInt(v.code), v.name);
    assert.equal(m.decodeCode(code), BigInt(v.index));
  }
});

test("decode observations: noise, erasures, wrong key", () => {
  const m = Mark.create(key, "TM32");
  const code = m.encodeIndex(4242n);
  const obs: Array<[bigint, number]> = Array.from({ length: 144 }, (_, s) => [BigInt(s), m.segmentVariant(code, BigInt(s))]);
  obs[5][1] ^= 1;
  const d = m.decodeObservations(obs);
  assert.equal(d.code, code);
  assert.equal(d.index, 4242n);
  const partial = obs.filter(([s]) => ![1n, 2n, 3n].includes(s % 48n));
  assert.equal(m.decodeObservations(partial).erasures, 3);
  throwsCode(() => m.decodeObservations(obs.slice(0, 40)), "TOO_MANY_ERASURES");
  assert.throws(() => Mark.create(new Uint8Array(32).fill(9), "TM32").decodeObservations(obs));
  assert.deepEqual(m.scoreCandidates(obs, [m.encodeIndex(1n), code])[0], [143, code]);
});

test("errors and accusation probability", () => {
  throwsCode(() => fromText("TM32-0000000"), "BAD_TEXT");
  throwsCode(() => Mark.create(key, "TM24").encodeIndex(1n << 24n), "INDEX_RANGE");
  throwsCode(() => deriveAssetKey(new Uint8Array(31), te.encode("t"), te.encode("a")), "SHORT_KEY");
  assert.ok(falseMatchProbability(1_000_000, 200, 190) < 1e-9);
  assert.ok(falseMatchProbability(1_000_000, 48, 30) > 1e-9);
});

console.log(`\n${passed} tests passed`);
