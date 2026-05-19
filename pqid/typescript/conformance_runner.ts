// TypeScript conformance runner. Usage: tsx conformance_runner.ts <vectors.json>
import * as fs from "node:fs";
import {
  SIZE_BYTES, VARIANT_HLC,
  encodeBase64URL, decodeBase64URL,
  encodeCrockford, decodeCrockford,
  decode, HLCGenerator,
  setNowMsForTesting,
} from "./pqid.js";

interface Record {
  name: string;
  op: string;
  input_hex?: string;
  input_str?: string;
  input_kind?: string;
  expected_hex?: string;
  expected_str?: string;
  expected?: any;
  start?: { l_old: number; c_old: number };
  physical_time_ms?: number;
  observe?: { l_msg: number; c_msg: number } | null;
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.substr(2 * i, 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

type Result = { ok: true } | { ok: false; detail: string };

function runDecode(r: Record): Result {
  const raw = hexToBytes(r.input_hex!);
  try {
    const d = decode(raw);
    const exp = r.expected;
    if (d.variant !== exp.variant) return { ok: false, detail: `variant got=${d.variant} want=${exp.variant}` };
    if (d.timestampMs !== exp.timestamp_ms) return { ok: false, detail: `ts got=${d.timestampMs} want=${exp.timestamp_ms}` };
    if (d.counter !== exp.counter) return { ok: false, detail: `counter got=${d.counter} want=${exp.counter}` };
    const gotRand = bytesToHex(d.random);
    if (gotRand !== exp.random_hex) return { ok: false, detail: `random got=${gotRand} want=${exp.random_hex}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, detail: `error: ${(e as Error).message}` };
  }
}

function runEncodeB64(r: Record): Result {
  const raw = hexToBytes(r.input_hex!);
  const s = encodeBase64URL(raw);
  if (s !== r.expected_str) return { ok: false, detail: `got=${s} want=${r.expected_str}` };
  return { ok: true };
}

function runDecodeB64(r: Record): Result {
  try {
    const raw = decodeBase64URL(r.input_str!);
    const got = bytesToHex(raw);
    if (got !== r.expected_hex) return { ok: false, detail: `got=${got} want=${r.expected_hex}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, detail: `error: ${(e as Error).message}` };
  }
}

function runEncodeCrockford(r: Record): Result {
  const raw = hexToBytes(r.input_hex!);
  const s = encodeCrockford(raw);
  if (s !== r.expected_str) return { ok: false, detail: `got=${s} want=${r.expected_str}` };
  return { ok: true };
}

function runDecodeCrockford(r: Record): Result {
  try {
    const raw = decodeCrockford(r.input_str!);
    const got = bytesToHex(raw);
    if (got !== r.expected_hex) return { ok: false, detail: `got=${got} want=${r.expected_hex}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, detail: `error: ${(e as Error).message}` };
  }
}

function runValidateInvalid(r: Record): Result {
  try {
    if (r.input_kind === "binary_hex") {
      const h = r.input_hex!;
      if (h.length !== 2 * SIZE_BYTES) return { ok: true };
      decode(hexToBytes(h));
    } else if (r.input_kind === "b64") {
      decodeBase64URL(r.input_str!);
    } else if (r.input_kind === "crockford") {
      decodeCrockford(r.input_str!);
    } else {
      return { ok: false, detail: `unknown input_kind ${r.input_kind}` };
    }
    return { ok: false, detail: "expected error, got success" };
  } catch {
    return { ok: true };
  }
}

function runHLCOverflow(r: Record): Result {
  const g = new HLCGenerator();
  g.setStateForTesting(r.start!.l_old, r.start!.c_old);
  setNowMsForTesting(r.physical_time_ms!);
  let raw: Uint8Array;
  try {
    if (r.observe == null) {
      raw = g.newId();
    } else {
      const peer = new Uint8Array(SIZE_BYTES);
      const lMsg = r.observe.l_msg;
      const cMsg = r.observe.c_msg;
      peer[0] = Math.floor(lMsg / 0x10000000000) & 0xff;
      peer[1] = Math.floor(lMsg / 0x100000000) & 0xff;
      peer[2] = (lMsg >>> 24) & 0xff;
      peer[3] = (lMsg >>> 16) & 0xff;
      peer[4] = (lMsg >>> 8) & 0xff;
      peer[5] = lMsg & 0xff;
      peer[6] = VARIANT_HLC;
      peer[7] = (cMsg >>> 8) & 0xff;
      peer[8] = cMsg & 0xff;
      raw = g.newId(peer);
    }
  } catch (e) {
    setNowMsForTesting(null);
    return { ok: false, detail: `error: ${(e as Error).message}` };
  }
  setNowMsForTesting(null);
  const d = decode(raw);
  if (d.timestampMs !== r.expected.l_new || d.counter !== r.expected.c_new) {
    return {
      ok: false,
      detail: `got=(l=${d.timestampMs}, c=${d.counter}) want=(l=${r.expected.l_new}, c=${r.expected.c_new})`,
    };
  }
  return { ok: true };
}

function dispatch(r: Record): Result {
  switch (r.op) {
    case "decode": return runDecode(r);
    case "encode_b64": return runEncodeB64(r);
    case "decode_b64": return runDecodeB64(r);
    case "encode_crockford": return runEncodeCrockford(r);
    case "decode_crockford": return runDecodeCrockford(r);
    case "validate_invalid": return runValidateInvalid(r);
    case "hlc_overflow": return runHLCOverflow(r);
  }
  return { ok: false, detail: `unknown op ${r.op}` };
}

function main(argv: string[]): number {
  if (argv.length !== 1) {
    console.error("usage: conformance_runner <vectors.json>");
    return 2;
  }
  const records: Record[] = JSON.parse(fs.readFileSync(argv[0], "utf8"));
  let failures = 0;
  for (const r of records) {
    if (r.name === "doc") continue;
    const result = dispatch(r);
    if (result.ok) {
      console.log(`PASS ${r.name}`);
    } else {
      console.log(`FAIL ${r.name} ${result.detail}`);
      failures++;
    }
  }
  return failures > 0 ? 1 : 0;
}

process.exit(main(process.argv.slice(2)));
