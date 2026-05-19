import {
  newPqid, newHlcPqid, StandardGenerator, HLCGenerator,
  encodeBase64URL, decodeBase64URL, encodeCrockford, decodeCrockford,
} from "./pqid.js";
import { randomUUID } from "node:crypto";

function bench(name: string, n: number, fn: () => unknown): { name: string; ops: number } {
  // Warmup
  for (let i = 0; i < 5_000; i++) fn();
  let best = 0;
  for (let trial = 0; trial < 5; trial++) {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < n; i++) fn();
    const elapsed = Number(process.hrtime.bigint() - t0) / 1e9;
    const ops = n / elapsed;
    if (ops > best) best = ops;
  }
  return { name, ops: best };
}

console.log("PQID TypeScript benchmarks");
console.log(`Node ${process.version}`);
console.log("─".repeat(70));

const stdGen = new StandardGenerator();
const hlcGen = new HLCGenerator();
const sample = newPqid();
const sample64 = encodeBase64URL(sample);
const sample32 = encodeCrockford(sample);

const benches = [
  bench("crypto.randomUUID()",       300_000, () => randomUUID()),
  bench("PQID Standard (locked default)", 200_000, () => newPqid()),
  bench("PQID Standard (raw generator)",  200_000, () => stdGen.newId()),
  bench("PQID HLC (locked default)",      200_000, () => newHlcPqid()),
  bench("PQID HLC (raw generator)",       200_000, () => hlcGen.newId()),
  bench("encode Base64URL",          1_000_000, () => encodeBase64URL(sample)),
  bench("decode Base64URL",          1_000_000, () => decodeBase64URL(sample64)),
  bench("encode Crockford Base32",     500_000, () => encodeCrockford(sample)),
  bench("decode Crockford Base32",     500_000, () => decodeCrockford(sample32)),
];

const baseline = benches[0].ops;
console.log(`${"Operation".padEnd(38)} ${"ops/sec".padStart(14)}   ${"rel".padStart(7)}`);
console.log("─".repeat(70));
for (const { name, ops } of benches) {
  const rel = ops / baseline;
  console.log(`${name.padEnd(38)} ${Math.round(ops).toLocaleString().padStart(14)}   ${rel.toFixed(2).padStart(6)}x`);
}
