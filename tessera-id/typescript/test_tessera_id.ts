import {
  newTesseraId, newHlcTesseraId, decode, encodeBase64URL, decodeBase64URL,
  encodeCrockford, decodeCrockford, StandardGenerator, HLCGenerator,
  HLCDriftError, UnknownVariantError, SIZE_BYTES, setNowMsForTesting,
  VARIANT_STANDARD, VARIANT_HLC, ENCODED_LEN_B64, ENCODED_LEN_B32,
} from "./tessera_id.js";

let failed = 0;
function ok(cond: unknown, msg: string): void {
  if (cond) {
    console.log("✓", msg);
  } else {
    console.log("✗", msg);
    failed++;
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// --- size / variant ---
ok(newTesseraId().length === SIZE_BYTES, "Standard TesseraID is 41 bytes");
ok(newHlcTesseraId().length === SIZE_BYTES, "HLC TesseraID is 41 bytes");
ok(newTesseraId()[6] === VARIANT_STANDARD, "Standard variant byte");
ok(newHlcTesseraId()[6] === VARIANT_HLC, "HLC variant byte");

// --- uniqueness ---
{
  const seen = new Set<string>();
  for (let i = 0; i < 100_000; i++) {
    seen.add(Buffer.from(newTesseraId()).toString("hex"));
  }
  ok(seen.size === 100_000, "100k unique Standard TesseraIDs");
}

// --- monotonicity ---
{
  const g = new StandardGenerator();
  let prev = g.newId();
  let mono = true;
  for (let i = 0; i < 10_000; i++) {
    const cur = g.newId();
    if (Buffer.compare(cur, prev) <= 0) { mono = false; break; }
    prev = cur;
  }
  ok(mono, "Standard monotonic within a generator");

  const h = new HLCGenerator();
  let hp = h.newId();
  let hm = true;
  for (let i = 0; i < 10_000; i++) {
    const cur = h.newId();
    if (Buffer.compare(cur, hp) <= 0) { hm = false; break; }
    hp = cur;
  }
  ok(hm, "HLC monotonic within a generator");
}

// --- decode roundtrip ---
{
  const id = newTesseraId();
  const d = decode(id);
  ok(d.variant === VARIANT_STANDARD, "decode variant");
  ok(d.timestampMs > 0, "decode timestamp present");
  ok(d.random.length === 32, "decode random 32 bytes");
}

// --- Base64URL roundtrip ---
{
  const id = newTesseraId();
  const s = encodeBase64URL(id);
  ok(s.length === ENCODED_LEN_B64, `Base64URL length is ${ENCODED_LEN_B64}`);
  ok(compareBytes(decodeBase64URL(s), id), "Base64URL roundtrip");
}

// --- Crockford roundtrip ---
{
  const id = newTesseraId();
  const s = encodeCrockford(id);
  ok(s.length === ENCODED_LEN_B32, `Crockford length is ${ENCODED_LEN_B32}`);
  ok(compareBytes(decodeCrockford(s), id), "Crockford roundtrip");
  ok(compareBytes(decodeCrockford(s.toLowerCase()), id), "Crockford case-insensitive");
}

// --- variant rejection ---
{
  const id = newTesseraId();
  const bad = new Uint8Array(id);
  bad[6] = 0xFF;
  let threw = false;
  try { decode(bad); } catch (e) { threw = e instanceof UnknownVariantError; }
  ok(threw, "unknown variant rejected on decode");
}

// --- counter exhaust under clock regression ---
// The spec (sec03) requires the exhaust spin to run `while now <= last_ts`:
// the emitted ID must carry a timestamp strictly greater than lastTs, never
// a regressed one (which would sort before its predecessor).
{
  const T0 = 1_750_000_000_000;
  let calls = 0;
  setNowMsForTesting(() => {
    calls++;
    // First reads: regressed clock; then the clock finally passes lastTs.
    return calls < 5 ? T0 - 5_000 : T0 + 1;
  });
  const g = new StandardGenerator();
  g.setStateForTesting(T0, 0xffff); // any step exhausts the counter
  const id = g.newId();
  setNowMsForTesting(null);
  const d = decode(id);
  ok(
    d.timestampMs > T0,
    "counter exhaust under clock regression advances past lastTs",
  );
}

// --- string decoders reject unknown variants (both text forms) ---
{
  const id = newTesseraId();
  for (const bad of [0x00, 0x03, 0x7f, 0xff]) {
    const tampered = new Uint8Array(id);
    tampered[6] = bad;

    let threwB64 = false;
    try { decodeBase64URL(encodeBase64URL(tampered)); }
    catch (e) { threwB64 = e instanceof UnknownVariantError; }
    ok(threwB64, `Base64URL decode rejects unknown variant 0x${bad.toString(16)}`);

    let threwCk = false;
    try { decodeCrockford(encodeCrockford(tampered)); }
    catch (e) { threwCk = e instanceof UnknownVariantError; }
    ok(threwCk, `Crockford decode rejects unknown variant 0x${bad.toString(16)}`);
  }

  // Known variants still decode through both text forms.
  for (const good of [VARIANT_STANDARD, VARIANT_HLC]) {
    const okBytes = new Uint8Array(id);
    okBytes[6] = good;
    ok(
      compareBytes(decodeBase64URL(encodeBase64URL(okBytes)), okBytes),
      `Base64URL decode accepts variant 0x${good.toString(16)}`,
    );
    ok(
      compareBytes(decodeCrockford(encodeCrockford(okBytes)), okBytes),
      `Crockford decode accepts variant 0x${good.toString(16)}`,
    );
  }
}

// --- HLC drift bound ---
{
  const g = new HLCGenerator();
  const peer = new Uint8Array(SIZE_BYTES);
  const futureTs = Date.now() + 120_000;
  // Write 48-bit timestamp + 0x02 variant + zero counter + zero random.
  const tsHi = Math.floor(futureTs / 0x100000000);
  const tsLo = futureTs >>> 0;
  peer[0] = (tsHi >>> 8) & 0xff;
  peer[1] = tsHi & 0xff;
  peer[2] = (tsLo >>> 24) & 0xff;
  peer[3] = (tsLo >>> 16) & 0xff;
  peer[4] = (tsLo >>> 8) & 0xff;
  peer[5] = tsLo & 0xff;
  peer[6] = 0x02;
  let threw = false;
  try { g.newId(peer); } catch (e) { threw = e instanceof HLCDriftError; }
  ok(threw, "HLC rejects out-of-bound drift");
}

// --- HLC observation merges peer state ---
{
  const g = new HLCGenerator();
  const a = g.newId();
  const da = decode(a);
  const peer = new Uint8Array(SIZE_BYTES);
  const peerTs = da.timestampMs + 1000;
  const tsHi = Math.floor(peerTs / 0x100000000);
  const tsLo = peerTs >>> 0;
  peer[0] = (tsHi >>> 8) & 0xff;
  peer[1] = tsHi & 0xff;
  peer[2] = (tsLo >>> 24) & 0xff;
  peer[3] = (tsLo >>> 16) & 0xff;
  peer[4] = (tsLo >>> 8) & 0xff;
  peer[5] = tsLo & 0xff;
  peer[6] = 0x02;
  const b = g.newId(peer);
  ok(decode(b).timestampMs >= peerTs, "HLC advances to peer's logical time");
}

if (failed > 0) {
  console.log(`\n${failed} test(s) FAILED`);
  process.exit(1);
} else {
  console.log("\nAll tests passed.");
}
