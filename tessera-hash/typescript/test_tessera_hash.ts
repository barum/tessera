import {
  hashOnly, hashAt, decode, verify, validate, validateMinTimestamp,
  encodeBase64URL, decodeBase64URL, encodeCrockford, decodeCrockford,
  Generator, TesseraHashError, InvalidEncodingError, UnknownVariantError,
  SIZE_BYTES, TAIL_BYTES, VARIANT_HASH, ENCODED_LEN_B64, ENCODED_LEN_B32,
  setNowMsForTesting,
} from "./tessera_hash.js";

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

const content = new TextEncoder().encode("hello, world");

// --- size / variant ---
{
  const g = new Generator();
  const h = g.newId(content);
  ok(h.length === SIZE_BYTES, "TesseraHash is 73 bytes");
  ok(h[6] === VARIANT_HASH, "variant byte is 0x03");
}

// --- determinism: same content, same tail; hashOnly agrees ---
{
  const g1 = new Generator();
  const g2 = new Generator();
  const h1 = g1.newId(content);
  const h2 = g2.newId(content);
  ok(compareBytes(h1.subarray(9), h2.subarray(9)), "same content produces same tail");
  ok(compareBytes(h1.subarray(9), hashOnly(content)), "hashOnly matches generator tail");
  ok(hashOnly(content).length === TAIL_BYTES, "hashOnly returns 64 bytes");
}

// --- monotonicity ---
{
  const g = new Generator();
  let prev = g.newId(new TextEncoder().encode("0"));
  let mono = true;
  for (let i = 1; i < 10_000; i++) {
    const cur = g.newId(i % 2 === 0 ? content : new TextEncoder().encode("diff"));
    if (Buffer.compare(Buffer.from(cur), Buffer.from(prev)) <= 0) { mono = false; break; }
    prev = cur;
  }
  ok(mono, "10k IDs strictly monotonic");
}

// --- hashAt range ---
{
  const maxTs = 2 ** 48 - 1;
  const h = hashAt(content, maxTs, 0);
  ok(decode(h).timestampMs === maxTs, "hashAt(max ts) round-trips");
  let threw = false;
  try { hashAt(content, 2 ** 48, 0); } catch (e) { threw = e instanceof TesseraHashError; }
  ok(threw, "hashAt(2^48) throws TesseraHashError (never masks to 48 bits)");
}

// --- decode / validate ---
{
  const h = hashAt(content, 1_700_000_000_000, 7);
  const d = decode(h);
  ok(d.variant === VARIANT_HASH && d.timestampMs === 1_700_000_000_000 && d.counter === 7,
    "decode parses header fields");
  ok(compareBytes(d.tail, hashOnly(content)), "decode extracts tail");
  let threw = false;
  try { validate(h.subarray(0, 41)); } catch (e) { threw = e instanceof TesseraHashError; }
  ok(threw, "validate(short buffer) throws");
  const tampered = h.slice();
  tampered[6] = 0x05;
  threw = false;
  try { validate(tampered); } catch (e) { threw = e instanceof UnknownVariantError; }
  ok(threw, "validate(variant 0x05) throws UnknownVariantError");
  threw = false;
  try { decode(tampered); } catch (e) { threw = e instanceof UnknownVariantError; }
  ok(threw, "decode(variant 0x05) throws UnknownVariantError");
}

// --- Base64URL round-trip ---
{
  const h = hashAt(content, 1_700_000_000_123, 1);
  const s = encodeBase64URL(h);
  ok(s.length === ENCODED_LEN_B64, "Base64URL is 98 chars");
  ok(compareBytes(decodeBase64URL(s), h), "Base64URL round-trip");
  let threw = false;
  try { decodeBase64URL(s.slice(0, 97)); } catch (e) { threw = e instanceof InvalidEncodingError; }
  ok(threw, "short Base64URL throws InvalidEncodingError");
}

// --- Crockford round-trip ---
{
  const h = hashAt(content, 1_700_000_000_123, 1);
  const s = encodeCrockford(h);
  ok(s.length === ENCODED_LEN_B32, "Crockford is 117 chars");
  ok(compareBytes(decodeCrockford(s), h), "Crockford round-trip");
  ok(compareBytes(decodeCrockford(s.toLowerCase()), h), "Crockford decode is case-insensitive");
  let threw = false;
  try { decodeCrockford(s.slice(0, -1) + "U"); } catch (e) { threw = e instanceof InvalidEncodingError; }
  ok(threw, "invalid Crockford char throws InvalidEncodingError");
}

// --- text-form unknown-variant rejection (spec sec03) ---
{
  const h = hashAt(content, 1_700_000_000_000, 0);
  for (const bad of [0x00, 0x01, 0x02, 0x04, 0x05, 0xff]) {
    const tampered = h.slice();
    tampered[6] = bad;
    let threwB64 = false;
    try { decodeBase64URL(encodeBase64URL(tampered)); }
    catch (e) { threwB64 = e instanceof UnknownVariantError; }
    let threwB32 = false;
    try { decodeCrockford(encodeCrockford(tampered)); }
    catch (e) { threwB32 = e instanceof UnknownVariantError; }
    ok(threwB64 && threwB32,
      `text decode rejects variant 0x${bad.toString(16).padStart(2, "0")} as UnknownVariantError`);
  }
}

// --- verify ---
{
  const g = new Generator();
  const h = g.newId(content);
  ok(verify(h, content), "verify(correct content) is true");
  ok(!verify(h, new TextEncoder().encode("hello, worlD")), "verify(wrong content) is false");
  ok(!verify(h.subarray(0, 41), content), "verify(short buffer) is false");
}

// --- validateMinTimestamp ---
{
  ok(validateMinTimestamp(hashAt(content, 1_700_000_000_001, 0)), "post-epoch timestamp passes");
  ok(!validateMinTimestamp(hashAt(content, 1_000_000, 0)), "pre-epoch timestamp fails");
}

// --- clock regression: timestamp clamps, never goes backward ---
{
  const g = new Generator();
  const T = 1_750_000_000_000;
  g.setStateForTesting(T, 7);
  setNowMsForTesting(T - 10);
  const h = g.newId(content);
  setNowMsForTesting(null);
  const d = decode(h);
  ok(d.timestampMs === T && d.counter === 8, "regressed clock clamps to last_ts, counter advances");
}

console.log(failed === 0 ? "ALL TESTS PASSED" : `${failed} TESTS FAILED`);
process.exit(failed === 0 ? 0 : 1);
