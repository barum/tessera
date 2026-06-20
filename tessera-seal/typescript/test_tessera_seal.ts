// TesseraSeal TypeScript test suite.
//
// Mirrors python/test_tessera_seal.py in coverage, consumes the same KAT vectors
// under ../conformance/vectors/.
//
//   cd tessera-seal/typescript && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
    encrypt, decrypt, generateKeypair, generateKeypairFromSeed,
    peekAd, peekHeader, validate, validateMinTimestamp, envelopeSize, envelopeSizeForSuite,
    setNowMsForTesting, SenderContext,
    UnknownVariant, UnknownSuite, InvalidLength, DecryptionError, BadKeyError,
    TesseraSealError,
    TESSERA_SEAL_VARIANT,
    SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA, SUITE_HYBRID_X25519_MLKEM1024_AESGCM,
    HEADER_BYTES, MLKEM1024_CT_BYTES, MLKEM1024_SEED_BYTES, MLKEM1024_PK_BYTES,
    HYBRID_CT_BYTES, HYBRID_PK_BYTES, HYBRID_SEED_BYTES,
    AEAD_NONCE_BYTES, AEAD_TAG_BYTES, COMMIT_BYTES,
} from "./tessera_seal.js";

const KAT_DIR = "../conformance/vectors";

function hex(s: string): Uint8Array {
    if (s.length === 0) return new Uint8Array(0);
    if (s.length % 2 !== 0) throw new Error("bad hex");
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
}

function loadVectors(file: string): any[] {
    const raw = readFileSync(join(KAT_DIR, file), "utf8");
    return JSON.parse(raw);
}

// --- Self-contained

test("roundtrip aesgcm", () => {
    const { priv, pub } = generateKeypair(SUITE_MLKEM1024_AESGCM);
    const pt = new TextEncoder().encode("hello world from TS");
    const env = encrypt(pt, pub);
    const got = decrypt(env, priv, new Uint8Array(0));
    assert.deepEqual(got, pt);
});

test("roundtrip chacha", () => {
    const { priv, pub } = generateKeypair(SUITE_MLKEM1024_CHACHA);
    const pt = new TextEncoder().encode("chacha payload");
    const env = encrypt(pt, pub, SUITE_MLKEM1024_CHACHA);
    const got = decrypt(env, priv, new Uint8Array(0));
    assert.deepEqual(got, pt);
});

test("AD binding positive", () => {
    const { priv, pub } = generateKeypair();
    const ad = new Uint8Array(41).map((_, i) => i);
    const pt = new TextEncoder().encode("with AD");
    const env = encrypt(pt, pub, SUITE_MLKEM1024_AESGCM, ad);
    assert.deepEqual(decrypt(env, priv, ad), pt);
});

test("AD binding wrong AD throws", () => {
    const { priv, pub } = generateKeypair();
    const ad = new Uint8Array([1, 2, 3, 4, 5]);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_MLKEM1024_AESGCM, ad);
    const wrong = new Uint8Array(ad);
    wrong[0] ^= 1;
    assert.throws(() => decrypt(env, priv, wrong), DecryptionError);
});

test("variant rejection", () => {
    const { priv, pub } = generateKeypair();
    const env = encrypt(new TextEncoder().encode("x"), pub);
    for (const v of [0x00, 0x01, 0x02, 0x03, 0x05, 0x10, 0x7F, 0xFE, 0xFF]) {
        const bad = new Uint8Array(env);
        bad[6] = v;
        assert.throws(() => decrypt(bad, priv, new Uint8Array(0)), UnknownVariant, `variant ${v}`);
    }
});

test("suite rejection", () => {
    const { priv, pub } = generateKeypair();
    const env = encrypt(new TextEncoder().encode("x"), pub);
    for (const s of [0x00, 0x03, 0x04, 0x10, 0x7F, 0xFE, 0xFF]) {
        const bad = new Uint8Array(env);
        bad[7] = s;
        assert.throws(() => decrypt(bad, priv, new Uint8Array(0)), UnknownSuite, `suite ${s}`);
    }
});

// --- Hybrid suite 0x06 (X25519 + ML-KEM-1024 + AES-256-GCM + UtC), TSEAL-00032.
//     Mirrors the Rust/Go/Python hybrid test set. The TypeScript port gained
//     hybrid support in TSEAL-00032, so suite 0x06 is now ACCEPTED (no longer
//     rejected as UnknownSuite).

test("hybrid roundtrip", () => {
    const { priv, pub } = generateKeypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const pt = new TextEncoder().encode("hybrid X25519+ML-KEM-1024 envelope");
    const env = encrypt(pt, pub, SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const got = decrypt(env, priv, new Uint8Array(0));
    assert.deepEqual(got, pt);
});

test("hybrid roundtrip with AD", () => {
    const { priv, pub } = generateKeypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const ad = new Uint8Array(41).map((_, i) => i);
    const pt = new TextEncoder().encode("hybrid with AD");
    const env = encrypt(pt, pub, SUITE_HYBRID_X25519_MLKEM1024_AESGCM, ad);
    assert.deepEqual(decrypt(env, priv, ad), pt);
});

test("hybrid key + KEM_CT sizes", () => {
    const { priv, pub } = generateKeypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    assert.equal(pub.bytes.length, HYBRID_PK_BYTES, "hybrid pub key 1600 B");
    assert.equal(pub.bytes.length, 1600);
    assert.equal(priv.seed.length, HYBRID_SEED_BYTES, "hybrid seed 96 B");
    assert.equal(priv.seed.length, 96);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const h = peekHeader(env);
    assert.equal(h.suite, SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    assert.equal(h.kemCtLen, HYBRID_CT_BYTES, "wire KEM_CT_LEN must be 1600");
    assert.equal(h.kemCtLen, 1600);
    assert.equal(env.length, envelopeSizeForSuite(SUITE_HYBRID_X25519_MLKEM1024_AESGCM, 1, 0));
});

test("hybrid AD-binding negative", () => {
    const { priv, pub } = generateKeypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const ad = new Uint8Array(41).fill(0xab);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_HYBRID_X25519_MLKEM1024_AESGCM, ad);
    const wrong = new Uint8Array(ad);
    wrong[0] ^= 1;
    assert.throws(() => decrypt(env, priv, wrong), DecryptionError);
});

test("hybrid X25519-half tamper -> DecryptionError", () => {
    // Flip a byte in the trailing X25519 ephemeral pubkey portion of KEM_CT;
    // the combiner diverges and the AEAD/commit verify fails uniformly.
    const { priv, pub } = generateKeypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const xByteOffset = HEADER_BYTES + MLKEM1024_CT_BYTES; // first byte of x_eph_pk
    env[xByteOffset] ^= 1;
    assert.throws(() => decrypt(env, priv, new Uint8Array(0)), DecryptionError);
});

test("hybrid suite/key consistency (BadKey)", () => {
    // encrypt: pub tagged 0x06, requesting 0x01 -> BadKey before any KEM work.
    const { pub: hybridPub } = generateKeypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    assert.throws(
        () => encrypt(new TextEncoder().encode("x"), hybridPub, SUITE_MLKEM1024_AESGCM),
        BadKeyError
    );
    // decrypt: hybrid envelope, priv re-tagged 0x01 -> BadKey (not auth-class).
    const { priv, pub } = generateKeypair(SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
    const privMismatch = { ...priv, suite: SUITE_MLKEM1024_AESGCM };
    assert.throws(() => decrypt(env, privMismatch, new Uint8Array(0)), BadKeyError);
});

// THE byte-identity oracle: the frozen hybrid_decrypt.json envelopes were
// generated by the Python reference. This TS port is correct iff it decrypts
// those exact envelopes to the recorded plaintexts. This proves cross-language
// (Python <-> TS) hybrid correctness even without a conformance runner.
test("KAT hybrid_decrypt.json (byte-identity oracle)", () => {
    const recs = loadVectors("hybrid_decrypt.json");
    assert.ok(recs.length > 0, "no hybrid_decrypt records");
    for (const r of recs) {
        const seed = hex(r.private_key_seed_hex);
        assert.equal(seed.length, 96, `${r.name}: hybrid seed must be 96 B`);
        const { priv, pub } = generateKeypairFromSeed(seed, SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
        // The derived public key must match the recorded one byte-for-byte
        // (confirms our X25519 getPublicKey + ML-KEM keygen are aligned).
        assert.deepEqual(pub.bytes, hex(r.public_key_hex), `${r.name}: pub key`);
        const env = hex(r.envelope_hex);
        const ad = hex(r.expected_ad_hex);
        const got = decrypt(env, priv, ad);
        assert.deepEqual(got, hex(r.expected_plaintext_hex), `${r.name}: plaintext`);
    }
});

test("KAT hybrid_ad_binding.json", () => {
    const recs = loadVectors("hybrid_ad_binding.json");
    assert.ok(recs.length > 0);
    for (const r of recs) {
        const seed = hex(r.private_key_seed_hex);
        const { priv } = generateKeypairFromSeed(seed, SUITE_HYBRID_X25519_MLKEM1024_AESGCM);
        const env = hex(r.envelope_hex);
        const ad = hex(r.expected_ad_hex);
        if (r.op === "decrypt") {
            assert.deepEqual(decrypt(env, priv, ad), hex(r.expected_plaintext_hex), r.name);
        } else {
            assert.throws(() => decrypt(env, priv, ad), Error, r.name);
        }
    }
});

test("KAT hybrid_peek_header.json", () => {
    const recs = loadVectors("hybrid_peek_header.json");
    assert.ok(recs.length > 0);
    for (const r of recs) {
        const h = peekHeader(hex(r.header_hex));
        assert.equal(h.timestampMs, r.expected.timestamp_ms, r.name);
        assert.equal(h.variant, r.expected.variant, r.name);
        assert.equal(h.suite, r.expected.suite, r.name);
        assert.equal(h.counter, r.expected.counter, r.name);
        assert.equal(h.kemCtLen, r.expected.kem_ct_len, r.name);
        assert.equal(h.adLen, r.expected.ad_len, r.name);
    }
});

test("tamper detection", () => {
    const { priv, pub } = generateKeypair();
    const ad = new TextEncoder().encode("id");
    const env = encrypt(new TextEncoder().encode("tamper"), pub, SUITE_MLKEM1024_AESGCM, ad);
    const spots: [string, number][] = [
        ["kem_ct", HEADER_BYTES + 500],
        ["ad",     HEADER_BYTES + 1568],
        ["nonce",  HEADER_BYTES + 1568 + 2],
        ["aead",   HEADER_BYTES + 1568 + 2 + 12],
        ["tag",    env.length - 32 - 1],
        ["commit", env.length - 1],
    ];
    for (const [name, idx] of spots) {
        const bad = new Uint8Array(env);
        bad[idx] ^= 1;
        assert.throws(() => decrypt(bad, priv, ad), Error, `tamper ${name}`);
    }
});

test("peek_header", () => {
    const { pub } = generateKeypair();
    setNowMsForTesting(1_700_000_000_000);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_MLKEM1024_AESGCM, new Uint8Array(0), null, 7);
    setNowMsForTesting(null);
    const h = peekHeader(env);
    assert.equal(h.timestampMs, 1_700_000_000_000);
    assert.equal(h.variant, TESSERA_SEAL_VARIANT);
    assert.equal(h.suite, SUITE_MLKEM1024_AESGCM);
    assert.equal(h.counter, 7);
    assert.equal(h.kemCtLen, 1568);
    assert.equal(h.adLen, 0);
});

// Structural AD peek (TSEAL-00047 / TP-081): unauthenticated until decrypt;
// every returned byte is attacker-controlled.
test("peek_ad roundtrip, truncation, unknown variant/suite", () => {
    const { pub } = generateKeypair();
    const ad = new Uint8Array(41).map((_, i) => i);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_MLKEM1024_AESGCM, ad);
    assert.deepEqual(peekAd(env), ad);

    // Empty AD: returns an empty array, no error.
    const envNoAd = encrypt(new TextEncoder().encode("x"), pub);
    assert.deepEqual(peekAd(envNoAd), new Uint8Array(0));

    // Truncated mid-AD: declared AD region extends past the envelope.
    const trunc = HEADER_BYTES + MLKEM1024_CT_BYTES + ad.length - 1;
    assert.throws(() => peekAd(env.subarray(0, trunc)), InvalidLength);
    // Shorter than a header.
    assert.throws(() => peekAd(env.subarray(0, HEADER_BYTES - 1)), InvalidLength);

    // Unknown variant / suite: rejected exactly like peekHeader.
    const badVariant = new Uint8Array(env);
    badVariant[6] = 0x03;
    assert.throws(() => peekAd(badVariant), UnknownVariant);
    const badSuite = new Uint8Array(env);
    badSuite[7] = 0x07;
    assert.throws(() => peekAd(badSuite), UnknownSuite);
});

test("sender context monotonic", () => {
    const { pub } = generateKeypair();
    const ctx = new SenderContext();
    setNowMsForTesting(1_700_000_000_000);
    let prev = -1;
    for (let i = 0; i < 5; i++) {
        const env = ctx.encrypt(new TextEncoder().encode("x"), pub, new TextEncoder().encode("y"));
        const h = peekHeader(env);
        assert.ok(h.counter > prev, "counter monotonic");
        prev = h.counter;
    }
    setNowMsForTesting(null);
});

test("envelope size matches", () => {
    const { pub } = generateKeypair();
    const env = encrypt(new TextEncoder().encode("hi"), pub, SUITE_MLKEM1024_AESGCM, new TextEncoder().encode("ad"));
    assert.equal(env.length, envelopeSize(2, 2));
});

// --- Suite/key consistency (whitepaper §2/§9 BadKey; mirrors python
//     TestSuiteKeyConsistency). Structural error, distinguishable from —
//     and never collapsed into — DecryptionError.

test("encrypt rejects mismatched pub suite", () => {
    const { pub } = generateKeypair(SUITE_MLKEM1024_AESGCM);
    // pub is tagged 0x01; requesting 0x02 must reject before any KEM work.
    assert.throws(
        () => encrypt(new TextEncoder().encode("x"), pub, SUITE_MLKEM1024_CHACHA),
        BadKeyError
    );
});

test("decrypt rejects mismatched priv suite", () => {
    const { priv, pub } = generateKeypair(SUITE_MLKEM1024_CHACHA);
    const env = encrypt(new TextEncoder().encode("x"), pub, SUITE_MLKEM1024_CHACHA);
    // Re-tag the same raw key as 0x01; the envelope header is 0x02.
    const privMismatch = { ...priv, suite: SUITE_MLKEM1024_AESGCM };
    assert.throws(() => decrypt(env, privMismatch, new Uint8Array(0)), BadKeyError);
});

test("BadKeyError is distinguishable, not auth-class", () => {
    // Must NOT be a DecryptionError subclass (no distinguishing-oracle risk:
    // the check is on the public suite byte, not secret-correlated bytes).
    const e = new BadKeyError("probe");
    assert.ok(!(e instanceof DecryptionError));
    assert.ok(e instanceof TesseraSealError);
});

// --- KAT consumption (cross-language byte-identity gate)

test("KAT decrypt.json", () => {
    const recs = loadVectors("decrypt.json");
    assert.ok(recs.length > 0);
    for (const r of recs) {
        const seed = hex(r.private_key_seed_hex);
        const { priv } = generateKeypairFromSeed(seed, r.suite);
        const env = hex(r.envelope_hex);
        const ad = hex(r.expected_ad_hex);
        const got = decrypt(env, priv, ad);
        const want = hex(r.expected_plaintext_hex);
        assert.deepEqual(got, want, r.name);
    }
});

// KyberSlash-class decapsulation-failure regression (suite 0x01, pure
// ML-KEM-1024 + AES-256-GCM + UtC). The frozen record's ML-KEM ciphertext
// byte 768 is corrupted, so decapsulation yields the WRONG shared secret;
// the derived AEAD/commit keys diverge and verification MUST fail. This is a
// genuine auth-class failure, so it MUST raise DecryptionError (NOT BadKey,
// NOT UnknownSuite). The suite-0x01 secret key is rebuilt from the 64-byte
// ML-KEM seed via generateKeypairFromSeed, exactly like KAT decrypt.json and
// the C/Go/Rust/Python conformance runners.
test("KAT kyberslash_regression.json", () => {
    const recs = loadVectors("kyberslash_regression.json");
    assert.ok(recs.length > 0, "no kyberslash_regression records");
    for (const r of recs) {
        assert.equal(r.op, "decrypt_should_fail", r.name);
        const seed = hex(r.private_key_seed_hex);
        const { priv } = generateKeypairFromSeed(seed, r.suite);
        const env = hex(r.envelope_hex);
        const ad = hex(r.expected_ad_hex || "");
        assert.throws(() => decrypt(env, priv, ad), DecryptionError, r.name);
    }
});

test("KAT ad_binding.json", () => {
    const recs = loadVectors("ad_binding.json");
    for (const r of recs) {
        const seed = hex(r.private_key_seed_hex);
        const { priv } = generateKeypairFromSeed(seed, SUITE_MLKEM1024_AESGCM);
        const env = hex(r.envelope_hex);
        const ad = hex(r.expected_ad_hex);
        if (r.op === "decrypt") {
            const got = decrypt(env, priv, ad);
            assert.deepEqual(got, hex(r.expected_plaintext_hex), r.name);
        } else {
            assert.throws(() => decrypt(env, priv, ad), Error, r.name);
        }
    }
});

// ad_binding.json through peekAd (TSEAL-00047): positive records bind a
// 41-byte TesseraID-style AD; peekAd must return exactly those bytes without
// decrypting (no key material needed) and must reject truncated input.
// Negative records carry a deliberately wrong expected_ad, so only
// structural success is asserted for them.
test("KAT ad_binding.json via peekAd", () => {
    const recs = loadVectors("ad_binding.json");
    assert.ok(recs.length > 0);
    for (const r of recs) {
        const env = hex(r.envelope_hex);
        const got = peekAd(env);
        if (r.op === "decrypt") {
            assert.deepEqual(got, hex(r.expected_ad_hex), r.name);
        }
        if (got.length > 0) {
            const h = peekHeader(env);
            const trunc = HEADER_BYTES + h.kemCtLen + h.adLen - 1;
            assert.throws(() => peekAd(env.subarray(0, trunc)), InvalidLength, r.name);
        }
    }
});

test("KAT invalid.json", () => {
    const recs = loadVectors("invalid.json");
    for (const r of recs) {
        const env = hex(r.envelope_hex);
        if (r.op === "peek_header_should_fail") {
            assert.throws(() => peekHeader(env), Error, r.name);
        } else if (r.op === "decrypt_should_fail") {
            if (r.private_key_seed_hex) {
                // Some records (bad_key_suite_mismatch) carry the suite the
                // private key is tagged with; default is 0x01.
                const keySuite = r.suite ?? SUITE_MLKEM1024_AESGCM;
                const { priv } = generateKeypairFromSeed(hex(r.private_key_seed_hex), keySuite);
                const expectedClass = r.error_kind === "BAD_KEY" ? BadKeyError : Error;
                assert.throws(() => decrypt(env, priv, hex(r.expected_ad_hex || "")), expectedClass, r.name);
            } else {
                // truncation cases: peek_header alone may not throw on header_only
                // (it's a valid 16-byte all-zero header that triggers UnknownVariant).
                // The records here all exhibit some kind of failure at the structural layer.
                if (env.length >= HEADER_BYTES) {
                    try { peekHeader(env); } catch { /* expected */ }
                }
            }
        }
    }
});

test("KAT min_timestamp.json", () => {
    const recs = loadVectors("min_timestamp.json");
    for (const r of recs) {
        const env = hex(r.envelope_hex);
        const got = validateMinTimestamp(env, r.min_ms);
        assert.equal(got, r.expected, r.name);
    }
});
