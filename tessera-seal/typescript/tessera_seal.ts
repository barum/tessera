/**
 * TesseraSeal v1 — TypeScript reference implementation.
 *
 * Pure post-quantum encryption envelope: ML-KEM-1024 + AES-256-GCM (or
 * ChaCha20-Poly1305) + a 32-byte UtC commitment tag, with deterministic
 * AEAD nonce derived via HKDF-SHA3-256.
 *
 * Authority order: whitepaper -> python/tessera_seal.py -> c/tessera_seal.h ->
 * THIS MODULE. Cross-language KAT vectors live under ../conformance/vectors/.
 *
 * Uses Paul Miller's noble libraries:
 *   - @noble/post-quantum for ML-KEM-1024
 *   - @noble/ciphers for AES-256-GCM and ChaCha20-Poly1305
 *   - @noble/hashes for SHA3-256, SHAKE-256, HMAC-SHA3-256, HKDF-SHA3-256
 *
 * No "Kyber" naming leaks: ml_kem1024 from noble is re-exported as MlKem1024.
 */

import { randomBytes } from "node:crypto";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { shake256, sha3_256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";

export const MLKem1024 = ml_kem1024;

// --- Constants (must match python/tessera_seal.py and c/tessera_seal.h byte-for-byte)

export const TESSERA_SEAL_VARIANT = 0x04 as const;
export const SUITE_MLKEM1024_AESGCM = 0x01 as const;
export const SUITE_MLKEM1024_CHACHA = 0x02 as const;
export const HEADER_BYTES = 16 as const;
export const MLKEM1024_PK_BYTES = 1568 as const;
export const MLKEM1024_SK_BYTES = 3168 as const;
export const MLKEM1024_CT_BYTES = 1568 as const;
export const MLKEM1024_SS_BYTES = 32 as const;
export const MLKEM1024_SEED_BYTES = 64 as const;
export const AEAD_NONCE_BYTES = 12 as const;
export const AEAD_TAG_BYTES = 16 as const;
export const COMMIT_BYTES = 32 as const;
export const MAX_KEM_CT_LEN = 4096 as const;
export const MAX_AD_LEN = 65_536 as const;
export const MAX_PLAINTEXT = 4 * 1024 * 1024 * 1024;

const TS_BYTES = 6;
const VARIANT_OFFSET = 6;
const SUITE_OFFSET = 7;
const CTR_OFFSET = 8;
const CTR_BYTES = 2;
const KEM_CT_LEN_OFFSET = 10;
const KEM_CT_LEN_BYTES = 2;
const AD_LEN_OFFSET = 12;
const AD_LEN_BYTES = 4;

// frozen v1 wire tags — not rebrandable names. These domain-separation labels
// are hashed INTO the envelope; changing the literal text breaks every vector.
const SALT_LABEL = new TextEncoder().encode("pqcrypt v1 header");
const INFO_AEAD_KEY = new TextEncoder().encode("pqcrypt v1 aead k");
const INFO_AEAD_NONCE = new TextEncoder().encode("pqcrypt v1 aead n");
const INFO_COMMIT_KEY = new TextEncoder().encode("pqcrypt v1 commit");
const INFO_TIMING_PAD = new TextEncoder().encode("pqcrypt v1 timing pad");

// --- Errors

export class TesseraSealError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "TesseraSealError";
    }
}
export class UnknownVariant extends TesseraSealError {
    constructor(b: number) {
        super(`unknown variant byte 0x${b.toString(16).padStart(2, "0")}`);
        this.name = "UnknownVariant";
    }
}
export class UnknownSuite extends TesseraSealError {
    constructor(b: number) {
        super(`unknown suite byte 0x${b.toString(16).padStart(2, "0")}`);
        this.name = "UnknownSuite";
    }
}
export class InvalidLength extends TesseraSealError {
    constructor(message: string) {
        super(message);
        this.name = "InvalidLength";
    }
}
/**
 * Suite/key consistency failure (whitepaper §2, §9 — BAD_KEY).
 *
 * Thrown when encrypt() is given a recipient public key whose suite tag
 * does not match the requested suite, or when decrypt() is given a
 * private key whose suite tag does not match the envelope header's suite.
 * This is a **structural** error, caught before the authentication-class
 * path. It is intentionally distinguishable from DecryptionError (no
 * oracle merge): the check is on the public suite byte, not on
 * secret-correlated bytes.
 */
export class BadKeyError extends TesseraSealError {
    constructor(message: string) {
        super(message);
        this.name = "BadKeyError";
    }
}
/**
 * Single class for every authentication-class failure: bad AEAD tag,
 * bad UtC commit tag, bad KEM ciphertext, AD mismatch, derived-nonce
 * mismatch. The decrypt path is constant-time across these.
 */
export class DecryptionError extends TesseraSealError {
    constructor() {
        super("envelope failed authentication");
        this.name = "DecryptionError";
    }
}

// --- Clock override (KAT determinism only)

let nowMsOverride: number | null = null;
export function setNowMsForTesting(value: number | null): void {
    nowMsOverride = value;
}
function nowMs(): number {
    return nowMsOverride !== null ? nowMsOverride : Date.now();
}

// --- Suite check

function checkSuite(suite: number): void {
    if (suite !== SUITE_MLKEM1024_AESGCM && suite !== SUITE_MLKEM1024_CHACHA) {
        throw new UnknownSuite(suite);
    }
}

// --- Keys (opaque wrappers)

export interface PublicKey {
    bytes: Uint8Array;
    suite: number;
}

export interface PrivateKey {
    bytes: Uint8Array;      // 3168-byte expanded form (FIPS 203)
    seed: Uint8Array;       // 64-byte (d || z) — kept for KAT round-trips
    suite: number;
}

export function generateKeypair(suite: number = SUITE_MLKEM1024_AESGCM): { priv: PrivateKey; pub: PublicKey } {
    checkSuite(suite);
    const seed = randomBytes(MLKEM1024_SEED_BYTES);
    return generateKeypairFromSeed(seed, suite);
}

export function generateKeypairFromSeed(
    seed: Uint8Array,
    suite: number = SUITE_MLKEM1024_AESGCM
): { priv: PrivateKey; pub: PublicKey } {
    checkSuite(suite);
    if (seed.length !== MLKEM1024_SEED_BYTES) {
        throw new TesseraSealError(`seed must be ${MLKEM1024_SEED_BYTES} bytes`);
    }
    const { secretKey, publicKey } = MLKem1024.keygen(seed);
    return {
        priv: { bytes: secretKey, seed: new Uint8Array(seed), suite },
        pub: { bytes: publicKey, suite },
    };
}

export function publicKeyFromBytes(pk: Uint8Array, suite: number = SUITE_MLKEM1024_AESGCM): PublicKey {
    checkSuite(suite);
    if (pk.length !== MLKEM1024_PK_BYTES) {
        throw new TesseraSealError(`public key must be ${MLKEM1024_PK_BYTES} bytes`);
    }
    return { bytes: new Uint8Array(pk), suite };
}

// --- Header pack/unpack

export interface DecodedHeader {
    timestampMs: number;
    variant: number;
    suite: number;
    counter: number;
    kemCtLen: number;
    adLen: number;
}

function packHeader(out: Uint8Array, tsMs: number, variant: number, suite: number,
                    counter: number, kemCtLen: number, adLen: number): void {
    // 48-bit big-endian timestamp; we use BigInt to avoid >32-bit precision issues.
    const ts = BigInt(tsMs);
    out[0] = Number((ts >> 40n) & 0xffn);
    out[1] = Number((ts >> 32n) & 0xffn);
    out[2] = Number((ts >> 24n) & 0xffn);
    out[3] = Number((ts >> 16n) & 0xffn);
    out[4] = Number((ts >> 8n) & 0xffn);
    out[5] = Number(ts & 0xffn);
    out[6] = variant;
    out[7] = suite;
    out[8] = (counter >>> 8) & 0xff;
    out[9] = counter & 0xff;
    out[10] = (kemCtLen >>> 8) & 0xff;
    out[11] = kemCtLen & 0xff;
    out[12] = (adLen >>> 24) & 0xff;
    out[13] = (adLen >>> 16) & 0xff;
    out[14] = (adLen >>> 8) & 0xff;
    out[15] = adLen & 0xff;
}

function unpackHeader(input: Uint8Array): DecodedHeader {
    const ts =
        (BigInt(input[0]!) << 40n) |
        (BigInt(input[1]!) << 32n) |
        (BigInt(input[2]!) << 24n) |
        (BigInt(input[3]!) << 16n) |
        (BigInt(input[4]!) << 8n) |
        BigInt(input[5]!);
    return {
        timestampMs: Number(ts),
        variant: input[6]!,
        suite: input[7]!,
        counter: (input[8]! << 8) | input[9]!,
        kemCtLen: (input[10]! << 8) | input[11]!,
        adLen:
            (input[12]! * 0x1000000) +
            ((input[13]! << 16) | (input[14]! << 8) | input[15]!),
    };
}

export function peekHeader(env: Uint8Array): DecodedHeader {
    if (env.length < HEADER_BYTES) throw new InvalidLength("envelope shorter than header");
    const h = unpackHeader(env);
    if (h.variant !== TESSERA_SEAL_VARIANT) throw new UnknownVariant(h.variant);
    if (h.suite !== SUITE_MLKEM1024_AESGCM && h.suite !== SUITE_MLKEM1024_CHACHA) {
        throw new UnknownSuite(h.suite);
    }
    if (h.kemCtLen > MAX_KEM_CT_LEN) throw new InvalidLength(`kem_ct_len ${h.kemCtLen}`);
    if (h.adLen > MAX_AD_LEN) throw new InvalidLength(`ad_len ${h.adLen}`);
    return h;
}

/**
 * Returns a copy of the cleartext-on-wire associated-data bytes WITHOUT
 * decrypting — the routing-before-decrypt companion to peekHeader()
 * (TSEAL-00047). The canonical use case is the TesseraID-as-AD pattern:
 * route an envelope by the 41-byte TesseraID it is bound to, then decrypt.
 *
 * WARNING: the returned bytes are UNAUTHENTICATED until decrypt()
 * succeeds — every byte is attacker-controlled. Use them only for
 * routing/lookup; never act on them as trusted data.
 *
 * Rejects exactly what peekHeader() rejects (unknown variant/suite, bad
 * declared lengths) plus InvalidLength when the declared AD region extends
 * past the envelope (truncated input).
 */
export function peekAd(env: Uint8Array): Uint8Array {
    const h = peekHeader(env);
    const start = HEADER_BYTES + h.kemCtLen;
    const end = start + h.adLen;
    if (env.length < end) throw new InvalidLength("ad region extends past envelope end");
    return env.slice(start, end);
}

export function validate(env: Uint8Array): boolean {
    try {
        const h = peekHeader(env);
        const need = HEADER_BYTES + h.kemCtLen + h.adLen + AEAD_NONCE_BYTES + AEAD_TAG_BYTES + COMMIT_BYTES;
        return env.length >= need;
    } catch {
        return false;
    }
}

export function validateMinTimestamp(env: Uint8Array, minMs: number): boolean {
    try {
        const h = peekHeader(env);
        return h.timestampMs >= minMs;
    } catch {
        return false;
    }
}

export function envelopeSize(ptLen: number, adLen: number): number {
    return HEADER_BYTES + MLKEM1024_CT_BYTES + adLen + AEAD_NONCE_BYTES + ptLen + AEAD_TAG_BYTES + COMMIT_BYTES;
}

// --- KDF schedule

function concat(...parts: Uint8Array[]): Uint8Array {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}

interface SessionKeys {
    kAead: Uint8Array;
    nonce: Uint8Array;
    kCommit: Uint8Array;
}

function deriveSessionKeys(headerBytes: Uint8Array, ssMLKEM: Uint8Array): SessionKeys {
    const salt = shake256(concat(SALT_LABEL, headerBytes), { dkLen: 32 });
    const kAead = hkdf(sha3_256, ssMLKEM, salt, INFO_AEAD_KEY, 32);
    const nonce = hkdf(sha3_256, ssMLKEM, salt, INFO_AEAD_NONCE, AEAD_NONCE_BYTES);
    const kCommit = hkdf(sha3_256, ssMLKEM, salt, INFO_COMMIT_KEY, 32);
    return { kAead, nonce, kCommit };
}

function deriveSyntheticKeys(headerBytes: Uint8Array): SessionKeys {
    const saltInput = concat(SALT_LABEL, headerBytes, INFO_TIMING_PAD);
    const salt = shake256(saltInput, { dkLen: 32 });
    const zero = new Uint8Array(32);
    return {
        kAead: hkdf(sha3_256, zero, salt, INFO_AEAD_KEY, 32),
        nonce: hkdf(sha3_256, zero, salt, INFO_AEAD_NONCE, AEAD_NONCE_BYTES),
        kCommit: hkdf(sha3_256, zero, salt, INFO_COMMIT_KEY, 32),
    };
}

// --- AEAD dispatch

function aeadEncrypt(suite: number, key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad: Uint8Array): Uint8Array {
    if (suite === SUITE_MLKEM1024_AESGCM) {
        return gcm(key, nonce, aad).encrypt(pt);
    } else if (suite === SUITE_MLKEM1024_CHACHA) {
        return chacha20poly1305(key, nonce, aad).encrypt(pt);
    }
    throw new UnknownSuite(suite);
}

function aeadDecrypt(suite: number, key: Uint8Array, nonce: Uint8Array, ctTag: Uint8Array, aad: Uint8Array): Uint8Array | null {
    try {
        if (suite === SUITE_MLKEM1024_AESGCM) {
            return gcm(key, nonce, aad).decrypt(ctTag);
        } else if (suite === SUITE_MLKEM1024_CHACHA) {
            return chacha20poly1305(key, nonce, aad).decrypt(ctTag);
        }
    } catch {
        return null;
    }
    return null;
}

// --- UtC commit

function utcCommit(kCommit: Uint8Array, header: Uint8Array, kemCt: Uint8Array, ad: Uint8Array, aeadCt: Uint8Array): Uint8Array {
    return hmac(sha3_256, kCommit, concat(header, kemCt, ad, aeadCt));
}

// --- Constant-time compare

function ctEq(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        // Run an equal-length compare to itself to keep timing flat.
        let d = 0;
        for (let i = 0; i < a.length; i++) d |= a[i]! ^ a[i]!;
        void d;
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
    return diff === 0;
}

// --- Encrypt

export function encrypt(
    pt: Uint8Array,
    recipientPub: PublicKey,
    suite: number = SUITE_MLKEM1024_AESGCM,
    ad: Uint8Array = new Uint8Array(0),
    tsMs: number | null = null,
    counter: number = 0
): Uint8Array {
    checkSuite(suite);
    // Suite/key consistency (whitepaper §2, §9). Reject a recipient key whose
    // suite tag does not match the requested suite — structural BadKey, before
    // any KEM work. Defends the documented suite-confusion attack.
    if (recipientPub.suite !== suite) {
        throw new BadKeyError(
            `recipient public key suite 0x${recipientPub.suite.toString(16).padStart(2, "0")} ` +
            `!= requested suite 0x${suite.toString(16).padStart(2, "0")}`
        );
    }
    if (ad.length > MAX_AD_LEN) throw new InvalidLength("ad too large");
    if (pt.length > MAX_PLAINTEXT) throw new InvalidLength("pt too large");
    const ts = tsMs === null ? nowMs() : tsMs;
    if (ts >= 2 ** 48) throw new InvalidLength("ts overflow");

    // ML-KEM-1024 Encaps
    const { cipherText, sharedSecret } = MLKem1024.encapsulate(recipientPub.bytes);
    if (cipherText.length !== MLKEM1024_CT_BYTES || sharedSecret.length !== MLKEM1024_SS_BYTES) {
        throw new TesseraSealError("ML-KEM produced unexpected sizes");
    }

    // Header
    const header = new Uint8Array(HEADER_BYTES);
    packHeader(header, ts, TESSERA_SEAL_VARIANT, suite, counter, MLKEM1024_CT_BYTES, ad.length);

    const sk = deriveSessionKeys(header, sharedSecret);

    // AEAD AAD = header || kem_ct || ad
    const aad = concat(header, cipherText, ad);
    const aeadBlob = aeadEncrypt(suite, sk.kAead, sk.nonce, pt, aad);
    const aeadCt = aeadBlob.subarray(0, pt.length);
    const aeadTag = aeadBlob.subarray(pt.length);

    const commit = utcCommit(sk.kCommit, header, cipherText, ad, aeadCt);

    return concat(header, cipherText, ad, sk.nonce, aeadCt, aeadTag, commit);
}

// --- Decrypt

export function decrypt(env: Uint8Array, priv: PrivateKey, expectedAd: Uint8Array): Uint8Array {
    if (env.length < HEADER_BYTES) throw new InvalidLength("short");
    const h = peekHeader(env);
    // Suite/key consistency (whitepaper §2, §9). Reject a private key whose
    // suite tag does not match the envelope header's suite — structural BadKey,
    // before any KEM/AEAD work. Distinguishable-but-safe: the check is on the
    // public suite byte, not on secret-correlated bytes.
    if (priv.suite !== h.suite) {
        throw new BadKeyError(
            `private key suite 0x${priv.suite.toString(16).padStart(2, "0")} ` +
            `!= envelope header suite 0x${h.suite.toString(16).padStart(2, "0")}`
        );
    }
    const need = HEADER_BYTES + h.kemCtLen + h.adLen + AEAD_NONCE_BYTES + AEAD_TAG_BYTES + COMMIT_BYTES;
    if (env.length < need) throw new InvalidLength("truncated");
    const aeadCtLen = env.length - need;

    const headerBytes = env.subarray(0, HEADER_BYTES);
    let p = HEADER_BYTES;
    const kemCt = env.subarray(p, p + h.kemCtLen); p += h.kemCtLen;
    const ad = env.subarray(p, p + h.adLen); p += h.adLen;
    const nonceWire = env.subarray(p, p + AEAD_NONCE_BYTES); p += AEAD_NONCE_BYTES;
    const aeadCt = env.subarray(p, p + aeadCtLen); p += aeadCtLen;
    const aeadTag = env.subarray(p, p + AEAD_TAG_BYTES); p += AEAD_TAG_BYTES;
    const commitWire = env.subarray(p, p + COMMIT_BYTES);

    // ML-KEM Decaps. FO transform implicit-rejects on bad ct -> pseudorandom ss.
    let ssMLKEM: Uint8Array;
    let ssOk = true;
    try {
        ssMLKEM = MLKem1024.decapsulate(kemCt, priv.bytes);
    } catch {
        ssOk = false;
        ssMLKEM = new Uint8Array(MLKEM1024_SS_BYTES);
    }
    const sk = deriveSessionKeys(headerBytes, ssMLKEM);

    const nonceMatch = ctEq(nonceWire, sk.nonce);
    const adMatch = ad.length === expectedAd.length
        ? ctEq(ad, expectedAd)
        : (ctEq(ad, ad), false);

    const expectedCommit = utcCommit(sk.kCommit, headerBytes, kemCt, ad, aeadCt);
    const commitMatch = ctEq(commitWire, expectedCommit);

    const aad = concat(headerBytes, kemCt, ad);
    const ctTag = concat(aeadCt, aeadTag);
    const pt = aeadDecrypt(h.suite, sk.kAead, nonceWire, ctTag, aad);
    const aeadOk = pt !== null;

    if (ssOk && nonceMatch && adMatch && commitMatch && aeadOk) {
        return pt!;
    }
    // Synthetic-key timing pad
    deriveSyntheticKeys(headerBytes);
    throw new DecryptionError();
}

// --- Sender context

export class SenderContext {
    private lastTs = 0;
    private counter = 0;
    constructor(public readonly suite: number = SUITE_MLKEM1024_AESGCM) {
        checkSuite(suite);
    }
    private nextTsCtr(): [number, number] {
        const now = nowMs();
        if (now > this.lastTs) {
            this.lastTs = now;
            this.counter = 0;
        } else {
            this.counter = (this.counter + 1) & 0xffff;
            if (this.counter === 0) this.lastTs += 1;
        }
        return [this.lastTs, this.counter];
    }
    encrypt(pt: Uint8Array, pub: PublicKey, ad: Uint8Array = new Uint8Array(0)): Uint8Array {
        const [ts, ctr] = this.nextTsCtr();
        return encrypt(pt, pub, this.suite, ad, ts, ctr);
    }
}
