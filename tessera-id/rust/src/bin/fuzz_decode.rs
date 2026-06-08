//! Rust decoder fuzz harness.
//!
//! Drives randomized bytes / strings into TesseraId::from_bytes, from_base64url,
//! and from_crockford for ITERS iterations and asserts:
//!   1. Decoders either succeed OR return Err(...). They MUST NOT panic.
//!   2. On success, encoding and re-decoding round-trips.
//!   3. Deterministically-constructed valid TesseraIDs always decode.
//!
//! Usage: cargo run --release --bin fuzz_decode -- [ITERS]
//! ITERS defaults to 200_000.

use std::env;
use std::process::ExitCode;

use tessera_id::{TesseraId, SIZE_BYTES, ENCODED_LEN_B64, ENCODED_LEN_B32, VARIANT_STANDARD, VARIANT_HLC};

const B64_ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const CR_ALPHA: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOilo";

// Tiny xoshiro128**-style PRNG, deterministic, no third-party crate.
struct Rng { s: [u32; 4] }

impl Rng {
    fn new(seed: u64) -> Self {
        let lo = seed as u32;
        let hi = (seed >> 32) as u32;
        Rng { s: [lo, hi, lo.wrapping_mul(0x9E3779B9), hi.wrapping_mul(0x85EBCA77)] }
    }
    fn next(&mut self) -> u32 {
        let result = self.s[0].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1].wrapping_shl(9);
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(11);
        result
    }
    fn range(&mut self, n: u32) -> u32 { if n == 0 { 0 } else { self.next() % n } }
    fn byte(&mut self) -> u8 { self.next() as u8 }
    fn bytes(&mut self, n: usize) -> Vec<u8> { (0..n).map(|_| self.byte()).collect() }
}

fn fuzz_binary(rng: &mut Rng) {
    let len = if rng.range(10) < 7 { SIZE_BYTES } else { rng.range(97) as usize };
    let buf = rng.bytes(len);
    if let Ok(p) = TesseraId::from_bytes(&buf) {
        let s64 = p.to_base64url();
        assert_eq!(TesseraId::from_base64url(&s64).expect("re-decode b64").as_bytes(), p.as_bytes());
        let s32 = p.to_crockford();
        assert_eq!(TesseraId::from_crockford(&s32).expect("re-decode crockford").as_bytes(), p.as_bytes());
    }
}

fn fuzz_b64(rng: &mut Rng) {
    let len = if rng.range(10) < 7 { ENCODED_LEN_B64 } else { rng.range(97) as usize };
    let s: String = (0..len).map(|_| B64_ALPHA[rng.range(B64_ALPHA.len() as u32) as usize] as char).collect();
    if let Ok(p) = TesseraId::from_base64url(&s) {
        assert_eq!(p.to_base64url(), s, "b64 not bijective on {:?}", s);
    }
}

fn fuzz_crockford(rng: &mut Rng) {
    let len = if rng.range(10) < 7 { ENCODED_LEN_B32 } else { rng.range(97) as usize };
    let s: String = (0..len).map(|_| CR_ALPHA[rng.range(CR_ALPHA.len() as u32) as usize] as char).collect();
    if let Ok(p) = TesseraId::from_crockford(&s) {
        // Canonical form is uppercase; the input may use confusables/lowercase.
        let canonical = p.to_crockford();
        let p2 = TesseraId::from_crockford(&canonical).expect("re-decode canonical");
        assert_eq!(p.as_bytes(), p2.as_bytes());
    }
}

fn fuzz_valid(rng: &mut Rng) {
    let ts: i64 = (((rng.next() as i64) << 16) | (rng.next() as i64 & 0xFFFF)) & ((1i64 << 48) - 1);
    let variant = if rng.byte() & 1 == 0 { VARIANT_STANDARD } else { VARIANT_HLC };
    let counter = (rng.next() & 0xFFFF) as u16;
    let mut raw = [0u8; SIZE_BYTES];
    raw[0] = (ts >> 40) as u8;
    raw[1] = (ts >> 32) as u8;
    raw[2] = (ts >> 24) as u8;
    raw[3] = (ts >> 16) as u8;
    raw[4] = (ts >> 8) as u8;
    raw[5] = ts as u8;
    raw[6] = variant;
    raw[7] = (counter >> 8) as u8;
    raw[8] = counter as u8;
    for i in 9..SIZE_BYTES { raw[i] = rng.byte(); }
    let p = TesseraId::from_bytes(&raw).expect("constructed TesseraID must decode");
    assert_eq!(p.variant(), variant);
    assert_eq!(p.timestamp_ms(), ts);
    assert_eq!(p.counter(), counter);
}

fn main() -> ExitCode {
    let iters: usize = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let seed: u64 = env::var("TESSERA_ID_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(20260519);
    let mut rng = Rng::new(seed);
    println!("fuzz_decode: ITERS={} SEED={}", iters, seed);
    for i in 0..iters {
        fuzz_binary(&mut rng);
        fuzz_b64(&mut rng);
        fuzz_crockford(&mut rng);
        fuzz_valid(&mut rng);
        if i % 10_000 == 0 && i > 0 {
            println!("  {} iterations OK", i);
        }
    }
    println!("OK: {} iterations × 4 cases = {} ops", iters, iters * 4);
    ExitCode::from(0)
}
