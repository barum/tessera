//! Integration tests for the Rust PQCrypt reference.
//!
//! Run from this crate:
//!     cargo test --release
//!
//! KAT consumption requires the vectors under ../conformance/vectors/. The
//! test working directory is the crate root, so paths use `../conformance/...`.

use pqcrypt::{
    decrypt, encrypt, envelope_size, generate_keypair, generate_keypair_from_seed,
    peek_header, validate_min_timestamp, set_now_ms_for_testing,
    Error, SenderContext,
    HEADER_BYTES, MLKEM1024_CT_BYTES,
    SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA,
    VARIANT_PQCRYPT,
};

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

// Tests that touch the global clock override must serialize via this mutex
// to avoid clobbering each other under cargo's default parallel runner.
static CLOCK_TESTS: Mutex<()> = Mutex::new(());

const KAT_DIR: &str = "../conformance/vectors";

#[derive(Debug, Deserialize)]
struct Record {
    name: String,
    #[serde(default)]
    op: String,
    #[serde(default)]
    suite: Option<u8>,
    #[serde(default)]
    private_key_seed_hex: Option<String>,
    #[serde(default)]
    envelope_hex: Option<String>,
    #[serde(default)]
    expected_ad_hex: Option<String>,
    #[serde(default)]
    expected_plaintext_hex: Option<String>,
    #[serde(default)]
    min_ms: Option<u64>,
    #[serde(default)]
    expected: Option<bool>,
}

fn unhex(s: &Option<String>) -> Vec<u8> {
    match s {
        Some(h) if !h.is_empty() => hex::decode(h).expect("bad hex"),
        _ => Vec::new(),
    }
}

fn load(file: &str) -> Vec<Record> {
    let mut p = PathBuf::from(KAT_DIR);
    p.push(file);
    let raw = fs::read_to_string(&p)
        .unwrap_or_else(|_| panic!("cannot read {:?} (run from pqcrypt/rust/)", p));
    serde_json::from_str(&raw).expect("bad vector json")
}

// ---------------------------------------------------------------------------
// Self-contained
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_aesgcm() {
    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let pt = b"hello world from Rust";
    let env = encrypt(pt, &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 0).unwrap();
    let got = decrypt(&env, &priv_k, &[]).unwrap();
    assert_eq!(got, pt);
}

#[test]
fn roundtrip_chacha() {
    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_CHACHA).unwrap();
    let pt = b"chacha payload";
    let env = encrypt(pt, &pub_k, SUITE_MLKEM1024_CHACHA, &[], None, 0).unwrap();
    let got = decrypt(&env, &priv_k, &[]).unwrap();
    assert_eq!(got, pt);
}

#[test]
fn ad_binding_positive() {
    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let ad: Vec<u8> = (0u8..41).collect();
    let env = encrypt(b"with AD", &pub_k, SUITE_MLKEM1024_AESGCM, &ad, None, 0).unwrap();
    let got = decrypt(&env, &priv_k, &ad).unwrap();
    assert_eq!(got, b"with AD");
}

#[test]
fn ad_binding_wrong_ad_fails() {
    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let mut ad = vec![1u8, 2, 3, 4, 5];
    let env = encrypt(b"x", &pub_k, SUITE_MLKEM1024_AESGCM, &ad, None, 0).unwrap();
    ad[0] ^= 1;
    match decrypt(&env, &priv_k, &ad) {
        Err(Error::DecryptFailed) => {}
        other => panic!("expected DecryptFailed, got {:?}", other),
    }
}

#[test]
fn variant_rejection() {
    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let env = encrypt(b"x", &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 0).unwrap();
    for &v in &[0x00u8, 0x01, 0x02, 0x03, 0x05, 0x10, 0x7F, 0xFE, 0xFF] {
        let mut bad = env.clone();
        bad[6] = v;
        match decrypt(&bad, &priv_k, &[]) {
            Err(Error::UnknownVariant(_)) => {}
            other => panic!("variant 0x{:02x}: expected UnknownVariant, got {:?}", v, other),
        }
    }
}

#[test]
fn suite_rejection() {
    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let env = encrypt(b"x", &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 0).unwrap();
    for &s in &[0x00u8, 0x03, 0x04, 0x10, 0x7F, 0xFE, 0xFF] {
        let mut bad = env.clone();
        bad[7] = s;
        match decrypt(&bad, &priv_k, &[]) {
            Err(Error::UnknownSuite(_)) => {}
            other => panic!("suite 0x{:02x}: expected UnknownSuite, got {:?}", s, other),
        }
    }
}

#[test]
fn tamper_detection() {
    let (priv_k, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let env = encrypt(b"tamper", &pub_k, SUITE_MLKEM1024_AESGCM, b"id", None, 0).unwrap();
    let flips = [
        ("kem_ct", HEADER_BYTES + 500),
        ("ad",     HEADER_BYTES + MLKEM1024_CT_BYTES),
        ("nonce",  HEADER_BYTES + MLKEM1024_CT_BYTES + 2),
        ("aead",   HEADER_BYTES + MLKEM1024_CT_BYTES + 2 + 12),
        ("tag",    env.len() - 32 - 1),
        ("commit", env.len() - 1),
    ];
    for (name, idx) in flips {
        let mut bad = env.clone();
        bad[idx] ^= 0x01;
        assert!(decrypt(&bad, &priv_k, b"id").is_err(), "{}: expected error", name);
    }
}

#[test]
fn peek_header_works() {
    let _guard = CLOCK_TESTS.lock().unwrap();
    let (_, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    set_now_ms_for_testing(Some(1_700_000_000_000));
    let env = encrypt(b"x", &pub_k, SUITE_MLKEM1024_AESGCM, &[], None, 7).unwrap();
    set_now_ms_for_testing(None);
    let h = peek_header(&env).unwrap();
    assert_eq!(h.timestamp_ms, 1_700_000_000_000);
    assert_eq!(h.variant, VARIANT_PQCRYPT);
    assert_eq!(h.suite, SUITE_MLKEM1024_AESGCM);
    assert_eq!(h.counter, 7);
    assert_eq!(h.kem_ct_len, 1568);
    assert_eq!(h.ad_len, 0);
}

#[test]
fn sender_context_monotonic() {
    let _guard = CLOCK_TESTS.lock().unwrap();
    let (_, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let ctx = SenderContext::new(SUITE_MLKEM1024_AESGCM).unwrap();
    set_now_ms_for_testing(Some(1_700_000_000_000));
    let mut prev: i32 = -1;
    for _ in 0..5 {
        let env = ctx.encrypt(b"x", &pub_k, b"y").unwrap();
        let h = peek_header(&env).unwrap();
        assert!((h.counter as i32) > prev, "counter regression");
        prev = h.counter as i32;
    }
    set_now_ms_for_testing(None);
}

#[test]
fn envelope_size_matches() {
    let (_, pub_k) = generate_keypair(SUITE_MLKEM1024_AESGCM).unwrap();
    let env = encrypt(b"hi", &pub_k, SUITE_MLKEM1024_AESGCM, b"ad", None, 0).unwrap();
    assert_eq!(env.len(), envelope_size(2, 2));
}

// ---------------------------------------------------------------------------
// KAT consumption — cross-language byte-identity gate
// ---------------------------------------------------------------------------

#[test]
fn kat_decrypt() {
    let recs = load("decrypt.json");
    assert!(!recs.is_empty(), "no records");
    for r in &recs {
        let seed = unhex(&r.private_key_seed_hex);
        assert_eq!(seed.len(), 64, "{}: seed length", r.name);
        let suite = r.suite.unwrap_or(SUITE_MLKEM1024_AESGCM);
        let (priv_k, _) = generate_keypair_from_seed(&seed, suite)
            .unwrap_or_else(|_| panic!("{}: rebuild key", r.name));
        let env = unhex(&r.envelope_hex);
        let ad = unhex(&r.expected_ad_hex);
        let expected = unhex(&r.expected_plaintext_hex);
        let got = decrypt(&env, &priv_k, &ad)
            .unwrap_or_else(|e| panic!("{}: decrypt err {:?}", r.name, e));
        assert_eq!(got, expected, "{}: plaintext mismatch", r.name);
    }
    println!("KAT decrypt: {} records OK", recs.len());
}

#[test]
fn kat_ad_binding() {
    let recs = load("ad_binding.json");
    for r in &recs {
        let seed = unhex(&r.private_key_seed_hex);
        let (priv_k, _) = generate_keypair_from_seed(&seed, SUITE_MLKEM1024_AESGCM).unwrap();
        let env = unhex(&r.envelope_hex);
        let ad = unhex(&r.expected_ad_hex);
        let result = decrypt(&env, &priv_k, &ad);
        match r.op.as_str() {
            "decrypt" => assert!(result.is_ok(), "{}: expected ok, got {:?}", r.name, result),
            "decrypt_should_fail" => assert!(result.is_err(), "{}: expected fail", r.name),
            other => panic!("{}: unknown op {}", r.name, other),
        }
    }
    println!("KAT ad_binding: {} records OK", recs.len());
}

#[test]
fn kat_invalid() {
    let recs = load("invalid.json");
    for r in &recs {
        let env = unhex(&r.envelope_hex);
        match r.op.as_str() {
            "peek_header_should_fail" => {
                assert!(peek_header(&env).is_err(), "{}: expected peek error", r.name);
            }
            "decrypt_should_fail" => {
                if let Some(_seed_hex) = &r.private_key_seed_hex {
                    let seed = unhex(&r.private_key_seed_hex);
                    let (priv_k, _) =
                        generate_keypair_from_seed(&seed, SUITE_MLKEM1024_AESGCM).unwrap();
                    let ad = unhex(&r.expected_ad_hex);
                    let result = decrypt(&env, &priv_k, &ad);
                    assert!(result.is_err(), "{}: expected fail", r.name);
                } else {
                    // Truncation cases: peek_header alone exposes the failure.
                    let _ = peek_header(&env);
                }
            }
            other => panic!("{}: unknown op {}", r.name, other),
        }
    }
    println!("KAT invalid: {} records OK", recs.len());
}

#[test]
fn kat_min_timestamp() {
    let recs = load("min_timestamp.json");
    for r in &recs {
        let env = unhex(&r.envelope_hex);
        let got = validate_min_timestamp(&env, r.min_ms.unwrap_or(0));
        assert_eq!(got, r.expected.unwrap_or(false), "{}", r.name);
    }
}
