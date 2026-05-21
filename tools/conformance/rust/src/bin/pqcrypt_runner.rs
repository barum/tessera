//! Rust conformance runner for PQCrypt KAT vectors.
//! Usage: pqcrypt_runner <vectors.json>

use std::env;
use std::fs;
use std::process::ExitCode;

use pqcrypt::{
    decrypt, generate_keypair_from_seed, peek_header, validate_min_timestamp,
    SUITE_MLKEM1024_AESGCM,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Debug)]
struct Record {
    name: String,
    op: String,
    #[serde(default)]
    suite: Option<u8>,
    #[serde(default)]
    private_key_seed_hex: Option<String>,
    #[serde(default)]
    envelope_hex: Option<String>,
    #[serde(default)]
    header_hex: Option<String>,
    #[serde(default)]
    expected_ad_hex: Option<String>,
    #[serde(default)]
    expected_plaintext_hex: Option<String>,
    #[serde(default)]
    expected_commit_hex: Option<String>,
    #[serde(default)]
    k_commit_hex: Option<String>,
    #[serde(default)]
    kem_ct_hex: Option<String>,
    #[serde(default)]
    ad_hex: Option<String>,
    #[serde(default)]
    aead_ct_hex: Option<String>,
    #[serde(default)]
    min_ms: Option<u64>,
    #[serde(default)]
    expected: Option<Value>,
}

fn unhex(s: &Option<String>) -> Vec<u8> {
    match s {
        Some(h) if !h.is_empty() => hex::decode(h).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn run_decrypt(r: &Record, should_fail: bool) -> bool {
    let seed = unhex(&r.private_key_seed_hex);
    if seed.len() != 64 {
        return false;
    }
    let suite = r.suite.unwrap_or(SUITE_MLKEM1024_AESGCM);
    let (priv_k, _) = match generate_keypair_from_seed(&seed, suite) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let env = unhex(&r.envelope_hex);
    let ad = unhex(&r.expected_ad_hex);
    let result = decrypt(&env, &priv_k, &ad);
    if should_fail {
        return result.is_err();
    }
    match result {
        Ok(pt) => pt == unhex(&r.expected_plaintext_hex),
        Err(_) => false,
    }
}

fn run_peek_header(r: &Record) -> bool {
    let hdr = unhex(&r.header_hex);
    if hdr.len() < 16 {
        return false;
    }
    let mut padded = vec![0u8; 16 + 1700];
    padded[..16].copy_from_slice(&hdr[..16]);
    let h = match peek_header(&padded) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let exp = match &r.expected {
        Some(Value::Object(m)) => m,
        _ => return false,
    };
    let check = |k: &str, got: u64| -> bool {
        exp.get(k).and_then(|v| v.as_u64()).map(|w| w == got).unwrap_or(false)
    };
    check("timestamp_ms", h.timestamp_ms)
        && check("variant", h.variant as u64)
        && check("suite", h.suite as u64)
        && check("counter", h.counter as u64)
        && check("kem_ct_len", h.kem_ct_len as u64)
        && check("ad_len", h.ad_len as u64)
}

fn run_peek_header_should_fail(r: &Record) -> bool {
    let env = unhex(&r.envelope_hex);
    peek_header(&env).is_err()
}

fn run_utc_commit(r: &Record) -> bool {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_256;
    type HmacSha3_256 = Hmac<Sha3_256>;

    let k = unhex(&r.k_commit_hex);
    let hdr = unhex(&r.header_hex);
    let kem_ct = unhex(&r.kem_ct_hex);
    let ad = unhex(&r.ad_hex);
    let aead_ct = unhex(&r.aead_ct_hex);
    let want = unhex(&r.expected_commit_hex);

    let mut mac = <HmacSha3_256 as hmac::digest::KeyInit>::new_from_slice(&k)
        .expect("HMAC key");
    hmac::Mac::update(&mut mac, &hdr);
    hmac::Mac::update(&mut mac, &kem_ct);
    hmac::Mac::update(&mut mac, &ad);
    hmac::Mac::update(&mut mac, &aead_ct);
    let got = mac.finalize().into_bytes().to_vec();
    got == want
}

fn run_validate_min_timestamp(r: &Record) -> bool {
    let env = unhex(&r.envelope_hex);
    let got = validate_min_timestamp(&env, r.min_ms.unwrap_or(0));
    let want = r.expected.as_ref().and_then(|v| v.as_bool()).unwrap_or(false);
    got == want
}

fn dispatch(r: &Record) -> Option<bool> {
    match r.op.as_str() {
        "decrypt" => Some(run_decrypt(r, false)),
        "decrypt_should_fail" => {
            if r.private_key_seed_hex.is_none() {
                // truncation cases — peek alone exposes the failure
                let env = unhex(&r.envelope_hex);
                Some(peek_header(&env).is_err())
            } else {
                Some(run_decrypt(r, true))
            }
        }
        "peek_header" => Some(run_peek_header(r)),
        "peek_header_should_fail" => Some(run_peek_header_should_fail(r)),
        "utc_commit" => Some(run_utc_commit(r)),
        "validate_min_timestamp" => {
            if r.envelope_hex.is_some() {
                Some(run_validate_min_timestamp(r))
            } else {
                None // PQID-shape; skip
            }
        }
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: pqcrypt_runner <vectors.json>");
        return ExitCode::from(2);
    }
    let raw = match fs::read_to_string(&args[1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read: {}", e);
            return ExitCode::from(2);
        }
    };
    let recs: Vec<Record> = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse: {}", e);
            return ExitCode::from(2);
        }
    };
    let mut fails = 0;
    for r in &recs {
        match dispatch(r) {
            Some(true) => println!("PASS {}", r.name),
            Some(false) => {
                println!("FAIL {}", r.name);
                fails += 1;
            }
            None => {} // skipped silently
        }
    }
    if fails > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS }
}
