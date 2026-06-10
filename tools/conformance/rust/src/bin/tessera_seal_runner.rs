//! Rust conformance runner for TesseraSeal KAT vectors.
//! Usage: tessera_seal_runner <vectors.json>

use std::env;
use std::fs;
use std::process::ExitCode;

use tessera_seal::{
    decrypt, generate_keypair_from_seed, peek_header, validate_min_timestamp,
    Error, SUITE_MLKEM1024_AESGCM,
};
use serde::Deserialize;
use serde_json::Value;

/// Outcome of one record: pass, fail-with-detail, or skip-with-reason.
enum Outcome {
    Pass,
    Fail(String),
    Skip(&'static str),
}

/// Map the Rust error taxonomy to the vector schema's error_kind enum
/// (TESS-00007 / TP-022). The harness asserts this per should-fail record so
/// the normative BAD_KEY-vs-auth-class distinction is mechanically enforced.
fn error_kind(e: &Error) -> &'static str {
    match e {
        Error::UnknownVariant(_) => "UNKNOWN_VARIANT",
        Error::UnknownSuite(_) => "UNKNOWN_SUITE",
        Error::InvalidLength(_) => "INVALID_LEN",
        Error::BadKey(_) => "BAD_KEY",
        Error::DecryptFailed => "DECRYPT_FAILED",
        Error::Internal(_) => "<unmapped Internal>",
    }
}

/// Assert the record's error_kind against the observed error (no-op when the
/// vector carries no error_kind).
fn check_error_kind(r: &Record, e: &Error) -> Outcome {
    match &r.error_kind {
        None => Outcome::Pass,
        Some(want) => {
            let got = error_kind(e);
            if got == want {
                Outcome::Pass
            } else {
                Outcome::Fail(format!("error_kind got={} want={}", got, want))
            }
        }
    }
}

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
    error_kind: Option<String>,
    #[serde(default)]
    expected: Option<Value>,
}

fn unhex(s: &Option<String>) -> Vec<u8> {
    match s {
        Some(h) if !h.is_empty() => hex::decode(h).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn run_decrypt(r: &Record, should_fail: bool) -> Outcome {
    let seed = unhex(&r.private_key_seed_hex);
    // 64 bytes = ML-KEM-1024 seed (suites 0x01/0x02); 96 bytes = hybrid seed
    // (ML-KEM seed || X25519 scalar) for suite 0x06.
    if seed.len() != 64 && seed.len() != 96 {
        return Outcome::Fail("bad private_key_seed_hex length".to_string());
    }
    let suite = r.suite.unwrap_or(SUITE_MLKEM1024_AESGCM);
    let (priv_k, _) = match generate_keypair_from_seed(&seed, suite) {
        Ok(t) => t,
        Err(_) => return Outcome::Fail("keygen from seed failed".to_string()),
    };
    let env = unhex(&r.envelope_hex);
    let ad = unhex(&r.expected_ad_hex);
    let result = decrypt(&env, &priv_k, &ad);
    if should_fail {
        return match result {
            Ok(_) => Outcome::Fail("expected failure, got success".to_string()),
            Err(e) => check_error_kind(r, &e),
        };
    }
    match result {
        Ok(pt) if pt == unhex(&r.expected_plaintext_hex) => Outcome::Pass,
        Ok(_) => Outcome::Fail("plaintext mismatch".to_string()),
        Err(e) => Outcome::Fail(format!("decrypt error: {}", e)),
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

fn run_peek_header_should_fail(r: &Record) -> Outcome {
    let env = unhex(&r.envelope_hex);
    match peek_header(&env) {
        Ok(_) => Outcome::Fail("peek succeeded, expected failure".to_string()),
        Err(e) => check_error_kind(r, &e),
    }
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

fn bool_outcome(ok: bool, what: &str) -> Outcome {
    if ok {
        Outcome::Pass
    } else {
        Outcome::Fail(what.to_string())
    }
}

fn dispatch(r: &Record) -> Outcome {
    match r.op.as_str() {
        "decrypt" => run_decrypt(r, false),
        "decrypt_should_fail" => {
            if r.private_key_seed_hex.is_none() {
                // truncation cases — peek alone exposes the failure
                let env = unhex(&r.envelope_hex);
                match peek_header(&env) {
                    Ok(_) => Outcome::Fail("peek succeeded, expected failure".to_string()),
                    Err(e) => check_error_kind(r, &e),
                }
            } else {
                run_decrypt(r, true)
            }
        }
        "peek_header" => bool_outcome(run_peek_header(r), "peek_header mismatch"),
        "peek_header_should_fail" => run_peek_header_should_fail(r),
        "utc_commit" => bool_outcome(run_utc_commit(r), "commit mismatch"),
        "validate_min_timestamp" => {
            if r.envelope_hex.is_some() {
                bool_outcome(run_validate_min_timestamp(r), "min_timestamp mismatch")
            } else {
                Outcome::Skip("TesseraID-shape validate_min_timestamp")
            }
        }
        _ => Outcome::Skip("unsupported op"),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: tessera_seal_runner <vectors.json>");
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
        // 'doc' pseudo-records are documentation, not executable tests. Emit an
        // explicit SKIP line so the harness can reconcile record counts (TP-021).
        if r.name == "doc" {
            println!("SKIP {} (doc pseudo-record)", r.name);
            continue;
        }
        match dispatch(r) {
            Outcome::Pass => println!("PASS {}", r.name),
            Outcome::Fail(detail) => {
                println!("FAIL {} {}", r.name, detail);
                fails += 1;
            }
            Outcome::Skip(reason) => println!("SKIP {} ({})", r.name, reason),
        }
    }
    if fails > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS }
}
