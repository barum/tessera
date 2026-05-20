//! Rust conformance runner. Usage: conformance_runner <vectors.json>

use std::env;
use std::fs;
use std::process::ExitCode;

use pqid::{
    set_now_ms_for_testing, HlcGenerator, Pqid, VARIANT_HLC, SIZE_BYTES,
};
use pqid::pqhash::{self, Pqhash, PQHASH_SIZE_BYTES};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Record {
    name: String,
    op: String,
    #[serde(default)]
    input_hex: Option<String>,
    #[serde(default)]
    input_str: Option<String>,
    #[serde(default)]
    input_kind: Option<String>,
    #[serde(default)]
    expected_hex: Option<String>,
    #[serde(default)]
    expected_str: Option<String>,
    #[serde(default)]
    expected: Option<Value>,
    #[serde(default)]
    start: Option<Value>,
    #[serde(default)]
    physical_time_ms: Option<i64>,
    #[serde(default)]
    observe: Option<Value>,
    #[serde(default)]
    expected_tail_hex: Option<String>,
    #[serde(default)]
    content_hex: Option<String>,
}

fn hex_to_arr(s: &str) -> Result<[u8; SIZE_BYTES], String> {
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != SIZE_BYTES {
        return Err(format!("hex len {} != {}", bytes.len(), SIZE_BYTES));
    }
    let mut arr = [0u8; SIZE_BYTES];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn run_decode(r: &Record) -> Result<(), String> {
    let arr = hex_to_arr(r.input_hex.as_ref().unwrap())?;
    let p = Pqid::from_bytes(&arr).map_err(|e| format!("from_bytes: {:?}", e))?;
    let exp = r.expected.as_ref().unwrap();
    let want_variant = exp["variant"].as_i64().unwrap() as u8;
    let want_ts = exp["timestamp_ms"].as_i64().unwrap();
    let want_ctr = exp["counter"].as_i64().unwrap() as u16;
    let want_rand = exp["random_hex"].as_str().unwrap();
    if p.variant() != want_variant {
        return Err(format!("variant got={} want={}", p.variant(), want_variant));
    }
    if p.timestamp_ms() != want_ts {
        return Err(format!("ts got={} want={}", p.timestamp_ms(), want_ts));
    }
    if p.counter() != want_ctr {
        return Err(format!("counter got={} want={}", p.counter(), want_ctr));
    }
    let got_rand = hex::encode(p.random());
    if got_rand != want_rand {
        return Err(format!("random got={} want={}", got_rand, want_rand));
    }
    Ok(())
}

fn run_encode_b64(r: &Record) -> Result<(), String> {
    let arr = hex_to_arr(r.input_hex.as_ref().unwrap())?;
    let p = Pqid(arr);
    let s = p.to_base64url();
    let want = r.expected_str.as_ref().unwrap();
    if &s != want {
        return Err(format!("got={} want={}", s, want));
    }
    Ok(())
}

fn run_decode_b64(r: &Record) -> Result<(), String> {
    let p = Pqid::from_base64url(r.input_str.as_ref().unwrap())
        .map_err(|e| format!("from_base64url: {:?}", e))?;
    let got = hex::encode(p.as_bytes());
    let want = r.expected_hex.as_ref().unwrap();
    if &got != want {
        return Err(format!("got={} want={}", got, want));
    }
    Ok(())
}

fn run_encode_crockford(r: &Record) -> Result<(), String> {
    let arr = hex_to_arr(r.input_hex.as_ref().unwrap())?;
    let p = Pqid(arr);
    let s = p.to_crockford();
    let want = r.expected_str.as_ref().unwrap();
    if &s != want {
        return Err(format!("got={} want={}", s, want));
    }
    Ok(())
}

fn run_decode_crockford(r: &Record) -> Result<(), String> {
    let p = Pqid::from_crockford(r.input_str.as_ref().unwrap())
        .map_err(|e| format!("from_crockford: {:?}", e))?;
    let got = hex::encode(p.as_bytes());
    let want = r.expected_hex.as_ref().unwrap();
    if &got != want {
        return Err(format!("got={} want={}", got, want));
    }
    Ok(())
}

fn run_validate_invalid(r: &Record) -> Result<(), String> {
    let kind = r.input_kind.as_ref().unwrap().as_str();
    match kind {
        "binary_hex" => {
            let h = r.input_hex.as_ref().unwrap();
            let bytes = match hex::decode(h) {
                Ok(b) => b,
                Err(_) => return Ok(()),
            };
            match Pqid::from_bytes(&bytes) {
                Ok(_) => Err("expected error, got success".into()),
                Err(_) => Ok(()),
            }
        }
        "b64" => match Pqid::from_base64url(r.input_str.as_ref().unwrap()) {
            Ok(_) => Err("expected error, got success".into()),
            Err(_) => Ok(()),
        },
        "crockford" => match Pqid::from_crockford(r.input_str.as_ref().unwrap()) {
            Ok(_) => Err("expected error, got success".into()),
            Err(_) => Ok(()),
        },
        _ => Err(format!("unknown input_kind {:?}", kind)),
    }
}

fn run_validate_min_timestamp(r: &Record) -> Result<(), String> {
    let arr = hex_to_arr(r.input_hex.as_ref().unwrap())?;
    let p = pqid::Pqid(arr);
    let got = p.validate_min_timestamp();
    let want = r.expected.as_ref().and_then(|v| v.as_bool())
        .ok_or_else(|| "no expected bool".to_string())?;
    if got != want {
        return Err(format!("got={} want={}", got, want));
    }
    Ok(())
}

fn run_hlc_overflow(r: &Record) -> Result<(), String> {
    if r.name == "doc" {
        return Ok(());
    }
    let start = r.start.as_ref().unwrap();
    let l_old = start["l_old"].as_i64().unwrap();
    let c_old = start["c_old"].as_i64().unwrap() as u16;
    let pt = r.physical_time_ms.unwrap();

    let mut g = HlcGenerator::new();
    g.set_state_for_testing(l_old, c_old);
    set_now_ms_for_testing(pt);

    let result = if let Some(obs) = &r.observe {
        if obs.is_null() {
            g.new_id(None)
        } else {
            let l_msg = obs["l_msg"].as_i64().unwrap();
            let c_msg = obs["c_msg"].as_i64().unwrap() as u16;
            let mut peer = [0u8; SIZE_BYTES];
            peer[0] = (l_msg >> 40) as u8;
            peer[1] = (l_msg >> 32) as u8;
            peer[2] = (l_msg >> 24) as u8;
            peer[3] = (l_msg >> 16) as u8;
            peer[4] = (l_msg >> 8) as u8;
            peer[5] = l_msg as u8;
            peer[6] = VARIANT_HLC;
            peer[7] = (c_msg >> 8) as u8;
            peer[8] = c_msg as u8;
            let p = Pqid(peer);
            g.new_id(Some(&p))
        }
    } else {
        g.new_id(None)
    };

    set_now_ms_for_testing(-1);

    let p = result.map_err(|e| format!("new_id: {:?}", e))?;
    let exp = r.expected.as_ref().unwrap();
    let exp_l = exp["l_new"].as_i64().unwrap();
    let exp_c = exp["c_new"].as_i64().unwrap() as u16;
    if p.timestamp_ms() != exp_l || p.counter() != exp_c {
        return Err(format!(
            "got=(l={}, c={}) want=(l={}, c={})",
            p.timestamp_ms(),
            p.counter(),
            exp_l,
            exp_c
        ));
    }
    Ok(())
}

fn pqhash_from_hex(hex_s: &str) -> Result<Pqhash, String> {
    let bytes = hex::decode(hex_s).map_err(|e| e.to_string())?;
    if bytes.len() != PQHASH_SIZE_BYTES {
        return Err(format!("len {} != {}", bytes.len(), PQHASH_SIZE_BYTES));
    }
    let mut arr = [0u8; PQHASH_SIZE_BYTES];
    arr.copy_from_slice(&bytes);
    Ok(Pqhash(arr))
}

fn run_pqhash_hash_only(r: &Record) -> Result<(), String> {
    let content = hex::decode(r.input_hex.as_ref().unwrap()).map_err(|e| e.to_string())?;
    let tail = pqhash::hash_only(&content);
    let got = hex::encode(tail);
    let want = r.expected_tail_hex.as_ref().ok_or("no expected_tail_hex")?;
    if &got != want {
        return Err(format!("got={} want={}", got, want));
    }
    Ok(())
}

fn run_pqhash_decode(r: &Record) -> Result<(), String> {
    let p = pqhash_from_hex(r.input_hex.as_ref().unwrap())?;
    let exp = r.expected.as_ref().ok_or("no expected")?;
    if p.variant() as i64 != exp["variant"].as_i64().unwrap() {
        return Err("variant".into());
    }
    if p.timestamp_ms() != exp["timestamp_ms"].as_i64().unwrap() {
        return Err("ts".into());
    }
    if p.counter() as i64 != exp["counter"].as_i64().unwrap() {
        return Err("counter".into());
    }
    let got_tail = hex::encode(p.tail());
    let want_tail = exp["tail_hex"].as_str().unwrap();
    if got_tail != want_tail {
        return Err(format!("tail got={} want={}", got_tail, want_tail));
    }
    Ok(())
}

fn run_pqhash_encode_b64(r: &Record) -> Result<(), String> {
    let p = pqhash_from_hex(r.input_hex.as_ref().unwrap())?;
    let s = p.to_base64url();
    let want = r.expected_str.as_ref().unwrap();
    if &s != want { return Err(format!("got={} want={}", s, want)); }
    Ok(())
}

fn run_pqhash_decode_b64(r: &Record) -> Result<(), String> {
    let p = Pqhash::from_base64url(r.input_str.as_ref().unwrap())
        .map_err(|e| format!("{:?}", e))?;
    let got = hex::encode(p.as_bytes());
    let want = r.expected_hex.as_ref().unwrap();
    if &got != want { return Err(format!("got={} want={}", got, want)); }
    Ok(())
}

fn run_pqhash_encode_crockford(r: &Record) -> Result<(), String> {
    let p = pqhash_from_hex(r.input_hex.as_ref().unwrap())?;
    let s = p.to_crockford();
    let want = r.expected_str.as_ref().unwrap();
    if &s != want { return Err(format!("got={} want={}", s, want)); }
    Ok(())
}

fn run_pqhash_decode_crockford(r: &Record) -> Result<(), String> {
    let p = Pqhash::from_crockford(r.input_str.as_ref().unwrap())
        .map_err(|e| format!("{:?}", e))?;
    let got = hex::encode(p.as_bytes());
    let want = r.expected_hex.as_ref().unwrap();
    if &got != want { return Err(format!("got={} want={}", got, want)); }
    Ok(())
}

fn run_pqhash_validate_invalid(r: &Record) -> Result<(), String> {
    let kind = r.input_kind.as_ref().unwrap().as_str();
    match kind {
        "binary_hex" => {
            let h = r.input_hex.as_ref().unwrap();
            let bytes = match hex::decode(h) {
                Ok(b) => b,
                Err(_) => return Ok(()),
            };
            match Pqhash::from_bytes(&bytes) {
                Ok(_) => Err("expected error, got success".into()),
                Err(_) => Ok(()),
            }
        }
        "b64" => match Pqhash::from_base64url(r.input_str.as_ref().unwrap()) {
            Ok(_) => Err("expected error, got success".into()),
            Err(_) => Ok(()),
        },
        "crockford" => match Pqhash::from_crockford(r.input_str.as_ref().unwrap()) {
            Ok(_) => Err("expected error, got success".into()),
            Err(_) => Ok(()),
        },
        _ => Err(format!("unknown input_kind {:?}", kind)),
    }
}

fn run_pqhash_verify(r: &Record) -> Result<(), String> {
    let p = pqhash_from_hex(r.input_hex.as_ref().unwrap())?;
    let content = hex::decode(r.content_hex.as_ref().unwrap()).map_err(|e| e.to_string())?;
    let got = p.verify(&content);
    let want = r.expected.as_ref().and_then(|v| v.as_bool())
        .ok_or_else(|| "no expected bool".to_string())?;
    if got != want { return Err(format!("got={} want={}", got, want)); }
    Ok(())
}

fn dispatch(r: &Record) -> Result<(), String> {
    match r.op.as_str() {
        "decode" => run_decode(r),
        "encode_b64" => run_encode_b64(r),
        "decode_b64" => run_decode_b64(r),
        "encode_crockford" => run_encode_crockford(r),
        "decode_crockford" => run_decode_crockford(r),
        "validate_invalid" => run_validate_invalid(r),
        "hlc_overflow" => run_hlc_overflow(r),
        "validate_min_timestamp" => run_validate_min_timestamp(r),
        "pqhash_hash_only" => run_pqhash_hash_only(r),
        "pqhash_decode" => run_pqhash_decode(r),
        "pqhash_encode_b64" => run_pqhash_encode_b64(r),
        "pqhash_decode_b64" => run_pqhash_decode_b64(r),
        "pqhash_encode_crockford" => run_pqhash_encode_crockford(r),
        "pqhash_decode_crockford" => run_pqhash_decode_crockford(r),
        "pqhash_validate_invalid" => run_pqhash_validate_invalid(r),
        "pqhash_verify" => run_pqhash_verify(r),
        other => Err(format!("unknown op {:?}", other)),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: conformance_runner <vectors.json>");
        return ExitCode::from(2);
    }
    let data = match fs::read_to_string(&args[1]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(2);
        }
    };
    let records: Vec<Record> = match serde_json::from_str(&data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(2);
        }
    };

    let mut failures = 0;
    for r in &records {
        if r.name == "doc" {
            continue;
        }
        match dispatch(r) {
            Ok(()) => println!("PASS {}", r.name),
            Err(d) => {
                println!("FAIL {} {}", r.name, d);
                failures += 1;
            }
        }
    }
    if failures > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}
