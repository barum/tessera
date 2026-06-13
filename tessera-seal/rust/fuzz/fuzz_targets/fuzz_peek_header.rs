//! libFuzzer target: random bytes -> tessera_seal structural inspectors
//! (peek_header / peek_ad / validate). Must never panic (TESS-00016 / TP-096).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tessera_seal_fuzz::run_peek_header(data);
});
