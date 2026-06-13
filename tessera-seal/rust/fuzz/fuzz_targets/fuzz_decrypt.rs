//! libFuzzer target: random bytes -> tessera_seal::decrypt with a fixed test
//! key. Must never panic, only Err (TESS-00016 / TP-096).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tessera_seal_fuzz::run_decrypt(data);
});
