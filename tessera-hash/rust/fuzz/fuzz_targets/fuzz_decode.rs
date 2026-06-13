//! libFuzzer target: random bytes -> TesseraHash decoders (binary + both
//! text forms). Must never panic (TESS-00016 / TP-096).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tessera_hash_fuzz::run_decode(data);
});
