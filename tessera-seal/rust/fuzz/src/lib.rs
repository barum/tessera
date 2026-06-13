//! Harness bodies for the TesseraSeal fuzz targets (TESS-00016 / TP-096).
//!
//! The `fuzz_targets/*.rs` binaries call these functions under libFuzzer
//! (nightly + cargo-fuzz). The same bodies run on STABLE as unit tests:
//! `cargo test --lib` feeds each harness 10 000 deterministic pseudo-random
//! inputs (plus structure-aware mutants) as a no-nightly smoke check.
//!
//! Contract asserted on every input:
//!   - the decoder never panics (any panic aborts the fuzzer / fails the test);
//!   - accepts satisfy the structural postconditions (variant 0x04, allocated
//!     suite, length caps, plaintext strictly shorter than envelope);
//!   - the structural inspectors agree with each other (validate/peek_ad
//!     never accept what peek_header rejects).

use std::sync::OnceLock;

use tessera_seal::{
    HEADER_BYTES, MAX_AD_LEN, MAX_KEM_CT_LEN, MLKEM1024_SEED_BYTES, PrivateKey,
    SUITE_HYBRID_X25519_MLKEM1024_AESGCM, SUITE_MLKEM1024_AESGCM, SUITE_MLKEM1024_CHACHA,
    VARIANT_TESSERA_SEAL, decrypt, generate_keypair_from_seed, peek_ad, peek_header, validate,
};

/// Fixed test key (deterministic seed) for the decrypt target: corpus entries
/// keep their meaning across runs and machines.
fn fuzz_key() -> &'static PrivateKey {
    static KEY: OnceLock<PrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let seed: Vec<u8> = (0..MLKEM1024_SEED_BYTES as u8).collect();
        let (priv_key, _pub_key) = generate_keypair_from_seed(&seed, SUITE_MLKEM1024_AESGCM)
            .expect("fixed fuzz keypair");
        priv_key
    })
}

/// fuzz_decrypt body: random bytes -> decrypt with a fixed test key.
/// Must never panic; only `Err` (or a legitimately authenticated `Ok`).
pub fn run_decrypt(data: &[u8]) {
    let key = fuzz_key();
    if let Ok(pt) = decrypt(data, key, &[]) {
        assert!(
            pt.len() < data.len(),
            "decrypt accepted with plaintext ({} B) not shorter than envelope ({} B)",
            pt.len(),
            data.len()
        );
    }
    // Pin variant/suite so the fuzzer spends its budget past the cheap
    // structural checks, inside the KEM_CT_LEN/AD_LEN offset arithmetic and
    // the constant-time synthetic-key authentication path.
    if data.len() >= HEADER_BYTES {
        let mut mutant = data.to_vec();
        mutant[6] = VARIANT_TESSERA_SEAL;
        mutant[7] = SUITE_MLKEM1024_AESGCM;
        if let Ok(pt) = decrypt(&mutant, key, &[]) {
            assert!(pt.len() < mutant.len());
        }
    }
}

/// fuzz_peek_header body: random bytes -> structural inspectors.
pub fn run_peek_header(data: &[u8]) {
    match peek_header(data) {
        Ok(h) => {
            assert!(data.len() >= HEADER_BYTES);
            assert_eq!(h.variant, VARIANT_TESSERA_SEAL, "accepted bad variant");
            assert!(
                h.suite == SUITE_MLKEM1024_AESGCM
                    || h.suite == SUITE_MLKEM1024_CHACHA
                    || h.suite == SUITE_HYBRID_X25519_MLKEM1024_AESGCM,
                "accepted unallocated suite 0x{:02x}",
                h.suite
            );
            assert!(h.kem_ct_len as usize <= MAX_KEM_CT_LEN, "kem_ct_len over cap");
            assert!(h.ad_len as usize <= MAX_AD_LEN, "ad_len over cap");
            if let Ok(ad) = peek_ad(data) {
                assert_eq!(ad.len(), h.ad_len as usize, "peek_ad length != header ad_len");
                assert!(
                    HEADER_BYTES + h.kem_ct_len as usize + ad.len() <= data.len(),
                    "peek_ad read past envelope end"
                );
            }
        }
        Err(_) => {
            assert!(!validate(data), "validate accepted what peek_header rejected");
            assert!(peek_ad(data).is_err(), "peek_ad accepted what peek_header rejected");
        }
    }
}

#[cfg(test)]
mod smoke {
    use super::*;

    /// xorshift64* — deterministic, dependency-free PRNG for the smoke loop.
    /// (Test-input generation only; production randomness is OS-CSPRNG-only
    /// per the umbrella security invariants.)
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
    }

    /// Generates the i-th smoke input: random length (biased short, up to
    /// 4 KiB), random bytes, and every 4th input gets a plausible header
    /// (variant/suite valid, in-cap lengths) to reach deeper paths.
    fn smoke_input(rng: &mut Rng, i: usize) -> Vec<u8> {
        let len = match rng.next() % 4 {
            0 => (rng.next() % 24) as usize,                       // sub-header
            1 => HEADER_BYTES + (rng.next() % 64) as usize,        // header + small body
            2 => (rng.next() % 512) as usize,                      // mid
            _ => (rng.next() % 4096) as usize,                     // large
        };
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        if i % 4 == 0 && len >= HEADER_BYTES {
            buf[6] = VARIANT_TESSERA_SEAL;
            buf[7] = SUITE_MLKEM1024_AESGCM;
            let kem_ct_len = (rng.next() % (MAX_KEM_CT_LEN as u64 + 1)) as u16;
            buf[10..12].copy_from_slice(&kem_ct_len.to_be_bytes());
            let ad_len = (rng.next() % (MAX_AD_LEN as u64 + 1)) as u32;
            buf[12..16].copy_from_slice(&ad_len.to_be_bytes());
        }
        buf
    }

    #[test]
    fn smoke_run_decrypt_10k_random_inputs() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for i in 0..10_000 {
            run_decrypt(&smoke_input(&mut rng, i));
        }
    }

    #[test]
    fn smoke_run_peek_header_10k_random_inputs() {
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        for i in 0..10_000 {
            run_peek_header(&smoke_input(&mut rng, i));
        }
    }
}
