//! Harness body for the TesseraID fuzz target (TESS-00016 / TP-096).
//!
//! One target covers the full decode surface: the 41-byte binary form plus
//! BOTH canonical text forms (55-char Base64URL and 66-char Crockford
//! Base32, including the 2-bit trailing-pad guard), the latter by
//! reinterpreting the fuzz bytes as UTF-8.
//!
//! `fuzz_targets/fuzz_decode.rs` calls this under libFuzzer (nightly +
//! cargo-fuzz). The same body runs on STABLE as a unit test: `cargo test
//! --lib` feeds it 10 000 deterministic pseudo-random inputs.

use tessera_id::{SIZE_BYTES, TesseraId, VARIANT_HLC, VARIANT_STANDARD};

/// fuzz_decode body: bytes -> binary decoder, and (as UTF-8) both text
/// decoders. Must never panic; accepts must round-trip canonically.
pub fn run_decode(data: &[u8]) {
    // Binary wire form.
    if let Ok(id) = TesseraId::from_bytes(data) {
        assert_eq!(data.len(), SIZE_BYTES, "accepted wrong length");
        assert!(
            id.variant() == VARIANT_STANDARD || id.variant() == VARIANT_HLC,
            "accepted bad variant 0x{:02x}",
            id.variant()
        );
        let b64 = id.to_base64url();
        let back = TesseraId::from_base64url(&b64).expect("b64 round-trip decode");
        assert_eq!(back.as_bytes(), id.as_bytes(), "b64 round-trip changed bytes");
        let b32 = id.to_crockford();
        let back = TesseraId::from_crockford(&b32).expect("crockford round-trip decode");
        assert_eq!(back.as_bytes(), id.as_bytes(), "crockford round-trip changed bytes");
    }

    // Text forms: same bytes viewed as a string.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(id) = TesseraId::from_base64url(s) {
            // Canonical Base64URL is bijective: re-encode must equal input.
            assert_eq!(id.to_base64url(), s, "Base64URL decoder not bijective");
        }
        if let Ok(id) = TesseraId::from_crockford(s) {
            // Case and confusables (I/L->1, O->0) may fold; bytes may not
            // change across a canonical re-encode/re-decode cycle.
            let canonical = id.to_crockford();
            let again =
                TesseraId::from_crockford(&canonical).expect("canonical crockford re-decode");
            assert_eq!(again.as_bytes(), id.as_bytes(), "crockford canonical cycle changed bytes");
        }
    }
}

#[cfg(test)]
mod smoke {
    use super::*;

    /// xorshift64* — deterministic, dependency-free PRNG for the smoke loop.
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

    #[test]
    fn smoke_run_decode_10k_random_inputs() {
        let mut rng = Rng(0xA076_1D64_78BD_642F);
        for i in 0..10_000 {
            // Bias lengths around the interesting sizes: 41 (binary),
            // 55 (Base64URL), 66 (Crockford), plus arbitrary noise.
            let len = match rng.next() % 5 {
                0 => 41,
                1 => 55,
                2 => 66,
                3 => (rng.next() % 48) as usize,
                _ => (rng.next() % 128) as usize,
            };
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf);
            match i % 3 {
                // Raw bytes.
                0 => {}
                // Plausible binary form: valid variant byte.
                1 => {
                    if len > 6 {
                        buf[6] = if i % 2 == 0 { VARIANT_STANDARD } else { VARIANT_HLC };
                    }
                }
                // ASCII-ish: fold into the text-decoder alphabets.
                _ => {
                    for b in buf.iter_mut() {
                        *b &= 0x7F;
                    }
                }
            }
            run_decode(&buf);
        }
    }
}
