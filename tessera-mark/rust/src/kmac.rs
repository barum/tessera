//! KMAC256 and SHAKE256 helpers (NIST SP 800-185 / FIPS 202) built on the `sha3` crate's cSHAKE.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core, Shake256};

const RATE: usize = 136;

/// SP 800-185 §2.3.1 left_encode.
pub fn left_encode(x: u64) -> Vec<u8> {
    let be = x.to_be_bytes();
    let skip = be.iter().take(7).take_while(|b| **b == 0).count();
    let mut out = vec![(8 - skip) as u8];
    out.extend_from_slice(&be[skip..]);
    out
}

/// SP 800-185 §2.3.1 right_encode.
pub fn right_encode(x: u64) -> Vec<u8> {
    let be = x.to_be_bytes();
    let skip = be.iter().take(7).take_while(|b| **b == 0).count();
    let mut out = be[skip..].to_vec();
    out.push((8 - skip) as u8);
    out
}

/// SP 800-185 §2.3.2 encode_string.
pub fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode(8 * s.len() as u64);
    out.extend_from_slice(s);
    out
}

fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let mut z = left_encode(w as u64);
    z.extend_from_slice(x);
    while !z.len().is_multiple_of(w) {
        z.push(0);
    }
    z
}

/// KMAC256(K, X, L = 8*out_len, S).
pub fn kmac256(key: &[u8], data: &[u8], out_len: usize, custom: &[u8]) -> Vec<u8> {
    let mut h = CShake256::from_core(CShake256Core::new_with_function_name(b"KMAC", custom));
    h.update(&bytepad(&encode_string(key), RATE));
    h.update(data);
    h.update(&right_encode(8 * out_len as u64));
    let mut out = vec![0u8; out_len];
    h.finalize_xof().read(&mut out);
    out
}

/// SHAKE256(data, out_len).
pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(data);
    let mut out = vec![0u8; out_len];
    h.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_kmac256_sample6() {
        let key: Vec<u8> = (0x40u8..0x60).collect();
        let out = kmac256(&key, &[0, 1, 2, 3], 64, b"My Tagged Application");
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7\
             f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
        );
    }

    #[test]
    fn encodings() {
        assert_eq!(left_encode(0), vec![1, 0]);
        assert_eq!(left_encode(256), vec![2, 1, 0]);
        assert_eq!(right_encode(0), vec![0, 1]);
        assert_eq!(right_encode(512), vec![2, 0, 2]);
    }
}
