//! FF1 format-preserving encryption (NIST SP 800-38G §5.1) with AES-256.
//!
//! Used only by the optional FIPS PRP mode (SPEC §4.1.1). Numeral values are held in `u128`, so
//! the implementation supports radix^len < 2^128 and `d <= 16`, which covers every TesseraMark
//! profile (radix 2, n <= 64) and the NIST sample vectors.

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

/// FF1 instance keyed with a 32-byte AES-256 key.
pub struct Ff1 {
    aes: Aes256,
    radix: u32,
}

fn pow(radix: u32, m: usize) -> u128 {
    (radix as u128).pow(m as u32)
}

fn num(digits: &[u32], radix: u32) -> u128 {
    digits
        .iter()
        .fold(0u128, |acc, d| acc * radix as u128 + *d as u128)
}

fn str_m(mut x: u128, radix: u32, m: usize) -> Vec<u32> {
    let mut out = vec![0u32; m];
    for slot in out.iter_mut().rev() {
        *slot = (x % radix as u128) as u32;
        x /= radix as u128;
    }
    out
}

impl Ff1 {
    /// New FF1 over `radix` (2..=2^16).
    pub fn new(key: &[u8; 32], radix: u32) -> Self {
        assert!((2..=1 << 16).contains(&radix), "FF1 radix out of range");
        Self {
            aes: Aes256::new(GenericArray::from_slice(key)),
            radix,
        }
    }

    fn ciph(&self, block: &mut [u8; 16]) {
        let mut b = GenericArray::clone_from_slice(block);
        self.aes.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    fn prf(&self, data: &[u8]) -> [u8; 16] {
        let mut y = [0u8; 16];
        for chunk in data.chunks(16) {
            for (a, b) in y.iter_mut().zip(chunk) {
                *a ^= b;
            }
            self.ciph(&mut y);
        }
        y
    }

    /// Round value `y` for round `i` over half `x` (SP 800-38G steps 6.i-6.iv).
    fn round_y(&self, p: &[u8], tweak: &[u8], i: u8, x: &[u32], b: usize, d: usize) -> u128 {
        let pad = (16 - ((tweak.len() + b + 1) % 16)) % 16;
        let mut q = Vec::with_capacity(tweak.len() + pad + 1 + b);
        q.extend_from_slice(tweak);
        q.resize(tweak.len() + pad, 0);
        q.push(i);
        let nb = num(x, self.radix).to_be_bytes();
        q.extend_from_slice(&nb[16 - b..]);
        let mut pq = p.to_vec();
        pq.extend_from_slice(&q);
        let r = self.prf(&pq);
        let mut s = r.to_vec();
        let mut j = 1u128;
        while s.len() < d {
            let mut blk = (u128::from_be_bytes(r) ^ j).to_be_bytes();
            self.ciph(&mut blk);
            s.extend_from_slice(&blk);
            j += 1;
        }
        s[..d].iter().fold(0u128, |acc, v| (acc << 8) | *v as u128)
    }

    fn params(&self, n: usize, t: usize) -> (usize, usize, usize, usize, Vec<u8>) {
        let u = n / 2;
        let v = n - u;
        let max = pow(self.radix, v) - 1;
        let bits = (128 - max.leading_zeros()) as usize;
        let b = bits.div_ceil(8);
        let d = 4 * b.div_ceil(4) + 4;
        assert!(
            d <= 16 && n >= 2,
            "FF1 length unsupported by u128 implementation"
        );
        let mut p = vec![1u8, 2, 1];
        p.extend_from_slice(&self.radix.to_be_bytes()[1..]);
        p.push(10);
        p.push((u % 256) as u8);
        p.extend_from_slice(&(n as u32).to_be_bytes());
        p.extend_from_slice(&(t as u32).to_be_bytes());
        (u, v, b, d, p)
    }

    /// FF1.Encrypt(K, T, X).
    pub fn encrypt(&self, tweak: &[u8], x: &[u32]) -> Vec<u32> {
        let (u, v, b, d, p) = self.params(x.len(), tweak.len());
        let (mut a, mut bb) = (x[..u].to_vec(), x[u..].to_vec());
        for i in 0..10u8 {
            let m = if i % 2 == 0 { u } else { v };
            let y = self.round_y(&p, tweak, i, &bb, b, d);
            let modm = pow(self.radix, m);
            let c = (num(&a, self.radix) + y % modm) % modm;
            a = core::mem::replace(&mut bb, str_m(c, self.radix, m));
        }
        a.extend(bb);
        a
    }

    /// FF1.Decrypt(K, T, Y).
    pub fn decrypt(&self, tweak: &[u8], y_in: &[u32]) -> Vec<u32> {
        let (u, v, b, d, p) = self.params(y_in.len(), tweak.len());
        let (mut a, mut bb) = (y_in[..u].to_vec(), y_in[u..].to_vec());
        for i in (0..10u8).rev() {
            let m = if i % 2 == 0 { u } else { v };
            let y = self.round_y(&p, tweak, i, &a, b, d);
            let modm = pow(self.radix, m);
            let c = (num(&bb, self.radix) + modm - y % modm) % modm;
            bb = core::mem::replace(&mut a, str_m(c, self.radix, m));
        }
        a.extend(bb);
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digits(s: &str) -> Vec<u32> {
        s.chars().map(|c| c.to_digit(36).unwrap()).collect()
    }

    fn text(d: &[u32]) -> String {
        d.iter()
            .map(|v| char::from_digit(*v, 36).unwrap())
            .collect()
    }

    const KEY: [u8; 32] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC,
        0x6A, 0x94,
    ];

    fn check(radix: u32, tweak: &[u8], pt: &str, ct: &str) {
        let f = Ff1::new(&KEY, radix);
        let out = f.encrypt(tweak, &digits(pt));
        assert_eq!(text(&out), ct);
        assert_eq!(text(&f.decrypt(tweak, &out)), pt);
    }

    #[test]
    fn nist_sample7_aes256_no_tweak() {
        check(10, &[], "0123456789", "6657667009");
    }

    #[test]
    fn nist_sample8_aes256_tweak() {
        let t = [0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30];
        check(10, &t, "0123456789", "1001623463");
    }

    #[test]
    fn nist_sample9_aes256_radix36() {
        let t = [
            0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37,
        ];
        check(36, &t, "0123456789abcdefghi", "xs8a0azh2avyalyzuwd");
    }
}
