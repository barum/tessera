//! 16-byte record (SPEC §6) and human text form (SPEC §7).

use crate::kmac::{encode_string, shake256};
use crate::{MarkError, Profile};

/// TesseraMark variant byte (offset 6 of the record).
pub const VARIANT_MARK: u8 = 0x05;
/// Record length in bytes.
pub const RECORD_LEN: usize = 16;
const CROCKFORD: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// 6-byte public routing tag of an asset.
pub fn asset_tag(asset_id: &[u8]) -> [u8; 6] {
    let mut x = b"TesseraMark v1 asset tag".to_vec();
    x.extend(encode_string(asset_id));
    let mut out = [0u8; 6];
    out.copy_from_slice(&shake256(&x, 6));
    out
}

/// Validated 16-byte record: `ATAG(6) || 0x05 || PROFILE || CODE(8, BE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Record([u8; RECORD_LEN]);

impl Record {
    /// Builds a record for `code` under `profile`.
    pub fn new(asset_id: &[u8], profile: Profile, code: u64) -> Result<Self, MarkError> {
        if code > profile.max_code() {
            return Err(MarkError::CodeRange);
        }
        let mut b = [0u8; RECORD_LEN];
        b[..6].copy_from_slice(&asset_tag(asset_id));
        b[6] = VARIANT_MARK;
        b[7] = profile.id();
        b[8..].copy_from_slice(&code.to_be_bytes());
        Ok(Self(b))
    }

    /// Structural validation of raw bytes (no key needed).
    pub fn from_bytes(raw: &[u8]) -> Result<Self, MarkError> {
        if raw.len() != RECORD_LEN {
            return Err(MarkError::InvalidLen);
        }
        if raw[6] != VARIANT_MARK {
            return Err(MarkError::UnknownVariant);
        }
        let p = Profile::from_id(raw[7])?;
        let mut code = [0u8; 8];
        code.copy_from_slice(&raw[8..]);
        if u64::from_be_bytes(code) > p.max_code() {
            return Err(MarkError::Noncanonical);
        }
        let mut b = [0u8; RECORD_LEN];
        b.copy_from_slice(raw);
        Ok(Self(b))
    }

    /// Raw bytes.
    pub fn to_bytes(&self) -> [u8; RECORD_LEN] {
        self.0
    }

    /// Asset routing tag.
    pub fn asset_tag(&self) -> [u8; 6] {
        let mut t = [0u8; 6];
        t.copy_from_slice(&self.0[..6]);
        t
    }

    /// Profile.
    pub fn profile(&self) -> Profile {
        Profile::from_id(self.0[7]).expect("validated at construction")
    }

    /// Code.
    pub fn code(&self) -> u64 {
        let mut c = [0u8; 8];
        c.copy_from_slice(&self.0[8..]);
        u64::from_be_bytes(c)
    }
}

fn text_check(p: Profile, code: u64) -> u8 {
    let v = ((p.id() as u128) << p.code_bits()) | code as u128;
    CROCKFORD[(v % 37) as usize]
}

/// `TM32-<Crockford code>-<mod-37 check>`.
pub fn to_text(p: Profile, code: u64) -> Result<String, MarkError> {
    if code > p.max_code() {
        return Err(MarkError::CodeRange);
    }
    let n = p.code_bits();
    let nch = n.div_ceil(5);
    let v = (code as u128) << (nch * 5 - n);
    let body: String = (0..nch)
        .map(|i| CROCKFORD[((v >> (5 * (nch - 1 - i))) & 31) as usize] as char)
        .collect();
    Ok(format!(
        "{}-{}-{}",
        p.name(),
        body,
        text_check(p, code) as char
    ))
}

/// Parses the text form (case-insensitive, `I/L→1`, `O→0`).
pub fn from_text(text: &str) -> Result<(Profile, u64), MarkError> {
    let t: String = text
        .trim()
        .to_ascii_uppercase()
        .chars()
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    let parts: Vec<&str> = t.split('-').collect();
    let [name, body, check] = parts.as_slice() else {
        return Err(MarkError::BadText);
    };
    let p = Profile::from_name(name).map_err(|_| MarkError::BadText)?;
    let nch = p.code_bits().div_ceil(5) as usize;
    if body.len() != nch || check.len() != 1 {
        return Err(MarkError::BadText);
    }
    let mut v = 0u128;
    for ch in body.bytes() {
        let d = CROCKFORD[..32]
            .iter()
            .position(|c| *c == ch)
            .ok_or(MarkError::BadText)?;
        v = (v << 5) | d as u128;
    }
    let pad = nch as u32 * 5 - p.code_bits();
    if v & ((1u128 << pad) - 1) != 0 {
        return Err(MarkError::Noncanonical);
    }
    let code = (v >> pad) as u64;
    if text_check(p, code) != check.as_bytes()[0] {
        return Err(MarkError::BadCheck);
    }
    Ok((p, code))
}

/// Union-bound false-match probability for maximum-likelihood accusation (SPEC §5.2):
/// `min(1, candidates · P[Bin(observations, 1/2) >= agreements])`.
pub fn false_match_probability(candidates: u64, observations: u64, agreements: u64) -> f64 {
    if agreements == 0 || observations == 0 {
        return 1.0;
    }
    let ln_half_m = observations as f64 * core::f64::consts::LN_2;
    let mut ln_choose = 0.0f64;
    for i in 0..agreements {
        ln_choose += ((observations - i) as f64).ln() - ((i + 1) as f64).ln();
    }
    let mut tail = 0.0f64;
    let mut ln_c = ln_choose;
    for k in agreements..=observations {
        tail += (ln_c - ln_half_m).exp();
        if k < observations {
            ln_c += ((observations - k) as f64).ln() - ((k + 1) as f64).ln();
        }
    }
    (candidates as f64 * tail).min(1.0)
}
