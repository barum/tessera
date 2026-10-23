//! Per-(asset, profile) codec: keyed permutation, check tag, binding tag, A/B channel (SPEC §3-§5).

use zeroize::Zeroizing;

use crate::ff1::Ff1;
use crate::kmac::{encode_string, kmac256, left_encode};
use crate::{MarkError, Profile};

/// Minimum key length in bytes (SPEC §3).
pub const MIN_KEY_LEN: usize = 32;
/// Feistel rounds of the default KMAC PRP.
pub const FEISTEL_ROUNDS: u64 = 12;
const CUSTOM: &[u8] = b"TesseraMark v1";

/// Which keyed permutation maps index to code (SPEC §4.1). Not part of the wire record: a
/// deployment stores it next to the asset key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PrpMode {
    /// 12-round balanced Feistel with a KMAC256 round function (default).
    #[default]
    Kmac,
    /// FF1 (SP 800-38G) radix 2 under AES-256, for FIPS-constrained deployments.
    Ff1,
}

/// 32-byte per-asset key, zeroized on drop.
#[derive(Clone)]
pub struct AssetKey(Zeroizing<[u8; 32]>);

impl AssetKey {
    /// Wraps a raw 32-byte key (e.g. unwrapped from a KEK).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `K_asset = KMAC256(K_master, enc(tenant)||enc(asset_id)||enc(asset_hash), 256, ...)`.
    pub fn derive(
        master: &[u8],
        tenant: &[u8],
        asset_id: &[u8],
        asset_hash: &[u8],
    ) -> Result<Self, MarkError> {
        if master.len() < MIN_KEY_LEN {
            return Err(MarkError::ShortKey);
        }
        let mut ctx = encode_string(tenant);
        ctx.extend(encode_string(asset_id));
        ctx.extend(encode_string(asset_hash));
        let custom = [CUSTOM, b" asset key"].concat();
        Ok(Self::from_bytes(to32(&kmac256(master, &ctx, 32, &custom))))
    }
}

fn to32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

/// Result of a successful direct decode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Decoded {
    pub code: u64,
    pub index: u64,
    /// Fraction of observations agreeing with the decoded code.
    pub agreement: f64,
    pub erasures: u32,
}

/// Codec for one asset and profile.
pub struct Mark {
    profile: Profile,
    mode: PrpMode,
    k_prp: Zeroizing<[u8; 32]>,
    k_chk: Zeroizing<[u8; 32]>,
    k_wht: Zeroizing<[u8; 32]>,
    k_bnd: Zeroizing<[u8; 32]>,
    ff1: Option<Ff1>,
}

impl Mark {
    /// Codec with the default KMAC Feistel PRP.
    pub fn new(key: &AssetKey, profile: Profile) -> Self {
        Self::with_mode(key, profile, PrpMode::Kmac)
    }

    /// Codec with an explicit PRP mode.
    pub fn with_mode(key: &AssetKey, profile: Profile, mode: PrpMode) -> Self {
        let sub = |label: &[u8]| {
            let mut x = label.to_vec();
            x.push(profile.id());
            let custom = [CUSTOM, b" subkey"].concat();
            Zeroizing::new(to32(&kmac256(key.as_bytes(), &x, 32, &custom)))
        };
        let ff1 = match mode {
            PrpMode::Kmac => None,
            PrpMode::Ff1 => Some(Ff1::new(&sub(b"ff1"), 2)),
        };
        Self {
            profile,
            mode,
            k_prp: sub(b"prp"),
            k_chk: sub(b"check"),
            k_wht: sub(b"whiten"),
            k_bnd: sub(b"bind"),
            ff1,
        }
    }

    /// Profile of this codec.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// PRP mode of this codec.
    pub fn mode(&self) -> PrpMode {
        self.mode
    }

    fn half_bits(&self) -> u32 {
        self.profile.code_bits() / 2
    }

    fn round(&self, r: u64, half: u64) -> u64 {
        let h = self.half_bits();
        let nb = h.div_ceil(8) as usize;
        let mut x = left_encode(r);
        x.extend_from_slice(&half.to_be_bytes()[8 - nb..]);
        let out = kmac256(&self.k_prp[..], &x, nb, b"prp");
        out.iter().fold(0u64, |a, b| (a << 8) | *b as u64) & ((1u64 << h) - 1)
    }

    fn bits(&self, v: u64) -> Vec<u32> {
        let n = self.profile.code_bits();
        (0..n).rev().map(|i| ((v >> i) & 1) as u32).collect()
    }

    fn unbits(d: &[u32]) -> u64 {
        d.iter().fold(0u64, |a, b| (a << 1) | *b as u64)
    }

    /// code = PRP(index).
    pub fn encode_index(&self, index: u64) -> Result<u64, MarkError> {
        if index > self.profile.max_code() {
            return Err(MarkError::IndexRange);
        }
        if let Some(f) = &self.ff1 {
            return Ok(Self::unbits(
                &f.encrypt(&[self.profile.id()], &self.bits(index)),
            ));
        }
        let h = self.half_bits();
        let mask = (1u64 << h) - 1;
        let (mut l, mut r) = (index >> h, index & mask);
        for i in 0..FEISTEL_ROUNDS {
            (l, r) = (r, l ^ self.round(i, r));
        }
        Ok((l << h) | r)
    }

    /// index = PRP⁻¹(code).
    pub fn decode_code(&self, code: u64) -> Result<u64, MarkError> {
        if code > self.profile.max_code() {
            return Err(MarkError::CodeRange);
        }
        if let Some(f) = &self.ff1 {
            return Ok(Self::unbits(
                &f.decrypt(&[self.profile.id()], &self.bits(code)),
            ));
        }
        let h = self.half_bits();
        let mask = (1u64 << h) - 1;
        let (mut l, mut r) = (code >> h, code & mask);
        for i in (0..FEISTEL_ROUNDS).rev() {
            (l, r) = (r ^ self.round(i, l), l);
        }
        Ok((l << h) | r)
    }

    fn code_be(&self, code: u64) -> Vec<u8> {
        code.to_be_bytes()[8 - self.profile.code_bytes()..].to_vec()
    }

    /// Keyed check tag (`c` bits).
    pub fn check(&self, code: u64) -> u64 {
        let c = self.profile.check_bits();
        let tag = kmac256(
            &self.k_chk[..],
            &self.code_be(code),
            c.div_ceil(8) as usize,
            b"check",
        );
        let v = tag.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
        v >> ((8 - c % 8) % 8)
    }

    /// Channel word `code || check` (`L` bits).
    pub fn channel_word(&self, code: u64) -> u128 {
        ((code as u128) << self.profile.check_bits()) | self.check(code) as u128
    }

    /// Splits a channel word into `(code, check_ok)`.
    pub fn split_word(&self, word: u128) -> (u64, bool) {
        let c = self.profile.check_bits();
        let code = (word >> c) as u64;
        (code, (word & ((1u128 << c) - 1)) as u64 == self.check(code))
    }

    /// 32-byte binding tag of a code to the full session TesseraID (server-side evidence).
    pub fn binding(&self, code: u64, session_id: &[u8]) -> [u8; 32] {
        let mut x = self.code_be(code);
        x.extend(encode_string(session_id));
        to32(&kmac256(&self.k_bnd[..], &x, 32, b"bind"))
    }

    /// Keyed whitening bit of segment `s`.
    pub fn whiten(&self, segment: u64) -> u8 {
        kmac256(&self.k_wht[..], &segment.to_be_bytes(), 1, b"whiten")[0] & 1
    }

    /// A/B variant (0 = A, 1 = B) of `segment` for the session holding `code`.
    pub fn segment_variant(&self, code: u64, segment: u64) -> u8 {
        let l = self.profile.channel_bits() as u64;
        let pos = segment % l;
        let bit = ((self.channel_word(code) >> (l - 1 - pos)) & 1) as u8;
        bit ^ self.whiten(segment)
    }

    /// Variants for segments `start..start+count`.
    pub fn sequence(&self, code: u64, start: u64, count: u64) -> Vec<u8> {
        (start..start + count)
            .map(|s| self.segment_variant(code, s))
            .collect()
    }

    /// Direct decode from `(segment, variant)` observations (SPEC §5.1).
    pub fn decode_observations(&self, obs: &[(u64, u8)]) -> Result<Decoded, MarkError> {
        let l = self.profile.channel_bits() as usize;
        let mut votes = vec![[0u64; 2]; l];
        for &(s, v) in obs {
            votes[(s % l as u64) as usize][((v ^ self.whiten(s)) & 1) as usize] += 1;
        }
        let mut word = 0u128;
        let mut erased = Vec::new();
        for (pos, [z, o]) in votes.iter().enumerate() {
            word <<= 1;
            if z == o {
                erased.push(pos);
            } else if o > z {
                word |= 1;
            }
        }
        if erased.len() as u32 > self.profile.max_erasures() {
            return Err(MarkError::TooManyErasures);
        }
        let mut hits = Vec::new();
        for fill in 0u32..(1 << erased.len()) {
            let mut w = word;
            for (i, pos) in erased.iter().enumerate() {
                if (fill >> i) & 1 == 1 {
                    w |= 1u128 << (l - 1 - pos);
                }
            }
            let (code, ok) = self.split_word(w);
            if ok {
                hits.push(code);
            }
        }
        let code = match hits.as_slice() {
            [c] => *c,
            [] => return Err(MarkError::CheckFailed),
            _ => return Err(MarkError::Ambiguous),
        };
        let agree = obs
            .iter()
            .filter(|(s, v)| self.segment_variant(code, *s) == *v)
            .count();
        Ok(Decoded {
            code,
            index: self.decode_code(code)?,
            agreement: agree as f64 / obs.len().max(1) as f64,
            erasures: erased.len() as u32,
        })
    }

    /// Maximum-likelihood mode: `(agreements, code)` per candidate, best first (SPEC §5.2).
    pub fn score_candidates(&self, obs: &[(u64, u8)], codes: &[u64]) -> Vec<(usize, u64)> {
        let mut out: Vec<(usize, u64)> = codes
            .iter()
            .map(|&c| {
                (
                    obs.iter()
                        .filter(|(s, v)| self.segment_variant(c, *s) == *v)
                        .count(),
                    c,
                )
            })
            .collect();
        out.sort_by(|a, b| b.cmp(a));
        out
    }
}
