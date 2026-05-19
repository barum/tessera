//! # PQID — Post-Quantum Identifier (Rust implementation)
//!
//! 41-byte time-sortable identifiers with 256 bits of post-quantum-resistant
//! randomness. Two variants share the same wire format:
//!
//! * Variant `0x01` — Standard wall-clock + monotonic counter
//! * Variant `0x02` — Hybrid Logical Clock (HLC) for distributed causality
//!
//! ## Layout (41 bytes total)
//!
//! ```text
//! 0       6      7       9                              41
//! +-------+------+-------+------------------------------+
//! |  TS   | VER  |  CTR  |          Random              |
//! | 48 b  |  8 b | 16 b  |           256 b              |
//! +-------+------+-------+------------------------------+
//! ```

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Binary length of a PQID.
pub const SIZE_BYTES: usize = 41;
/// Length of the random tail in bytes (256 bits).
pub const RANDOM_FIELD_BYTES: usize = 32;

/// Variant byte for Standard PQIDs.
pub const VARIANT_STANDARD: u8 = 0x01;
/// Variant byte for HLC PQIDs.
pub const VARIANT_HLC: u8 = 0x02;

const MAX_COUNTER: u16 = u16::MAX;
const HLC_MAX_DRIFT_MS: i64 = 60_000;

/// Canonical Base64URL encoded length (no padding).
pub const ENCODED_LEN_B64: usize = 55;
/// Crockford Base32 encoded length.
pub const ENCODED_LEN_B32: usize = 66;

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidLength { got: usize, want: usize },
    UnknownVariant(u8),
    HlcDrift { drift_ms: i64 },
    InvalidEncoding(&'static str),
    Rng(getrandom::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidLength { got, want } => {
                write!(f, "pqid: invalid length: got {}, want {}", got, want)
            }
            Error::UnknownVariant(v) => write!(f, "pqid: unknown variant byte 0x{:02x}", v),
            Error::HlcDrift { drift_ms } => {
                write!(f, "pqid: observed HLC {} ms ahead of physical clock", drift_ms)
            }
            Error::InvalidEncoding(msg) => write!(f, "pqid: invalid encoding: {}", msg),
            Error::Rng(e) => write!(f, "pqid: RNG failure: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Rng(e)
    }
}

/// A 41-byte Post-Quantum Identifier.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pqid(pub [u8; SIZE_BYTES]);

impl Pqid {
    /// Generate a Standard (Variant 0x01) PQID using the thread-local generator.
    /// Panics if the OS RNG fails.
    #[inline]
    pub fn new() -> Self {
        DEFAULT_STANDARD.with(|g| g.lock().unwrap().new_id().expect("RNG failure"))
    }

    /// Like `new` but returns a `Result`.
    #[inline]
    pub fn try_new() -> Result<Self, Error> {
        DEFAULT_STANDARD.with(|g| g.lock().unwrap().new_id())
    }

    /// Generate an HLC PQID, optionally observing a peer.
    #[inline]
    pub fn new_hlc(observe: Option<&Pqid>) -> Result<Self, Error> {
        DEFAULT_HLC.with(|g| g.lock().unwrap().new_id(observe))
    }

    #[inline] pub fn variant(&self) -> u8 { self.0[6] }
    #[inline] pub fn is_hlc(&self) -> bool { self.variant() == VARIANT_HLC }
    #[inline] pub fn timestamp_ms(&self) -> i64 { read_timestamp(&self.0) }
    #[inline] pub fn counter(&self) -> u16 { u16::from_be_bytes([self.0[7], self.0[8]]) }
    #[inline]
    pub fn random(&self) -> &[u8; RANDOM_FIELD_BYTES] {
        <&[u8; RANDOM_FIELD_BYTES]>::try_from(&self.0[9..]).unwrap()
    }
    #[inline] pub fn as_bytes(&self) -> &[u8; SIZE_BYTES] { &self.0 }

    /// Parse a 41-byte slice; validates the variant byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE_BYTES {
            return Err(Error::InvalidLength { got: bytes.len(), want: SIZE_BYTES });
        }
        let v = bytes[6];
        if v != VARIANT_STANDARD && v != VARIANT_HLC {
            return Err(Error::UnknownVariant(v));
        }
        let mut arr = [0u8; SIZE_BYTES];
        arr.copy_from_slice(bytes);
        Ok(Pqid(arr))
    }

    /// Encode as 55-character Base64URL (no padding).
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64url(s: &str) -> Result<Self, Error> {
        if s.len() != ENCODED_LEN_B64 {
            return Err(Error::InvalidEncoding("Base64URL length must be 55"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| Error::InvalidEncoding("Base64URL decode failed"))?;
        Self::from_bytes(&bytes)
    }

    /// Encode as 66-character Crockford Base32 (uppercase).
    pub fn to_crockford(&self) -> String {
        let mut out = [0u8; ENCODED_LEN_B32];
        let mut buf: u64 = 0;
        let mut bits: u32 = 0;
        let mut idx = 0;
        for &b in &self.0 {
            buf = (buf << 8) | (b as u64);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out[idx] = CROCKFORD_ALPHABET[((buf >> bits) & 0x1F) as usize];
                idx += 1;
            }
        }
        if bits > 0 {
            out[idx] = CROCKFORD_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize];
            idx += 1;
        }
        debug_assert_eq!(idx, ENCODED_LEN_B32);
        // Alphabet is ASCII, so this is valid UTF-8.
        String::from_utf8(out.to_vec()).unwrap()
    }

    pub fn from_crockford(s: &str) -> Result<Self, Error> {
        if s.len() != ENCODED_LEN_B32 {
            return Err(Error::InvalidEncoding("Crockford length must be 66"));
        }
        let mut out = [0u8; SIZE_BYTES];
        let mut buf: u64 = 0;
        let mut bits: u32 = 0;
        let mut idx = 0;
        for &c in s.as_bytes() {
            let v = decode_crockford_char(c)?;
            buf = (buf << 5) | (v as u64);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out[idx] = ((buf >> bits) & 0xFF) as u8;
                idx += 1;
            }
        }
        if idx != SIZE_BYTES {
            return Err(Error::InvalidEncoding("Crockford decode short"));
        }
        if bits > 0 && (buf & ((1u64 << bits) - 1)) != 0 {
            return Err(Error::InvalidEncoding("Crockford overflow bits set"));
        }
        let v = out[6];
        if v != VARIANT_STANDARD && v != VARIANT_HLC {
            return Err(Error::UnknownVariant(v));
        }
        Ok(Pqid(out))
    }
}

impl Default for Pqid {
    fn default() -> Self { Pqid::new() }
}

impl std::fmt::Debug for Pqid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pqid({})", self.to_base64url())
    }
}

impl std::fmt::Display for Pqid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64url())
    }
}

#[inline]
fn decode_crockford_char(c: u8) -> Result<u8, Error> {
    Ok(match c {
        b'0' | b'O' | b'o' => 0,
        b'1' | b'I' | b'i' | b'L' | b'l' => 1,
        b'2'..=b'9' => c - b'0',
        b'A'..=b'H' => c - b'A' + 10,
        b'a'..=b'h' => c - b'a' + 10,
        b'J' | b'j' => 18,
        b'K' | b'k' => 19,
        b'M' | b'm' => 20,
        b'N' | b'n' => 21,
        b'P' | b'p' => 22,
        b'Q' | b'q' => 23,
        b'R' | b'r' => 24,
        b'S' | b's' => 25,
        b'T' | b't' => 26,
        b'V' | b'v' => 27,
        b'W' | b'w' => 28,
        b'X' | b'x' => 29,
        b'Y' | b'y' => 30,
        b'Z' | b'z' => 31,
        _ => return Err(Error::InvalidEncoding("invalid Crockford char")),
    })
}

#[inline]
fn read_timestamp(b: &[u8]) -> i64 {
    ((b[0] as i64) << 40)
        | ((b[1] as i64) << 32)
        | ((b[2] as i64) << 24)
        | ((b[3] as i64) << 16)
        | ((b[4] as i64) << 8)
        | (b[5] as i64)
}

#[inline]
fn write_header(out: &mut [u8], ts: i64, variant: u8, counter: u16) {
    out[0] = (ts >> 40) as u8;
    out[1] = (ts >> 32) as u8;
    out[2] = (ts >> 24) as u8;
    out[3] = (ts >> 16) as u8;
    out[4] = (ts >> 8) as u8;
    out[5] = ts as u8;
    out[6] = variant;
    out[7] = (counter >> 8) as u8;
    out[8] = counter as u8;
}

use std::sync::atomic::{AtomicI64, Ordering};

/// Test-only clock override. When `OVERRIDE_NOW_MS` is non-negative,
/// `now_ms()` returns its value; otherwise it returns the real wall clock.
/// Conformance tests use this to drive HLC overflow scenarios.
static OVERRIDE_NOW_MS: AtomicI64 = AtomicI64::new(-1);

/// Override the clock source. Test-only. Pass `-1` to restore the real clock.
pub fn set_now_ms_for_testing(value_ms: i64) {
    OVERRIDE_NOW_MS.store(value_ms, Ordering::SeqCst);
}

#[inline]
fn now_ms() -> i64 {
    let override_val = OVERRIDE_NOW_MS.load(Ordering::SeqCst);
    if override_val >= 0 {
        return override_val;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Stateful generator for Standard PQIDs.
#[derive(Default)]
pub struct StandardGenerator {
    last_ts: i64,
    counter: u16,
}

impl StandardGenerator {
    pub const fn new() -> Self {
        StandardGenerator { last_ts: 0, counter: 0 }
    }

    pub fn new_id(&mut self) -> Result<Pqid, Error> {
        let mut out = [0u8; SIZE_BYTES];
        let mut rnd = [0u8; RANDOM_FIELD_BYTES + 1];
        getrandom::fill(&mut rnd)?;

        let mut ts = now_ms();
        if ts < self.last_ts {
            ts = self.last_ts;
        }

        if ts == self.last_ts {
            let step = 1u16 + ((rnd[0] & 0x0F) as u16);
            match self.counter.checked_add(step) {
                Some(c) => self.counter = c,
                None => {
                    while now_ms() == ts {
                        std::hint::spin_loop();
                    }
                    ts = now_ms();
                    self.counter = rnd[0] as u16;
                }
            }
        } else {
            self.counter = rnd[0] as u16;
        }
        self.last_ts = ts;

        write_header(&mut out, ts, VARIANT_STANDARD, self.counter);
        out[9..].copy_from_slice(&rnd[1..]);
        Ok(Pqid(out))
    }
}

/// Stateful generator for HLC PQIDs.
#[derive(Default)]
pub struct HlcGenerator {
    l: i64,
    c: u16,
}

impl HlcGenerator {
    pub const fn new() -> Self {
        HlcGenerator { l: 0, c: 0 }
    }

    /// Test-only: force the internal (l, c) state. Production code should
    /// never need this.
    pub fn set_state_for_testing(&mut self, l: i64, c: u16) {
        self.l = l;
        self.c = c;
    }

    pub fn new_id(&mut self, observe: Option<&Pqid>) -> Result<Pqid, Error> {
        let mut out = [0u8; SIZE_BYTES];
        let mut rnd = [0u8; RANDOM_FIELD_BYTES];
        getrandom::fill(&mut rnd)?;

        let pt = now_ms();
        let l_old = self.l;
        let c_old = self.c;

        let (mut l_new, c_new) = if let Some(peer) = observe {
            let l_msg = read_timestamp(&peer.0);
            let c_msg = peer.counter();

            if l_msg - pt > HLC_MAX_DRIFT_MS {
                return Err(Error::HlcDrift { drift_ms: l_msg - pt });
            }

            let l_new = l_old.max(l_msg).max(pt);
            let c_new = if l_new == l_old && l_new == l_msg {
                c_old.max(c_msg).wrapping_add(1)
            } else if l_new == l_old {
                c_old.wrapping_add(1)
            } else if l_new == l_msg {
                c_msg.wrapping_add(1)
            } else {
                0
            };
            (l_new, c_new)
        } else if l_old > pt {
            (l_old, c_old.wrapping_add(1))
        } else {
            (pt, 0)
        };

        // Counter overflow: bump l by 1 ms.
        if c_new == 0 && l_new == l_old && c_old == MAX_COUNTER {
            l_new += 1;
        }

        self.l = l_new;
        self.c = c_new;

        write_header(&mut out, l_new, VARIANT_HLC, c_new);
        out[9..].copy_from_slice(&rnd);
        Ok(Pqid(out))
    }
}

thread_local! {
    static DEFAULT_STANDARD: Mutex<StandardGenerator> = Mutex::new(StandardGenerator::new());
    static DEFAULT_HLC: Mutex<HlcGenerator> = Mutex::new(HlcGenerator::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn size() {
        assert_eq!(Pqid::new().0.len(), SIZE_BYTES);
    }

    #[test]
    fn variant() {
        assert_eq!(Pqid::new().variant(), VARIANT_STANDARD);
        assert_eq!(Pqid::new_hlc(None).unwrap().variant(), VARIANT_HLC);
    }

    #[test]
    fn uniqueness() {
        const N: usize = 100_000;
        let mut g = StandardGenerator::new();
        let mut seen = HashSet::with_capacity(N);
        for _ in 0..N {
            let id = g.new_id().unwrap();
            assert!(seen.insert(id));
        }
    }

    #[test]
    fn monotonic() {
        let mut g = StandardGenerator::new();
        let mut prev = g.new_id().unwrap();
        for _ in 0..10_000 {
            let cur = g.new_id().unwrap();
            assert!(cur > prev);
            prev = cur;
        }
    }

    #[test]
    fn b64_roundtrip() {
        let id = Pqid::new();
        let s = id.to_base64url();
        assert_eq!(s.len(), ENCODED_LEN_B64);
        assert_eq!(Pqid::from_base64url(&s).unwrap(), id);
    }

    #[test]
    fn crockford_roundtrip() {
        let id = Pqid::new();
        let s = id.to_crockford();
        assert_eq!(s.len(), ENCODED_LEN_B32);
        assert_eq!(Pqid::from_crockford(&s).unwrap(), id);
        assert_eq!(Pqid::from_crockford(&s.to_lowercase()).unwrap(), id);
    }

    #[test]
    fn unknown_variant_rejected() {
        let id = Pqid::new();
        let mut bytes = id.0;
        bytes[6] = 0xFF;
        assert!(matches!(Pqid::from_bytes(&bytes), Err(Error::UnknownVariant(0xFF))));
    }

    #[test]
    fn hlc_drift() {
        let mut g = HlcGenerator::new();
        let mut peer = [0u8; SIZE_BYTES];
        let bad_ts = now_ms() + 120_000;
        write_header(&mut peer, bad_ts, VARIANT_HLC, 0);
        let peer = Pqid(peer);
        assert!(matches!(g.new_id(Some(&peer)), Err(Error::HlcDrift { .. })));
    }
}
