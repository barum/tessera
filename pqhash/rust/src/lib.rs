//! PQHash — Post-Quantum Content Identifier (Rust implementation).
//!
//! 73-byte sortable content identifier with a 512-bit SHAKE-256 tail.
//! Variant byte 0x03. Sibling to PQID, NOT a hash function. See spec
//! sec03 / sec:pqhash.

use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

pub const PQHASH_SIZE_BYTES: usize = 73;
pub const PQHASH_TAIL_BYTES: usize = 64;
pub const PQHASH_TAIL_OFFSET: usize = 9;

pub const VARIANT_PQHASH: u8 = 0x03;

pub const PQHASH_ENCODED_LEN_B64: usize = 98;
pub const PQHASH_ENCODED_LEN_B32: usize = 117;

pub const PQHASH_MIN_TIMESTAMP_MS: i64 = 1_700_000_000_000;

const MAX_COUNTER: u16 = u16::MAX;
const MAX_TIMESTAMP_MS: u64 = (1u64 << 48) - 1;

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqhashError {
    InvalidLength { got: usize, want: usize },
    UnknownVariant(u8),
    InvalidEncoding(&'static str),
}

impl std::fmt::Display for PqhashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqhashError::InvalidLength { got, want } => {
                write!(f, "pqhash: invalid length: got {}, want {}", got, want)
            }
            PqhashError::UnknownVariant(v) => write!(f, "pqhash: variant must be 0x03, got 0x{:02x}", v),
            PqhashError::InvalidEncoding(s) => write!(f, "pqhash: invalid encoding: {}", s),
        }
    }
}

impl std::error::Error for PqhashError {}

/// A 73-byte PQHash.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pqhash(pub [u8; PQHASH_SIZE_BYTES]);

impl std::fmt::Debug for Pqhash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pqhash({})", self.to_base64url())
    }
}

static OVERRIDE_NOW_MS_PQHASH: AtomicI64 = AtomicI64::new(-1);

pub fn set_pqhash_now_ms_for_testing(value_ms: i64) {
    OVERRIDE_NOW_MS_PQHASH.store(value_ms, Ordering::SeqCst);
}

fn now_ms_pqhash() -> i64 {
    let o = OVERRIDE_NOW_MS_PQHASH.load(Ordering::SeqCst);
    if o >= 0 { return o; }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn shake256_64(content: &[u8]) -> [u8; PQHASH_TAIL_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(content);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; PQHASH_TAIL_BYTES];
    reader.read(&mut out);
    out
}

fn write_header(out: &mut [u8], ts: u64, counter: u16) {
    out[0] = (ts >> 40) as u8;
    out[1] = (ts >> 32) as u8;
    out[2] = (ts >> 24) as u8;
    out[3] = (ts >> 16) as u8;
    out[4] = (ts >> 8) as u8;
    out[5] = ts as u8;
    out[6] = VARIANT_PQHASH;
    out[7] = (counter >> 8) as u8;
    out[8] = counter as u8;
}

fn read_timestamp(b: &[u8]) -> i64 {
    ((b[0] as i64) << 40)
        | ((b[1] as i64) << 32)
        | ((b[2] as i64) << 24)
        | ((b[3] as i64) << 16)
        | ((b[4] as i64) << 8)
        | (b[5] as i64)
}

/// Stateless: 64-byte SHAKE-256 digest of content.
pub fn hash_only(content: &[u8]) -> [u8; PQHASH_TAIL_BYTES] {
    shake256_64(content)
}

/// Construct a PQHash with an explicit (timestamp_ms, counter).
pub fn hash_at(content: &[u8], timestamp_ms: u64, counter: u16) -> Result<Pqhash, PqhashError> {
    if timestamp_ms > MAX_TIMESTAMP_MS {
        return Err(PqhashError::InvalidEncoding("timestamp_ms out of range"));
    }
    let mut out = [0u8; PQHASH_SIZE_BYTES];
    write_header(&mut out, timestamp_ms, counter);
    let tail = shake256_64(content);
    out[PQHASH_TAIL_OFFSET..].copy_from_slice(&tail);
    Ok(Pqhash(out))
}

/// Generator for PQHash. Internally locked.
pub struct PqhashGenerator {
    inner: Mutex<PqhashGenState>,
}
struct PqhashGenState { last_ts: u64, counter: u16 }

impl Default for PqhashGenerator {
    fn default() -> Self { Self::new() }
}

impl PqhashGenerator {
    pub fn new() -> Self {
        PqhashGenerator { inner: Mutex::new(PqhashGenState { last_ts: 0, counter: 0 }) }
    }

    pub fn set_state_for_testing(&self, ts: u64, counter: u16) {
        let mut s = self.inner.lock().unwrap();
        s.last_ts = ts;
        s.counter = counter;
    }

    pub fn new_id(&self, content: &[u8]) -> Pqhash {
        let tail = shake256_64(content);
        let mut s = self.inner.lock().unwrap();
        let mut ts = now_ms_pqhash() as u64;
        if ts < s.last_ts { ts = s.last_ts; }
        if ts == s.last_ts {
            let next: u32 = s.counter as u32 + 1;
            if next > MAX_COUNTER as u32 {
                loop {
                    ts = now_ms_pqhash() as u64;
                    if ts > s.last_ts { break; }
                }
                s.counter = 0;
            } else {
                s.counter = next as u16;
            }
        } else {
            s.counter = 0;
        }
        s.last_ts = ts;

        let mut out = [0u8; PQHASH_SIZE_BYTES];
        write_header(&mut out, ts, s.counter);
        out[PQHASH_TAIL_OFFSET..].copy_from_slice(&tail);
        Pqhash(out)
    }
}

impl Pqhash {
    #[inline] pub fn variant(&self) -> u8 { self.0[6] }
    #[inline] pub fn timestamp_ms(&self) -> i64 { read_timestamp(&self.0) }
    #[inline] pub fn counter(&self) -> u16 { u16::from_be_bytes([self.0[7], self.0[8]]) }
    #[inline] pub fn tail(&self) -> &[u8; PQHASH_TAIL_BYTES] {
        <&[u8; PQHASH_TAIL_BYTES]>::try_from(&self.0[PQHASH_TAIL_OFFSET..]).unwrap()
    }
    #[inline] pub fn as_bytes(&self) -> &[u8; PQHASH_SIZE_BYTES] { &self.0 }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqhashError> {
        if bytes.len() != PQHASH_SIZE_BYTES {
            return Err(PqhashError::InvalidLength { got: bytes.len(), want: PQHASH_SIZE_BYTES });
        }
        if bytes[6] != VARIANT_PQHASH {
            return Err(PqhashError::UnknownVariant(bytes[6]));
        }
        let mut arr = [0u8; PQHASH_SIZE_BYTES];
        arr.copy_from_slice(bytes);
        Ok(Pqhash(arr))
    }

    /// Constant-time verify of the tail against SHAKE-256(content).
    pub fn verify(&self, content: &[u8]) -> bool {
        if self.0[6] != VARIANT_PQHASH { return false; }
        let expected = shake256_64(content);
        let mut diff: u8 = 0;
        for i in 0..PQHASH_TAIL_BYTES {
            diff |= self.0[PQHASH_TAIL_OFFSET + i] ^ expected[i];
        }
        diff == 0
    }

    pub fn validate_min_timestamp(&self) -> bool {
        self.timestamp_ms() >= PQHASH_MIN_TIMESTAMP_MS
    }

    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base64url(s: &str) -> Result<Self, PqhashError> {
        if s.len() != PQHASH_ENCODED_LEN_B64 {
            return Err(PqhashError::InvalidEncoding("Base64URL length must be 98"));
        }
        let bytes = URL_SAFE_NO_PAD.decode(s)
            .map_err(|_| PqhashError::InvalidEncoding("Base64URL decode failed"))?;
        if bytes.len() != PQHASH_SIZE_BYTES {
            return Err(PqhashError::InvalidEncoding("decoded length mismatch"));
        }
        let p = Self::from_bytes(&bytes)?;
        // Bijection check: re-encoding must reproduce the input exactly.
        if p.to_base64url() != s {
            return Err(PqhashError::InvalidEncoding("non-canonical Base64URL (pad bits non-zero)"));
        }
        Ok(p)
    }

    pub fn to_crockford(&self) -> String {
        let mut out = [0u8; PQHASH_ENCODED_LEN_B32];
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
        debug_assert_eq!(idx, PQHASH_ENCODED_LEN_B32);
        String::from_utf8(out.to_vec()).unwrap()
    }

    pub fn from_crockford(s: &str) -> Result<Self, PqhashError> {
        if s.len() != PQHASH_ENCODED_LEN_B32 {
            return Err(PqhashError::InvalidEncoding("Crockford length must be 117"));
        }
        let mut out = [0u8; PQHASH_SIZE_BYTES];
        let mut buf: u64 = 0;
        let mut bits: u32 = 0;
        let mut idx = 0;
        for &c in s.as_bytes() {
            let v = decode_crockford_char(c)?;
            buf = (buf << 5) | (v as u64);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                if idx >= PQHASH_SIZE_BYTES {
                    return Err(PqhashError::InvalidEncoding("Crockford overflow"));
                }
                out[idx] = ((buf >> bits) & 0xFF) as u8;
                idx += 1;
            }
        }
        if idx != PQHASH_SIZE_BYTES {
            return Err(PqhashError::InvalidEncoding("Crockford decode short"));
        }
        if bits > 0 && (buf & ((1u64 << bits) - 1)) != 0 {
            return Err(PqhashError::InvalidEncoding("non-canonical Crockford (pad bits non-zero)"));
        }
        if out[6] != VARIANT_PQHASH {
            return Err(PqhashError::UnknownVariant(out[6]));
        }
        Ok(Pqhash(out))
    }
}

#[inline]
fn decode_crockford_char(c: u8) -> Result<u8, PqhashError> {
    Ok(match c {
        b'0' | b'O' | b'o' => 0,
        b'1' | b'I' | b'i' | b'L' | b'l' => 1,
        b'2'..=b'9' => c - b'0',
        b'A'..=b'H' => c - b'A' + 10,
        b'a'..=b'h' => c - b'a' + 10,
        b'J' | b'j' => 18, b'K' | b'k' => 19,
        b'M' | b'm' => 20, b'N' | b'n' => 21,
        b'P' | b'p' => 22, b'Q' | b'q' => 23,
        b'R' | b'r' => 24, b'S' | b's' => 25,
        b'T' | b't' => 26, b'V' | b'v' => 27,
        b'W' | b'w' => 28, b'X' | b'x' => 29,
        b'Y' | b'y' => 30, b'Z' | b'z' => 31,
        _ => return Err(PqhashError::InvalidEncoding("invalid Crockford char")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_and_variant() {
        let g = PqhashGenerator::new();
        let p = g.new_id(b"hello");
        assert_eq!(p.as_bytes().len(), 73);
        assert_eq!(p.variant(), 0x03);
    }

    #[test]
    fn determinism() {
        let g1 = PqhashGenerator::new();
        let g2 = PqhashGenerator::new();
        let h1 = g1.new_id(b"hello, world");
        let h2 = g2.new_id(b"hello, world");
        assert_eq!(h1.tail(), h2.tail());
        let t = hash_only(b"hello, world");
        assert_eq!(h1.tail(), &t);
    }

    #[test]
    fn verify_constant_time() {
        let g = PqhashGenerator::new();
        let p = g.new_id(b"verify me");
        assert!(p.verify(b"verify me"));
        assert!(!p.verify(b"verify mE"));
    }

    #[test]
    fn roundtrip() {
        let g = PqhashGenerator::new();
        let p = g.new_id(b"roundtrip");
        assert_eq!(Pqhash::from_base64url(&p.to_base64url()).unwrap(), p);
        assert_eq!(Pqhash::from_crockford(&p.to_crockford()).unwrap(), p);
    }
}
