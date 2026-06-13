//! TesseraSeal v1 — Rust reference implementation.
//!
//! Pure post-quantum encryption envelope: ML-KEM-1024 + AES-256-GCM (or
//! ChaCha20-Poly1305) + a 32-byte UtC commitment tag, with deterministic
//! AEAD nonce derived via HKDF-SHA3-256.
//!
//! Authority order: whitepaper -> python/tessera_seal.py -> c/tessera_seal.h -> THIS.
//! Cross-language KAT vectors live under ../conformance/vectors/.

#![forbid(unsafe_code)]

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{Aes256Gcm, Key as AesKey, aead::{Aead, KeyInit as AeadKeyInit, Payload}};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as MacKeyInit;
use ml_kem::{
    MlKem1024,
    kem::{Decapsulate, FromSeed, KeyExport},
};
use ml_kem::array::Array;
use sha3::{Sha3_256, Shake256};
use sha3::digest::{ExtendableOutput, Update as DigestUpdate, XofReader};

type EncapsulationKey1024 = ml_kem::kem::EncapsulationKey<MlKem1024>;
type DecapsulationKey1024 = ml_kem::kem::DecapsulationKey<MlKem1024>;
type HmacSha3_256 = Hmac<Sha3_256>;

// ---------------------------------------------------------------------------
// Constants (must match python/tessera_seal.py and c/tessera_seal.h byte-for-byte).
// ---------------------------------------------------------------------------

pub const VARIANT_TESSERA_SEAL: u8 = 0x04;
pub const SUITE_MLKEM1024_AESGCM: u8 = 0x01;
pub const SUITE_MLKEM1024_CHACHA: u8 = 0x02;
pub const SUITE_HYBRID_X25519_MLKEM1024_AESGCM: u8 = 0x06;
pub const HEADER_BYTES: usize = 16;
pub const MLKEM1024_PK_BYTES: usize = 1568;
pub const MLKEM1024_SK_BYTES: usize = 3168;
pub const MLKEM1024_CT_BYTES: usize = 1568;
pub const MLKEM1024_SS_BYTES: usize = 32;
pub const MLKEM1024_SEED_BYTES: usize = 64;
pub const X25519_PK_BYTES: usize = 32;
pub const X25519_SK_BYTES: usize = 32;
pub const X25519_SS_BYTES: usize = 32;
pub const HYBRID_PK_BYTES: usize = MLKEM1024_PK_BYTES + X25519_PK_BYTES;       // 1600
pub const HYBRID_SK_BYTES: usize = MLKEM1024_SK_BYTES + X25519_SK_BYTES;       // 3200
pub const HYBRID_CT_BYTES: usize = MLKEM1024_CT_BYTES + X25519_PK_BYTES;       // 1600
pub const HYBRID_SEED_BYTES: usize = MLKEM1024_SEED_BYTES + X25519_SK_BYTES;   // 96
pub const AEAD_NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;
pub const COMMIT_BYTES: usize = 32;
pub const MAX_KEM_CT_LEN: usize = 4096;
pub const MAX_AD_LEN: usize = 65_536;
pub const MAX_PLAINTEXT: u64 = 4 * 1024 * 1024 * 1024;

const SALT_LABEL: &[u8] = b"pqcrypt v1 header";              // frozen v1 wire tag — not a rebrandable name
const INFO_AEAD_KEY: &[u8] = b"pqcrypt v1 aead k";           // frozen v1 wire tag — not a rebrandable name
const INFO_AEAD_NONCE: &[u8] = b"pqcrypt v1 aead n";         // frozen v1 wire tag — not a rebrandable name
const INFO_COMMIT_KEY: &[u8] = b"pqcrypt v1 commit";         // frozen v1 wire tag — not a rebrandable name
const INFO_TIMING_PAD: &[u8] = b"pqcrypt v1 timing pad";     // frozen v1 wire tag — not a rebrandable name
const HYBRID_COMBINER_LABEL: &[u8] = b"pqcrypt v1 hybrid combiner"; // frozen v1 wire tag — not a rebrandable name

#[inline]
fn is_hybrid(suite: u8) -> bool { suite == SUITE_HYBRID_X25519_MLKEM1024_AESGCM }

#[inline]
fn kem_ct_size_for(suite: u8) -> usize {
    if is_hybrid(suite) { HYBRID_CT_BYTES } else { MLKEM1024_CT_BYTES }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    UnknownVariant(u8),
    UnknownSuite(u8),
    InvalidLength(&'static str),
    /// Single class for every authentication-class failure.
    DecryptFailed,
    BadKey(&'static str),
    Internal(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownVariant(v) => write!(f, "tessera_seal: unknown variant byte 0x{:02x}", v),
            Error::UnknownSuite(v)   => write!(f, "tessera_seal: unknown suite byte 0x{:02x}", v),
            Error::InvalidLength(s)  => write!(f, "tessera_seal: invalid length: {}", s),
            Error::DecryptFailed     => write!(f, "tessera_seal: envelope failed authentication"),
            Error::BadKey(s)         => write!(f, "tessera_seal: bad key: {}", s),
            Error::Internal(s)       => write!(f, "tessera_seal: internal: {}", s),
        }
    }
}

impl std::error::Error for Error {}

fn check_suite(suite: u8) -> Result<(), Error> {
    if suite == SUITE_MLKEM1024_AESGCM
        || suite == SUITE_MLKEM1024_CHACHA
        || suite == SUITE_HYBRID_X25519_MLKEM1024_AESGCM
    {
        Ok(())
    } else {
        Err(Error::UnknownSuite(suite))
    }
}

#[inline]
fn aead_is_aesgcm(suite: u8) -> bool {
    suite == SUITE_MLKEM1024_AESGCM || suite == SUITE_HYBRID_X25519_MLKEM1024_AESGCM
}

// ---------------------------------------------------------------------------
// Clock (test override)
// ---------------------------------------------------------------------------

static CLOCK_OVERRIDE: Mutex<Option<u64>> = Mutex::new(None);

pub fn set_now_ms_for_testing(value: Option<u64>) {
    *CLOCK_OVERRIDE.lock().unwrap() = value;
}

fn now_ms() -> u64 {
    if let Some(v) = *CLOCK_OVERRIDE.lock().unwrap() {
        return v;
    }
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

pub struct PublicKey {
    inner: EncapsulationKey1024,
    /// X25519 public key, present iff `suite == SUITE_HYBRID_*`.
    x_pub: Option<[u8; X25519_PK_BYTES]>,
    pub suite: u8,
}

pub struct PrivateKey {
    inner: DecapsulationKey1024,
    seed: Vec<u8>,
    /// X25519 scalar, present iff `suite == SUITE_HYBRID_*`.
    x_priv: Option<[u8; X25519_SK_BYTES]>,
    pub suite: u8,
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.inner.to_bytes().to_vec();
        if let Some(xp) = self.x_pub { out.extend_from_slice(&xp); }
        out
    }
    pub fn from_bytes(bytes: &[u8], suite: u8) -> Result<Self, Error> {
        check_suite(suite)?;
        if is_hybrid(suite) {
            if bytes.len() != HYBRID_PK_BYTES {
                return Err(Error::BadKey("hybrid ek must be 1600 bytes"));
            }
            let arr = Array::<u8, _>::try_from(&bytes[..MLKEM1024_PK_BYTES])
                .map_err(|_| Error::BadKey("ek size"))?;
            let inner = EncapsulationKey1024::new(&arr)
                .map_err(|_| Error::BadKey("ek rebuild"))?;
            let mut xp = [0u8; X25519_PK_BYTES];
            xp.copy_from_slice(&bytes[MLKEM1024_PK_BYTES..]);
            Ok(Self { inner, x_pub: Some(xp), suite })
        } else {
            if bytes.len() != MLKEM1024_PK_BYTES {
                return Err(Error::BadKey("ek must be 1568 bytes"));
            }
            let arr = Array::<u8, _>::try_from(bytes)
                .map_err(|_| Error::BadKey("ek size"))?;
            let inner = EncapsulationKey1024::new(&arr)
                .map_err(|_| Error::BadKey("ek rebuild"))?;
            Ok(Self { inner, x_pub: None, suite })
        }
    }
}

impl PrivateKey {
    /// Returns the seed bytes (64 for non-hybrid, 96 for hybrid).
    pub fn seed(&self) -> &[u8] { &self.seed }
}

/// Generate a fresh keypair via OS CSPRNG.
pub fn generate_keypair(suite: u8) -> Result<(PrivateKey, PublicKey), Error> {
    check_suite(suite)?;
    let seed_len = if is_hybrid(suite) { HYBRID_SEED_BYTES } else { MLKEM1024_SEED_BYTES };
    let mut seed = vec![0u8; seed_len];
    fill_random(&mut seed)?;
    generate_keypair_from_seed(&seed, suite)
}

fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    // Per umbrella security invariant #1: OS CSPRNG only, no userspace PRNG.
    // `getrandom::fill` routes to getentropy / getrandom(2) / BCryptGenRandom
    // per platform (TSEAL-00041) — no direct /dev/urandom device reads, and
    // failure surfaces an error instead of producing output.
    getrandom::fill(buf).map_err(|_| Error::Internal("CSPRNG"))
}

/// Deterministic keypair from a seed.
///
/// Non-hybrid suites: 64-byte FIPS 203 seed (d || z).
/// Hybrid suite 0x06: 96-byte seed (64-byte ML-KEM seed || 32-byte X25519 scalar).
pub fn generate_keypair_from_seed(seed: &[u8], suite: u8) -> Result<(PrivateKey, PublicKey), Error> {
    check_suite(suite)?;
    if is_hybrid(suite) {
        if seed.len() != HYBRID_SEED_BYTES {
            return Err(Error::BadKey("hybrid seed must be 96 bytes (64 ML-KEM || 32 X25519)"));
        }
        let mlkem_seed = &seed[..MLKEM1024_SEED_BYTES];
        let x_scalar: [u8; X25519_SK_BYTES] = seed[MLKEM1024_SEED_BYTES..].try_into()
            .map_err(|_| Error::BadKey("x25519 scalar size"))?;
        let seed_arr = Array::<u8, _>::try_from(mlkem_seed)
            .map_err(|_| Error::BadKey("ml-kem seed size"))?;
        let (dk, ek) = MlKem1024::from_seed(&seed_arr);
        // X25519 derives the public key from the scalar (with RFC 7748 clamping
        // applied by x25519_dalek internally on use).
        let x_priv = x25519_dalek::StaticSecret::from(x_scalar);
        let x_pub_pt = x25519_dalek::PublicKey::from(&x_priv);
        let x_pub_bytes = x_pub_pt.to_bytes();
        Ok((
            PrivateKey { inner: dk, seed: seed.to_vec(), x_priv: Some(x_scalar), suite },
            PublicKey  { inner: ek, x_pub: Some(x_pub_bytes), suite },
        ))
    } else {
        if seed.len() != MLKEM1024_SEED_BYTES {
            return Err(Error::BadKey("seed must be 64 bytes"));
        }
        let seed_arr = Array::<u8, _>::try_from(seed)
            .map_err(|_| Error::BadKey("seed size"))?;
        let (dk, ek) = MlKem1024::from_seed(&seed_arr);
        Ok((
            PrivateKey { inner: dk, seed: seed.to_vec(), x_priv: None, suite },
            PublicKey  { inner: ek, x_pub: None, suite },
        ))
    }
}

// ---------------------------------------------------------------------------
// Hybrid KEM helpers (suite 0x06)
// ---------------------------------------------------------------------------

fn hybrid_combine(ss_mlkem: &[u8], x_ss: &[u8], ml_kem_ct: &[u8], x_eph_pk: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        HYBRID_COMBINER_LABEL.len() + ss_mlkem.len() + x_ss.len()
            + ml_kem_ct.len() + x_eph_pk.len()
    );
    msg.extend_from_slice(HYBRID_COMBINER_LABEL);
    msg.extend_from_slice(ss_mlkem);
    msg.extend_from_slice(x_ss);
    msg.extend_from_slice(ml_kem_ct);
    msg.extend_from_slice(x_eph_pk);
    shake256(&msg, 32)
}

/// Suite-aware KEM Encaps. Returns `(ss_session_32, kem_ct)`. For hybrid,
/// `kem_ct = ml_kem_ct || x25519_ephemeral_pk` (1600 bytes).
fn suite_encaps(suite: u8, recipient_pub: &PublicKey) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // ML-KEM Encaps with fresh 32 bytes from the OS CSPRNG.
    let mut m = [0u8; 32];
    fill_random(&mut m)?;
    let m_arr = Array::<u8, _>::try_from(&m[..])
        .map_err(|_| Error::Internal("encaps randomness size"))?;
    let (ct, ss) = recipient_pub.inner.encapsulate_deterministic(&m_arr);
    let ml_kem_ct: Vec<u8> = ct.to_vec();
    let ss_mlkem: Vec<u8> = ss.to_vec();
    if ml_kem_ct.len() != MLKEM1024_CT_BYTES || ss_mlkem.len() != MLKEM1024_SS_BYTES {
        return Err(Error::Internal("ML-KEM sizes"));
    }
    if !is_hybrid(suite) {
        return Ok((ss_mlkem, ml_kem_ct));
    }
    let x_recipient = recipient_pub.x_pub
        .ok_or(Error::BadKey("hybrid pub missing X25519 half"))?;
    // Fresh ephemeral X25519 keypair via OS CSPRNG.
    let mut eph_scalar = [0u8; X25519_SK_BYTES];
    fill_random(&mut eph_scalar)?;
    let eph_priv = x25519_dalek::StaticSecret::from(eph_scalar);
    let eph_pub = x25519_dalek::PublicKey::from(&eph_priv);
    let eph_pub_bytes = eph_pub.to_bytes();
    let x_recipient_pt = x25519_dalek::PublicKey::from(x_recipient);
    let x_ss = eph_priv.diffie_hellman(&x_recipient_pt);
    let ss_session = hybrid_combine(&ss_mlkem, x_ss.as_bytes(), &ml_kem_ct, &eph_pub_bytes);

    let mut kem_ct = Vec::with_capacity(HYBRID_CT_BYTES);
    kem_ct.extend_from_slice(&ml_kem_ct);
    kem_ct.extend_from_slice(&eph_pub_bytes);
    Ok((ss_session, kem_ct))
}

/// Suite-aware KEM Decaps. Returns the 32-byte session shared secret.
fn suite_decaps(suite: u8, priv_key: &PrivateKey, kem_ct: &[u8]) -> Result<Vec<u8>, Error> {
    if !is_hybrid(suite) {
        let ct_arr = Array::<u8, _>::try_from(kem_ct)
            .map_err(|_| Error::InvalidLength("kem_ct size"))?;
        let ss = priv_key.inner.decapsulate(&ct_arr);
        return Ok(ss.to_vec());
    }
    if kem_ct.len() != HYBRID_CT_BYTES {
        return Err(Error::InvalidLength("hybrid kem_ct must be 1600 bytes"));
    }
    let ml_kem_ct = &kem_ct[..MLKEM1024_CT_BYTES];
    let x_eph_pk_bytes: [u8; X25519_PK_BYTES] = kem_ct[MLKEM1024_CT_BYTES..]
        .try_into().map_err(|_| Error::InvalidLength("x eph pk size"))?;
    let ct_arr = Array::<u8, _>::try_from(ml_kem_ct)
        .map_err(|_| Error::InvalidLength("ml-kem ct size"))?;
    let ss_mlkem = priv_key.inner.decapsulate(&ct_arr);
    let x_scalar = priv_key.x_priv
        .ok_or(Error::BadKey("hybrid priv missing X25519 half"))?;
    let x_priv_pt = x25519_dalek::StaticSecret::from(x_scalar);
    let x_eph_pub_pt = x25519_dalek::PublicKey::from(x_eph_pk_bytes);
    let x_ss = x_priv_pt.diffie_hellman(&x_eph_pub_pt);
    Ok(hybrid_combine(&ss_mlkem.to_vec(), x_ss.as_bytes(), ml_kem_ct, &x_eph_pk_bytes))
}

// ---------------------------------------------------------------------------
// Header pack/unpack
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct DecodedHeader {
    pub timestamp_ms: u64,
    pub variant: u8,
    pub suite: u8,
    pub counter: u16,
    pub kem_ct_len: u16,
    pub ad_len: u32,
}

fn pack_header(out: &mut [u8; HEADER_BYTES], ts_ms: u64, variant: u8, suite: u8,
               counter: u16, kem_ct_len: u16, ad_len: u32) {
    out[0] = (ts_ms >> 40) as u8; out[1] = (ts_ms >> 32) as u8;
    out[2] = (ts_ms >> 24) as u8; out[3] = (ts_ms >> 16) as u8;
    out[4] = (ts_ms >> 8) as u8;  out[5] = ts_ms as u8;
    out[6] = variant; out[7] = suite;
    out[8] = (counter >> 8) as u8; out[9] = counter as u8;
    out[10] = (kem_ct_len >> 8) as u8; out[11] = kem_ct_len as u8;
    out[12] = (ad_len >> 24) as u8; out[13] = (ad_len >> 16) as u8;
    out[14] = (ad_len >> 8) as u8;  out[15] = ad_len as u8;
}

fn unpack_header(input: &[u8]) -> DecodedHeader {
    DecodedHeader {
        timestamp_ms: ((input[0] as u64) << 40) | ((input[1] as u64) << 32)
            | ((input[2] as u64) << 24) | ((input[3] as u64) << 16)
            | ((input[4] as u64) << 8) | input[5] as u64,
        variant: input[6],
        suite:   input[7],
        counter: ((input[8] as u16) << 8) | input[9] as u16,
        kem_ct_len: ((input[10] as u16) << 8) | input[11] as u16,
        ad_len: ((input[12] as u32) << 24) | ((input[13] as u32) << 16)
            | ((input[14] as u32) << 8) | input[15] as u32,
    }
}

pub fn peek_header(env: &[u8]) -> Result<DecodedHeader, Error> {
    if env.len() < HEADER_BYTES {
        return Err(Error::InvalidLength("envelope shorter than header"));
    }
    let h = unpack_header(&env[..HEADER_BYTES]);
    if h.variant != VARIANT_TESSERA_SEAL { return Err(Error::UnknownVariant(h.variant)); }
    check_suite(h.suite)?;
    // Pin KEM_CT_LEN to the suite-required KEM-ciphertext size (1568 for the pure
    // ML-KEM-1024 suites 0x01/0x02; 1600 for hybrid 0x06). Accepting any other
    // value would let a fixed-size KEM read run past the envelope buffer in
    // length-unsafe ports (CWE-125, TSEAL-00049). Subsumes the old > MAX bound.
    if (h.kem_ct_len as usize) != kem_ct_size_for(h.suite) { return Err(Error::InvalidLength("kem_ct_len")); }
    if h.ad_len as usize > MAX_AD_LEN { return Err(Error::InvalidLength("ad_len")); }
    Ok(h)
}

/// Returns a copy of the cleartext-on-wire associated-data bytes WITHOUT
/// decrypting — the routing-before-decrypt companion to [`peek_header`]
/// (TSEAL-00047). The canonical use case is the TesseraID-as-AD pattern:
/// route an envelope by the 41-byte TesseraID it is bound to, then decrypt.
///
/// WARNING: the returned bytes are UNAUTHENTICATED until [`decrypt`]
/// succeeds — every byte is attacker-controlled. Use them only for
/// routing/lookup; never act on them as trusted data.
///
/// Rejects exactly what [`peek_header`] rejects (unknown variant/suite, bad
/// declared lengths) plus [`Error::InvalidLength`] when the declared AD
/// region extends past the envelope (truncated input).
pub fn peek_ad(env: &[u8]) -> Result<Vec<u8>, Error> {
    let h = peek_header(env)?;
    let start = HEADER_BYTES + h.kem_ct_len as usize;
    let end = start + h.ad_len as usize;
    if env.len() < end {
        return Err(Error::InvalidLength("ad region extends past envelope end"));
    }
    Ok(env[start..end].to_vec())
}

pub fn validate(env: &[u8]) -> bool {
    let h = match peek_header(env) { Ok(h) => h, Err(_) => return false };
    let need = HEADER_BYTES + h.kem_ct_len as usize + h.ad_len as usize
        + AEAD_NONCE_BYTES + AEAD_TAG_BYTES + COMMIT_BYTES;
    env.len() >= need
}

pub fn validate_min_timestamp(env: &[u8], min_ms: u64) -> bool {
    let h = match peek_header(env) { Ok(h) => h, Err(_) => return false };
    h.timestamp_ms >= min_ms
}

pub fn envelope_size(pt_len: usize, ad_len: usize) -> usize {
    envelope_size_for_suite(SUITE_MLKEM1024_AESGCM, pt_len, ad_len)
}

pub fn envelope_size_for_suite(suite: u8, pt_len: usize, ad_len: usize) -> usize {
    HEADER_BYTES + kem_ct_size_for(suite) + ad_len + AEAD_NONCE_BYTES
        + pt_len + AEAD_TAG_BYTES + COMMIT_BYTES
}

// ---------------------------------------------------------------------------
// SHAKE-256, HKDF-SHA3-256, HMAC-SHA3-256
// ---------------------------------------------------------------------------

fn shake256(input: &[u8], len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    DigestUpdate::update(&mut h, input);
    let mut reader = h.finalize_xof();
    let mut out = vec![0u8; len];
    reader.read(&mut out);
    out
}

fn hmac_sha3_256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha3_256 as MacKeyInit>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    Mac::update(&mut mac, msg);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() { &[0u8; 32][..] } else { salt };
    hmac_sha3_256(salt, ikm)
}

fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    let hk = Hkdf::<Sha3_256>::from_prk(prk).map_err(|_| Error::Internal("HKDF prk"))?;
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out).map_err(|_| Error::Internal("HKDF expand"))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Session keys
// ---------------------------------------------------------------------------

struct SessionKeys { k_aead: Vec<u8>, nonce: Vec<u8>, k_commit: Vec<u8> }

fn derive_session_keys(header_bytes: &[u8], ss_mlkem: &[u8]) -> Result<SessionKeys, Error> {
    let mut salt_in = Vec::with_capacity(SALT_LABEL.len() + header_bytes.len());
    salt_in.extend_from_slice(SALT_LABEL);
    salt_in.extend_from_slice(header_bytes);
    let salt = shake256(&salt_in, 32);
    let prk = hkdf_extract(&salt, ss_mlkem);
    Ok(SessionKeys {
        k_aead:   hkdf_expand(&prk, INFO_AEAD_KEY, 32)?,
        nonce:    hkdf_expand(&prk, INFO_AEAD_NONCE, AEAD_NONCE_BYTES)?,
        k_commit: hkdf_expand(&prk, INFO_COMMIT_KEY, 32)?,
    })
}

#[allow(dead_code)]
fn derive_synthetic_keys(header_bytes: &[u8]) -> SessionKeys {
    let mut salt_in = Vec::new();
    salt_in.extend_from_slice(SALT_LABEL);
    salt_in.extend_from_slice(header_bytes);
    salt_in.extend_from_slice(INFO_TIMING_PAD);
    let salt = shake256(&salt_in, 32);
    let prk = hkdf_extract(&salt, &[0u8; 32]);
    SessionKeys {
        k_aead:   hkdf_expand(&prk, INFO_AEAD_KEY, 32).unwrap_or_default(),
        nonce:    hkdf_expand(&prk, INFO_AEAD_NONCE, AEAD_NONCE_BYTES).unwrap_or_default(),
        k_commit: hkdf_expand(&prk, INFO_COMMIT_KEY, 32).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// AEAD dispatch
// ---------------------------------------------------------------------------

fn aead_encrypt(suite: u8, key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let payload = Payload { msg: pt, aad };
    if aead_is_aesgcm(suite) {
        let k = AesKey::<Aes256Gcm>::from_slice(key);
        Aes256Gcm::new(k).encrypt(nonce.into(), payload)
            .map_err(|_| Error::Internal("AES-GCM encrypt"))
    } else if suite == SUITE_MLKEM1024_CHACHA {
        ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::Internal("ChaCha key"))?
            .encrypt(nonce.into(), payload)
            .map_err(|_| Error::Internal("ChaCha encrypt"))
    } else {
        Err(Error::UnknownSuite(suite))
    }
}

fn aead_decrypt(suite: u8, key: &[u8], nonce: &[u8], ct_with_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let payload = Payload { msg: ct_with_tag, aad };
    if aead_is_aesgcm(suite) {
        let k = AesKey::<Aes256Gcm>::from_slice(key);
        Aes256Gcm::new(k).decrypt(nonce.into(), payload)
            .map_err(|_| Error::DecryptFailed)
    } else if suite == SUITE_MLKEM1024_CHACHA {
        ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::Internal("ChaCha key"))?
            .decrypt(nonce.into(), payload)
            .map_err(|_| Error::DecryptFailed)
    } else {
        Err(Error::UnknownSuite(suite))
    }
}

// ---------------------------------------------------------------------------
// UtC commit
// ---------------------------------------------------------------------------

fn utc_commit(k_commit: &[u8], header: &[u8], kem_ct: &[u8], ad: &[u8], aead_ct: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha3_256 as MacKeyInit>::new_from_slice(k_commit).expect("HMAC key");
    Mac::update(&mut mac, header);
    Mac::update(&mut mac, kem_ct);
    Mac::update(&mut mac, ad);
    Mac::update(&mut mac, aead_ct);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

// ---------------------------------------------------------------------------
// Constant-time compare
// ---------------------------------------------------------------------------

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        let mut d: u8 = 0;
        for &x in a { d |= x ^ x; }
        let _ = d;
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
    diff == 0
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

pub fn encrypt(pt: &[u8], recipient_pub: &PublicKey, suite: u8, ad: &[u8],
               ts_ms: Option<u64>, counter: u16) -> Result<Vec<u8>, Error> {
    check_suite(suite)?;
    if recipient_pub.suite != suite {
        return Err(Error::BadKey("recipient key suite mismatch"));
    }
    if ad.len() > MAX_AD_LEN { return Err(Error::InvalidLength("ad too large")); }
    if pt.len() as u64 > MAX_PLAINTEXT { return Err(Error::InvalidLength("pt too large")); }
    let ts_ms = ts_ms.unwrap_or_else(now_ms);
    if ts_ms >= (1u64 << 48) { return Err(Error::InvalidLength("ts overflow")); }

    let (ss_session, kem_ct) = suite_encaps(suite, recipient_pub)?;

    let mut header = [0u8; HEADER_BYTES];
    pack_header(&mut header, ts_ms, VARIANT_TESSERA_SEAL, suite, counter,
                kem_ct.len() as u16, ad.len() as u32);

    let sk = derive_session_keys(&header, &ss_session)?;

    let mut aad = Vec::with_capacity(HEADER_BYTES + MLKEM1024_CT_BYTES + ad.len());
    aad.extend_from_slice(&header);
    aad.extend_from_slice(&kem_ct);
    aad.extend_from_slice(ad);

    let aead_blob = aead_encrypt(suite, &sk.k_aead, &sk.nonce, pt, &aad)?;
    if aead_blob.len() != pt.len() + AEAD_TAG_BYTES {
        return Err(Error::Internal("AEAD output length"));
    }
    let aead_ct = &aead_blob[..pt.len()];
    let aead_tag = &aead_blob[pt.len()..];

    let commit = utc_commit(&sk.k_commit, &header, &kem_ct, ad, aead_ct);

    let mut out = Vec::with_capacity(envelope_size_for_suite(suite, pt.len(), ad.len()));
    out.extend_from_slice(&header);
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(ad);
    out.extend_from_slice(&sk.nonce);
    out.extend_from_slice(aead_ct);
    out.extend_from_slice(aead_tag);
    out.extend_from_slice(&commit);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

pub fn decrypt(env: &[u8], priv_key: &PrivateKey, expected_ad: &[u8]) -> Result<Vec<u8>, Error> {
    if env.len() < HEADER_BYTES { return Err(Error::InvalidLength("short")); }
    let h = peek_header(env)?;
    let need = HEADER_BYTES + h.kem_ct_len as usize + h.ad_len as usize
        + AEAD_NONCE_BYTES + AEAD_TAG_BYTES + COMMIT_BYTES;
    if env.len() < need { return Err(Error::InvalidLength("truncated")); }
    let aead_ct_len = env.len() - need;

    let header_bytes = &env[..HEADER_BYTES];
    let mut p = HEADER_BYTES;
    let kem_ct = &env[p..p + h.kem_ct_len as usize]; p += h.kem_ct_len as usize;
    let ad = &env[p..p + h.ad_len as usize]; p += h.ad_len as usize;
    let nonce_wire = &env[p..p + AEAD_NONCE_BYTES]; p += AEAD_NONCE_BYTES;
    let aead_ct = &env[p..p + aead_ct_len]; p += aead_ct_len;
    let aead_tag = &env[p..p + AEAD_TAG_BYTES]; p += AEAD_TAG_BYTES;
    let commit_wire = &env[p..p + COMMIT_BYTES];

    // Suite-aware KEM Decaps. For non-hybrid suites the FO transform implicit-
    // rejects bad ML-KEM ct by producing a pseudorandom ss; the AEAD verify
    // catches it. For hybrid 0x06, ml-kem half goes through the same FO path
    // and the X25519 half can produce any 32-byte secret (small-subgroup /
    // identity points yield zero — still authenticated by the combiner under
    // SHAKE-256).
    if priv_key.suite != h.suite {
        return Err(Error::BadKey("private key suite mismatch"));
    }
    let ss_session = match suite_decaps(h.suite, priv_key, kem_ct) {
        Ok(v) => v,
        Err(Error::InvalidLength(_)) => return Err(Error::DecryptFailed),
        Err(e) => return Err(e),
    };

    let sk = derive_session_keys(header_bytes, &ss_session)?;

    let nonce_match = ct_eq(nonce_wire, &sk.nonce);
    let ad_match = if ad.len() == expected_ad.len() {
        ct_eq(ad, expected_ad)
    } else {
        let _ = ct_eq(ad, ad);
        false
    };

    let expected_commit = utc_commit(&sk.k_commit, header_bytes, kem_ct, ad, aead_ct);
    let commit_match = ct_eq(commit_wire, &expected_commit);

    let mut aad = Vec::with_capacity(HEADER_BYTES + h.kem_ct_len as usize + h.ad_len as usize);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(kem_ct);
    aad.extend_from_slice(ad);

    let mut ct_tag = Vec::with_capacity(aead_ct.len() + AEAD_TAG_BYTES);
    ct_tag.extend_from_slice(aead_ct);
    ct_tag.extend_from_slice(aead_tag);

    let pt_result = aead_decrypt(h.suite, &sk.k_aead, nonce_wire, &ct_tag, &aad);
    let aead_ok = pt_result.is_ok();

    if nonce_match && ad_match && commit_match && aead_ok {
        return Ok(pt_result.unwrap());
    }
    let _ = derive_synthetic_keys(header_bytes);
    Err(Error::DecryptFailed)
}

// ---------------------------------------------------------------------------
// SenderContext
// ---------------------------------------------------------------------------

pub struct SenderContext {
    pub suite: u8,
    state: Mutex<(u64, u16)>,
}

impl SenderContext {
    pub fn new(suite: u8) -> Result<Self, Error> {
        check_suite(suite)?;
        Ok(Self { suite, state: Mutex::new((0, 0)) })
    }
    fn next_ts_ctr(&self) -> (u64, u16) {
        let mut st = self.state.lock().unwrap();
        let now = now_ms();
        if now > st.0 {
            st.0 = now; st.1 = 0;
        } else {
            st.1 = st.1.wrapping_add(1);
            if st.1 == 0 { st.0 = st.0.wrapping_add(1); }
        }
        (st.0, st.1)
    }
    pub fn encrypt(&self, pt: &[u8], pub_key: &PublicKey, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let (ts, ctr) = self.next_ts_ctr();
        encrypt(pt, pub_key, self.suite, ad, Some(ts), ctr)
    }
}
