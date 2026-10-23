//! TesseraMark — keyed compact forensic mark (variant byte `0x05`).
//!
//! A TesseraMark is a short (24–64 bit) keyed code for low-bandwidth forensic channels (A/B
//! segment watermarks, audio, image, text). It is a keyed permutation of a per-asset allocation
//! index, so codes are unique per asset, look random, and invert to the index without a search.
//! The variant byte appears only in the 16-byte storage [`Record`], never in the embedded word.
//! Normative text: `tessera-mark/SPEC.md`.

mod error;
mod ff1;
pub mod kmac;
mod mark;
mod profile;
mod record;

pub use error::MarkError;
pub use ff1::Ff1;
pub use mark::{AssetKey, Decoded, FEISTEL_ROUNDS, MIN_KEY_LEN, Mark, PrpMode};
pub use profile::Profile;
pub use record::{
    RECORD_LEN, Record, VARIANT_MARK, asset_tag, false_match_probability, from_text, to_text,
};
