//! Profiles (SPEC §2).

use crate::MarkError;

/// A TesseraMark profile: code width `n` and check width `c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    Tm24,
    Tm32,
    Tm40,
    Tm48,
    Tm64,
}

impl Profile {
    /// All profiles in PROFILE-byte order.
    pub const ALL: [Profile; 5] = [Self::Tm24, Self::Tm32, Self::Tm40, Self::Tm48, Self::Tm64];

    /// PROFILE byte.
    pub fn id(self) -> u8 {
        match self {
            Self::Tm24 => 0x01,
            Self::Tm32 => 0x02,
            Self::Tm40 => 0x03,
            Self::Tm48 => 0x04,
            Self::Tm64 => 0x05,
        }
    }

    /// Profile from its PROFILE byte.
    pub fn from_id(id: u8) -> Result<Self, MarkError> {
        Self::ALL
            .into_iter()
            .find(|p| p.id() == id)
            .ok_or(MarkError::UnknownProfile)
    }

    /// Name, e.g. `"TM32"`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Tm24 => "TM24",
            Self::Tm32 => "TM32",
            Self::Tm40 => "TM40",
            Self::Tm48 => "TM48",
            Self::Tm64 => "TM64",
        }
    }

    /// Profile from its name (case-insensitive).
    pub fn from_name(name: &str) -> Result<Self, MarkError> {
        Self::ALL
            .into_iter()
            .find(|p| p.name().eq_ignore_ascii_case(name))
            .ok_or(MarkError::UnknownProfile)
    }

    /// Code bits `n`.
    pub fn code_bits(self) -> u32 {
        match self {
            Self::Tm24 => 24,
            Self::Tm32 => 32,
            Self::Tm40 => 40,
            Self::Tm48 => 48,
            Self::Tm64 => 64,
        }
    }

    /// Check bits `c`.
    pub fn check_bits(self) -> u32 {
        if self == Self::Tm24 { 12 } else { 16 }
    }

    /// Channel word length `L = n + c`.
    pub fn channel_bits(self) -> u32 {
        self.code_bits() + self.check_bits()
    }

    /// Maximum erasures the direct decoder brute-forces (`c - 12`).
    pub fn max_erasures(self) -> u32 {
        self.check_bits().saturating_sub(12)
    }

    /// Largest valid code / index (`2^n - 1`).
    pub fn max_code(self) -> u64 {
        if self.code_bits() == 64 {
            u64::MAX
        } else {
            (1u64 << self.code_bits()) - 1
        }
    }

    pub(crate) fn code_bytes(self) -> usize {
        self.code_bits().div_ceil(8) as usize
    }
}
