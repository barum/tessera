//! Error codes (SPEC §10). Messages never reveal more than the code.

use core::fmt;

/// Every TesseraMark failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkError {
    ShortKey,
    BadProfile,
    IndexRange,
    CodeRange,
    InvalidLen,
    UnknownVariant,
    UnknownProfile,
    Noncanonical,
    TooManyErasures,
    CheckFailed,
    Ambiguous,
    BadText,
    BadCheck,
}

impl MarkError {
    /// The SPEC §10 code string, e.g. `"CHECK_FAILED"`.
    pub fn code(self) -> &'static str {
        match self {
            Self::ShortKey => "SHORT_KEY",
            Self::BadProfile => "BAD_PROFILE",
            Self::IndexRange => "INDEX_RANGE",
            Self::CodeRange => "CODE_RANGE",
            Self::InvalidLen => "INVALID_LEN",
            Self::UnknownVariant => "UNKNOWN_VARIANT",
            Self::UnknownProfile => "UNKNOWN_PROFILE",
            Self::Noncanonical => "NONCANONICAL",
            Self::TooManyErasures => "TOO_MANY_ERASURES",
            Self::CheckFailed => "CHECK_FAILED",
            Self::Ambiguous => "AMBIGUOUS",
            Self::BadText => "BAD_TEXT",
            Self::BadCheck => "BAD_CHECK",
        }
    }
}

impl fmt::Display for MarkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for MarkError {}
