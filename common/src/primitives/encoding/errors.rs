use bech32::{self, Error};
use core::fmt;

#[derive(thiserror::Error, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Bech32Error {
    /// missing separator
    #[error("Missing separator`")]
    NoSeparator,
    #[error("Invalid checksum")]
    FailedChecksum,
    #[error("Length either too short or too long")]
    InvalidLength,
    #[error("Char value not supported")]
    InvalidChar(char),
    #[error("Provided u8 value in the data is invalid")]
    InvalidData(u8),
    #[error("Padding issue")]
    InvalidPadding,
    #[error("Mix of lowercase and uppercase is not allowed")]
    MixCase,
    #[error("Only variant Bech32m is supported")]
    UnsupportedVariant,
    #[error("List of indices containing invalid characters in a bech32 string `{0:?}`")]
    ErrorLocation(Vec<usize>),
    #[error("Standard rust error: `{0}`")]
    StdError(#[from] fmt::Error),
}

impl From<bech32::Error> for Bech32Error {
    fn from(e: Error) -> Self {
        match e {
            Error::MissingSeparator => Self::NoSeparator,
            Error::InvalidChecksum => Self::FailedChecksum,
            Error::InvalidLength => Self::InvalidLength,
            Error::InvalidChar(x) => Self::InvalidChar(x),
            Error::InvalidData(x) => Self::InvalidData(x),
            Error::InvalidPadding => Self::InvalidPadding,
            Error::MixedCase => Self::MixCase,
        }
    }
}
