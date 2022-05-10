use bech32::{self, Error};
use core::fmt;
use displaydoc::Display;
use thiserror::Error;

#[derive(Error, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
pub enum Bech32Error {
    /// missing separator
    NoSeparator,
    /// Invalid checksum
    FailedChecksum,
    /// Length either too short or too long
    InvalidLength,
    /// char value not supported
    InvalidChar(char),
    /// the provided u8 value in the data is invalid
    InvalidData(u8),
    /// Padding issue
    InvalidPadding,
    /// a mix of lowercase and uppercase is not allowed
    MixCase,
    /// only variant Bech32M is supported
    UnsupportedVariant,
    /// list of indices containing invalid characters in a bech32 string
    ErrorLocation(Vec<usize>),
    /// wraps the rust error
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
