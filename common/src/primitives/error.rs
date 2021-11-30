use core::fmt;
use displaydoc::Display;
use thiserror::Error;

/// Error for primitives
#[derive(Error, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy, Display)]
pub enum Error {
    /// only variant Bech32M is supported
    UnsupportedBech32,
    /// wraps any Bech32 Error
    Bech32Error(#[from] bech32::Error),
    /// wraps the rust error
    CustomError(#[from] fmt::Error),
}
