use core::fmt;
use displaydoc::Display;

/// Error for primitives
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy, Display)]
pub enum Error {
    /// wraps any Bech32 Error
    Bech32Error(bech32::Error),
    /// wraps the rust error
    CustomError(fmt::Error),
}

impl Into<Error> for bech32::Error {
    fn into(self) -> Error {
        Error::Bech32Error(self)
    }
}
