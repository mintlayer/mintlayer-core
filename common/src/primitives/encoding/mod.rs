mod errors;
pub use errors::*;
mod base32;
mod bech32m;
mod decoded;
pub use bech32m::arbitrary_data_to_bech32m as encode;
pub use bech32m::bech32m_to_arbitrary_data as decode;
pub use decoded::DecodedArbitraryDataFromBech32;
pub use decoded::DecodedBase32FromBech32;

#[cfg(test)]
mod tests;
