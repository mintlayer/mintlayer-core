mod errors;
pub use errors::*;
mod base32;
mod bech32m;
pub use bech32m::decode;
pub use bech32m::encode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBase32FromBech32 {
    hrp: String,
    data: Vec<u8>,
}

impl DecodedBase32FromBech32 {
    pub fn get_hrp(&self) -> &str {
        &self.hrp
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    pub fn encode(self) -> Result<String, Bech32Error> {
        bech32m::encode(&self.hrp, self.data)
    }
}

#[cfg(test)]
mod tests;
