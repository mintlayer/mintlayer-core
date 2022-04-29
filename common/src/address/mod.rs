use crate::chain::ChainConfig;
use crate::primitives::id::default_hash;
use crate::primitives::{encoding, Bech32Error, DecodedBech32};
use crypto::hash::hash;
use parity_scale_codec::{Decode, Encode};

pub trait AddressableData<T: AsRef<[u8]>> {
    fn encode(&self) -> Result<String, Bech32Error> {
        encoding::encode(self.get_hrp(), self.get_data())
    }

    fn decode(&mut self, addr: &str) -> Result<DecodedBech32, Bech32Error> {
        encoding::decode(addr)
    }

    fn get_hrp(&self) -> &str;
    fn set_hrp(&mut self, hrp: String);

    fn get_data(&self) -> T;
    fn set_data(&mut self, data: &[u8]);
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    Bech32EncodingError(Bech32Error),
}

impl From<Bech32Error> for AddressError {
    fn from(err: Bech32Error) -> Self {
        AddressError::Bech32EncodingError(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Address {
    address: String,
}

impl Address {
    pub fn new<T: AsRef<[u8]>>(cfg: &ChainConfig, data: T) -> Result<Self, AddressError> {
        let h = hash::<crypto::hash::Sha256, _>(data);
        let h = hash::<crypto::hash::Ripemd160, _>(h);
        Ok(Self {
            address: encoding::encode(cfg.address_prefix(), h)?,
        })
    }

    pub(crate) fn new_with_hrp<T: AsRef<[u8]>>(hrp: &str, data: T) -> Result<Self, AddressError> {
        let h = hash::<crypto::hash::Sha256, _>(data);
        let h = hash::<crypto::hash::Ripemd160, _>(h);
        Ok(Self {
            address: encoding::encode(hrp, h)?,
        })
    }

    pub fn from_public_key(
        cfg: &ChainConfig,
        public_key: &crypto::key::PublicKey,
    ) -> Result<Self, AddressError> {
        let hash = default_hash(public_key.encode());
        Address::new(cfg, hash.encode())
    }

    pub fn get(&self) -> &str {
        &self.address
    }
}

// TODO: add address tests once decided
mod tests {
    #[test]
    #[allow(clippy::eq_op)]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
