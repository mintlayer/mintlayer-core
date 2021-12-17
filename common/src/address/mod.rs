use crate::chain::ChainConfig;
use crate::primitives::{encoding, Bech32Error};
use crypto::hash::hash;

pub trait AddressableData<T: AsRef<[u8]>> {
    fn encode(&self) -> Result<String, Bech32Error> {
        encoding::encode(self.get_hrp(), self.get_data())
    }

    fn decode(&mut self, addr: &str) -> Result<(), Bech32Error> {
        let decoded = encoding::decode(addr)?;
        self.set_data(decoded.data.as_ref());
        Ok(())
    }

    fn get_hrp(&self) -> &str;
    fn get_data(&self) -> T;
    fn set_data(&mut self, data: &[u8]);
}

pub enum AddressError {
    Bech32EncodingError(Bech32Error),
}

impl From<Bech32Error> for AddressError {
    fn from(err: Bech32Error) -> Self {
        AddressError::Bech32EncodingError(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
