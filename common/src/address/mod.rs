use crate::chain::ChainConfig;
use crate::primitives::{encoding, Bech32Error, DecodedBech32};
use crypto::key::PublicKey;
use parity_scale_codec::Encode;

use self::pubkeyhash::PublicKeyHash;

pub mod pubkeyhash;

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
    InvalidPrefix(String),
}

impl From<Bech32Error> for AddressError {
    fn from(err: Bech32Error) -> Self {
        AddressError::Bech32EncodingError(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    address: String,
}

impl Address {
    pub fn new<T: AsRef<[u8]>>(cfg: &ChainConfig, data: T) -> Result<Self, AddressError> {
        Self::new_with_hrp(cfg.address_prefix(), data)
    }

    #[allow(dead_code)]
    pub(crate) fn new_with_hrp<T: AsRef<[u8]>>(hrp: &str, data: T) -> Result<Self, AddressError> {
        let d = encoding::encode(hrp, data)?;
        Ok(Self { address: d })
    }

    pub fn data(&self, cfg: &ChainConfig) -> Result<Vec<u8>, AddressError> {
        let data = encoding::decode(&self.address)?;
        if data.get_hrp() != cfg.address_prefix() {
            return Err(AddressError::InvalidPrefix(data.get_hrp().to_owned()));
        }
        let data_inner = data.get_data();
        let result = data_inner.to_vec();
        Ok(result)
    }

    #[allow(dead_code)]
    fn data_internal(&self) -> Result<Vec<u8>, AddressError> {
        let data = encoding::decode(&self.address)?;
        Ok(data.get_data().to_owned())
    }

    pub fn from_public_key_hash(
        cfg: &ChainConfig,
        public_key_hash: &PublicKeyHash,
    ) -> Result<Self, AddressError> {
        let encoded = public_key_hash.encode();
        println!("pub key hash encoded: {:?}", encoded);
        Address::new(cfg, encoded)
    }

    pub fn from_public_key(
        cfg: &ChainConfig,
        public_key: &PublicKey,
    ) -> Result<Self, AddressError> {
        let public_key_hash = PublicKeyHash::from(public_key);
        Self::from_public_key_hash(cfg, &public_key_hash)
    }

    pub fn get(&self) -> &str {
        &self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::config::create_mainnet;
    use crypto::key::{KeyKind, PrivateKey};

    #[test]
    fn basic() {
        let cfg = create_mainnet();
        let (_priv_key, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let public_key_hash = PublicKeyHash::from(&pub_key);
        let address = Address::from_public_key_hash(&cfg, &public_key_hash)
            .expect("Address from pubkeyhash failed");
        let public_key_hash_restored_vec =
            address.data(&cfg).expect("Failed to extract public key hash from address");
        let public_key_hash_restored = PublicKeyHash::try_from(public_key_hash_restored_vec)
            .expect("Restoring public key hash from vec failed");
        assert_eq!(public_key_hash_restored, public_key_hash);
    }

    #[test]
    fn ensure_cfg_and_with_hrp_compatiblity() {
        let cfg = create_mainnet();
        let (_priv_key, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let public_key_hash = PublicKeyHash::from(&pub_key);
        let hrp = cfg.address_prefix();
        let address1 = Address::new(&cfg, public_key_hash.encode());
        let address2 = Address::new_with_hrp(cfg.address_prefix(), public_key_hash.encode());
        assert_eq!(address1, address2);
        assert_eq!(&address1.unwrap().address[0..hrp.len()], hrp);
    }
}
