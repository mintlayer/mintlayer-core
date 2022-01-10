mod internal;

use internal::*;
use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};
use rand::{CryptoRng, Rng};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum RistrettoKeyError {
    InvalidData,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub struct MLRistrettoPrivateKey {
    key_data: [u8; 32],
}

impl MLRistrettoPrivateKey {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> (MLRistrettoPrivateKey, MLRistrettoPublicKey) {
        use tari_crypto::keys::PublicKey;
        let pair = RistrettoPublicKey::random_keypair(rng);
        (
            Self::from_native(&pair.0),
            MLRistrettoPublicKey {
                pubkey_data: pair
                    .1
                    .as_bytes()
                    .try_into()
                    .expect("Ristretto Public Key size is expected to be 32-bytes (compressed)"),
            },
        )
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key_data.as_slice()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let sk = RistrettoSecretKey::from_bytes(bytes)
            .or_else(|_| Err(RistrettoKeyError::InvalidData))?;
        let result = Self::from_native(&sk);
        Ok(result)
    }

    pub fn as_native(&self) -> RistrettoSecretKey {
        RistrettoSecretKey::from_bytes(&self.key_data)
            .expect("The data is always expected to be valid")
    }

    pub fn from_native(native: &RistrettoSecretKey) -> Self {
        Self {
            key_data: native
                .as_bytes()
                .try_into()
                .expect("Ristretto Private Key size is expected to be 32-bytes"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub struct MLRistrettoPublicKey {
    pubkey_data: [u8; 32],
}

impl MLRistrettoPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.pubkey_data.as_slice()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RistrettoKeyError> {
        let pk = RistrettoPublicKey::from_bytes(bytes)
            .or_else(|_| Err(RistrettoKeyError::InvalidData))?;
        let result = Self::from_native(&pk);
        Ok(result)
    }

    pub fn as_native(&self) -> RistrettoPublicKey {
        RistrettoPublicKey::from_bytes(&self.pubkey_data)
            .expect("The data is always expected to be valid")
    }

    pub fn from_native(native: &RistrettoPublicKey) -> Self {
        Self {
            pubkey_data: native
                .as_bytes()
                .try_into()
                .expect("Ristretto Public Key size is expected to be 32-bytes"),
        }
    }

    pub fn from_private_key(private_key: &MLRistrettoPrivateKey) -> Self {
        use tari_crypto::keys::PublicKey;
        Self::from_native(&RistrettoPublicKey::from_secret_key(
            &private_key.as_native(),
        ))
    }
}
