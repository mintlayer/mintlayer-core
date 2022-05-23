use crypto::key::PublicKey;
use generic_array::sequence::Split;
use parity_scale_codec::{Decode, Encode};

use crate::{construct_fixed_hash, primitives::id::DefaultHashAlgo};

#[derive(thiserror::Error, Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicKeyHashError {
    #[error("Conversion from a data array tp public key hash failed; probably invalid length")]
    ConversionFromDataFailed,
}

const HASH_SIZE: usize = 20;

construct_fixed_hash! {
    #[derive(Encode, Decode)]
    pub struct PublicKeyHash(HASH_SIZE);
}

impl From<&PublicKey> for PublicKeyHash {
    fn from(pk: &PublicKey) -> Self {
        let hash = crypto::hash::hash::<DefaultHashAlgo, _>(pk.encode()).split().0.into();
        Self(hash)
    }
}

impl TryFrom<Vec<u8>> for PublicKeyHash {
    type Error = PublicKeyHashError;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        if v.len() != HASH_SIZE {
            return Err(PublicKeyHashError::ConversionFromDataFailed);
        }
        let array: [u8; HASH_SIZE] =
            v.try_into().map_err(|_| PublicKeyHashError::ConversionFromDataFailed)?;
        Ok(Self(array))
    }
}
