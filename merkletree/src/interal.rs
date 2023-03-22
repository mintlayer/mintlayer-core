use crypto::hash::StreamHasher;
use fixed_hash::construct_fixed_hash;
use generic_array::{typenum, GenericArray};

use crate::hasher::PairHasher;

construct_fixed_hash! {
    pub struct HashedData(32);
}

#[cfg(test)]
pub type HashAlgo = crypto::hash::Blake2b32;

#[cfg(test)]
pub fn hash_data<T: AsRef<[u8]> + Clone>(data: T) -> HashedData {
    crypto::hash::hash::<HashAlgo, _>(&data).into()
}

pub type HashAlgoStream = crypto::hash::Blake2b32Stream;

impl From<GenericArray<u8, typenum::U32>> for HashedData {
    fn from(val: GenericArray<u8, typenum::U32>) -> Self {
        Self(val.into())
    }
}

impl PairHasher for HashAlgoStream {
    type Type = HashedData;

    fn hash_pair(left: &Self::Type, right: &Self::Type) -> Self::Type {
        let mut hasher = HashAlgoStream::new();
        hasher.write(left);
        hasher.write(right);
        hasher.finalize().into()
    }

    fn hash_single(data: &Self::Type) -> Self::Type {
        let mut hasher = HashAlgoStream::new();
        hasher.write(data);
        hasher.finalize().into()
    }
}
