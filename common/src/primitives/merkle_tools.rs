use crypto::hash::StreamHasher;
use merkletree::hasher::PairHasher;

use super::{id::DefaultHashAlgoStream, H256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleHasher {}

impl PairHasher for MerkleHasher {
    type Type = H256;

    fn hash_pair(left: &Self::Type, right: &Self::Type) -> Self::Type {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(left);
        hasher.write(right);
        hasher.finalize().into()
    }

    fn hash_single(data: &Self::Type) -> Self::Type {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(data);
        hasher.finalize().into()
    }
}
