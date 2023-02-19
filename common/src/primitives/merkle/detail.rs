use crypto::hash::StreamHasher;
use merkletree::{hash::Hashable, merkle::Element};

use crate::primitives::{id::DefaultHashAlgoStream, H256};

/// This is the hashing algorithm implementation
/// used by MerkleTree; it basically contains
/// the hashing stream object
#[derive(Clone)]
pub struct BlockchainHashAlgorithm(DefaultHashAlgoStream);

impl Default for BlockchainHashAlgorithm {
    fn default() -> BlockchainHashAlgorithm {
        BlockchainHashAlgorithm(DefaultHashAlgoStream::new())
    }
}

impl std::hash::Hasher for BlockchainHashAlgorithm {
    fn write(&mut self, msg: &[u8]) {
        self.0.write(msg);
    }

    /// we don't implement this because we don't expect a u64 return;
    /// the correct return type comes in the Algorithm implementation
    /// in the hash() function
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

/// In this implementation we tell the merkle-tree crate how to calculate hashes
/// from individual nodes in the tree
impl merkletree::hash::Algorithm<H256> for BlockchainHashAlgorithm {
    fn hash(&mut self) -> H256 {
        self.0.finalize().into()
    }

    fn leaf(&mut self, leaf: H256) -> H256 {
        leaf
    }

    fn node(&mut self, left: H256, right: H256, _height: usize) -> H256 {
        self.0.write(left);
        self.0.write(right);
        self.hash()
    }

    fn multi_node(&mut self, nodes: &[H256], _height: usize) -> H256 {
        nodes.iter().for_each(|node| {
            self.0.write(node);
        });
        self.hash()
    }
}

impl Element for H256 {
    fn byte_len() -> usize {
        H256::len_bytes()
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(self.as_bytes())
    }

    fn from_slice(bytes: &[u8]) -> Self {
        H256(bytes.try_into().expect("merkle-tree internal error"))
    }
}

impl Hashable<BlockchainHashAlgorithm> for H256 {
    fn hash(&self, state: &mut BlockchainHashAlgorithm) {
        state.0.write(self.as_bytes());
    }

    fn hash_slice(data: &[Self], state: &mut BlockchainHashAlgorithm)
    where
        Self: Sized,
    {
        for d in data {
            state.0.write(d);
        }
    }
}
