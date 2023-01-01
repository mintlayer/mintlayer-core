// Copyright (c) 2021-2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::primitives::id::default_hash;
use crate::primitives::id::DefaultHashAlgoStream;
use crate::primitives::id::H256;
use crypto::hash::StreamHasher;
use merkletree::hash::Hashable;
use merkletree::merkle::Element;
use merkletree::merkle::MerkleTree;
use merkletree::store::VecStore;

/// This is the hashing algorithm implementation
/// used by MerkleTree; it basically contains
/// the hashing stream object
#[derive(Clone)]
pub struct BlockchainHashAlgorithm(DefaultHashAlgoStream);

fn next_pow2(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let leading_zeros = (n - 1).leading_zeros() as usize;
    let active_bits = usize::BITS as usize - leading_zeros;
    (1 << active_bits) as usize
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MerkleTreeFormError {
    #[error("Merkle tree input too small: {0}")]
    TooSmall(usize),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

fn merkletree_get_pad_data(elements: &[H256]) -> Vec<H256> {
    let orig_size = elements.len();
    let pow2_size = next_pow2(orig_size);

    assert!(pow2_size >= orig_size);

    let mut padding = Vec::new();
    for _idx in orig_size..pow2_size {
        let to_hash = padding
            .last()
            .unwrap_or_else(|| elements.last().expect("We already checked it's not empty"));
        let to_push = default_hash(to_hash);
        padding.push(to_push);
    }
    padding
}

impl From<anyhow::Error> for MerkleTreeFormError {
    fn from(err: anyhow::Error) -> Self {
        MerkleTreeFormError::Unknown(err.to_string())
    }
}

fn concatenate_with_padding_as_bytes(elements: &[H256], padding: Vec<H256>) -> Vec<u8> {
    let data = elements.iter().flat_map(|el| el.as_bytes().to_vec());
    let padding_data = padding.iter().flat_map(|el| el.as_bytes().to_vec());
    let data: Vec<u8> = data.into_iter().chain(padding_data.into_iter()).collect();
    data
}

/// Given a set of leaf hashes, calculate the merkle tree
/// Note: This WON'T hash the leaves
pub fn merkletree_from_vec(
    elements: &[H256],
) -> Result<MerkleTree<H256, BlockchainHashAlgorithm, VecStore<H256>>, MerkleTreeFormError> {
    if elements.len() < 2 {
        return Err(MerkleTreeFormError::TooSmall(elements.len()));
    }

    // pad up to the next power of two
    let padding = merkletree_get_pad_data(elements);

    // in order not to get MerkleTree library to rehash the children, we have to use u8 data
    // if we use the default MerkleTree::from_data() or similar, it'll hash the leaves
    let data: Vec<u8> = concatenate_with_padding_as_bytes(elements, padding);

    let tree = MerkleTree::from_byte_slice(&data)?;

    Ok(tree)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::id::default_hash;
    use merkletree::merkle::MerkleTree;
    use merkletree::store::VecStore;

    #[test]
    fn merkletree_too_small() {
        let t0 = merkletree_from_vec(&[]);
        assert_eq!(t0.unwrap_err(), MerkleTreeFormError::TooSmall(0));

        let t1 = merkletree_from_vec(&[H256::zero()]);
        assert_eq!(t1.unwrap_err(), MerkleTreeFormError::TooSmall(1));
    }

    #[test]
    fn merkletree_basic_two_leaf_node() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);

        let t: MerkleTree<H256, BlockchainHashAlgorithm, VecStore<_>> =
            MerkleTree::from_data(vec![v1, v2]).unwrap();

        // recreate the expected root
        let mut test_hasher = DefaultHashAlgoStream::new();
        test_hasher.write(default_hash(v1));
        test_hasher.write(default_hash(v2));

        assert_eq!(t.root(), test_hasher.finalize().into());
    }

    #[test]
    fn merkletree_basic_two_leaf_node_as_bytes() {
        // we use hashes immediately to calculate the root instead of using elements to hash
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);

        let data: Vec<u8> = vec![]
            .into_iter()
            .chain(default_hash(v1).as_bytes().iter())
            .into_iter()
            .chain(default_hash(v2).as_bytes().iter())
            .cloned()
            .collect();

        // recreate the expected root
        let mut test_hasher = DefaultHashAlgoStream::new();
        test_hasher.write(default_hash(H256::zero()));
        test_hasher.write(default_hash(H256::from_low_u64_be(1)));

        let t: MerkleTree<H256, BlockchainHashAlgorithm, VecStore<_>> =
            MerkleTree::from_byte_slice(&data).unwrap();

        assert_eq!(t.root(), test_hasher.finalize().into());
    }

    #[test]
    fn merkletree_basic_four_leaf_node() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);
        let v3 = H256::from_low_u64_be(2);
        let v4 = H256::from_low_u64_be(3);

        let t: MerkleTree<H256, BlockchainHashAlgorithm, VecStore<_>> =
            MerkleTree::from_data(vec![v1, v2, v3, v4]).unwrap();

        // recreate the expected root
        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(default_hash(v1));
        node10.write(default_hash(v2));

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(default_hash(v3));
        node11.write(default_hash(v4));

        let mut node00 = DefaultHashAlgoStream::new();
        let n10 = node10.finalize();
        node00.write(n10);
        let n11 = node11.finalize();
        node00.write(n11);

        let res = node00.finalize();

        assert_eq!(t.root(), res.into());
    }

    #[test]
    fn merkletree_basic_eight_leaf_node() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);
        let v3 = H256::from_low_u64_be(2);
        let v4 = H256::from_low_u64_be(3);
        let v5 = H256::from_low_u64_be(4);
        let v6 = H256::from_low_u64_be(5);
        let v7 = H256::from_low_u64_be(6);
        let v8 = H256::from_low_u64_be(7);

        let t: MerkleTree<H256, BlockchainHashAlgorithm, VecStore<_>> =
            MerkleTree::from_data(vec![v1, v2, v3, v4, v5, v6, v7, v8]).unwrap();

        // recreate the expected root
        let mut node20 = DefaultHashAlgoStream::new();
        node20.write(default_hash(v1));
        node20.write(default_hash(v2));

        let mut node21 = DefaultHashAlgoStream::new();
        node21.write(default_hash(v3));
        node21.write(default_hash(v4));

        let mut node22 = DefaultHashAlgoStream::new();
        node22.write(default_hash(v5));
        node22.write(default_hash(v6));

        let mut node23 = DefaultHashAlgoStream::new();
        node23.write(default_hash(v7));
        node23.write(default_hash(v8));

        let n20 = node20.finalize();
        let n21 = node21.finalize();
        let n22 = node22.finalize();
        let n23 = node23.finalize();

        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(n20);
        node10.write(n21);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(n22);
        node11.write(n23);

        let n10 = node10.finalize();
        let n11 = node11.finalize();

        let mut node00 = DefaultHashAlgoStream::new();
        node00.write(H256::from(n10));
        node00.write(H256::from(n11));

        let res = node00.finalize();

        assert_eq!(t.root(), H256::from(res));
    }

    #[test]
    fn merkletree_with_arbitrary_length_2() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);

        let t = merkletree_from_vec(&[v1, v2]).unwrap();

        // recreate the expected root
        let mut test_hasher = DefaultHashAlgoStream::new();
        test_hasher.write(v1);
        test_hasher.write(v2);

        assert_eq!(t.root(), test_hasher.finalize().into());
    }

    #[test]
    fn merkletree_with_arbitrary_length_3() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);
        let v3 = H256::from_low_u64_be(2);

        let t = merkletree_from_vec(&[v1, v2, v3]).unwrap();

        // recreate the expected root
        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(v1);
        node10.write(v2);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(v3);
        node11.write(default_hash(v3));

        let mut node00 = DefaultHashAlgoStream::new();
        let n10 = node10.finalize();
        node00.write(n10);
        let n11 = node11.finalize();
        node00.write(n11);

        let res = node00.finalize();

        assert_eq!(t.root(), res.into());
    }

    #[test]
    fn merkletree_with_arbitrary_length_5() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);
        let v3 = H256::from_low_u64_be(2);
        let v4 = H256::from_low_u64_be(3);
        let v5 = H256::from_low_u64_be(4);
        let v6 = default_hash(v5);
        let v7 = default_hash(v6);
        let v8 = default_hash(v7);

        let t = merkletree_from_vec(&[v1, v2, v3, v4, v5]).unwrap();

        // recreate the expected root
        let mut node20 = DefaultHashAlgoStream::new();
        node20.write(v1);
        node20.write(v2);

        let mut node21 = DefaultHashAlgoStream::new();
        node21.write(v3);
        node21.write(v4);

        let mut node22 = DefaultHashAlgoStream::new();
        node22.write(v5);
        node22.write(v6);

        let mut node23 = DefaultHashAlgoStream::new();
        node23.write(v7);
        node23.write(v8);

        let n20 = node20.finalize();
        let n21 = node21.finalize();
        let n22 = node22.finalize();
        let n23 = node23.finalize();

        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(n20);
        node10.write(n21);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(n22);
        node11.write(n23);

        let n10 = node10.finalize();
        let n11 = node11.finalize();

        let mut node00 = DefaultHashAlgoStream::new();
        node00.write(n10);
        node00.write(n11);

        let res = node00.finalize();

        assert_eq!(t.root(), res.into());
    }

    #[test]
    fn next_pow2_tests() {
        assert_eq!(next_pow2(0), 1);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(4), 4);
        assert_eq!(next_pow2(5), 8);
        assert_eq!(next_pow2(6), 8);
        assert_eq!(next_pow2(7), 8);
        assert_eq!(next_pow2(8), 8);
        assert_eq!(next_pow2(9), 16);
        assert_eq!(next_pow2(10), 16);
        assert_eq!(next_pow2(11), 16);
        assert_eq!(next_pow2(12), 16);
        assert_eq!(next_pow2(13), 16);
        assert_eq!(next_pow2(14), 16);
        assert_eq!(next_pow2(15), 16);
        assert_eq!(next_pow2(16), 16);
        (17..33).for_each(|n| assert_eq!(next_pow2(n), 32));
        (33..65).for_each(|n| assert_eq!(next_pow2(n), 64));
        (65..129).for_each(|n| assert_eq!(next_pow2(n), 128));
        (129..257).for_each(|n| assert_eq!(next_pow2(n), 256));
        (257..513).for_each(|n| assert_eq!(next_pow2(n), 512));
        (513..1025).for_each(|n| assert_eq!(next_pow2(n), 1024));
    }
}
