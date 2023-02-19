// Copyright (c) 2021-2023 RBB S.r.l
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

use crypto::hash::StreamHasher;

use crate::primitives::{
    id::{default_hash, DefaultHashAlgoStream},
    H256,
};

use super::MerkleTreeFormError;

/// Merkle tree in the form of a vector, where the bottom leaves are the based, and the root is
/// the last element.
#[derive(Debug)]
pub struct MerkleTree {
    tree: Vec<H256>,
}

fn next_pow2(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let leading_zeros = (n - 1).leading_zeros() as usize;
    let active_bits = usize::BITS as usize - leading_zeros;
    (1 << active_bits) as usize
}

#[test]
fn merkletree_basic_two_leaf_node() {
    let v1 = default_hash(H256::zero());
    let v2 = default_hash(H256::from_low_u64_be(1));

    let t = MerkleTree::from_leaves(vec![v1, v2]).unwrap();

    // recreate the expected root
    let mut test_hasher = DefaultHashAlgoStream::new();
    test_hasher.write(v1);
    test_hasher.write(v2);

    assert_eq!(t.root(), test_hasher.finalize().into());
}

fn create_merkletree_padding(elements: &[H256]) -> Vec<H256> {
    let orig_size = elements.len();
    let pow2_size = next_pow2(orig_size);

    assert!(pow2_size >= orig_size);

    let mut padding = Vec::with_capacity(pow2_size - orig_size);
    for _idx in orig_size..pow2_size {
        let to_hash = padding
            .last()
            .unwrap_or_else(|| elements.last().expect("We already checked it's not empty"));
        let to_push = default_hash(to_hash);
        padding.push(to_push);
    }
    padding
}

impl MerkleTree {
    fn combine_pair(left: &H256, right: &H256) -> H256 {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(left.as_bytes());
        hasher.write(right.as_bytes());
        H256::from(hasher.finalize())
    }

    /// Create a new merkle tree from a list of leaves.
    pub fn from_leaves(leaves: Vec<H256>) -> Result<Self, MerkleTreeFormError> {
        if leaves.is_empty() {
            return Err(MerkleTreeFormError::TooSmall(leaves.len()));
        }
        let padding = create_merkletree_padding(&leaves);
        let leaves = leaves.into_iter().chain(padding).collect::<Vec<_>>();
        let steps = leaves.len() - 1;
        let mut tree = Vec::with_capacity(2 * leaves.len() - 1);
        tree.extend(leaves.into_iter());
        for i in 0..steps {
            let el = Self::combine_pair(&tree[i * 2], &tree[i * 2 + 1]);
            tree.push(el);
        }
        let res = Self { tree };
        Ok(res)
    }

    /// Get the root of the merkle tree.
    pub fn root(&self) -> H256 {
        *self.tree.last().expect("By design, at least one element must exist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::id::{default_hash, DefaultHashAlgoStream};
    use crypto::hash::StreamHasher;

    #[test]
    fn merkletree_too_small() {
        let t0 = MerkleTree::from_leaves(vec![]);
        assert_eq!(t0.unwrap_err(), MerkleTreeFormError::TooSmall(0));
    }

    #[test]
    fn merkletree_basic_four_leaf_node() {
        let v1 = default_hash(H256::zero());
        let v2 = default_hash(H256::from_low_u64_be(1));
        let v3 = default_hash(H256::from_low_u64_be(2));
        let v4 = default_hash(H256::from_low_u64_be(3));

        let t = MerkleTree::from_leaves(vec![v1, v2, v3, v4]).unwrap();

        // recreate the expected root
        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(v1);
        node10.write(v2);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(v3);
        node11.write(v4);

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
        let v1 = default_hash(H256::zero());
        let v2 = default_hash(H256::from_low_u64_be(1));
        let v3 = default_hash(H256::from_low_u64_be(2));
        let v4 = default_hash(H256::from_low_u64_be(3));
        let v5 = default_hash(H256::from_low_u64_be(4));
        let v6 = default_hash(H256::from_low_u64_be(5));
        let v7 = default_hash(H256::from_low_u64_be(6));
        let v8 = default_hash(H256::from_low_u64_be(7));

        let t = MerkleTree::from_leaves(vec![v1, v2, v3, v4, v5, v6, v7, v8]).unwrap();

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
        node00.write(H256::from(n10));
        node00.write(H256::from(n11));

        let res = node00.finalize();

        assert_eq!(t.root(), H256::from(res));
    }

    #[test]
    fn merkletree_with_arbitrary_length_2() {
        let v1 = H256::zero();
        let v2 = H256::from_low_u64_be(1);

        let t = MerkleTree::from_leaves(vec![v1, v2]).unwrap();

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

        let t = MerkleTree::from_leaves(vec![v1, v2, v3]).unwrap();

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

        let t = MerkleTree::from_leaves(vec![v1, v2, v3, v4, v5]).unwrap();

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
