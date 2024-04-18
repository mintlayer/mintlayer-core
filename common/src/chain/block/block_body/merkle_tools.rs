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
use merkletree_mintlayer::hasher::PairHasher;

use crate::primitives::{id::DefaultHashAlgoStream, H256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleHasher {}

impl PairHasher for MerkleHasher {
    type NodeType = H256;

    fn hash_pair(left: &Self::NodeType, right: &Self::NodeType) -> Self::NodeType {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(left);
        hasher.write(right);
        hasher.finalize().into()
    }

    fn hash_single(data: &Self::NodeType) -> Self::NodeType {
        let mut hasher = DefaultHashAlgoStream::new();
        hasher.write(data);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use merkletree_mintlayer::tree::MerkleTree;

    use crate::primitives::id::default_hash;

    use super::*;

    #[test]
    fn fixed_values_for_merkletree() {
        let leaf1 = default_hash("0");
        let leaf2 = default_hash("1");
        let leaf3 = default_hash("2");
        let leaf4 = default_hash("3");

        // The tree is defined from a vector of leaves, from left to right
        let tree = MerkleTree::<H256, MerkleHasher>::from_leaves(vec![leaf1, leaf2, leaf3, leaf4])
            .unwrap();

        let tree_root = tree.root();
        println!("Merkle tree root: {}", hex::encode(tree_root));

        // Verify some properties about this tree
        // The number of leaves is 4
        assert_eq!(tree.leaf_count().get(), 4);
        // The number of levels is 3 (4 leaves -> 2 nodes -> 1 root)
        assert_eq!(tree.level_count().get(), 3);
        // Total number of nodes in the tree (4 + 2 + 1)
        assert_eq!(tree.total_node_count().get(), 7);

        // We attempt to recreate the expected root manually
        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(leaf1);
        node10.write(leaf2);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(leaf3);
        node11.write(leaf4);

        let mut node00 = DefaultHashAlgoStream::new();
        let n10 = node10.finalize();
        node00.write(n10);
        let n11 = node11.finalize();
        node00.write(n11);

        let root_that_we_created_manually = node00.finalize();

        // the root calculated matches the one calculated by the tree
        assert_eq!(tree.root(), root_that_we_created_manually.into());

        let expected_root_hex = "15c188fe5e6e63223be4d3db5aebf54402ffb71409dee9b1be29f7968853cfca";
        let expected_root = hex::decode(expected_root_hex).unwrap();
        assert_eq!(expected_root, tree.root().as_bytes());
    }
}
