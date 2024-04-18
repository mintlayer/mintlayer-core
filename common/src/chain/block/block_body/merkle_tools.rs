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
    use rstest::rstest;

    use crate::primitives::id::default_hash;

    use super::*;

    #[test]
    fn fixed_values_for_merkletree_4_leaves() {
        let leaf0 = default_hash("0");
        let leaf1 = default_hash("1");
        let leaf2 = default_hash("2");
        let leaf3 = default_hash("3");

        // The tree is defined from a vector of leaves, from left to right
        let tree = MerkleTree::<H256, MerkleHasher>::from_leaves(vec![leaf0, leaf1, leaf2, leaf3])
            .unwrap();

        // Verify some properties about this tree
        // The number of leaves is 4
        assert_eq!(tree.leaf_count().get(), 4);
        // The number of levels is 3 (4 leaves -> 2 nodes -> 1 root)
        assert_eq!(tree.level_count().get(), 3);
        // Total number of nodes in the tree (4 + 2 + 1)
        assert_eq!(tree.total_node_count().get(), 7);

        // We attempt to recreate the expected root manually
        let mut node10 = DefaultHashAlgoStream::new();
        node10.write(leaf0);
        node10.write(leaf1);

        let mut node11 = DefaultHashAlgoStream::new();
        node11.write(leaf2);
        node11.write(leaf3);

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

    #[rstest]
    #[trace]
    #[case(1, "e9f11462495399c0b8d0d8ec7128df9c0d7269cda23531a352b174bd29c3b631")]
    #[trace]
    #[case(2, "c352e4e7c11eb3373613a765cdce063c3c2d5aff8266587a734fef72af51404e")]
    #[trace]
    #[case(3, "2eddd1622a9e6a2c8252ab396849ffaa6eafd0125b82eb6ffea89732b344383e")]
    #[trace]
    #[case(4, "15c188fe5e6e63223be4d3db5aebf54402ffb71409dee9b1be29f7968853cfca")]
    #[trace]
    #[case(5, "d9ccbaadec9754eda8ef304b67a2c00afff706d000c69f18a51869cb5f17e53e")]
    #[trace]
    #[case(6, "777168561926e5b167e2b8c96bca35f4117df0b75f97387b1ad3c2492ffd2657")]
    #[trace]
    #[case(7, "2cc9c4d6685e528d910afb35cc8dce6c11a80ce6b295e7e5e4b836d8779cdf99")]
    #[trace]
    #[case(8, "8a3a5d6bd7fe9552e0a86139160e3a53e6e564ae7a78f4a26be8cf93e70a3b9f")]
    #[trace]
    #[case(9, "77b496939a6f66411367872ce20b905c38b27d5eba002060a102582b69561817")]
    #[trace]
    #[case(10, "cf694e272bcdc0b0632d4908c4f3feb5b3963044501b382974a681d45c4bd508")]
    fn fixed_values_for_merkletree_n_leaves(
        #[case] leaf_count: usize,
        #[case] expected_root_hex: &str,
    ) {
        let leaves = (0..leaf_count).map(|v| default_hash(v.to_string())).collect::<Vec<_>>();

        // The tree is defined from a vector of leaves, from left to right
        let tree = MerkleTree::<H256, MerkleHasher>::from_leaves(leaves).unwrap();

        let expected_root = hex::decode(expected_root_hex).unwrap();
        assert_eq!(expected_root, tree.root().as_bytes());
    }

    #[test]
    fn empty_tree_error() {
        MerkleTree::<H256, MerkleHasher>::from_leaves([]).unwrap_err();
    }
}
