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

use crate::primitives::{
    id::default_hash,
    merkle::{proof::multi::is_sorted_and_unique, tree::MerkleTree},
    H256,
};

use super::*;

#[test]
fn sorted_and_unique() {
    assert!(is_sorted_and_unique(&[]));
    assert!(is_sorted_and_unique(&[1]));
    assert!(is_sorted_and_unique(&[1, 2]));
    assert!(is_sorted_and_unique(&[1, 2, 5, 10]));
    assert!(is_sorted_and_unique(&[1, 2, 5, 10, 100]));

    assert!(!is_sorted_and_unique(&[1, 1]));
    assert!(!is_sorted_and_unique(&[2, 1]));
    assert!(!is_sorted_and_unique(&[1, 2, 5, 10, 100, 99]));
    assert!(!is_sorted_and_unique(&[2, 1, 2, 5, 10, 100]));
    assert!(!is_sorted_and_unique(&[1, 2, 5, 4, 10, 100]));
}

#[test]
fn empty_multi_proof() {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));

    let leaves = vec![v0, v1];
    let t = MerkleTree::from_leaves(leaves).unwrap();

    let multi_proof = MultiProofNodes::from_tree_leaves(&t, &[]);
    assert_eq!(
        multi_proof.unwrap_err(),
        MerkleTreeProofExtractionError::NoLeavesToCreateProof
    );
}

/// Proof of one leaf must be equivalent to single proof
#[test]
fn multi_proof_one_leaf_with_multiproof_as_single_proof() {
    let v0 = default_hash(H256::zero());

    let leaves = vec![v0];
    let t = MerkleTree::from_leaves(leaves).unwrap();

    let multi_proof = MultiProofNodes::from_tree_leaves(&t, &[0]).unwrap();
    let single_proof = SingleProofNodes::from_tree_leaf(&t, 0).unwrap();
    assert_eq!(multi_proof.nodes().len(), 0);
    assert_eq!(multi_proof.nodes(), single_proof.branch());
    assert_eq!(multi_proof.leaves().len(), 1);
    assert_eq!(multi_proof.leaves()[0], single_proof.leaf());
}

/// Proof of one leaf must be equivalent to single proof
#[test]
fn multi_proof_two_leaves_with_multiproof_as_single_proof() {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));

    let leaves = vec![v0, v1];
    let t = MerkleTree::from_leaves(leaves).unwrap();

    for i in 0..2 {
        let multi_proof = MultiProofNodes::from_tree_leaves(&t, &[i]).unwrap();
        let single_proof = SingleProofNodes::from_tree_leaf(&t, i).unwrap();
        assert_eq!(multi_proof.nodes().len(), 1);
        assert_eq!(multi_proof.nodes(), single_proof.branch());
        assert_eq!(multi_proof.leaves().len(), 1);
        assert_eq!(multi_proof.leaves()[0], single_proof.leaf());
    }
}

/// Proof of one leaf must be equivalent to single proof
#[test]
fn multi_proof_four_leaves_with_multiproof_as_single_proof() {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));
    let v2 = default_hash(H256::from_low_u64_be(2));
    let v3 = default_hash(H256::from_low_u64_be(3));

    let leaves = vec![v0, v1, v2, v3];
    let t = MerkleTree::from_leaves(leaves).unwrap();

    for i in 0..4 {
        let multi_proof = MultiProofNodes::from_tree_leaves(&t, &[i]).unwrap();
        let single_proof = SingleProofNodes::from_tree_leaf(&t, i).unwrap();
        assert_eq!(multi_proof.nodes().len(), 2);
        assert_eq!(multi_proof.nodes(), single_proof.branch());
        assert_eq!(multi_proof.leaves().len(), 1);
        assert_eq!(multi_proof.leaves()[0], single_proof.leaf());
    }
}

/// Proof of one leaf must be equivalent to single proof
#[test]
fn multi_proof_eight_leaves_with_multiproof_as_single_proof() {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));
    let v2 = default_hash(H256::from_low_u64_be(2));
    let v3 = default_hash(H256::from_low_u64_be(3));
    let v4 = default_hash(H256::from_low_u64_be(4));
    let v5 = default_hash(H256::from_low_u64_be(5));
    let v6 = default_hash(H256::from_low_u64_be(6));
    let v7 = default_hash(H256::from_low_u64_be(7));

    let leaves = vec![v0, v1, v2, v3, v4, v5, v6, v7];
    let t = MerkleTree::from_leaves(leaves).unwrap();

    for i in 0..8 {
        let multi_proof = MultiProofNodes::from_tree_leaves(&t, &[i]).unwrap();
        let single_proof = SingleProofNodes::from_tree_leaf(&t, i).unwrap();
        assert_eq!(multi_proof.nodes().len(), 3);
        assert_eq!(multi_proof.nodes(), single_proof.branch());
        assert_eq!(multi_proof.leaves().len(), 1);
        assert_eq!(multi_proof.leaves()[0], single_proof.leaf());
    }
}
