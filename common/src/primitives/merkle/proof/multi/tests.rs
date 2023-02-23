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

use rstest::rstest;

use crate::primitives::{
    id::default_hash,
    merkle::{proof::multi::is_sorted_and_unique, tree::MerkleTree},
    H256,
};

use super::*;

fn gen_leaves(n: usize) -> Vec<H256> {
    (0..n).map(|i| default_hash(H256::from_low_u64_be(i as u64))).collect()
}

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
    let leaves = gen_leaves(2);
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
    let leaves = gen_leaves(1);
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
    let leaves = gen_leaves(2);
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
    let leaves = gen_leaves(4);
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

/// The number of tests is the sum of binomial terms (n choose k) for k = 1..n-1, where n = 2 for 2 leaves, yielding 3 tests.
#[rstest]
#[rustfmt::skip]
#[case(&[0], vec![1])]
#[case(&[1], vec![0])]
#[case(&[0,1], vec![])]
fn multi_proof_two_leaves_with_proof_leaves(
    #[case] input: &[usize],
    #[case] nodes: Vec<usize>,
) {
    let leaves = gen_leaves(2);
    let t = MerkleTree::from_leaves(leaves).unwrap();

    let multi_proof = MultiProofNodes::from_tree_leaves(&t, input).unwrap();
    assert_eq!(multi_proof.nodes().iter().map(|n|n.abs_index()).collect::<Vec<_>>(), nodes);
    assert_eq!(
        multi_proof.leaves().iter().map(|leaf| leaf.abs_index()).collect::<Vec<_>>(),
        input
    );
}

/// The number of tests is the sum of binomial terms (n choose k) for k = 1..n-1, where n = 4 for 4 leaves, yielding 15 tests.
#[rstest]
#[rustfmt::skip]
#[case(&[0], vec![1,5])]
#[case(&[1], vec![0,5])]
#[case(&[2], vec![3,4])]
#[case(&[3], vec![2,4])]
#[case(&[0,1], vec![5])]
#[case(&[0,2], vec![1,3])]
#[case(&[0,3], vec![1,2])]
#[case(&[1,2], vec![0,3])]
#[case(&[1,3], vec![0,2])]
#[case(&[2,3], vec![4])]
#[case(&[0,1,2], vec![3])]
#[case(&[0,1,3], vec![2])]
#[case(&[0,2,3], vec![1])]
#[case(&[1,2,3], vec![0])]
#[case(&[0,1,2,3], vec![])]
fn multi_proof_four_leaves_with_proof_leaves(
    #[case] input: &[usize],
    #[case] nodes: Vec<usize>,
) {
    let leaves = gen_leaves(4);
    let t = MerkleTree::from_leaves(leaves).unwrap();

    let multi_proof = MultiProofNodes::from_tree_leaves(&t, input).unwrap();
    assert_eq!(multi_proof.nodes().iter().map(|n|n.abs_index()).collect::<Vec<_>>(), nodes);
    assert_eq!(
        multi_proof.leaves().iter().map(|leaf| leaf.abs_index()).collect::<Vec<_>>(),
        input
    );
}

/// Proof of one leaf must be equivalent to single proof
#[test]
fn multi_proof_eight_leaves_with_multiproof_as_single_proof() {
    let leaves = gen_leaves(8);
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

/// The number of tests is the sum of binomial terms (n choose k) for k = 1..n-1, where n = 8 for 8 leaves, yielding 254 tests.
#[rstest]
#[case(&[0], vec![1,9,13])]
#[case(&[1], vec![0,9,13])]
#[case(&[2], vec![3,8,13])]
#[case(&[3], vec![2,8,13])]
#[case(&[4], vec![5,11,12])]
#[case(&[5], vec![4,11,12])]
#[case(&[6], vec![7,10,12])]
#[case(&[7], vec![6,10,12])]
#[case(&[0,1], vec![9,13])]
#[case(&[0,2], vec![1,3,13])]
#[case(&[0,3], vec![1,2,13])]
#[case(&[0,4], vec![1,5,9,11])]
#[case(&[0,5], vec![1,4,9,11])]
#[case(&[0,6], vec![1,7,9,10])]
#[case(&[0,7], vec![1,6,9,10])]
#[case(&[1,2], vec![0,3,13])]
#[case(&[1,3], vec![0,2,13])]
#[case(&[1,4], vec![0,5,9,11])]
#[case(&[1,5], vec![0,4,9,11])]
#[case(&[1,6], vec![0,7,9,10])]
#[case(&[1,7], vec![0,6,9,10])]
#[case(&[2,3], vec![8,13])]
#[case(&[2,4], vec![3,5,8,11])]
#[case(&[2,5], vec![3,4,8,11])]
#[case(&[2,6], vec![3,7,8,10])]
#[case(&[2,7], vec![3,6,8,10])]
#[case(&[3,4], vec![2,5,8,11])]
#[case(&[3,5], vec![2,4,8,11])]
#[case(&[3,6], vec![2,7,8,10])]
#[case(&[3,7], vec![2,6,8,10])]
#[case(&[4,5], vec![11,12])]
#[case(&[4,6], vec![5,7,12])]
#[case(&[4,7], vec![5,6,12])]
#[case(&[5,6], vec![4,7,12])]
#[case(&[5,7], vec![4,6,12])]
#[case(&[6,7], vec![10,12])]
#[case(&[0,1,2], vec![3,13])]
#[case(&[0,1,3], vec![2,13])]
#[case(&[0,1,4], vec![5,9,11])]
#[case(&[0,1,5], vec![4,9,11])]
#[case(&[0,1,6], vec![7,9,10])]
#[case(&[0,1,7], vec![6,9,10])]
#[case(&[0,2,3], vec![1,13])]
#[case(&[0,2,4], vec![1,3,5,11])]
#[case(&[0,2,5], vec![1,3,4,11])]
#[case(&[0,2,6], vec![1,3,7,10])]
#[case(&[0,2,7], vec![1,3,6,10])]
#[case(&[0,3,4], vec![1,2,5,11])]
#[case(&[0,3,5], vec![1,2,4,11])]
#[case(&[0,3,6], vec![1,2,7,10])]
#[case(&[0,3,7], vec![1,2,6,10])]
#[case(&[0,4,5], vec![1,9,11])]
#[case(&[0,4,6], vec![1,5,7,9])]
#[case(&[0,4,7], vec![1,5,6,9])]
#[case(&[0,5,6], vec![1,4,7,9])]
#[case(&[0,5,7], vec![1,4,6,9])]
#[case(&[0,6,7], vec![1,9,10])]
#[case(&[1,2,3], vec![0,13])]
#[case(&[1,2,4], vec![0,3,5,11])]
#[case(&[1,2,5], vec![0,3,4,11])]
#[case(&[1,2,6], vec![0,3,7,10])]
#[case(&[1,2,7], vec![0,3,6,10])]
#[case(&[1,3,4], vec![0,2,5,11])]
#[case(&[1,3,5], vec![0,2,4,11])]
#[case(&[1,3,6], vec![0,2,7,10])]
#[case(&[1,3,7], vec![0,2,6,10])]
#[case(&[1,4,5], vec![0,9,11])]
#[case(&[1,4,6], vec![0,5,7,9])]
#[case(&[1,4,7], vec![0,5,6,9])]
#[case(&[1,5,6], vec![0,4,7,9])]
#[case(&[1,5,7], vec![0,4,6,9])]
#[case(&[1,6,7], vec![0,9,10])]
#[case(&[2,3,4], vec![5,8,11])]
#[case(&[2,3,5], vec![4,8,11])]
#[case(&[2,3,6], vec![7,8,10])]
#[case(&[2,3,7], vec![6,8,10])]
#[case(&[2,4,5], vec![3,8,11])]
#[case(&[2,4,6], vec![3,5,7,8])]
#[case(&[2,4,7], vec![3,5,6,8])]
#[case(&[2,5,6], vec![3,4,7,8])]
#[case(&[2,5,7], vec![3,4,6,8])]
#[case(&[2,6,7], vec![3,8,10])]
#[case(&[3,4,5], vec![2,8,11])]
#[case(&[3,4,6], vec![2,5,7,8])]
#[case(&[3,4,7], vec![2,5,6,8])]
#[case(&[3,5,6], vec![2,4,7,8])]
#[case(&[3,5,7], vec![2,4,6,8])]
#[case(&[3,6,7], vec![2,8,10])]
#[case(&[4,5,6], vec![7,12])]
#[case(&[4,5,7], vec![6,12])]
#[case(&[4,6,7], vec![5,12])]
#[case(&[5,6,7], vec![4,12])]
#[case(&[0,1,2,3], vec![13])]
#[case(&[0,1,2,4], vec![3,5,11])]
#[case(&[0,1,2,5], vec![3,4,11])]
#[case(&[0,1,2,6], vec![3,7,10])]
#[case(&[0,1,2,7], vec![3,6,10])]
#[case(&[0,1,3,4], vec![2,5,11])]
#[case(&[0,1,3,5], vec![2,4,11])]
#[case(&[0,1,3,6], vec![2,7,10])]
#[case(&[0,1,3,7], vec![2,6,10])]
#[case(&[0,1,4,5], vec![9,11])]
#[case(&[0,1,4,6], vec![5,7,9])]
#[case(&[0,1,4,7], vec![5,6,9])]
#[case(&[0,1,5,6], vec![4,7,9])]
#[case(&[0,1,5,7], vec![4,6,9])]
#[case(&[0,1,6,7], vec![9,10])]
#[case(&[0,2,3,4], vec![1,5,11])]
#[case(&[0,2,3,5], vec![1,4,11])]
#[case(&[0,2,3,6], vec![1,7,10])]
#[case(&[0,2,3,7], vec![1,6,10])]
#[case(&[0,2,4,5], vec![1,3,11])]
#[case(&[0,2,4,6], vec![1,3,5,7])]
#[case(&[0,2,4,7], vec![1,3,5,6])]
#[case(&[0,2,5,6], vec![1,3,4,7])]
#[case(&[0,2,5,7], vec![1,3,4,6])]
#[case(&[0,2,6,7], vec![1,3,10])]
#[case(&[0,3,4,5], vec![1,2,11])]
#[case(&[0,3,4,6], vec![1,2,5,7])]
#[case(&[0,3,4,7], vec![1,2,5,6])]
#[case(&[0,3,5,6], vec![1,2,4,7])]
#[case(&[0,3,5,7], vec![1,2,4,6])]
#[case(&[0,3,6,7], vec![1,2,10])]
#[case(&[0,4,5,6], vec![1,7,9])]
#[case(&[0,4,5,7], vec![1,6,9])]
#[case(&[0,4,6,7], vec![1,5,9])]
#[case(&[0,5,6,7], vec![1,4,9])]
#[case(&[1,2,3,4], vec![0,5,11])]
#[case(&[1,2,3,5], vec![0,4,11])]
#[case(&[1,2,3,6], vec![0,7,10])]
#[case(&[1,2,3,7], vec![0,6,10])]
#[case(&[1,2,4,5], vec![0,3,11])]
#[case(&[1,2,4,6], vec![0,3,5,7])]
#[case(&[1,2,4,7], vec![0,3,5,6])]
#[case(&[1,2,5,6], vec![0,3,4,7])]
#[case(&[1,2,5,7], vec![0,3,4,6])]
#[case(&[1,2,6,7], vec![0,3,10])]
#[case(&[1,3,4,5], vec![0,2,11])]
#[case(&[1,3,4,6], vec![0,2,5,7])]
#[case(&[1,3,4,7], vec![0,2,5,6])]
#[case(&[1,3,5,6], vec![0,2,4,7])]
#[case(&[1,3,5,7], vec![0,2,4,6])]
#[case(&[1,3,6,7], vec![0,2,10])]
#[case(&[1,4,5,6], vec![0,7,9])]
#[case(&[1,4,5,7], vec![0,6,9])]
#[case(&[1,4,6,7], vec![0,5,9])]
#[case(&[1,5,6,7], vec![0,4,9])]
#[case(&[2,3,4,5], vec![8,11])]
#[case(&[2,3,4,6], vec![5,7,8])]
#[case(&[2,3,4,7], vec![5,6,8])]
#[case(&[2,3,5,6], vec![4,7,8])]
#[case(&[2,3,5,7], vec![4,6,8])]
#[case(&[2,3,6,7], vec![8,10])]
#[case(&[2,4,5,6], vec![3,7,8])]
#[case(&[2,4,5,7], vec![3,6,8])]
#[case(&[2,4,6,7], vec![3,5,8])]
#[case(&[2,5,6,7], vec![3,4,8])]
#[case(&[3,4,5,6], vec![2,7,8])]
#[case(&[3,4,5,7], vec![2,6,8])]
#[case(&[3,4,6,7], vec![2,5,8])]
#[case(&[3,5,6,7], vec![2,4,8])]
#[case(&[4,5,6,7], vec![12])]
#[case(&[0,1,2,3,4], vec![5,11])]
#[case(&[0,1,2,3,5], vec![4,11])]
#[case(&[0,1,2,3,6], vec![7,10])]
#[case(&[0,1,2,3,7], vec![6,10])]
#[case(&[0,1,2,4,5], vec![3,11])]
#[case(&[0,1,2,4,6], vec![3,5,7])]
#[case(&[0,1,2,4,7], vec![3,5,6])]
#[case(&[0,1,2,5,6], vec![3,4,7])]
#[case(&[0,1,2,5,7], vec![3,4,6])]
#[case(&[0,1,2,6,7], vec![3,10])]
#[case(&[0,1,3,4,5], vec![2,11])]
#[case(&[0,1,3,4,6], vec![2,5,7])]
#[case(&[0,1,3,4,7], vec![2,5,6])]
#[case(&[0,1,3,5,6], vec![2,4,7])]
#[case(&[0,1,3,5,7], vec![2,4,6])]
#[case(&[0,1,3,6,7], vec![2,10])]
#[case(&[0,1,4,5,6], vec![7,9])]
#[case(&[0,1,4,5,7], vec![6,9])]
#[case(&[0,1,4,6,7], vec![5,9])]
#[case(&[0,1,5,6,7], vec![4,9])]
#[case(&[0,2,3,4,5], vec![1,11])]
#[case(&[0,2,3,4,6], vec![1,5,7])]
#[case(&[0,2,3,4,7], vec![1,5,6])]
#[case(&[0,2,3,5,6], vec![1,4,7])]
#[case(&[0,2,3,5,7], vec![1,4,6])]
#[case(&[0,2,3,6,7], vec![1,10])]
#[case(&[0,2,4,5,6], vec![1,3,7])]
#[case(&[0,2,4,5,7], vec![1,3,6])]
#[case(&[0,2,4,6,7], vec![1,3,5])]
#[case(&[0,2,5,6,7], vec![1,3,4])]
#[case(&[0,3,4,5,6], vec![1,2,7])]
#[case(&[0,3,4,5,7], vec![1,2,6])]
#[case(&[0,3,4,6,7], vec![1,2,5])]
#[case(&[0,3,5,6,7], vec![1,2,4])]
#[case(&[0,4,5,6,7], vec![1,9])]
#[case(&[1,2,3,4,5], vec![0,11])]
#[case(&[1,2,3,4,6], vec![0,5,7])]
#[case(&[1,2,3,4,7], vec![0,5,6])]
#[case(&[1,2,3,5,6], vec![0,4,7])]
#[case(&[1,2,3,5,7], vec![0,4,6])]
#[case(&[1,2,3,6,7], vec![0,10])]
#[case(&[1,2,4,5,6], vec![0,3,7])]
#[case(&[1,2,4,5,7], vec![0,3,6])]
#[case(&[1,2,4,6,7], vec![0,3,5])]
#[case(&[1,2,5,6,7], vec![0,3,4])]
#[case(&[1,3,4,5,6], vec![0,2,7])]
#[case(&[1,3,4,5,7], vec![0,2,6])]
#[case(&[1,3,4,6,7], vec![0,2,5])]
#[case(&[1,3,5,6,7], vec![0,2,4])]
#[case(&[1,4,5,6,7], vec![0,9])]
#[case(&[2,3,4,5,6], vec![7,8])]
#[case(&[2,3,4,5,7], vec![6,8])]
#[case(&[2,3,4,6,7], vec![5,8])]
#[case(&[2,3,5,6,7], vec![4,8])]
#[case(&[2,4,5,6,7], vec![3,8])]
#[case(&[3,4,5,6,7], vec![2,8])]
#[case(&[0,1,2,3,4,5], vec![11])]
#[case(&[0,1,2,3,4,6], vec![5,7])]
#[case(&[0,1,2,3,4,7], vec![5,6])]
#[case(&[0,1,2,3,5,6], vec![4,7])]
#[case(&[0,1,2,3,5,7], vec![4,6])]
#[case(&[0,1,2,3,6,7], vec![10])]
#[case(&[0,1,2,4,5,6], vec![3,7])]
#[case(&[0,1,2,4,5,7], vec![3,6])]
#[case(&[0,1,2,4,6,7], vec![3,5])]
#[case(&[0,1,2,5,6,7], vec![3,4])]
#[case(&[0,1,3,4,5,6], vec![2,7])]
#[case(&[0,1,3,4,5,7], vec![2,6])]
#[case(&[0,1,3,4,6,7], vec![2,5])]
#[case(&[0,1,3,5,6,7], vec![2,4])]
#[case(&[0,1,4,5,6,7], vec![9])]
#[case(&[0,2,3,4,5,6], vec![1,7])]
#[case(&[0,2,3,4,5,7], vec![1,6])]
#[case(&[0,2,3,4,6,7], vec![1,5])]
#[case(&[0,2,3,5,6,7], vec![1,4])]
#[case(&[0,2,4,5,6,7], vec![1,3])]
#[case(&[0,3,4,5,6,7], vec![1,2])]
#[case(&[1,2,3,4,5,6], vec![0,7])]
#[case(&[1,2,3,4,5,7], vec![0,6])]
#[case(&[1,2,3,4,6,7], vec![0,5])]
#[case(&[1,2,3,5,6,7], vec![0,4])]
#[case(&[1,2,4,5,6,7], vec![0,3])]
#[case(&[1,3,4,5,6,7], vec![0,2])]
#[case(&[2,3,4,5,6,7], vec![8])]
#[case(&[0,1,2,3,4,5,6], vec![7])]
#[case(&[0,1,2,3,4,5,7], vec![6])]
#[case(&[0,1,2,3,4,6,7], vec![5])]
#[case(&[0,1,2,3,5,6,7], vec![4])]
#[case(&[0,1,2,4,5,6,7], vec![3])]
#[case(&[0,1,3,4,5,6,7], vec![2])]
#[case(&[0,2,3,4,5,6,7], vec![1])]
#[case(&[0,1,2,3,4,5,6,7], vec![])]
fn multi_proof_eight_leaves_with_proof_leaves(#[case] input: &[usize], #[case] nodes: Vec<usize>) {
    let leaves = gen_leaves(8);
    let t = MerkleTree::from_leaves(leaves).unwrap();

    let multi_proof = MultiProofNodes::from_tree_leaves(&t, input).unwrap();
    assert_eq!(
        multi_proof.nodes().iter().map(|n| n.abs_index()).collect::<Vec<_>>(),
        nodes
    );
    assert_eq!(
        multi_proof.leaves().iter().map(|leaf| leaf.abs_index()).collect::<Vec<_>>(),
        input
    );
}
