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
use test_utils::random::{make_seedable_rng, Seed};

use crate::primitives::{
    id::default_hash,
    merkle::{proof::single::SingleProofNodes, tree::MerkleTree},
    H256,
};

fn gen_leaves(n: usize) -> Vec<H256> {
    (0..n).map(|i| default_hash(H256::from_low_u64_be(i as u64))).collect()
}

#[test]
fn single_proof_one_leaf() {
    let v0 = default_hash(H256::zero());

    let leaves = vec![v0];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let leaf_index = 0;
    let p0 = SingleProofNodes::from_tree_leaf(&t, leaf_index).unwrap();
    assert_eq!(p0.branch().len(), 0);

    assert!(p0.into_values().verify(leaves[leaf_index], t.root()).is_none());
}

#[rstest]
#[trace]
#[case(2, 0, &[1])]
#[case(2, 1, &[0])]
#[case(4, 0, &[1,5])]
#[case(4, 1, &[0,5])]
#[case(4, 2, &[3,4])]
#[case(4, 3, &[2,4])]
#[case(8, 0, &[1,9,13])]
#[case(8, 1, &[0,9,13])]
#[case(8, 2, &[3,8,13])]
#[case(8, 3, &[2,8,13])]
#[case(8, 4, &[5,11,12])]
#[case(8, 5, &[4,11,12])]
#[case(8, 6, &[7,10,12])]
#[case(8, 7, &[6,10,12])]
#[case(16, 0, &[1,17,25,29])]
#[case(16, 1, &[0,17,25,29])]
#[case(16, 2, &[3,16,25,29])]
#[case(16, 3, &[2,16,25,29])]
#[case(16, 4, &[5,19,24,29])]
#[case(16, 5, &[4,19,24,29])]
#[case(16, 6, &[7,18,24,29])]
#[case(16, 7, &[6,18,24,29])]
#[case(16, 8, &[9,21,27,28])]
#[case(16, 9, &[8,21,27,28])]
#[case(16, 10, &[11,20,27,28])]
#[case(16, 11, &[10,20,27,28])]
#[case(16, 12, &[13,23,26,28])]
#[case(16, 13, &[12,23,26,28])]
#[case(16, 14, &[15,22,26,28])]
#[case(16, 15, &[14,22,26,28])]
fn single_proof_eight_leaves(
    #[case] leaf_count: usize,
    #[case] leaf_index: usize,
    #[case] branch: &[usize],
) {
    let leaves = gen_leaves(leaf_count);
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let p = SingleProofNodes::from_tree_leaf(&t, leaf_index).unwrap();
    assert_eq!(
        p.branch().iter().map(|n| n.abs_index()).collect::<Vec<_>>(),
        branch
    );

    assert!(p.into_values().verify(leaves[leaf_index], t.root()).unwrap());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 2)]
#[trace]
#[case(Seed::from_entropy(), 4)]
#[trace]
#[case(Seed::from_entropy(), 8)]
#[trace]
#[case(Seed::from_entropy(), 16)]
#[trace]
#[case(Seed::from_entropy(), 32)]
#[trace]
#[case(Seed::from_entropy(), 64)]
fn single_proof_eight_leaves_tamper_with_nodes(#[case] seed: Seed, #[case] leaf_count: usize) {
    let mut rng = make_seedable_rng(seed);

    let leaves = gen_leaves(leaf_count);
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    for (leaf_index, _) in leaves.iter().enumerate() {
        let proof = SingleProofNodes::from_tree_leaf(&t, leaf_index).unwrap().into_values();

        // Tamper with the proof
        for node_index in 0..proof.branch.len() {
            let mut p = proof.clone();
            p.branch[node_index] = H256::random_using(&mut rng);
            assert!(!p.verify(leaves[leaf_index], t.root()).unwrap());
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 2)]
#[trace]
#[case(Seed::from_entropy(), 4)]
#[trace]
#[case(Seed::from_entropy(), 8)]
#[trace]
#[case(Seed::from_entropy(), 16)]
#[trace]
#[case(Seed::from_entropy(), 32)]
#[trace]
#[case(Seed::from_entropy(), 64)]
fn single_proof_eight_leaves_tamper_with_leaf(#[case] seed: Seed, #[case] leaf_count: usize) {
    let mut rng = make_seedable_rng(seed);

    let leaves = gen_leaves(leaf_count);
    let t = MerkleTree::from_leaves(leaves).unwrap();

    for leaf_index in 0..leaf_count {
        let proof = SingleProofNodes::from_tree_leaf(&t, leaf_index).unwrap().into_values();

        // Use a botched leaf
        assert!(!proof.verify(H256::random_using(&mut rng), t.root()).unwrap());
    }
}
