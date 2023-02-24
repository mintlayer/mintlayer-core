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

use crate::primitives::{id::default_hash, merkle::tree::MerkleTree, H256};

fn gen_leaves(n: usize) -> Vec<H256> {
    (0..n).map(|i| default_hash(H256::from_low_u64_be(i as u64))).collect()
}

#[test]
fn single_proof_one_leaf() {
    let v0 = default_hash(H256::zero());

    let leaves = vec![v0];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let leaf_index = 0;
    let p0 = t.proof_from_leaf(leaf_index).unwrap();
    assert_eq!(p0.branch().len(), 0);

    assert!(p0.into_values().verify(leaves[leaf_index], t.root()).is_none());
}

#[rstest]
#[case(0, &[1])]
#[case(1, &[0])]
fn single_proof_two_leaves(#[case] leaf_index: usize, #[case] branch: &[usize]) {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));

    let leaves = vec![v0, v1];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let p = t.proof_from_leaf(leaf_index).unwrap();
    assert_eq!(
        p.branch().iter().map(|n| n.abs_index()).collect::<Vec<_>>(),
        branch
    );
    assert!(p.into_values().verify(leaves[leaf_index], t.root()).unwrap());
}

#[rstest]
#[case(0, &[1,5])]
#[case(1, &[0,5])]
#[case(2, &[3,4])]
#[case(3, &[2,4])]
fn single_proof_four_leaves(#[case] leaf_index: usize, #[case] branch: &[usize]) {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));
    let v2 = default_hash(H256::from_low_u64_be(2));
    let v3 = default_hash(H256::from_low_u64_be(3));

    let leaves = vec![v0, v1, v2, v3];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let p = t.proof_from_leaf(leaf_index).unwrap();
    assert_eq!(
        p.branch().iter().map(|n| n.abs_index()).collect::<Vec<_>>(),
        branch
    );

    assert!(p.into_values().verify(leaves[leaf_index], t.root()).unwrap());
}

#[rstest]
#[case(0, &[1,9,13])]
#[case(1, &[0,9,13])]
#[case(2, &[3,8,13])]
#[case(3, &[2,8,13])]
#[case(4, &[5,11,12])]
#[case(5, &[4,11,12])]
#[case(6, &[7,10,12])]
#[case(7, &[6,10,12])]
fn single_proof_eight_leaves(#[case] leaf_index: usize, #[case] branch: &[usize]) {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));
    let v2 = default_hash(H256::from_low_u64_be(2));
    let v3 = default_hash(H256::from_low_u64_be(3));
    let v4 = default_hash(H256::from_low_u64_be(4));
    let v5 = default_hash(H256::from_low_u64_be(5));
    let v6 = default_hash(H256::from_low_u64_be(6));
    let v7 = default_hash(H256::from_low_u64_be(7));

    let leaves = vec![v0, v1, v2, v3, v4, v5, v6, v7];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let p = t.proof_from_leaf(leaf_index).unwrap();
    assert_eq!(
        p.branch().iter().map(|n| n.abs_index()).collect::<Vec<_>>(),
        branch
    );

    assert!(p.into_values().verify(leaves[leaf_index], t.root()).unwrap());
}

#[rstest]
#[case(Seed::from_entropy(), 2)]
#[case(Seed::from_entropy(), 4)]
#[case(Seed::from_entropy(), 8)]
#[case(Seed::from_entropy(), 16)]
#[case(Seed::from_entropy(), 32)]
#[case(Seed::from_entropy(), 64)]
fn single_proof_eight_leaves_tamper_with_nodes(#[case] seed: Seed, #[case] leaf_count: usize) {
    let mut rng = make_seedable_rng(seed);

    let leaves = gen_leaves(leaf_count);
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    for (leaf_index, _) in leaves.iter().enumerate() {
        let proof = t.proof_from_leaf(leaf_index).unwrap().into_values();

        // Tamper with the proof
        for node_index in 0..proof.branch.len() {
            let mut p = proof.clone();
            p.branch[node_index] = H256::random_using(&mut rng);
            assert!(!p.verify(leaves[leaf_index], t.root()).unwrap());
        }
    }
}

#[rstest]
#[case(Seed::from_entropy(), 2)]
#[case(Seed::from_entropy(), 4)]
#[case(Seed::from_entropy(), 8)]
#[case(Seed::from_entropy(), 16)]
#[case(Seed::from_entropy(), 32)]
#[case(Seed::from_entropy(), 64)]
fn single_proof_eight_leaves_tamper_with_leaf(#[case] seed: Seed, #[case] leaf_count: usize) {
    let mut rng = make_seedable_rng(seed);

    let leaves = gen_leaves(leaf_count);
    let t = MerkleTree::from_leaves(leaves).unwrap();

    for leaf_index in 0..leaf_count {
        let proof = t.proof_from_leaf(leaf_index).unwrap().into_values();

        // Use a botched leaf
        assert!(!proof.verify(H256::random_using(&mut rng), t.root()).unwrap());
    }
}
