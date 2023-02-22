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

use crate::primitives::{id::default_hash, merkle::tree::MerkleTree, H256};

#[test]
fn single_proof_one_leaf() {
    let v0 = default_hash(H256::zero());

    let leaves = vec![v0];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    {
        let leaf_index = 0;
        let p0 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p0.proof().len(), 0);

        assert!(p0.verify(leaves[leaf_index], t.root()));
    }
}

#[test]
fn single_proof_two_leaves() {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));

    let leaves = vec![v0, v1];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    {
        let leaf_index = 0;
        let p0 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p0.proof().len(), 1);
        assert_eq!(p0.proof()[0].position(), (0, 1));

        assert!(p0.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 1;
        let p1 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p1.proof().len(), 1);
        assert_eq!(p1.proof()[0].position(), (0, 0));

        assert!(p1.verify(leaves[leaf_index], t.root()));
    }
}

#[test]
fn single_proof_four_leaves() {
    let v0 = default_hash(H256::zero());
    let v1 = default_hash(H256::from_low_u64_be(1));
    let v2 = default_hash(H256::from_low_u64_be(2));
    let v3 = default_hash(H256::from_low_u64_be(3));

    let leaves = vec![v0, v1, v2, v3];
    let t = MerkleTree::from_leaves(leaves.clone()).unwrap();

    {
        let leaf_index = 0;
        let p0 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p0.proof().len(), 2);
        assert_eq!(p0.proof()[0].position(), (0, 1));
        assert_eq!(p0.proof()[1].position(), (1, 1));

        assert!(p0.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 1;
        let p1 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p1.proof().len(), 2);
        assert_eq!(p1.proof()[0].position(), (0, 0));
        assert_eq!(p1.proof()[1].position(), (1, 1));

        assert!(p1.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 2;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 2);
        assert_eq!(p2.proof()[0].position(), (0, 3));
        assert_eq!(p2.proof()[1].position(), (1, 0));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 3;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 2);
        assert_eq!(p2.proof()[0].position(), (0, 2));
        assert_eq!(p2.proof()[1].position(), (1, 0));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
}

#[test]
fn single_proof_eight_leaves() {
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

    {
        let leaf_index = 0;
        let p0 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p0.proof().len(), 3);
        assert_eq!(p0.proof()[0].position(), (0, 1));
        assert_eq!(p0.proof()[1].position(), (1, 1));
        assert_eq!(p0.proof()[2].position(), (2, 1));

        assert!(p0.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 1;
        let p1 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p1.proof().len(), 3);
        assert_eq!(p1.proof()[0].position(), (0, 0));
        assert_eq!(p1.proof()[1].position(), (1, 1));
        assert_eq!(p1.proof()[2].position(), (2, 1));

        assert!(p1.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 2;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 3);
        assert_eq!(p2.proof()[0].position(), (0, 3));
        assert_eq!(p2.proof()[1].position(), (1, 0));
        assert_eq!(p2.proof()[2].position(), (2, 1));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 3;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 3);
        assert_eq!(p2.proof()[0].position(), (0, 2));
        assert_eq!(p2.proof()[1].position(), (1, 0));
        assert_eq!(p2.proof()[2].position(), (2, 1));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 4;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 3);
        assert_eq!(p2.proof()[0].position(), (0, 5));
        assert_eq!(p2.proof()[1].position(), (1, 3));
        assert_eq!(p2.proof()[2].position(), (2, 0));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 5;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 3);
        assert_eq!(p2.proof()[0].position(), (0, 4));
        assert_eq!(p2.proof()[1].position(), (1, 3));
        assert_eq!(p2.proof()[2].position(), (2, 0));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 6;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 3);
        assert_eq!(p2.proof()[0].position(), (0, 7));
        assert_eq!(p2.proof()[1].position(), (1, 2));
        assert_eq!(p2.proof()[2].position(), (2, 0));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
    {
        let leaf_index = 7;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.proof().len(), 3);
        assert_eq!(p2.proof()[0].position(), (0, 6));
        assert_eq!(p2.proof()[1].position(), (1, 2));
        assert_eq!(p2.proof()[2].position(), (2, 0));

        assert!(p2.verify(leaves[leaf_index], t.root()));
    }
}
