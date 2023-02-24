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
        assert_eq!(p0.branch().len(), 0);

        assert!(p0.into_values().verify(leaves[leaf_index], t.root()).is_none());
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
        assert_eq!(p0.branch().len(), 1);
        assert_eq!(p0.branch()[0].abs_index(), 1);

        assert!(p0.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 1;
        let p1 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p1.branch().len(), 1);
        assert_eq!(p1.branch()[0].abs_index(), 0);

        assert!(p1.into_values().verify(leaves[leaf_index], t.root()).unwrap());
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
        assert_eq!(p0.branch().len(), 2);
        assert_eq!(p0.branch()[0].abs_index(), 1);
        assert_eq!(p0.branch()[1].abs_index(), 5);

        assert!(p0.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 1;
        let p1 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p1.branch().len(), 2);
        assert_eq!(p1.branch()[0].abs_index(), 0);
        assert_eq!(p1.branch()[1].abs_index(), 5);

        assert!(p1.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 2;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.branch().len(), 2);
        assert_eq!(p2.branch()[0].abs_index(), 3);
        assert_eq!(p2.branch()[1].abs_index(), 4);

        assert!(p2.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 3;
        let p3 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p3.branch().len(), 2);
        assert_eq!(p3.branch()[0].abs_index(), 2);
        assert_eq!(p3.branch()[1].abs_index(), 4);

        assert!(p3.into_values().verify(leaves[leaf_index], t.root()).unwrap());
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
        assert_eq!(p0.branch().len(), 3);
        assert_eq!(p0.branch()[0].abs_index(), 1);
        assert_eq!(p0.branch()[1].abs_index(), 9);
        assert_eq!(p0.branch()[2].abs_index(), 13);

        assert!(p0.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 1;
        let p1 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p1.branch().len(), 3);
        assert_eq!(p1.branch()[0].abs_index(), 0);
        assert_eq!(p1.branch()[1].abs_index(), 9);
        assert_eq!(p1.branch()[2].abs_index(), 13);

        assert!(p1.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 2;
        let p2 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p2.branch().len(), 3);
        assert_eq!(p2.branch()[0].abs_index(), 3);
        assert_eq!(p2.branch()[1].abs_index(), 8);
        assert_eq!(p2.branch()[2].abs_index(), 13);

        assert!(p2.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 3;
        let p3 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p3.branch().len(), 3);
        assert_eq!(p3.branch()[0].abs_index(), 2);
        assert_eq!(p3.branch()[1].abs_index(), 8);
        assert_eq!(p3.branch()[2].abs_index(), 13);

        assert!(p3.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 4;
        let p4 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p4.branch().len(), 3);
        assert_eq!(p4.branch()[0].abs_index(), 5);
        assert_eq!(p4.branch()[1].abs_index(), 11);
        assert_eq!(p4.branch()[2].abs_index(), 12);

        assert!(p4.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 5;
        let p5 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p5.branch().len(), 3);
        assert_eq!(p5.branch()[0].abs_index(), 4);
        assert_eq!(p5.branch()[1].abs_index(), 11);
        assert_eq!(p5.branch()[2].abs_index(), 12);

        assert!(p5.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 6;
        let p6 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p6.branch().len(), 3);
        assert_eq!(p6.branch()[0].abs_index(), 7);
        assert_eq!(p6.branch()[1].abs_index(), 10);
        assert_eq!(p6.branch()[2].abs_index(), 12);

        assert!(p6.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
    {
        let leaf_index = 7;
        let p7 = t.proof_from_leaf(leaf_index).unwrap();
        assert_eq!(p7.branch().len(), 3);
        assert_eq!(p7.branch()[0].abs_index(), 6);
        assert_eq!(p7.branch()[1].abs_index(), 10);
        assert_eq!(p7.branch()[2].abs_index(), 12);

        assert!(p7.into_values().verify(leaves[leaf_index], t.root()).unwrap());
    }
}
