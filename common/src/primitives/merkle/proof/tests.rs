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
fn single_proof_eight_leaves() {
    let v1 = default_hash(H256::zero());
    let v2 = default_hash(H256::from_low_u64_be(1));
    let v3 = default_hash(H256::from_low_u64_be(2));
    let v4 = default_hash(H256::from_low_u64_be(3));
    let v5 = default_hash(H256::from_low_u64_be(4));
    let v6 = default_hash(H256::from_low_u64_be(5));
    let v7 = default_hash(H256::from_low_u64_be(6));
    let v8 = default_hash(H256::from_low_u64_be(7));

    let t = MerkleTree::from_leaves(vec![v1, v2, v3, v4, v5, v6, v7, v8]).unwrap();

    let p0 = t.proof_from_leaf(0).unwrap().unwrap();
    assert_eq!(p0.proof().len(), 3);
    assert_eq!(p0.proof()[0].position(), (0, 1));
    assert_eq!(p0.proof()[1].position(), (1, 1));
    assert_eq!(p0.proof()[2].position(), (2, 1));
}
