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

use merkletree_mintlayer::{tree::MerkleTree, MerkleTreeFormError};

use crate::{
    chain::SignedTransaction,
    primitives::id::{self, Idable, H256},
};

use super::{merkle_tools::MerkleHasher, BlockBody};

fn tx_hasher(tx: &SignedTransaction) -> H256 {
    tx.transaction().get_id().to_hash()
}

fn tx_witness_hasher(tx: &SignedTransaction) -> H256 {
    tx.serialized_hash()
}

pub fn calculate_tx_merkle_tree(
    body: &BlockBody,
) -> Result<MerkleTree<H256, MerkleHasher>, MerkleTreeFormError> {
    calculate_generic_merkle_tree(tx_hasher, body)
}

pub fn calculate_witness_merkle_tree(
    body: &BlockBody,
) -> Result<MerkleTree<H256, MerkleHasher>, MerkleTreeFormError> {
    calculate_generic_merkle_tree(tx_witness_hasher, body)
}

/// Calculate the merkle tree for the given body of the block.
fn calculate_generic_merkle_tree(
    tx_hasher: fn(&SignedTransaction) -> H256,
    body: &BlockBody,
) -> Result<MerkleTree<H256, MerkleHasher>, MerkleTreeFormError> {
    let rewards_hash = id::hash_encoded(&body.reward);

    let hashes: Vec<H256> = std::iter::once(rewards_hash)
        .chain(body.transactions.iter().map(tx_hasher))
        .collect();
    let tree = MerkleTree::<H256, MerkleHasher>::from_leaves(hashes)?;
    Ok(tree)
}
